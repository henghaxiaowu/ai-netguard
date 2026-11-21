use crate::healthcheck::{encode_powershell_encoded_command, encode_utf8_b64};
use crate::models::{
    app_data_dir, default_browser_profiles, AppConfig, BrowserFingerprintMode, BrowserProfile,
    DownloadProgress, LogBuffer,
};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use url::Url;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const FALLBACK_CHROMIUM_URL: &str = "https://github.com/ungoogled-software/ungoogled-chromium-windows/releases/download/157.0.8103.78-1.1/ungoogled-chromium_157.0.8103.78-1.1_windows_x64.zip";
const FALLBACK_CHROMIUM_SHA256: &str =
    "2b1d113b055f827b573cd1fa2bc46511691c0aa427802397cfc05e52350ef212";
const MAX_ZIP_ENTRIES: usize = 20_000;
const MAX_ZIP_UNCOMPRESSED_BYTES: u64 = 1_500_000_000;

pub(crate) struct KillOnCloseJob(OwnedHandle);

impl KillOnCloseJob {
    pub(crate) fn new() -> windows::core::Result<Self> {
        unsafe {
            let handle = CreateJobObjectW(None, None)?;
            let job = OwnedHandle::from_raw_handle(handle.0);
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                std::mem::size_of_val(&limits) as u32,
            )?;
            Ok(Self(job))
        }
    }

    pub(crate) fn assign(&self, child: &Child) -> windows::core::Result<()> {
        unsafe {
            AssignProcessToJobObject(
                HANDLE(self.0.as_raw_handle()),
                HANDLE(child.as_raw_handle()),
            )
        }
    }
}

pub struct ProcessLauncher {
    job: Option<KillOnCloseJob>,
    browser_children: HashMap<String, Child>,
    desktop_child: Option<Child>,
}

impl ProcessLauncher {
    pub fn new() -> Self {
        Self {
            job: KillOnCloseJob::new().ok(),
            browser_children: HashMap::new(),
            desktop_child: None,
        }
    }

    fn assign_to_job(&self, child: &Child) {
        if let Some(job) = &self.job {
            let _ = job.assign(child);
        }
    }

    pub fn is_profile_running(&mut self, profile_id: &str) -> bool {
        if let Some(child) = self.browser_children.get_mut(profile_id) {
            match child.try_wait() {
                Ok(None) => return true,
                _ => {
                    self.browser_children.remove(profile_id);
                }
            }
        }
        false
    }

    pub fn running_browser_profile_ids(&mut self) -> Vec<String> {
        self.browser_children
            .retain(|_, child| matches!(child.try_wait(), Ok(None)));
        let mut ids: Vec<String> = self.browser_children.keys().cloned().collect();
        ids.sort();
        ids
    }

    pub fn is_browser_running(&mut self) -> bool {
        !self.running_browser_profile_ids().is_empty()
    }

    pub fn close_browser_profile(&mut self, profile_id: &str) -> bool {
        if let Some(mut child) = self.browser_children.remove(profile_id) {
            if matches!(child.try_wait(), Ok(None)) {
                let _ = child.kill();
                let _ = child.wait();
                return true;
            }
        }
        false
    }

    pub fn resolve_browser_path(&self, cfg: &AppConfig) -> Option<PathBuf> {
        if let Some(custom) = cfg.custom_browser_path.as_deref() {
            let p = PathBuf::from(custom.trim());
            if !custom.trim().is_empty() && p.exists() {
                return Some(p);
            }
        }
        let dir = app_data_dir().join("browser");
        find_chrome_exe_in(&dir)
    }

    pub fn resolve_claude_desktop_path(&self, cfg: &AppConfig) -> Option<PathBuf> {
        if let Some(custom) = cfg.claude_desktop_path.as_deref() {
            let p = PathBuf::from(custom.trim());
            if !custom.trim().is_empty() && p.exists() {
                return Some(p);
            }
        }
        let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from)?;
        let anthropic_dir = local.join("AnthropicClaude");
        if let Some(app_exe) = find_latest_squirrel_claude_exe(&anthropic_dir) {
            return Some(app_exe);
        }
        for cand in [
            anthropic_dir.join("claude.exe"),
            local.join("Programs").join("claude-desktop").join("Claude.exe"),
        ] {
            if cand.exists() {
                return Some(cand);
            }
        }
        None
    }

    pub fn resolve_claude_desktop_wfp_paths(&self, cfg: &AppConfig) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(main_exe) = self.resolve_claude_desktop_path(cfg) {
            paths.push(main_exe);
        }
        if let Some(local) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            let dir = local.join("AnthropicClaude");
            for name in ["claude.exe", "Update.exe"] {
                let p = dir.join(name);
                if p.exists() && !paths.contains(&p) {
                    paths.push(p);
                }
            }
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let fname = entry.file_name().to_string_lossy().to_lowercase();
                    if fname.starts_with("app-") && entry.path().is_dir() {
                        for sub in ["claude.exe", "squirrel.exe"] {
                            let p = entry.path().join(sub);
                            if p.exists() && !paths.contains(&p) {
                                paths.push(p);
                            }
                        }
                    }
                }
            }
        }
        paths
    }

    pub fn detect_claude_cli(&self) -> Option<PathBuf> {
        let output = Command::new("where.exe")
            .arg("claude")
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.lines().next().map(|s| PathBuf::from(s.trim()))
    }

    pub fn ensure_strict_cli_shim(&self) -> Result<(PathBuf, Option<PathBuf>), String> {
        let cli_path = self
            .detect_claude_cli()
            .ok_or("未在系统 PATH 中检测到 claude CLI")?;
        let bin_dir = app_data_dir().join("bin");
        fs::create_dir_all(&bin_dir).map_err(|e| e.to_string())?;

        // Check if claude is an npm .cmd shim backed by node.exe + cli.js
        let ext = cli_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if ext == "exe" {
            let shim = bin_dir.join("ai-claude.exe");
            copy_if_changed(&cli_path, &shim)?;
            return Ok((shim, None));
        }

        // Locate node.exe and @anthropic-ai/claude-code/cli.js
        let node_out = Command::new("where.exe")
            .arg("node")
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("定位 node.exe 失败: {e}"))?;
        let node_path = String::from_utf8_lossy(&node_out.stdout)
            .lines()
            .next()
            .map(|s| PathBuf::from(s.trim()))
            .filter(|p| p.exists())
            .ok_or("未找到 node.exe，无法构建独立 ai-node.exe 沙盒")?;

        let shim = bin_dir.join("ai-node.exe");
        copy_if_changed(&node_path, &shim)?;

        let appdata = std::env::var_os("APPDATA").map(PathBuf::from);
        let cli_js = appdata
            .map(|d| {
                d.join("npm")
                    .join("node_modules")
                    .join("@anthropic-ai")
                    .join("claude-code")
                    .join("cli.js")
            })
            .filter(|p| p.exists())
            .or_else(|| {
                cli_path.parent().map(|d| {
                    d.join("node_modules")
                        .join("@anthropic-ai")
                        .join("claude-code")
                        .join("cli.js")
                })
            })
            .filter(|p| p.exists());

        Ok((shim, cli_js))
    }

    pub fn launch_browser_url(
        &mut self,
        cfg: &AppConfig,
        target_url: &str,
        logs: Arc<LogBuffer>,
    ) -> Result<String, String> {
        let profile = cfg
            .browser_profiles
            .iter()
            .find(|p| p.id == "default")
            .cloned()
            .unwrap_or_else(|| default_browser_profiles().into_iter().next().unwrap());
        let bound_node_id = profile
            .node_id
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(cfg.active_node_id.as_str());
        let bound_node = cfg.nodes.iter().find(|n| n.id == bound_node_id);
        let tz = profile
            .fingerprint
            .timezone
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| bound_node.and_then(|n| n.timezone.as_deref()).map(str::trim).filter(|s| !s.is_empty()))
            .unwrap_or("Asia/Seoul")
            .to_string();
        let locale = profile
            .fingerprint
            .locale
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| bound_node.and_then(|n| n.locale.as_deref()).map(str::trim).filter(|s| !s.is_empty()))
            .unwrap_or("ko-KR")
            .to_string();
        let node_label = bound_node
            .map(|n| n.name.clone())
            .unwrap_or_else(|| "主出口".into());

        self.launch_browser_profile(
            cfg,
            &profile,
            cfg.browser_port,
            &node_label,
            &tz,
            &locale,
            target_url,
            logs,
        )
    }

    pub fn launch_browser_profile(
        &mut self,
        cfg: &AppConfig,
        profile: &BrowserProfile,
        socks_port: u16,
        node_label: &str,
        effective_tz: &str,
        effective_locale: &str,
        target_url: &str,
        logs: Arc<LogBuffer>,
    ) -> Result<String, String> {
        let exe = self
            .resolve_browser_path(cfg)
            .ok_or("未安装专属防泄漏浏览器，请先点击下载或指定便携 Chromium 路径")?;

        if !target_url.starts_with("https://") {
            return Err("出于安全考虑，专属浏览器仅允许启动 https:// 目标地址".into());
        }

        let (profile_dir, _) = profile_storage_dirs(&profile.id)?;
        let should_inject_ext = matches!(
            profile.fingerprint_mode,
            BrowserFingerprintMode::IsolatedFingerprint
        ) || cfg.align_fingerprint;
        let locale_for_prefs = should_inject_ext.then_some(effective_locale);
        harden_browser_preferences(&profile_dir, locale_for_prefs)?;

        // If this exact profile window is already running, opening the URL passes a new tab
        // into that profile's isolated process without affecting any other profile.
        if self.is_profile_running(&profile.id) {
            Command::new(&exe)
                .arg(format!("--user-data-dir={}", profile_dir.display()))
                .arg(target_url)
                .spawn()
                .map_err(|e| format!("在浏览器环境 [{}] 打开页面失败: {e}", profile.name))?;
            logs.push(format!(
                "已在浏览器环境 [{}] ({node_label}) 打开: {target_url}",
                profile.name
            ));
            return Ok(format!("已在 [{}] 打开 {target_url}", profile.name));
        }

        let mut cmd = Command::new(&exe);
        cmd.arg(format!("--user-data-dir={}", profile_dir.display()))
            .arg(format!("--proxy-server=socks5://127.0.0.1:{socks_port}"))
            .arg("--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1")
            .arg("--force-webrtc-ip-handling-policy")
            .arg("--webrtc-ip-handling-policy=disable_non_proxied_udp")
            .arg("--disable-quic")
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--disable-sync")
            .arg("--disable-background-networking");

        if should_inject_ext {
            cmd.arg(format!("--lang={effective_locale}"));
            let ext_dir = ensure_profile_fingerprint_extension(profile, effective_tz, effective_locale)?;
            cmd.arg("--disable-features=DisableLoadExtensionCommandLineSwitch")
                .arg(format!("--load-extension={}", ext_dir.display()));
        }

        if matches!(
            profile.fingerprint_mode,
            BrowserFingerprintMode::IsolatedFingerprint
        ) {
            let sw = profile.fingerprint.screen_width.clamp(800, 3840);
            let sh = profile.fingerprint.screen_height.clamp(600, 2160);
            cmd.arg(format!("--window-size={sw},{sh}"));
            if let Some(ua) = profile
                .fingerprint
                .user_agent
                .as_deref()
                .map(|s| s.chars().filter(|c| !c.is_control()).collect::<String>())
            {
                let trimmed = ua.trim();
                if !trimmed.is_empty() {
                    cmd.arg(format!("--user-agent={trimmed}"));
                }
            }
        }

        cmd.arg(target_url);

        let child = cmd
            .spawn()
            .map_err(|e| format!("启动浏览器环境 [{}] 失败: {e}", profile.name))?;
        self.assign_to_job(&child);
        self.browser_children.insert(profile.id.clone(), child);

        let mode_label = match profile.fingerprint_mode {
            BrowserFingerprintMode::CleanAlign => "纯净对齐",
            BrowserFingerprintMode::IsolatedFingerprint => "完整独立指纹",
        };
        logs.push(format!(
            "已启动浏览器环境 [{}] ({mode_label}, 出口: {node_label}, SOCKS5 127.0.0.1:{socks_port}) -> {target_url}",
            profile.name
        ));
        Ok(format!(
            "已启动 [{}] -> {node_label} (:{socks_port})",
            profile.name
        ))
    }

    pub fn is_desktop_running(&mut self) -> bool {
        if let Some(child) = &mut self.desktop_child {
            match child.try_wait() {
                Ok(None) => true,
                _ => {
                    self.desktop_child = None;
                    false
                }
            }
        } else {
            false
        }
    }

    pub fn launch_claude_desktop(
        &mut self,
        cfg: &AppConfig,
        pac_port: u16,
        logs: Arc<LogBuffer>,
    ) -> Result<String, String> {
        let exe = self
            .resolve_claude_desktop_path(cfg)
            .ok_or("未检测到 Windows 版 Claude Desktop，请在“规则与隔离加固”中指定 Claude.exe 路径")?;

        // If user launched an untracked Claude instance from Start Menu earlier, close it first
        // so Electron's single-instance lock won't ignore our --proxy-pac-url argument.
        if !self.is_desktop_running() {
            let _ = Command::new("taskkill.exe")
                .args(["/IM", "claude.exe", "/F"])
                .creation_flags(CREATE_NO_WINDOW)
                .output();
            for _ in 0..15 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                let alive = Command::new("tasklist.exe")
                    .args(["/FI", "IMAGENAME eq claude.exe", "/NH"])
                    .creation_flags(CREATE_NO_WINDOW)
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase().contains("claude.exe"))
                    .unwrap_or(false);
                if !alive {
                    break;
                }
            }
        }

        if let Some(appdata) = std::env::var_os("APPDATA").map(PathBuf::from) {
            let claude_pref = appdata.join("Claude").join("Preferences");
            let _ = sanitize_claude_preferences_file(&claude_pref);
        }

        // NOTE: Claude Desktop 3.6556.2 explicitly rejects `--proxy-server` and `--host-resolver-rules`,
        // but honors `--proxy-pac-url` cleanly! Combined with WFP port-locked loopback and sing-box
        // protocol:quic/IPv6 reject rules, 100% of traffic exits via our SOCKS5 proxy at `browser_port`
        // without injecting `--disable-quic`/`--lang` anomalies into Electron attestation checks.
        let clean_env = crate::app_env::build_clean_base_env();
        let mut cmd = Command::new(&exe);
        cmd.env_clear()
            .envs(&clean_env)
            .arg(format!("--proxy-pac-url=http://127.0.0.1:{pac_port}/proxy.pac"))
            .arg("--force-webrtc-ip-handling-policy")
            .arg("--webrtc-ip-handling-policy=disable_non_proxied_udp")
            .env("HTTP_PROXY", format!("http://127.0.0.1:{}", cfg.cli_port))
            .env("HTTPS_PROXY", format!("http://127.0.0.1:{}", cfg.cli_port))
            .env("ALL_PROXY", format!("socks5h://127.0.0.1:{}", cfg.cli_port))
            .env("NO_PROXY", &cfg.extra_no_proxy);

        let child = cmd
            .spawn()
            .map_err(|e| format!("启动 Claude Desktop 失败: {e}"))?;
        self.assign_to_job(&child);
        self.desktop_child = Some(child);
        logs.push(format!(
            "已通过 PAC 代理 (127.0.0.1:{pac_port} -> SOCKS5 :{}) 启动 Claude Desktop ({})",
            cfg.browser_port,
            exe.display()
        ));
        Ok("Claude Desktop 已在安全隔离模式下启动".into())
    }

    pub fn launch_claude_terminal(
        &self,
        cfg: &AppConfig,
        work_dir: &str,
        strict_wfp: bool,
        logs: Arc<LogBuffer>,
    ) -> Result<String, String> {
        let http_proxy = format!("http://127.0.0.1:{}", cfg.cli_port);
        let socks_proxy = format!("socks5h://127.0.0.1:{}", cfg.cli_port);

        let strict_hint = if strict_wfp {
            let (shim, cli_js) = self.ensure_strict_cli_shim()?;
            let shim_b64 = encode_utf8_b64(&shim.to_string_lossy());
            if let Some(js) = cli_js {
                let js_b64 = encode_utf8_b64(&js.to_string_lossy());
                format!(
                    "$__ngShim = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{shim_b64}')); \
                     $__ngJs = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{js_b64}')); \
                     $env:AI_CLAUDE_SHIM = $__ngShim; \
                     function claude {{ & $__ngShim $__ngJs @args }}; \
                     Write-Host '[AI NetGuard] 严格 WFP 锁死模式已启用 (ai-node.exe)' -ForegroundColor Green"
                )
            } else {
                format!(
                    "$__ngShim = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{shim_b64}')); \
                     function claude {{ & $__ngShim @args }}; \
                     Write-Host '[AI NetGuard] 严格 WFP 锁死模式已启用 (ai-claude.exe)' -ForegroundColor Green"
                )
            }
        } else {
            "Write-Host '[AI NetGuard] 智能分流安全终端已就绪 (Anthropic -> 干净出口, 内网走 NO_PROXY)' -ForegroundColor Cyan".to_string()
        };

        let clean_no_proxy: String = cfg
            .extra_no_proxy
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        let no_proxy_b64 = encode_utf8_b64(&clean_no_proxy);
        let init_ps = format!(
            "$env:HTTP_PROXY='{http_proxy}'; \
             $env:HTTPS_PROXY='{http_proxy}'; \
             $env:ALL_PROXY='{socks_proxy}'; \
             $env:NO_PROXY=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{no_proxy_b64}')); \
             {strict_hint}"
        );
        let encoded_cmd = encode_powershell_encoded_command(&init_ps);

        let target_dir = if Path::new(work_dir).exists() {
            work_dir
        } else {
            "C:\\"
        };

        // Pass Base64 UTF-16LE -EncodedCommand so NO_PROXY quotes/Unicode characters cannot break parsing.
        let wt_res = Command::new("wt.exe")
            .args([
                "-d",
                target_dir,
                "powershell.exe",
                "-NoLogo",
                "-NoExit",
                "-EncodedCommand",
                &encoded_cmd,
            ])
            .spawn();

        if wt_res.is_err() {
            Command::new("powershell.exe")
                .args(["-NoLogo", "-NoExit", "-EncodedCommand", &encoded_cmd])
                .current_dir(target_dir)
                .spawn()
                .map_err(|e| format!("启动安全终端失败: {e}"))?;
        }

        logs.push(format!("已打开安全终端 (工作目录: {target_dir}, 严格模式: {strict_wfp})"));
        Ok("安全终端已打开".into())
    }
}

#[derive(Deserialize)]
struct GhRelease {
    assets: Vec<GhAsset>,
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    digest: Option<String>,
}

fn parse_sha256_digest(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let hex_part = trimmed
        .strip_prefix("sha256:")
        .or_else(|| trimmed.strip_prefix("SHA256:"))
        .unwrap_or(trimmed);
    if hex_part.len() == 64 && hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hex_part.to_ascii_lowercase())
    } else {
        None
    }
}

fn is_allowed_chromium_url(url_str: &str) -> bool {
    let Ok(url) = Url::parse(url_str) else {
        return false;
    };
    url.scheme() == "https"
        && matches!(
            url.host_str(),
            Some("github.com") | Some("objects.githubusercontent.com") | Some("release-assets.githubusercontent.com")
        )
        && if url.host_str() == Some("github.com") {
            url.path()
                .starts_with("/ungoogled-software/ungoogled-chromium-windows/releases/download/")
        } else {
            true
        }
}

fn parse_expanded_assets_html(html: &str) -> Option<(String, String)> {
    let marker = "/ungoogled-software/ungoogled-chromium-windows/releases/download/";
    let mut search_from = 0usize;
    while let Some(rel_idx) = html[search_from..].find(marker) {
        let abs_start = search_from + rel_idx;
        let rest = &html[abs_start..];
        let end_quote = rest.find('"')?;
        let rel_path = &rest[..end_quote];
        if rel_path.ends_with("windows_x64.zip") {
            let full_url = format!("https://github.com{rel_path}");
            let block_end = html[abs_start..]
                .find("</a>")
                .map(|a| {
                    let after_a = abs_start + a + 4;
                    let next_row = html[after_a..].find("<a href=").unwrap_or(4096);
                    (after_a + next_row).min(html.len())
                })
                .unwrap_or((abs_start + 4096).min(html.len()));
            let row = &html[abs_start..block_end];
            if let Some(sha_pos) = row.find("sha256:") {
                let candidate = &row[sha_pos + 7..];
                if candidate.len() >= 64 {
                    if let Some(hash) = parse_sha256_digest(&candidate[..64]) {
                        return Some((full_url, hash));
                    }
                }
            }
        }
        search_from = abs_start + marker.len();
    }
    None
}

async fn resolve_chromium_download(client: &reqwest::Client) -> (String, String) {
    if let Ok(resp) = client
        .get("https://api.github.com/repos/ungoogled-software/ungoogled-chromium-windows/releases/latest")
        .send()
        .await
    {
        if resp.status().is_success() {
            if let Ok(rel) = resp.json::<GhRelease>().await {
                if let Some(asset) = rel
                    .assets
                    .into_iter()
                    .find(|a| a.name.ends_with("windows_x64.zip"))
                {
                    if let Some(digest) = asset.digest.as_deref().and_then(parse_sha256_digest) {
                        if is_allowed_chromium_url(&asset.browser_download_url) {
                            return (asset.browser_download_url, digest);
                        }
                    }
                }
            }
        }
    }

    // Fallback metadata lookup via GitHub release redirect + expanded_assets HTML (not API rate-limited)
    if let Ok(latest_resp) = client
        .get("https://github.com/ungoogled-software/ungoogled-chromium-windows/releases/latest")
        .send()
        .await
    {
        let resolved = latest_resp.url().as_str().to_string();
        if let Some(tag) = resolved.rsplit('/').next().filter(|t| !t.is_empty() && *t != "latest") {
            let expanded_url = format!(
                "https://github.com/ungoogled-software/ungoogled-chromium-windows/releases/expanded_assets/{tag}"
            );
            if let Ok(exp_resp) = client.get(&expanded_url).send().await {
                if exp_resp.status().is_success() {
                    if let Ok(html) = exp_resp.text().await {
                        if let Some((url, hash)) = parse_expanded_assets_html(&html) {
                            if is_allowed_chromium_url(&url) {
                                return (url, hash);
                            }
                        }
                    }
                }
            }
        }
    }

    (
        FALLBACK_CHROMIUM_URL.to_string(),
        FALLBACK_CHROMIUM_SHA256.to_string(),
    )
}

pub fn validate_and_strip_zip_entry_path(raw_name: &str) -> Result<Option<PathBuf>, String> {
    if raw_name.contains('\0') {
        return Err("ZIP 条目包含空字节，拒绝解压".into());
    }
    let normalized = raw_name.replace('\\', "/");
    if normalized.starts_with('/') || normalized.starts_with("//") {
        return Err(format!("ZIP 条目包含绝对路径: {raw_name}"));
    }

    let raw_segments: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    if raw_segments.is_empty() {
        return Ok(None);
    }

    // Validate EVERY segment BEFORE stripping the top-level directory so payloads like
    // `top/../../evil.txt` or `C:/evil.txt` cannot hide behind directory stripping.
    for seg in &raw_segments {
        if *seg == "." || *seg == ".." || seg.contains(':') || seg.chars().any(|c| c.is_control())
        {
            return Err(format!("ZIP 条目存在非法路径成分: {raw_name}"));
        }
    }

    let rest = &raw_segments[1..];
    if rest.is_empty() {
        return Ok(None);
    }

    let mut stripped = PathBuf::new();
    for seg in rest {
        stripped.push(seg);
    }
    if stripped.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(format!("ZIP 剥离顶层目录后仍含非普通路径成分: {raw_name}"));
    }
    Ok(Some(stripped))
}

fn ensure_no_symlink_components(root: &Path, dest: &Path) -> Result<(), String> {
    let rel = dest
        .strip_prefix(root)
        .map_err(|_| "目标路径逃逸解压根目录".to_string())?;
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        cur.push(comp);
        if let Ok(meta) = fs::symlink_metadata(&cur) {
            if meta.file_type().is_symlink() {
                return Err(format!("检测到符号链接目录或文件，拒绝写入: {}", cur.display()));
            }
        }
    }
    Ok(())
}

pub fn extract_chromium_zip_safe(zip_path: &Path, target_dir: &Path) -> Result<(), String> {
    if target_dir.exists() {
        let _ = fs::remove_dir_all(target_dir);
    }
    fs::create_dir_all(target_dir).map_err(|e| e.to_string())?;
    let canon_root = fs::canonicalize(target_dir).map_err(|e| e.to_string())?;

    let file = File::open(zip_path).map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(format!("ZIP 文件条目数过多 ({}), 拒绝解压", archive.len()));
    }

    let mut total_bytes: u64 = 0;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
        if entry.is_symlink()
            || entry
                .unix_mode()
                .map(|m| (m & 0o170000) == 0o120000)
                .unwrap_or(false)
        {
            return Err(format!("拒绝解压 ZIP 符号链接条目: {}", entry.name()));
        }
        if entry.enclosed_name().is_none() {
            return Err(format!("ZIP 条目含未封闭不安全路径: {}", entry.name()));
        }

        let Some(stripped) = validate_and_strip_zip_entry_path(entry.name())? else {
            continue;
        };

        let dest = target_dir.join(&stripped);
        ensure_no_symlink_components(target_dir, &dest)?;

        if entry.is_dir() {
            fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
            let canon_dir = fs::canonicalize(&dest).map_err(|e| e.to_string())?;
            if !canon_dir.starts_with(&canon_root) {
                return Err("解压目录越出目标根目录".into());
            }
        } else {
            let parent = dest.parent().ok_or("无效的目标文件父目录")?;
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            let canon_parent = fs::canonicalize(parent).map_err(|e| e.to_string())?;
            if !canon_parent.starts_with(&canon_root) {
                return Err("解压文件路径越出目标根目录".into());
            }

            let remaining = MAX_ZIP_UNCOMPRESSED_BYTES.saturating_sub(total_bytes);
            if remaining == 0 {
                return Err("ZIP 解压总大小超过安全上限".into());
            }
            let mut outfile = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&dest)
                .map_err(|e| format!("创建解压文件 {} 失败: {e}", dest.display()))?;
            let mut bounded = (&mut entry).take(remaining + 1);
            let written = std::io::copy(&mut bounded, &mut outfile).map_err(|e| e.to_string())?;
            total_bytes = total_bytes.saturating_add(written);
            if total_bytes > MAX_ZIP_UNCOMPRESSED_BYTES {
                return Err("ZIP 解压体积异常膨胀（疑似 Zip Bomb），已终止".into());
            }
        }
    }
    Ok(())
}

pub async fn download_and_install_browser(
    app: AppHandle,
    logs: Arc<LogBuffer>,
) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .user_agent("AI-NetGuard/0.1")
        .build()
        .map_err(|e| e.to_string())?;

    let (download_url, expected_sha256) = resolve_chromium_download(&client).await;
    if !is_allowed_chromium_url(&download_url) {
        return Err(format!("拒绝从非受信任来源下载浏览器: {download_url}"));
    }

    logs.push(format!(
        "开始下载便携版 Ungoogled-Chromium: {download_url} (SHA-256: {expected_sha256})"
    ));

    let resp = client
        .get(&download_url)
        .send()
        .await
        .map_err(|e| format!("下载请求失败: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("下载返回 HTTP {}", resp.status()));
    }

    let total = resp.content_length().unwrap_or(0);
    let zip_path = app_data_dir().join("ungoogled-chromium.zip");
    let mut out = File::create(&zip_path).map_err(|e| format!("创建临时压缩包失败: {e}"))?;
    let mut hasher = Sha256::new();

    let mut downloaded: u64 = 0;
    let mut last_emit = 0u64;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| format!("下载流中断: {e}"))?;
        hasher.update(&bytes);
        out.write_all(&bytes).map_err(|e| e.to_string())?;
        downloaded += bytes.len() as u64;
        if downloaded - last_emit >= 1024 * 512 || (total > 0 && downloaded >= total) {
            last_emit = downloaded;
            let _ = app.emit(
                "browser-download-progress",
                DownloadProgress {
                    stage: "downloading".into(),
                    downloaded_bytes: downloaded,
                    total_bytes: total,
                    message: format!(
                        "正在下载便携 Chromium ({:.1} MB / {:.1} MB)...",
                        downloaded as f64 / 1048576.0,
                        total as f64 / 1048576.0
                    ),
                },
            );
        }
    }
    drop(out);

    let actual_sha256 = hex::encode(hasher.finalize());
    if !guard_protocol::constant_time_eq_bytes(&actual_sha256, &expected_sha256) {
        let _ = fs::remove_file(&zip_path);
        return Err(format!(
            "Chromium 归档 SHA-256 校验失败: 预期 {expected_sha256}, 实际 {actual_sha256}"
        ));
    }
    logs.push(format!("Chromium 归档 SHA-256 校验通过 ({actual_sha256})"));

    let _ = app.emit(
        "browser-download-progress",
        DownloadProgress {
            stage: "extracting".into(),
            downloaded_bytes: downloaded,
            total_bytes: total,
            message: "SHA-256 校验通过，正在安全解压到独立目录...".into(),
        },
    );

    let target_dir = app_data_dir().join("browser");
    let zip_clone = zip_path.clone();
    let target_clone = target_dir.clone();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let res = extract_chromium_zip_safe(&zip_clone, &target_clone);
        let _ = fs::remove_file(&zip_clone);
        res
    })
    .await
    .map_err(|e| e.to_string())??;

    let _ = app.emit(
        "browser-download-progress",
        DownloadProgress {
            stage: "done".into(),
            downloaded_bytes: downloaded,
            total_bytes: total,
            message: "便携版防泄漏浏览器安装完成".into(),
        },
    );
    logs.push(format!("专属防泄漏浏览器已解压至 {}", target_dir.display()));
    Ok("专属防泄漏浏览器安装成功".into())
}

fn find_latest_squirrel_claude_exe(anthropic_dir: &Path) -> Option<PathBuf> {
    if !anthropic_dir.exists() {
        return None;
    }
    let mut apps: Vec<(String, PathBuf)> = fs::read_dir(anthropic_dir)
        .ok()?
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.to_lowercase().starts_with("app-") && e.path().is_dir() {
                let exe = e.path().join("claude.exe");
                if exe.exists() {
                    return Some((name, exe));
                }
            }
            None
        })
        .collect();
    apps.sort_by(|a, b| b.0.cmp(&a.0));
    apps.into_iter().next().map(|(_, p)| p)
}

fn find_chrome_exe_in(dir: &Path) -> Option<PathBuf> {
    if !dir.exists() {
        return None;
    }
    let direct = dir.join("chrome.exe");
    if direct.exists() {
        return Some(direct);
    }
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let cand = entry.path().join("chrome.exe");
        if cand.exists() {
            return Some(cand);
        }
    }
    None
}

fn copy_if_changed(src: &Path, dst: &Path) -> Result<(), String> {
    let src_len = fs::metadata(src).map(|m| m.len()).unwrap_or(0);
    let dst_len = fs::metadata(dst).map(|m| m.len()).unwrap_or(u64::MAX);
    if !dst.exists() || src_len != dst_len {
        fs::copy(src, dst).map_err(|e| format!("复制沙盒进程副本失败: {e}"))?;
    }
    Ok(())
}

fn harden_browser_preferences(
    profile_dir: &Path,
    locale: Option<&str>,
) -> Result<(), String> {
    let default_dir = profile_dir.join("Default");
    fs::create_dir_all(&default_dir).map_err(|e| e.to_string())?;
    harden_preferences_file(&default_dir.join("Preferences"), locale)
}

fn harden_preferences_file(pref_path: &Path, locale: Option<&str>) -> Result<(), String> {
    if let Some(parent) = pref_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let mut root: Value = if pref_path.exists() {
        fs::read_to_string(&pref_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| json!({}))
    } else {
        json!({})
    };

    root["dns_over_https"] = json!({ "mode": "off" });
    root["webrtc"] = json!({ "ip_handling_policy": "disable_non_proxied_udp" });
    root["net"] = json!({ "network_prediction_options": 2 });
    root["safebrowsing"] = json!({ "enabled": false });
    if let Some(loc) = locale {
        let base_lang = loc.split('-').next().unwrap_or(loc);
        let accept = if base_lang.eq_ignore_ascii_case("en") {
            format!("{loc},{base_lang}")
        } else {
            format!("{loc},{base_lang},en-US,en")
        };
        root["intl"] = json!({ "accept_languages": accept });
    }

    let pretty = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
    fs::write(&pref_path, pretty).map_err(|e| format!("写入浏览器防泄漏配置失败: {e}"))?;
    Ok(())
}

/// Keeps WebRTC UDP protection for Claude Desktop while removing stripped Chromium overrides
/// (`safebrowsing: false`, `network_prediction_options: 2`, forced `intl`) that can trip hCaptcha.
fn sanitize_claude_preferences_file(pref_path: &Path) -> Result<(), String> {
    if !pref_path.exists() {
        return Ok(());
    }
    let mut root: Value = fs::read_to_string(pref_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}));

    if let Some(obj) = root.as_object_mut() {
        obj.remove("safebrowsing");
        obj.remove("net");
        obj.remove("dns_over_https");
        obj.remove("intl");
        obj.insert(
            "webrtc".into(),
            json!({ "ip_handling_policy": "disable_non_proxied_udp" }),
        );
    }

    let pretty = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
    fs::write(pref_path, pretty).map_err(|e| format!("更新 Claude Desktop 配置失败: {e}"))?;
    Ok(())
}

pub fn sanitize_profile_id(id: &str) -> Result<String, String> {
    let trimmed = id.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err("浏览器环境 ID 长度必须为 1-64 个字符".into());
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(format!(
            "非法的浏览器环境 ID（仅允许英文、数字、- 与 _）: {trimmed}"
        ));
    }
    Ok(trimmed.to_string())
}

pub fn profile_storage_dirs(profile_id: &str) -> Result<(PathBuf, PathBuf), String> {
    let safe_id = sanitize_profile_id(profile_id)?;
    if safe_id == "default" {
        Ok((
            app_data_dir().join("browser-profile"),
            app_data_dir().join("fingerprint-ext"),
        ))
    } else {
        Ok((
            app_data_dir().join("browser-profiles").join(&safe_id),
            app_data_dir().join("fingerprint-exts").join(&safe_id),
        ))
    }
}

#[cfg(test)]
fn ensure_fingerprint_extension(timezone: &str, locale: &str) -> Result<PathBuf, String> {
    let mut profile = default_browser_profiles().into_iter().next().unwrap();
    profile.id = "default".into();
    profile.fingerprint_mode = BrowserFingerprintMode::CleanAlign;
    ensure_profile_fingerprint_extension(&profile, timezone, locale)
}

pub fn ensure_profile_fingerprint_extension(
    profile: &BrowserProfile,
    timezone: &str,
    locale: &str,
) -> Result<PathBuf, String> {
    let (_, ext_dir) = profile_storage_dirs(&profile.id)?;
    fs::create_dir_all(&ext_dir).map_err(|e| e.to_string())?;

    let manifest = json!({
        "manifest_version": 3,
        "name": format!("AI NetGuard Profile Alignment ({})", profile.id),
        "version": "1.1.0",
        "description": "Aligns Intl timezone, navigator languages, and optional isolated browser fingerprint",
        "content_scripts": [{
            "matches": ["<all_urls>"],
            "js": ["align.js"],
            "run_at": "document_start",
            "all_frames": true,
            "match_about_blank": true,
            "world": "MAIN"
        }]
    });
    fs::write(
        ext_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    let base_lang = locale.split('-').next().unwrap_or(locale);
    let langs_vec = if base_lang.eq_ignore_ascii_case("en") {
        vec![locale.to_string(), base_lang.to_string()]
    } else {
        vec![
            locale.to_string(),
            base_lang.to_string(),
            "en-US".to_string(),
            "en".to_string(),
        ]
    };
    let tz_json = serde_json::to_string(timezone).map_err(|e| e.to_string())?;
    let loc_json = serde_json::to_string(locale).map_err(|e| e.to_string())?;
    let langs_json = serde_json::to_string(&langs_vec).map_err(|e| e.to_string())?;

    let mut script = format!(
        r#"(() => {{
  const TARGET_TZ = {tz_json};
  const TARGET_LOCALE = {loc_json};
  const TARGET_LANGS = Object.freeze({langs_json});
  if (globalThis.__aiNetguardAligned) return;
  Object.defineProperty(globalThis, "__aiNetguardAligned", {{ value: true }});

  const OrigDTF = Intl.DateTimeFormat;
  const origResolvedOptions = OrigDTF.prototype.resolvedOptions;
  const hostDefaultTz = origResolvedOptions.call(new OrigDTF()).timeZone;

  function calcOffsetMinutes(date) {{
    try {{
      const parts = new OrigDTF("en-US", {{
        timeZone: TARGET_TZ,
        timeZoneName: "shortOffset"
      }}).formatToParts(date);
      const tzPart = parts.find((p) => p.type === "timeZoneName")?.value || "";
      if (tzPart === "GMT" || tzPart === "UTC") return 0;
      const m = /GMT([+-])(\d{{1,2}})(?::?(\d{{2}}))?/.exec(tzPart);
      if (m) {{
        const sign = m[1] === "+" ? -1 : 1;
        const hrs = parseInt(m[2], 10) || 0;
        const mins = parseInt(m[3] || "0", 10) || 0;
        return sign * (hrs * 60 + mins);
      }}
    }} catch {{}}
    return -540;
  }}

  function PatchedDateTimeFormat(locales, options) {{
    const opts = options ? Object.assign({{}}, options) : {{}};
    if (!opts.timeZone) opts.timeZone = TARGET_TZ;
    return new OrigDTF(locales !== undefined ? locales : TARGET_LOCALE, opts);
  }}
  PatchedDateTimeFormat.prototype = OrigDTF.prototype;
  PatchedDateTimeFormat.supportedLocalesOf = OrigDTF.supportedLocalesOf.bind(OrigDTF);
  try {{
    Object.defineProperty(Intl, "DateTimeFormat", {{
      value: PatchedDateTimeFormat,
      configurable: true,
      writable: true
    }});
  }} catch {{}}

  try {{
    OrigDTF.prototype.resolvedOptions = function resolvedOptions() {{
      const res = origResolvedOptions.call(this);
      if (res && res.timeZone === hostDefaultTz) {{
        res.timeZone = TARGET_TZ;
      }}
      return res;
    }};
  }} catch {{}}

  try {{
    Date.prototype.getTimezoneOffset = function getTimezoneOffset() {{
      if (Number.isNaN(this.getTime())) return NaN;
      return calcOffsetMinutes(this);
    }};
  }} catch {{}}

  for (const method of ["toLocaleString", "toLocaleDateString", "toLocaleTimeString"]) {{
    const orig = Date.prototype[method];
    try {{
      Date.prototype[method] = function(locales, options) {{
        const opts = options ? Object.assign({{}}, options) : {{}};
        if (!opts.timeZone) opts.timeZone = TARGET_TZ;
        return orig.call(this, locales !== undefined ? locales : TARGET_LOCALE, opts);
      }};
    }} catch {{}}
  }}

  try {{
    Object.defineProperty(Navigator.prototype, "language", {{
      get: () => TARGET_LOCALE,
      configurable: true
    }});
    Object.defineProperty(Navigator.prototype, "languages", {{
      get: () => TARGET_LANGS,
      configurable: true
    }});
  }} catch {{}}
}})();
"#
    );

    if matches!(
        profile.fingerprint_mode,
        BrowserFingerprintMode::IsolatedFingerprint
    ) {
        let sw = profile.fingerprint.screen_width.clamp(800, 3840);
        let sh = profile.fingerprint.screen_height.clamp(600, 2160);
        let avail_h = sh.saturating_sub(40).max(200);
        let dpr = if profile.fingerprint.device_pixel_ratio.is_finite() {
            profile.fingerprint.device_pixel_ratio.clamp(1.0, 3.0)
        } else {
            1.0
        };
        let hw = profile.fingerprint.hardware_concurrency.clamp(2, 64);
        let mem = profile.fingerprint.device_memory.clamp(2, 64);
        let vendor = profile.fingerprint.webgl_vendor.trim();
        let vendor_str = if vendor.is_empty() {
            "Google Inc. (NVIDIA)"
        } else {
            vendor
        };
        let renderer = profile.fingerprint.webgl_renderer.trim();
        let renderer_str = if renderer.is_empty() {
            "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"
        } else {
            renderer
        };
        let raw_seed = profile.fingerprint.noise_seed.trim();
        let seed_str = if raw_seed.is_empty() {
            profile.id.as_str()
        } else {
            raw_seed
        };

        let fp_cfg = json!({
            "sw": sw,
            "sh": sh,
            "ah": avail_h,
            "dpr": dpr,
            "hw": hw,
            "mem": mem,
            "vendor": vendor_str,
            "renderer": renderer_str,
            "seed": seed_str,
        });
        let fp_cfg_json = serde_json::to_string(&fp_cfg).map_err(|e| e.to_string())?;
        let isolated_js = format!(
            r#"(() => {{
  const FP = {fp_cfg_json};
  if (globalThis.__aiNetguardIsolatedFp) return;
  Object.defineProperty(globalThis, "__aiNetguardIsolatedFp", {{ value: true }});

  function fnv1a32(str) {{
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {{
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }}
    return h >>> 0;
  }}

  function mulberry32(a) {{
    return function() {{
      let t = (a += 0x6d2b79f5);
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    }};
  }}

  const defProp = (proto, key, getter) => {{
    try {{
      Object.defineProperty(proto, key, {{ get: getter, configurable: true }});
    }} catch {{}}
  }};

  defProp(Screen.prototype, "width", () => FP.sw);
  defProp(Screen.prototype, "height", () => FP.sh);
  defProp(Screen.prototype, "availWidth", () => FP.sw);
  defProp(Screen.prototype, "availHeight", () => FP.ah);
  defProp(Screen.prototype, "colorDepth", () => 24);
  defProp(Screen.prototype, "pixelDepth", () => 24);
  defProp(window, "devicePixelRatio", () => FP.dpr);
  defProp(Navigator.prototype, "hardwareConcurrency", () => FP.hw);
  defProp(Navigator.prototype, "deviceMemory", () => FP.mem);

  const patchWebGL = (Ctor) => {{
    if (!Ctor || !Ctor.prototype || !Ctor.prototype.getParameter) return;
    const origGetParam = Ctor.prototype.getParameter;
    Ctor.prototype.getParameter = function getParameter(pname) {{
      if (pname === 37445) return FP.vendor;
      if (pname === 37446) return FP.renderer;
      return origGetParam.call(this, pname);
    }};
  }};
  patchWebGL(globalThis.WebGLRenderingContext);
  patchWebGL(globalThis.WebGL2RenderingContext);

  function perturbPixelData(data, w, h) {{
    if (!data || !data.length || w <= 0 || h <= 0) return;
    const rng = mulberry32(fnv1a32(FP.seed + ":" + w + "x" + h));
    const pixelCount = Math.floor(data.length / 4);
    const hits = Math.min(8, Math.max(2, Math.floor(pixelCount / 64)));
    let applied = 0;
    for (let i = 0; i < pixelCount && applied < hits; i++) {{
      const p = Math.floor(rng() * pixelCount);
      const base = p * 4;
      if (data[base + 3] > 0) {{
        const chan = Math.floor(rng() * 3);
        data[base + chan] = data[base + chan] ^ 1;
        applied++;
      }}
    }}
  }}

  const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function getImageData(sx, sy, sw, sh, settings) {{
    const img = origGetImageData.call(this, sx, sy, sw, sh, settings);
    try {{
      perturbPixelData(img.data, img.width, img.height);
    }} catch {{}}
    return img;
  }};

  const makePatchedCanvasClone = (src) => {{
    const w = src.width | 0;
    const h = src.height | 0;
    if (w <= 0 || h <= 0 || w * h > 4000000) return null;
    const clone = document.createElement("canvas");
    clone.width = w;
    clone.height = h;
    const ctx = clone.getContext("2d");
    if (!ctx) return null;
    ctx.drawImage(src, 0, 0);
    const img = origGetImageData.call(ctx, 0, 0, w, h);
    perturbPixelData(img.data, w, h);
    ctx.putImageData(img, 0, 0);
    return clone;
  }};

  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function toDataURL(...args) {{
    try {{
      if (this.getContext("2d")) {{
        const clone = makePatchedCanvasClone(this);
        if (clone) return origToDataURL.apply(clone, args);
      }}
    }} catch {{}}
    return origToDataURL.apply(this, args);
  }};

  const origToBlob = HTMLCanvasElement.prototype.toBlob;
  HTMLCanvasElement.prototype.toBlob = function toBlob(callback, ...args) {{
    try {{
      if (this.getContext("2d")) {{
        const clone = makePatchedCanvasClone(this);
        if (clone) return origToBlob.apply(clone, [callback, ...args]);
      }}
    }} catch {{}}
    return origToBlob.apply(this, [callback, ...args]);
  }};

  if (globalThis.AudioBuffer && AudioBuffer.prototype.getChannelData) {{
    const patchedBuffers = new WeakSet();
    const origGetChannelData = AudioBuffer.prototype.getChannelData;
    AudioBuffer.prototype.getChannelData = function getChannelData(channel) {{
      const buf = origGetChannelData.call(this, channel);
      try {{
        if (!patchedBuffers.has(buf)) {{
          patchedBuffers.add(buf);
          const rng = mulberry32(fnv1a32(FP.seed + ":audio:" + channel + ":" + buf.length));
          const step = Math.max(1, Math.floor(buf.length / 64));
          for (let i = 0; i < buf.length; i += step) {{
            buf[i] += (rng() - 0.5) * 1e-7;
          }}
        }}
      }} catch {{}}
      return buf;
    }};
  }}
}})();
"#
        );
        script.push('\n');
        script.push_str(&isolated_js);
    }

    fs::write(ext_dir.join("align.js"), script).map_err(|e| e.to_string())?;
    Ok(ext_dir)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_extension_builds_valid_mv3() {
        let dir = ensure_fingerprint_extension("Asia/Seoul", "ko-KR").unwrap();
        let manifest = fs::read_to_string(dir.join("manifest.json")).unwrap();
        let js = fs::read_to_string(dir.join("align.js")).unwrap();
        assert!(manifest.contains("\"manifest_version\": 3"));
        assert!(js.contains("Asia/Seoul"));
        assert!(js.contains("ko-KR"));
        assert!(!js.contains("__aiNetguardIsolatedFp"));
        assert!(!js.contains("webgl_renderer"));
    }

    #[test]
    fn sanitize_profile_id_and_isolated_fingerprint_mv3() {
        assert!(sanitize_profile_id("").is_err());
        assert!(sanitize_profile_id("../escape").is_err());
        assert!(sanitize_profile_id("a/b").is_err());
        assert!(sanitize_profile_id("jp-kawasaki_01").is_ok());

        let mut profile = default_browser_profiles().into_iter().next().unwrap();
        profile.id = "test-iso-jp".into();
        profile.fingerprint_mode = BrowserFingerprintMode::IsolatedFingerprint;
        profile.fingerprint.screen_width = 1440;
        profile.fingerprint.screen_height = 900;
        profile.fingerprint.hardware_concurrency = 12;
        profile.fingerprint.device_memory = 16;
        profile.fingerprint.webgl_vendor = "Google Inc. (AMD)".into();
        profile.fingerprint.webgl_renderer = "ANGLE (AMD, Radeon RX 6700 XT Direct3D11)".into();
        profile.fingerprint.noise_seed = "seed-abc-123".into();

        let dir = ensure_profile_fingerprint_extension(&profile, "Asia/Tokyo", "ja-JP").unwrap();
        let js = fs::read_to_string(dir.join("align.js")).unwrap();
        assert!(js.contains("Asia/Tokyo"));
        assert!(js.contains("ja-JP"));
        assert!(js.contains("__aiNetguardIsolatedFp"));
        assert!(js.contains("seed-abc-123"));
        assert!(js.contains("Radeon RX 6700 XT"));
        assert!(js.contains("getChannelData"));
        assert!(js.contains("toDataURL"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn claude_desktop_wfp_discovery_finds_real_electron_exe() {
        let launcher = ProcessLauncher::new();
        let cfg = AppConfig::default();
        let resolved = launcher.resolve_claude_desktop_path(&cfg);
        assert!(resolved.is_some(), "expected Claude Desktop exe installed");
        let resolved_str = resolved.unwrap().to_string_lossy().to_lowercase();
        assert!(
            resolved_str.contains("\\app-") && resolved_str.ends_with("\\claude.exe"),
            "expected Squirrel app-* binary, got {resolved_str}"
        );
        let all = launcher.resolve_claude_desktop_wfp_paths(&cfg);
        assert!(all.len() >= 3, "expected stub, Update.exe, and app-*/claude.exe");
    }

    #[test]
    fn sanitize_claude_preferences_removes_bot_hostile_overrides() {
        let p = std::env::temp_dir().join("ng-test-claude-prefs.json");
        fs::write(
            &p,
            r#"{"dns_over_https":{"mode":"off"},"intl":{"accept_languages":"ko-KR,ko"},"net":{"network_prediction_options":2},"partition":{"zoom":{}},"safebrowsing":{"enabled":false},"webrtc":{"ip_handling_policy":"default"}}"#,
        )
        .unwrap();
        sanitize_claude_preferences_file(&p).unwrap();
        let out: Value = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
        let _ = fs::remove_file(&p);
        assert!(out.get("safebrowsing").is_none());
        assert!(out.get("net").is_none());
        assert!(out.get("dns_over_https").is_none());
        assert!(out.get("intl").is_none());
        assert!(out.get("partition").is_some());
        assert_eq!(out["webrtc"]["ip_handling_policy"], "disable_non_proxied_udp");
    }

    #[test]
    fn zip_extraction_rejects_traversal_and_symlinks() {
        assert!(validate_and_strip_zip_entry_path("../evil.exe").is_err());
        assert!(validate_and_strip_zip_entry_path("top/../../evil.exe").is_err());
        assert!(validate_and_strip_zip_entry_path(r"top\..\evil.exe").is_err());
        assert!(validate_and_strip_zip_entry_path("top/C:/evil.exe").is_err());
        assert_eq!(
            validate_and_strip_zip_entry_path("top/locales/en-US.pak").unwrap(),
            Some(PathBuf::from("locales").join("en-US.pak"))
        );

        let base = std::env::temp_dir().join("ng-zip-sec-test");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        // 1. Traversal archive must fail before writing outside
        let trav_zip = base.join("trav.zip");
        {
            let f = File::create(&trav_zip).unwrap();
            let mut zw = zip::ZipWriter::new(f);
            zw.start_file("top/../../escaped.txt", zip::write::SimpleFileOptions::default())
                .unwrap();
            zw.write_all(b"pwned").unwrap();
            zw.finish().unwrap();
        }
        let target = base.join("out");
        assert!(extract_chromium_zip_safe(&trav_zip, &target).is_err());
        assert!(!base.join("escaped.txt").exists());

        // 2. Symlink entry must fail
        let sym_zip = base.join("sym.zip");
        {
            let f = File::create(&sym_zip).unwrap();
            let mut zw = zip::ZipWriter::new(f);
            zw.add_symlink(
                "top/link.exe",
                "/etc/passwd",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
            zw.finish().unwrap();
        }
        assert!(extract_chromium_zip_safe(&sym_zip, &target).is_err());

        // 3. Valid archive strips top folder cleanly
        let good_zip = base.join("good.zip");
        {
            let f = File::create(&good_zip).unwrap();
            let mut zw = zip::ZipWriter::new(f);
            zw.start_file("chromium-root/chrome.exe", zip::write::SimpleFileOptions::default())
                .unwrap();
            zw.write_all(b"MZ").unwrap();
            zw.finish().unwrap();
        }
        extract_chromium_zip_safe(&good_zip, &target).unwrap();
        assert!(target.join("chrome.exe").exists());
        let _ = fs::remove_dir_all(&base);
    }
}
