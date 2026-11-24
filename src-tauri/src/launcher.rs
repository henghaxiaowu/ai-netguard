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
use std::io::{Cursor, Read, Write};
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
const FP_CHROMIUM_REPO_PREFIX: &str = "/adryfish/fingerprint-chromium/releases/download/";
const FP_CHROMIUM_FALLBACK_URL: &str = "https://github.com/adryfish/fingerprint-chromium/releases/download/150.0.7871.186/ungoogled-chromium_150.0.7871.186-1.1_windows_x64.zip";
const FP_CHROMIUM_FALLBACK_SHA256: &str =
    "4d549c326e51ebbabf562fd365eb5380d9d4a81200da2c60f075c688d9a77e03";
const CWS_CRX_URL: &str = "https://github.com/NeverDecaf/chromium-web-store/releases/download/v1.5.5.4/Chromium.Web.Store.crx";
const CWS_CRX_SHA256: &str =
    "63c075b4a25b11af2c536dad191946e8d9547f92d5b6c257b2ce4138d2996f32";
const FP_ENGINE_MARKER_FILE: &str = ".fingerprint-chromium";
const MAX_ZIP_ENTRIES: usize = 20_000;
const MAX_ZIP_UNCOMPRESSED_BYTES: u64 = 1_500_000_000;
const MAX_CRX_ENTRIES: usize = 500;
const MAX_CRX_UNCOMPRESSED_BYTES: u64 = 20_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedBrowserEngine {
    FingerprintChromium(PathBuf),
    LegacyChromium(PathBuf),
}

impl ResolvedBrowserEngine {
    pub fn exe_path(&self) -> &PathBuf {
        match self {
            Self::FingerprintChromium(p) | Self::LegacyChromium(p) => p,
        }
    }

    pub fn is_fingerprint_chromium(&self) -> bool {
        matches!(self, Self::FingerprintChromium(_))
    }
}

pub fn web_store_extension_dir() -> PathBuf {
    app_data_dir()
        .join("extensions")
        .join("chromium-web-store")
}

pub fn chrome_newtab_extension_dir() -> PathBuf {
    app_data_dir()
        .join("extensions")
        .join("chrome-newtab")
}

pub fn is_web_store_ext_installed() -> bool {
    web_store_extension_dir().join("manifest.json").exists()
}

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

struct RunningBrowserEntry {
    child: Child,
    cdp_port: u16,
}

pub fn pick_free_loopback_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("分配本地回环 CDP 端口失败: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("读取本地回环端口失败: {e}"))?
        .port();
    Ok(port)
}

pub struct ProcessLauncher {
    job: Option<KillOnCloseJob>,
    browser_children: HashMap<String, RunningBrowserEntry>,
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
        if let Some(entry) = self.browser_children.get_mut(profile_id) {
            match entry.child.try_wait() {
                Ok(None) => return true,
                _ => {
                    self.browser_children.remove(profile_id);
                }
            }
        }
        false
    }

    pub fn running_profile_cdp_port(&mut self, profile_id: &str) -> Option<u16> {
        if let Some(entry) = self.browser_children.get_mut(profile_id) {
            match entry.child.try_wait() {
                Ok(None) => return Some(entry.cdp_port),
                _ => {
                    self.browser_children.remove(profile_id);
                }
            }
        }
        None
    }

    pub fn running_browser_profile_ids(&mut self) -> Vec<String> {
        self.browser_children
            .retain(|_, entry| matches!(entry.child.try_wait(), Ok(None)));
        let mut ids: Vec<String> = self.browser_children.keys().cloned().collect();
        ids.sort();
        ids
    }

    pub fn is_browser_running(&mut self) -> bool {
        !self.running_browser_profile_ids().is_empty()
    }

    pub fn close_browser_profile(&mut self, profile_id: &str) -> bool {
        if let Some(mut entry) = self.browser_children.remove(profile_id) {
            if matches!(entry.child.try_wait(), Ok(None)) {
                let _ = entry.child.kill();
                let _ = entry.child.wait();
                return true;
            }
        }
        false
    }

    pub fn resolve_fp_browser_path(&self) -> Option<PathBuf> {
        let dir = app_data_dir().join("browser-fp");
        find_chrome_exe_in(&dir)
    }

    pub fn resolve_legacy_browser_path(&self) -> Option<PathBuf> {
        let dir = app_data_dir().join("browser");
        find_chrome_exe_in(&dir)
    }

    pub fn resolve_browser_engine(&self, cfg: &AppConfig) -> Option<ResolvedBrowserEngine> {
        if let Some(custom) = cfg.custom_browser_path.as_deref() {
            let p = PathBuf::from(custom.trim());
            if !custom.trim().is_empty() && p.exists() {
                let is_fp = p
                    .parent()
                    .map(|d| d.join(FP_ENGINE_MARKER_FILE).exists())
                    .unwrap_or(false);
                return Some(if is_fp {
                    ResolvedBrowserEngine::FingerprintChromium(p)
                } else {
                    ResolvedBrowserEngine::LegacyChromium(p)
                });
            }
        }
        if let Some(fp_exe) = self.resolve_fp_browser_path() {
            return Some(ResolvedBrowserEngine::FingerprintChromium(fp_exe));
        }
        if let Some(legacy_exe) = self.resolve_legacy_browser_path() {
            return Some(ResolvedBrowserEngine::LegacyChromium(legacy_exe));
        }
        None
    }

    pub fn resolve_browser_path(&self, cfg: &AppConfig) -> Option<PathBuf> {
        self.resolve_browser_engine(cfg)
            .map(|engine| engine.exe_path().clone())
    }

    pub fn resolve_all_browser_wfp_paths(&self, cfg: &AppConfig) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();
        let push_unique = |list: &mut Vec<PathBuf>, p: PathBuf| {
            let p_str = p.to_string_lossy();
            if !list
                .iter()
                .any(|existing| existing.to_string_lossy().eq_ignore_ascii_case(&p_str))
            {
                list.push(p);
            }
        };
        if let Some(custom) = cfg.custom_browser_path.as_deref() {
            let p = PathBuf::from(custom.trim());
            if !custom.trim().is_empty() && p.exists() {
                push_unique(&mut out, p);
            }
        }
        if let Some(fp) = self.resolve_fp_browser_path() {
            push_unique(&mut out, fp);
        }
        if let Some(legacy) = self.resolve_legacy_browser_path() {
            push_unique(&mut out, legacy);
        }
        out
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

        let proxy_url = format!("socks5://127.0.0.1:{}", cfg.browser_port);
        self.launch_browser_profile(
            cfg,
            &profile,
            &proxy_url,
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
        proxy_server_url: &str,
        node_label: &str,
        effective_tz: &str,
        effective_locale: &str,
        target_url: &str,
        logs: Arc<LogBuffer>,
    ) -> Result<String, String> {
        let engine = self
            .resolve_browser_engine(cfg)
            .ok_or("未安装专属防泄漏浏览器，请先点击下载 Fingerprint-Chromium 150")?;
        let is_fp = engine.is_fingerprint_chromium();
        let exe = engine.exe_path().clone();

        let parsed_target = url::Url::parse(target_url.trim())
            .map_err(|e| format!("专属浏览器目标 URL 格式无效: {e}"))?;
        let scheme = parsed_target.scheme().to_ascii_lowercase();
        if (scheme != "http" && scheme != "https")
            || parsed_target.host_str().map(str::trim).unwrap_or("").is_empty()
        {
            return Err("出于安全考虑，专属浏览器仅允许启动有效的 http(s):// 目标地址".into());
        }

        let (profile_dir, _) = profile_storage_dirs_for_engine(&profile.id, is_fp)?;
        let should_align = matches!(
            profile.fingerprint_mode,
            BrowserFingerprintMode::IsolatedFingerprint
        ) || cfg.align_fingerprint;
        let locale_for_prefs = should_align.then_some(effective_locale);
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

        let legacy_ext_dir = if !is_fp && should_align {
            Some(ensure_profile_fingerprint_extension(
                profile,
                effective_tz,
                effective_locale,
            )?)
        } else {
            None
        };
        let cws_dir = web_store_extension_dir();
        let cws_ext_opt = cws_dir.join("manifest.json").exists().then_some(cws_dir);
        let ntp_ext_opt = match ensure_chrome_newtab_extension() {
            Ok(dir) => Some(dir),
            Err(err) => {
                logs.push(format!("生成 Chrome 风格新标签页扩展失败（已跳过）: {err}"));
                None
            }
        };

        let cdp_port = pick_free_loopback_port()?;
        let args = build_browser_launch_args(
            is_fp,
            profile,
            &profile_dir,
            proxy_server_url,
            effective_tz,
            effective_locale,
            cfg.align_fingerprint,
            cws_ext_opt.as_deref(),
            ntp_ext_opt.as_deref(),
            legacy_ext_dir.as_deref(),
            Some(cdp_port),
            target_url,
        );

        let mut cmd = Command::new(&exe);
        cmd.args(&args);

        let child = cmd
            .spawn()
            .map_err(|e| format!("启动浏览器环境 [{}] 失败: {e}", profile.name))?;
        self.assign_to_job(&child);
        self.browser_children.insert(
            profile.id.clone(),
            RunningBrowserEntry { child, cdp_port },
        );

        let engine_label = if is_fp {
            "Fingerprint-Chromium"
        } else {
            "Chromium"
        };
        let mode_label = match profile.fingerprint_mode {
            BrowserFingerprintMode::CleanAlign => "纯净对齐",
            BrowserFingerprintMode::IsolatedFingerprint => "完整独立指纹",
        };
        logs.push(format!(
            "已启动 [{engine_label}] 浏览器环境 [{}] ({mode_label}, 出口: {node_label}, 代理 {proxy_server_url}) -> {target_url}",
            profile.name
        ));
        Ok(format!(
            "已启动 [{}] -> {node_label} ({proxy_server_url})",
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

fn is_allowed_github_release_url(url_str: &str, repo_prefix: &str) -> bool {
    let Ok(url) = Url::parse(url_str) else {
        return false;
    };
    url.scheme() == "https"
        && matches!(
            url.host_str(),
            Some("github.com")
                | Some("objects.githubusercontent.com")
                | Some("release-assets.githubusercontent.com")
        )
        && if url.host_str() == Some("github.com") {
            url.path().starts_with(repo_prefix)
        } else {
            true
        }
}

pub fn is_allowed_fp_chromium_url(url_str: &str) -> bool {
    is_allowed_github_release_url(url_str, FP_CHROMIUM_REPO_PREFIX)
}

pub fn is_allowed_cws_url(url_str: &str) -> bool {
    is_allowed_github_release_url(url_str, "/NeverDecaf/chromium-web-store/releases/download/")
}

fn parse_expanded_assets_html(html: &str, marker: &str, suffix: &str) -> Option<(String, String)> {
    let mut search_from = 0usize;
    while let Some(rel_idx) = html[search_from..].find(marker) {
        let abs_start = search_from + rel_idx;
        let rest = &html[abs_start..];
        let end_quote = rest.find('"')?;
        let rel_path = &rest[..end_quote];
        if rel_path.ends_with(suffix) {
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

async fn send_with_proxy_fallback(
    direct: &reqwest::Client,
    proxy: Option<&reqwest::Client>,
    url: &str,
) -> Result<reqwest::Response, String> {
    match direct.get(url).send().await {
        Ok(resp) if resp.status().is_success() => Ok(resp),
        first_res => {
            if let Some(px) = proxy {
                match px.get(url).send().await {
                    Ok(resp) => return Ok(resp),
                    Err(pe) => {
                        if let Ok(r) = first_res {
                            return Ok(r);
                        }
                        return Err(format!("直连与代理下载均失败: {pe}"));
                    }
                }
            }
            match first_res {
                Ok(resp) => Ok(resp),
                Err(e) => Err(format!("网络请求失败: {e}")),
            }
        }
    }
}

async fn resolve_fp_chromium_download(
    direct: &reqwest::Client,
    proxy: Option<&reqwest::Client>,
) -> (String, String) {
    if let Ok(resp) = send_with_proxy_fallback(
        direct,
        proxy,
        "https://api.github.com/repos/adryfish/fingerprint-chromium/releases/latest",
    )
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
                        if is_allowed_fp_chromium_url(&asset.browser_download_url) {
                            return (asset.browser_download_url, digest);
                        }
                    }
                }
            }
        }
    }

    if let Ok(latest_resp) = send_with_proxy_fallback(
        direct,
        proxy,
        "https://github.com/adryfish/fingerprint-chromium/releases/latest",
    )
    .await
    {
        let resolved = latest_resp.url().as_str().to_string();
        if let Some(tag) = resolved
            .rsplit('/')
            .next()
            .filter(|t| !t.is_empty() && *t != "latest")
        {
            let expanded_url = format!(
                "https://github.com/adryfish/fingerprint-chromium/releases/expanded_assets/{tag}"
            );
            if let Ok(exp_resp) = send_with_proxy_fallback(direct, proxy, &expanded_url).await {
                if exp_resp.status().is_success() {
                    if let Ok(html) = exp_resp.text().await {
                        if let Some((url, hash)) = parse_expanded_assets_html(
                            &html,
                            FP_CHROMIUM_REPO_PREFIX,
                            "windows_x64.zip",
                        ) {
                            if is_allowed_fp_chromium_url(&url) {
                                return (url, hash);
                            }
                        }
                    }
                }
            }
        }
    }

    (
        FP_CHROMIUM_FALLBACK_URL.to_string(),
        FP_CHROMIUM_FALLBACK_SHA256.to_string(),
    )
}

fn validate_raw_zip_segments(raw_name: &str) -> Result<Vec<String>, String> {
    if raw_name.contains('\0') {
        return Err("ZIP 条目包含空字节，拒绝解压".into());
    }
    let normalized = raw_name.replace('\\', "/");
    if normalized.starts_with('/') || normalized.starts_with("//") {
        return Err(format!("ZIP 条目包含绝对路径: {raw_name}"));
    }

    let raw_segments: Vec<String> = normalized
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    // Validate EVERY segment BEFORE any stripping so payloads like `top/../../evil.txt`
    // or `C:/evil.txt` cannot hide behind directory stripping.
    for seg in &raw_segments {
        if seg == "." || seg == ".." || seg.contains(':') || seg.chars().any(|c| c.is_control()) {
            return Err(format!("ZIP 条目存在非法路径成分: {raw_name}"));
        }
    }
    Ok(raw_segments)
}

pub fn validate_zip_entry_path_no_strip(raw_name: &str) -> Result<Option<PathBuf>, String> {
    let segs = validate_raw_zip_segments(raw_name)?;
    if segs.is_empty() {
        return Ok(None);
    }
    let mut path = PathBuf::new();
    for seg in &segs {
        path.push(seg);
    }
    if path.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(format!("ZIP 条目含非普通路径成分: {raw_name}"));
    }
    Ok(Some(path))
}

pub fn validate_and_strip_zip_entry_path(raw_name: &str) -> Result<Option<PathBuf>, String> {
    let segs = validate_raw_zip_segments(raw_name)?;
    if segs.len() <= 1 {
        return Ok(None);
    }
    let mut stripped = PathBuf::new();
    for seg in &segs[1..] {
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

fn extract_zip_archive_safe<R: Read + std::io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    target_dir: &Path,
    max_entries: usize,
    max_bytes: u64,
    allow_strip_common_top_dir: bool,
) -> Result<(), String> {
    if archive.len() > max_entries {
        return Err(format!("ZIP 文件条目数过多 ({}), 拒绝解压", archive.len()));
    }

    let mut common_top: Option<String> = None;
    let mut uniform_top = true;
    let mut has_nested = false;

    for i in 0..archive.len() {
        let entry = archive.by_index(i).map_err(|e| e.to_string())?;
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
        let segs = validate_raw_zip_segments(entry.name())?;
        if let Some(first) = segs.first() {
            if segs.len() >= 2 {
                has_nested = true;
            } else if !entry.is_dir() {
                uniform_top = false;
            }
            match &common_top {
                None => common_top = Some(first.clone()),
                Some(prev) if prev != first => uniform_top = false,
                _ => {}
            }
        }
    }

    let strip_top = allow_strip_common_top_dir && uniform_top && has_nested;

    if target_dir.exists() {
        fs::remove_dir_all(target_dir).map_err(|e| {
            format!(
                "清理旧目录 {} 失败（请先关闭正在运行的指纹浏览器窗口）: {e}",
                target_dir.display()
            )
        })?;
    }
    fs::create_dir_all(target_dir).map_err(|e| e.to_string())?;
    let canon_root = fs::canonicalize(target_dir).map_err(|e| e.to_string())?;

    let mut total_bytes: u64 = 0;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
        let rel_path_opt = if strip_top {
            validate_and_strip_zip_entry_path(entry.name())?
        } else {
            validate_zip_entry_path_no_strip(entry.name())?
        };
        let Some(rel_path) = rel_path_opt else {
            continue;
        };

        let dest = target_dir.join(&rel_path);
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

            let remaining = max_bytes.saturating_sub(total_bytes);
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
            if total_bytes > max_bytes {
                return Err("ZIP 解压体积异常膨胀（疑似 Zip Bomb），已终止".into());
            }
        }
    }
    Ok(())
}

pub fn extract_chromium_zip_safe(zip_path: &Path, target_dir: &Path) -> Result<(), String> {
    let file = File::open(zip_path).map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    extract_zip_archive_safe(
        &mut archive,
        target_dir,
        MAX_ZIP_ENTRIES,
        MAX_ZIP_UNCOMPRESSED_BYTES,
        true,
    )
}

pub fn extract_crx3_safe(crx_bytes: &[u8], target_dir: &Path) -> Result<(), String> {
    if crx_bytes.len() < 16 || &crx_bytes[0..4] != b"Cr24" {
        return Err("无效的 CRX3 扩展包（缺少 Cr24 文件头）".into());
    }
    let version = u32::from_le_bytes([crx_bytes[4], crx_bytes[5], crx_bytes[6], crx_bytes[7]]);
    if version != 3 {
        return Err(format!("不支持的 CRX 扩展版本: {version}（仅支持 CRX3）"));
    }
    let header_len =
        u32::from_le_bytes([crx_bytes[8], crx_bytes[9], crx_bytes[10], crx_bytes[11]]) as usize;
    let zip_offset = 12usize
        .checked_add(header_len)
        .ok_or_else(|| "CRX3 头长度溢出".to_string())?;
    if zip_offset + 4 > crx_bytes.len() || &crx_bytes[zip_offset..zip_offset + 4] != b"PK\x03\x04" {
        return Err("CRX3 扩展包 ZIP 载荷偏移无效".into());
    }

    let parent = target_dir.parent().ok_or("无效的扩展安装目录")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let staging = parent.join(format!("cws-staging-{}", std::process::id()));
    let _ = fs::remove_dir_all(&staging);

    let mut archive =
        zip::ZipArchive::new(Cursor::new(&crx_bytes[zip_offset..])).map_err(|e| e.to_string())?;
    if let Err(err) = extract_zip_archive_safe(
        &mut archive,
        &staging,
        MAX_CRX_ENTRIES,
        MAX_CRX_UNCOMPRESSED_BYTES,
        false,
    ) {
        let _ = fs::remove_dir_all(&staging);
        return Err(err);
    }

    if !staging.join("manifest.json").exists() {
        let _ = fs::remove_dir_all(&staging);
        return Err("CRX3 解压后缺少 manifest.json".into());
    }

    if target_dir.exists() {
        fs::remove_dir_all(target_dir).map_err(|e| {
            let _ = fs::remove_dir_all(&staging);
            format!("替换扩展目录 {} 失败: {e}", target_dir.display())
        })?;
    }
    fs::rename(&staging, target_dir).map_err(|e| {
        let _ = fs::remove_dir_all(&staging);
        format!("激活 Chrome 商店扩展目录失败: {e}")
    })?;
    Ok(())
}

fn mark_fp_engine_installed(browser_dir: &Path) -> Result<(), String> {
    fs::write(browser_dir.join(FP_ENGINE_MARKER_FILE), b"fingerprint-chromium-150\n")
        .map_err(|e| format!("写入内核标记失败: {e}"))?;
    if let Some(exe) = find_chrome_exe_in(browser_dir) {
        if let Some(exe_dir) = exe.parent() {
            if exe_dir != browser_dir {
                fs::write(exe_dir.join(FP_ENGINE_MARKER_FILE), b"fingerprint-chromium-150\n")
                    .map_err(|e| format!("写入内核标记失败: {e}"))?;
            }
        }
    }
    Ok(())
}

async fn install_cws_extension(
    direct: &reqwest::Client,
    proxy: Option<&reqwest::Client>,
    logs: &Arc<LogBuffer>,
) -> Result<(), String> {
    if !is_allowed_cws_url(CWS_CRX_URL) {
        return Err("非受信任的 Chrome 商店扩展来源".into());
    }
    let resp = send_with_proxy_fallback(direct, proxy, CWS_CRX_URL).await?;
    if !resp.status().is_success() {
        return Err(format!("Chrome 商店扩展下载返回 HTTP {}", resp.status()));
    }
    let final_url = resp.url().as_str().to_string();
    if !is_allowed_cws_url(&final_url) {
        return Err(format!("扩展跳转来源不受信任: {final_url}"));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("读取扩展数据失败: {e}"))?;
    let actual_sha256 = hex::encode(Sha256::digest(&bytes));
    if !guard_protocol::constant_time_eq_bytes(&actual_sha256, CWS_CRX_SHA256) {
        return Err(format!(
            "Chrome 商店扩展 SHA-256 校验失败: 预期 {CWS_CRX_SHA256}, 实际 {actual_sha256}"
        ));
    }

    let target_ext_dir = web_store_extension_dir();
    let bytes_owned = bytes.to_vec();
    tokio::task::spawn_blocking(move || extract_crx3_safe(&bytes_owned, &target_ext_dir))
        .await
        .map_err(|e| e.to_string())??;

    logs.push(format!(
        "Chrome 商店扩展 (chromium-web-store v1.5.5.4) SHA-256 校验通过并安装至 {}",
        web_store_extension_dir().display()
    ));
    Ok(())
}

pub async fn download_and_install_browser(
    app: AppHandle,
    proxy_fallback: Option<String>,
    logs: Arc<LogBuffer>,
) -> Result<String, String> {
    let direct_client = reqwest::Client::builder()
        .user_agent("AI-NetGuard/0.1")
        .connect_timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let proxy_client = match proxy_fallback.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(p_url) => reqwest::Proxy::all(p_url).ok().and_then(|proxy| {
            reqwest::Client::builder()
                .user_agent("AI-NetGuard/0.1")
                .proxy(proxy)
                .connect_timeout(std::time::Duration::from_secs(15))
                .build()
                .ok()
        }),
        None => None,
    };

    let mut cws_note: Option<String> = None;

    // If Fingerprint-Chromium 150 is already installed cleanly, allow repairing missing CWS extension alone.
    let target_dir = app_data_dir().join("browser-fp");
    if target_dir.join(FP_ENGINE_MARKER_FILE).exists() && find_chrome_exe_in(&target_dir).is_some() {
        if !is_web_store_ext_installed() {
            let _ = app.emit(
                "browser-download-progress",
                DownloadProgress {
                    stage: "extracting".into(),
                    downloaded_bytes: 0,
                    total_bytes: 0,
                    message: "Fingerprint-Chromium 150 已安装，正在补装 Chrome 应用商店扩展...".into(),
                },
            );
            install_cws_extension(&direct_client, proxy_client.as_ref(), &logs).await?;
            let _ = app.emit(
                "browser-download-progress",
                DownloadProgress {
                    stage: "done".into(),
                    downloaded_bytes: 0,
                    total_bytes: 0,
                    message: "Chrome 应用商店扩展安装完成".into(),
                },
            );
            return Ok("已为 Fingerprint-Chromium 150 补装 Chrome 商店扩展".into());
        }
    }

    let (download_url, expected_sha256) =
        resolve_fp_chromium_download(&direct_client, proxy_client.as_ref()).await;
    if !is_allowed_fp_chromium_url(&download_url) {
        return Err(format!("拒绝从非受信任来源下载浏览器: {download_url}"));
    }

    logs.push(format!(
        "开始下载开源 Fingerprint-Chromium 150: {download_url} (SHA-256: {expected_sha256})"
    ));

    let resp = send_with_proxy_fallback(&direct_client, proxy_client.as_ref(), &download_url).await?;
    if !resp.status().is_success() {
        return Err(format!("下载返回 HTTP {}", resp.status()));
    }
    let final_url = resp.url().as_str().to_string();
    if !is_allowed_fp_chromium_url(&final_url) {
        return Err(format!("下载重定向来源不受信任: {final_url}"));
    }

    let total = resp.content_length().unwrap_or(0);
    let zip_path = app_data_dir().join("fingerprint-chromium.zip");
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
                        "正在下载 Fingerprint-Chromium 150 ({:.1} MB / {:.1} MB)...",
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
            "Fingerprint-Chromium 归档 SHA-256 校验失败: 预期 {expected_sha256}, 实际 {actual_sha256}"
        ));
    }
    logs.push(format!(
        "Fingerprint-Chromium 归档 SHA-256 校验通过 ({actual_sha256})"
    ));

    let _ = app.emit(
        "browser-download-progress",
        DownloadProgress {
            stage: "extracting".into(),
            downloaded_bytes: downloaded,
            total_bytes: total,
            message: "SHA-256 校验通过，正在安全解压到独立内核目录...".into(),
        },
    );

    let staging_dir = app_data_dir().join("browser-fp-staging");
    let zip_clone = zip_path.clone();
    let staging_clone = staging_dir.clone();
    let target_clone = target_dir.clone();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let extract_res = extract_chromium_zip_safe(&zip_clone, &staging_clone);
        let _ = fs::remove_file(&zip_clone);
        extract_res?;
        if find_chrome_exe_in(&staging_clone).is_none() {
            let _ = fs::remove_dir_all(&staging_clone);
            return Err("解压完成但未找到 chrome.exe".into());
        }
        mark_fp_engine_installed(&staging_clone)?;

        let backup_dir = app_data_dir().join("browser-fp-old");
        let _ = fs::remove_dir_all(&backup_dir);
        let had_existing = target_clone.exists();
        if had_existing {
            fs::rename(&target_clone, &backup_dir).map_err(|e| {
                let _ = fs::remove_dir_all(&staging_clone);
                format!("请先关闭所有正在运行的 Fingerprint-Chromium 窗口再升级内核: {e}")
            })?;
        }
        if let Err(e) = fs::rename(&staging_clone, &target_clone) {
            if had_existing {
                let _ = fs::rename(&backup_dir, &target_clone);
            }
            let _ = fs::remove_dir_all(&staging_clone);
            return Err(format!("激活 Fingerprint-Chromium 150 内核目录失败: {e}"));
        }
        if had_existing {
            let _ = fs::remove_dir_all(&backup_dir);
        }
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())??;

    let _ = harden_browser_preferences(&app_data_dir().join("browser-profile-fp"), None);

    let _ = app.emit(
        "browser-download-progress",
        DownloadProgress {
            stage: "extracting".into(),
            downloaded_bytes: downloaded,
            total_bytes: total,
            message: "正在安装 Chrome 应用商店扩展支持 (chromium-web-store)...".into(),
        },
    );

    if let Err(err) = install_cws_extension(&direct_client, proxy_client.as_ref(), &logs).await {
        logs.push(format!("Chrome 商店扩展自动安装跳过（可稍后重试）: {err}"));
        cws_note = Some(err);
    }

    let _ = app.emit(
        "browser-download-progress",
        DownloadProgress {
            stage: "done".into(),
            downloaded_bytes: downloaded,
            total_bytes: total,
            message: "Fingerprint-Chromium 150 安装完成".into(),
        },
    );
    logs.push(format!(
        "Fingerprint-Chromium 150 已安装至 {}",
        target_dir.display()
    ));
    match cws_note {
        None => Ok("Fingerprint-Chromium 150 内核与 Chrome 商店插件安装成功".into()),
        Some(err) => Ok(format!(
            "Fingerprint-Chromium 150 内核安装成功（Chrome 商店插件可稍后点「补装商店插件」重试: {err}）"
        )),
    }
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
        root["intl"] = json!({ "accept_languages": build_accept_languages(loc) });
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

pub fn profile_storage_dirs_for_engine(
    profile_id: &str,
    is_fp: bool,
) -> Result<(PathBuf, PathBuf), String> {
    if !is_fp {
        return profile_storage_dirs(profile_id);
    }
    let safe_id = sanitize_profile_id(profile_id)?;
    if safe_id == "default" {
        Ok((
            app_data_dir().join("browser-profile-fp"),
            app_data_dir().join("fingerprint-ext-fp"),
        ))
    } else {
        Ok((
            app_data_dir().join("browser-profiles-fp").join(&safe_id),
            app_data_dir().join("fingerprint-exts-fp").join(&safe_id),
        ))
    }
}

pub fn compute_fingerprint_seed_u32(seed_input: &str) -> u32 {
    let trimmed = seed_input.trim();
    let mut hash: u32 = 0x811c_9dc5;
    for &b in trimmed.as_bytes() {
        hash ^= u32::from(b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    // Keep within positive signed 32-bit int range (1..=i32::MAX) for C++ StringToInt/Uint compatibility.
    let masked = hash & 0x7FFF_FFFF;
    if masked == 0 {
        1
    } else {
        masked
    }
}

pub fn build_accept_languages(locale: &str) -> String {
    let loc = locale.trim();
    if loc.is_empty() {
        return "en-US,en".to_string();
    }
    let base_lang = loc.split('-').next().unwrap_or(loc);
    if base_lang.eq_ignore_ascii_case("en") {
        format!("{loc},{base_lang}")
    } else {
        format!("{loc},{base_lang},en-US,en")
    }
}

const NTP_MANIFEST_JSON: &str = r#"{
  "manifest_version": 3,
  "name": "AI NetGuard New Tab",
  "version": "1.0.0",
  "description": "Clean offline Google Chrome-style New Tab page for AI NetGuard browser profiles.",
  "chrome_url_overrides": {
    "newtab": "newtab.html"
  }
}
"#;

const NTP_HTML: &str = r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>新标签页</title>
  <link rel="stylesheet" href="newtab.css">
</head>
<body>
  <header class="top-nav" aria-label="常用服务快捷入口">
    <a class="nav-link" href="https://mail.google.com/">Gmail</a>
    <a class="nav-link" href="https://gemini.google.com/app">Gemini</a>
    <a class="nav-link" href="https://claude.ai/">Claude</a>
    <a class="nav-link" href="https://fuck-claude.vercel.app/">IP 检测</a>
  </header>

  <main class="ntp-main">
    <div class="google-wordmark" role="img" aria-label="Google">
      <span class="g-blue">G</span><span class="g-red">o</span><span class="g-yellow">o</span><span class="g-blue">g</span><span class="g-green">l</span><span class="g-red">e</span>
    </div>

    <form id="search-form" class="search-form" role="search">
      <svg class="search-icon" viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="10.5" cy="10.5" r="6.5" fill="none" stroke="currentColor" stroke-width="2"></circle>
        <line x1="15.5" y1="15.5" x2="20.5" y2="20.5" stroke="currentColor" stroke-width="2" stroke-linecap="round"></line>
      </svg>
      <input
        id="search-input"
        class="search-input"
        type="search"
        autocomplete="off"
        spellcheck="false"
        autofocus
        aria-label="在 Google 上搜索，或者输入一个网址"
        placeholder="在 Google 上搜索，或者输入一个网址"
      >
      <button type="submit" class="search-submit-btn" aria-label="搜索或前往网址" title="Google 搜索">
        <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
          <path d="M5 12h13M13 6l6 6-6 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>
        </svg>
      </button>
    </form>

    <section id="shortcuts-grid" class="shortcuts-grid" aria-label="快捷方式"></section>

    <div class="ntp-actions">
      <button id="reset-shortcuts-btn" type="button" class="reset-btn">
        恢复默认快捷方式
      </button>
    </div>
  </main>

  <dialog id="add-shortcut-dialog" class="shortcut-dialog" aria-labelledby="add-shortcut-title">
    <form id="add-shortcut-form" method="dialog" class="dialog-form">
      <h2 id="add-shortcut-title" class="dialog-title">添加快捷方式</h2>
      <div class="field">
        <label for="sc-name">名称</label>
        <input id="sc-name" type="text" maxlength="24" required placeholder="例如 ChatGPT">
      </div>
      <div class="field">
        <label for="sc-url">网址</label>
        <input id="sc-url" type="text" required placeholder="例如 https://chatgpt.com">
      </div>
      <p id="sc-error" class="dialog-error" hidden></p>
      <div class="dialog-footer">
        <button id="sc-cancel-btn" type="button" class="btn-secondary">取消</button>
        <button type="submit" class="btn-primary">完成</button>
      </div>
    </form>
  </dialog>

  <script defer src="newtab.js"></script>
</body>
</html>
"#;

const NTP_CSS: &str = r#":root {
  --bg: #ffffff;
  --fg: #202124;
  --muted: #5f6368;
  --surface: #ffffff;
  --tile-bg: #f1f3f4;
  --tile-hover: rgba(32, 33, 36, 0.08);
  --shadow-search: 0 1px 6px rgba(32, 33, 36, 0.28);
  --shadow-search-hover: 0 2px 10px rgba(32, 33, 36, 0.34);
  --border-subtle: #dadce0;
  --accent: #1a73e8;
  --accent-fg: #ffffff;
  --danger: #d93025;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #202124;
    --fg: #e8eaed;
    --muted: #9aa0a6;
    --surface: #303134;
    --tile-bg: #3c4043;
    --tile-hover: rgba(232, 234, 237, 0.1);
    --shadow-search: 0 1px 6px rgba(0, 0, 0, 0.45);
    --shadow-search-hover: 0 2px 10px rgba(0, 0, 0, 0.55);
    --border-subtle: #5f6368;
    --accent: #8ab4f8;
    --accent-fg: #202124;
    --danger: #f28b82;
  }
}

* {
  box-sizing: border-box;
}

html,
body {
  margin: 0;
  padding: 0;
  min-height: 100vh;
  background-color: var(--bg);
  color: var(--fg);
  font-family: "Microsoft YaHei UI", "Segoe UI", system-ui, -apple-system, sans-serif;
  -webkit-font-smoothing: antialiased;
}

.top-nav {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  gap: 18px;
  padding: 16px 24px 0;
  font-size: 13px;
}

.nav-link {
  color: var(--fg);
  text-decoration: none;
  opacity: 0.88;
}

.nav-link:hover {
  text-decoration: underline;
  opacity: 1;
}

.ntp-main {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: clamp(54px, 11vh, 116px) 16px 40px;
}

.google-wordmark {
  user-select: none;
  font-family: "Product Sans", "Segoe UI", Arial, sans-serif;
  font-size: clamp(56px, 8vw, 84px);
  font-weight: 500;
  line-height: 1.05;
  letter-spacing: -2.2px;
  margin-bottom: 28px;
}

.g-blue { color: #4285f4; }
.g-red { color: #ea4335; }
.g-yellow { color: #fbbc05; }
.g-green { color: #34a853; }

.search-form {
  display: flex;
  align-items: center;
  gap: 10px;
  width: min(561px, calc(100vw - 32px));
  height: 46px;
  padding: 0 8px 0 18px;
  border-radius: 24px;
  background-color: var(--surface);
  box-shadow: var(--shadow-search);
  transition: box-shadow 0.16s ease;
}

.search-form:hover,
.search-form:focus-within {
  box-shadow: var(--shadow-search-hover);
}

.search-icon {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
  color: var(--muted);
}

.search-input {
  flex: 1;
  min-width: 0;
  height: 100%;
  border: none;
  outline: none;
  background: transparent;
  color: var(--fg);
  font-size: 15px;
  font-family: inherit;
}

.search-input::placeholder {
  color: var(--muted);
}

.search-input::-webkit-search-cancel-button {
  -webkit-appearance: none;
}

.search-submit-btn {
  display: inline-grid;
  place-items: center;
  width: 32px;
  height: 32px;
  border: none;
  border-radius: 50%;
  background: transparent;
  color: var(--muted);
  cursor: pointer;
  flex-shrink: 0;
  transition: background-color 0.14s ease, color 0.14s ease;
}

.search-submit-btn:hover {
  background-color: var(--tile-hover);
  color: var(--fg);
}

.shortcuts-grid {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 8px 4px;
  width: min(576px, calc(100vw - 24px));
  margin-top: 26px;
}

.tile-wrap {
  position: relative;
  width: 112px;
  border-radius: 8px;
  transition: background-color 0.14s ease;
}

.tile-wrap:hover {
  background-color: var(--tile-hover);
}

.tile-link,
.tile-add-btn {
  display: flex;
  flex-direction: column;
  align-items: center;
  width: 100%;
  padding: 14px 8px 12px;
  border: none;
  background: transparent;
  color: var(--fg);
  text-decoration: none;
  font-family: inherit;
  cursor: pointer;
}

.tile-circle {
  display: inline-grid;
  place-items: center;
  width: 48px;
  height: 48px;
  border-radius: 50%;
  background-color: var(--tile-bg);
  margin-bottom: 12px;
  font-size: 19px;
  font-weight: 600;
  color: #ffffff;
}

.tile-circle-add {
  color: var(--fg);
  font-size: 24px;
  font-weight: 400;
}

.tile-title {
  width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  text-align: center;
  font-size: 13px;
  line-height: 1.3;
}

.tile-remove {
  position: absolute;
  top: 4px;
  right: 4px;
  display: grid;
  place-items: center;
  width: 22px;
  height: 22px;
  border: none;
  border-radius: 50%;
  background: transparent;
  color: var(--muted);
  font-size: 14px;
  line-height: 1;
  cursor: pointer;
  opacity: 0;
  transition: opacity 0.14s ease, background-color 0.14s ease;
}

.tile-wrap:hover .tile-remove,
.tile-wrap:focus-within .tile-remove {
  opacity: 1;
}

.tile-remove:hover {
  background-color: var(--tile-hover);
  color: var(--fg);
}

.ntp-actions {
  margin-top: 22px;
}

.reset-btn {
  border: 1px solid var(--border-subtle);
  border-radius: 16px;
  background: transparent;
  color: var(--muted);
  padding: 5px 12px;
  font-size: 12px;
  font-family: inherit;
  cursor: pointer;
  opacity: 0.72;
  transition: opacity 0.14s ease, background-color 0.14s ease;
}

.reset-btn:hover {
  opacity: 1;
  background-color: var(--tile-hover);
  color: var(--fg);
}

.shortcut-dialog {
  width: min(360px, calc(100vw - 32px));
  margin: auto;
  padding: 20px;
  border: 1px solid var(--border-subtle);
  border-radius: 12px;
  background: var(--surface);
  color: var(--fg);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.25);
}

.shortcut-dialog::backdrop {
  background: rgba(0, 0, 0, 0.42);
}

.dialog-form {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.dialog-title {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 5px;
  font-size: 12px;
  color: var(--muted);
}

.field input {
  height: 36px;
  padding: 0 10px;
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
  background: var(--bg);
  color: var(--fg);
  font-size: 13px;
  font-family: inherit;
}

.field input:focus {
  outline: 2px solid var(--accent);
  outline-offset: 1px;
}

.dialog-error {
  margin: 0;
  font-size: 12px;
  color: var(--danger);
}

.dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 4px;
}

.btn-secondary,
.btn-primary {
  height: 32px;
  padding: 0 14px;
  border-radius: 16px;
  font-size: 13px;
  font-family: inherit;
  cursor: pointer;
}

.btn-secondary {
  border: 1px solid var(--border-subtle);
  background: transparent;
  color: var(--fg);
}

.btn-primary {
  border: none;
  background: var(--accent);
  color: var(--accent-fg);
  font-weight: 500;
}
"#;

const NTP_JS: &str = r##"(() => {
  const STORAGE_KEY = "ng_ntp_shortcuts_v1";
  const DEFAULT_SHORTCUTS = [
    { title: "Google", url: "https://www.google.com/", color: "#4285f4" },
    { title: "Gmail", url: "https://mail.google.com/", color: "#ea4335" },
    { title: "Gemini", url: "https://gemini.google.com/app", color: "#8e24aa" },
    { title: "Claude", url: "https://claude.ai/", color: "#d97706" },
    { title: "ChatGPT", url: "https://chatgpt.com/", color: "#10a37f" },
    { title: "YouTube", url: "https://www.youtube.com/", color: "#e53935" },
    { title: "GitHub", url: "https://github.com/", color: "#24292f" },
    { title: "IP 检测", url: "https://fuck-claude.vercel.app/", color: "#6d5bd0" }
  ];
  const PALETTE = ["#4285f4", "#ea4335", "#0f9d58", "#8e24aa", "#d97706", "#00897b", "#5c6bc0"];

  const searchForm = document.getElementById("search-form");
  const searchInput = document.getElementById("search-input");
  const grid = document.getElementById("shortcuts-grid");
  const resetBtn = document.getElementById("reset-shortcuts-btn");
  const dialog = document.getElementById("add-shortcut-dialog");
  const dialogForm = document.getElementById("add-shortcut-form");
  const scName = document.getElementById("sc-name");
  const scUrl = document.getElementById("sc-url");
  const scError = document.getElementById("sc-error");
  const scCancelBtn = document.getElementById("sc-cancel-btn");

  function colorForText(s) {
    let h = 0;
    for (let i = 0; i < s.length; i += 1) {
      h = (h * 31 + s.charCodeAt(i)) >>> 0;
    }
    return PALETTE[h % PALETTE.length];
  }

  function normalizeHttpUrl(raw) {
    const trimmed = String(raw || "").trim();
    if (!trimmed) return null;
    const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : "https://" + trimmed;
    try {
      const parsed = new URL(candidate);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return null;
      }
      return parsed.href;
    } catch {
      return null;
    }
  }

  function resolveNavigationTarget(raw) {
    const trimmed = String(raw || "").trim();
    if (!trimmed) return null;
    if (/^https?:\/\//i.test(trimmed)) {
      try {
        const parsed = new URL(trimmed);
        if (parsed.protocol === "http:" || parsed.protocol === "https:") {
          return parsed.href;
        }
      } catch {
        // Fall through to Google search
      }
    }
    if (!/\s/.test(trimmed)) {
      if (/^(localhost|(\d{1,3}\.){3}\d{1,3})(:\d{1,5})?(\/.*)?$/i.test(trimmed)) {
        return "http://" + trimmed;
      }
      if (/^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d{1,5})?(\/.*)?$/i.test(trimmed)) {
        return "https://" + trimmed;
      }
    }
    return "https://www.google.com/search?q=" + encodeURIComponent(trimmed);
  }

  function loadShortcuts() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return DEFAULT_SHORTCUTS.map((s) => Object.assign({}, s));
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) {
        return DEFAULT_SHORTCUTS.map((s) => Object.assign({}, s));
      }
      return parsed.filter((item) => item && typeof item.title === "string" && normalizeHttpUrl(item.url));
    } catch {
      return DEFAULT_SHORTCUTS.map((s) => Object.assign({}, s));
    }
  }

  function saveShortcuts(list) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
    } catch {
      // Ignore storage errors inside restricted contexts
    }
  }

  function badgeLetter(title, url) {
    const clean = String(title || "").trim();
    if (clean) return Array.from(clean)[0].toUpperCase();
    try {
      const host = new URL(url).hostname.replace(/^www\./, "");
      return (host[0] || "W").toUpperCase();
    } catch {
      return "W";
    }
  }

  function renderShortcuts() {
    const list = loadShortcuts();
    grid.replaceChildren();

    list.forEach((sc, index) => {
      const wrap = document.createElement("div");
      wrap.className = "tile-wrap";

      const link = document.createElement("a");
      link.className = "tile-link";
      link.href = normalizeHttpUrl(sc.url) || "https://www.google.com/";
      link.title = sc.title + " · " + link.href;

      const circle = document.createElement("span");
      circle.className = "tile-circle";
      circle.style.backgroundColor = sc.color || colorForText(sc.title || link.href);
      circle.textContent = badgeLetter(sc.title, link.href);

      const label = document.createElement("span");
      label.className = "tile-title";
      label.textContent = sc.title;

      link.appendChild(circle);
      link.appendChild(label);

      const removeBtn = document.createElement("button");
      removeBtn.type = "button";
      removeBtn.className = "tile-remove";
      removeBtn.setAttribute("aria-label", "移除快捷方式 " + sc.title);
      removeBtn.textContent = "×";
      removeBtn.addEventListener("click", (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        const next = loadShortcuts().filter((_, idx) => idx !== index);
        saveShortcuts(next);
        renderShortcuts();
      });

      wrap.appendChild(link);
      wrap.appendChild(removeBtn);
      grid.appendChild(wrap);
    });

    if (list.length < 16) {
      const addWrap = document.createElement("div");
      addWrap.className = "tile-wrap";

      const addBtn = document.createElement("button");
      addBtn.type = "button";
      addBtn.className = "tile-add-btn";

      const circle = document.createElement("span");
      circle.className = "tile-circle tile-circle-add";
      circle.textContent = "+";

      const label = document.createElement("span");
      label.className = "tile-title";
      label.textContent = "添加快捷方式";

      addBtn.appendChild(circle);
      addBtn.appendChild(label);
      addBtn.addEventListener("click", () => {
        scName.value = "";
        scUrl.value = "";
        scError.hidden = true;
        scError.textContent = "";
        dialog.showModal();
        scName.focus();
      });

      addWrap.appendChild(addBtn);
      grid.appendChild(addWrap);
    }
  }

  searchForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const target = resolveNavigationTarget(searchInput.value);
    if (target) {
      window.location.href = target;
    }
  });

  scCancelBtn.addEventListener("click", () => {
    dialog.close();
  });

  dialogForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const title = scName.value.trim();
    const normalizedUrl = normalizeHttpUrl(scUrl.value);
    if (!title) {
      scError.textContent = "请输入快捷方式名称";
      scError.hidden = false;
      return;
    }
    if (!normalizedUrl) {
      scError.textContent = "请输入有效的 http:// 或 https:// 网址";
      scError.hidden = false;
      return;
    }
    const list = loadShortcuts();
    list.push({
      title,
      url: normalizedUrl,
      color: colorForText(title)
    });
    saveShortcuts(list);
    dialog.close();
    renderShortcuts();
  });

  resetBtn.addEventListener("click", () => {
    localStorage.removeItem(STORAGE_KEY);
    renderShortcuts();
  });

  renderShortcuts();
})();
"##;

pub fn write_chrome_newtab_extension_to(ext_dir: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(ext_dir).map_err(|e| format!("创建新标签页扩展目录失败: {e}"))?;
    fs::write(ext_dir.join("manifest.json"), NTP_MANIFEST_JSON)
        .map_err(|e| format!("写入新标签页 manifest.json 失败: {e}"))?;
    fs::write(ext_dir.join("newtab.html"), NTP_HTML)
        .map_err(|e| format!("写入 newtab.html 失败: {e}"))?;
    fs::write(ext_dir.join("newtab.css"), NTP_CSS)
        .map_err(|e| format!("写入 newtab.css 失败: {e}"))?;
    fs::write(ext_dir.join("newtab.js"), NTP_JS)
        .map_err(|e| format!("写入 newtab.js 失败: {e}"))?;
    Ok(ext_dir.to_path_buf())
}

pub fn ensure_chrome_newtab_extension() -> Result<PathBuf, String> {
    write_chrome_newtab_extension_to(&chrome_newtab_extension_dir())
}

#[allow(clippy::too_many_arguments)]
pub fn build_browser_launch_args(
    is_fp: bool,
    profile: &BrowserProfile,
    profile_dir: &Path,
    proxy_server_url: &str,
    effective_tz: &str,
    effective_locale: &str,
    align_fingerprint: bool,
    cws_ext_dir: Option<&Path>,
    ntp_ext_dir: Option<&Path>,
    legacy_ext_dir: Option<&Path>,
    cdp_port: Option<u16>,
    target_url: &str,
) -> Vec<String> {
    let mut args = vec![
        format!("--user-data-dir={}", profile_dir.display()),
        format!("--proxy-server={proxy_server_url}"),
        "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1 , EXCLUDE localhost , EXCLUDE ::1".to_string(),
        "--force-webrtc-ip-handling-policy".to_string(),
        "--webrtc-ip-handling-policy=disable_non_proxied_udp".to_string(),
        "--disable-quic".to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--disable-sync".to_string(),
        "--disable-background-networking".to_string(),
        "--lang=zh-CN".to_string(),
    ];

    let should_align = matches!(
        profile.fingerprint_mode,
        BrowserFingerprintMode::IsolatedFingerprint
    ) || align_fingerprint;

    let clean_ua = profile
        .fingerprint
        .user_agent
        .as_deref()
        .map(|s| s.chars().filter(|c| !c.is_control()).collect::<String>())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if is_fp {
        args.push("--disable-non-proxied-udp".to_string());
        args.push("--extension-mime-request-handling=always-prompt-for-install".to_string());

        if should_align {
            let raw_seed = profile.fingerprint.noise_seed.trim();
            let seed_src = if raw_seed.is_empty() {
                profile.id.as_str()
            } else {
                raw_seed
            };
            let seed_num = compute_fingerprint_seed_u32(seed_src);
            args.push(format!("--fingerprint={seed_num}"));
            args.push("--fingerprint-platform=windows".to_string());
            args.push("--fingerprint-brand=Chrome".to_string());
            args.push(format!("--timezone={effective_tz}"));
            args.push(format!(
                "--accept-lang={}",
                build_accept_languages(effective_locale)
            ));

            if matches!(profile.fingerprint_mode, BrowserFingerprintMode::CleanAlign) {
                args.push("--disable-spoofing=font,audio,canvas,clientrects,gpu".to_string());
            } else {
                let hw = profile.fingerprint.hardware_concurrency.clamp(2, 64);
                let sw = profile.fingerprint.screen_width.clamp(800, 3840);
                let sh = profile.fingerprint.screen_height.clamp(600, 2160);
                args.push(format!("--fingerprint-hardware-concurrency={hw}"));
                args.push(format!("--window-size={sw},{sh}"));
                if let Some(ua) = clean_ua {
                    args.push(format!("--user-agent={ua}"));
                }
            }
        }

        let mut ext_paths: Vec<String> = Vec::new();
        if let Some(cws) = cws_ext_dir {
            ext_paths.push(cws.display().to_string());
        }
        if let Some(ntp) = ntp_ext_dir {
            ext_paths.push(ntp.display().to_string());
        }
        if !ext_paths.is_empty() {
            args.push("--disable-features=DisableLoadExtensionCommandLineSwitch".to_string());
            args.push(format!("--load-extension={}", ext_paths.join(",")));
        }
    } else {
        let mut ext_paths: Vec<String> = Vec::new();
        if should_align {
            if let Some(leg) = legacy_ext_dir {
                ext_paths.push(leg.display().to_string());
            }
        }
        if let Some(cws) = cws_ext_dir {
            ext_paths.push(cws.display().to_string());
            args.push("--extension-mime-request-handling=always-prompt-for-install".to_string());
        }
        if let Some(ntp) = ntp_ext_dir {
            ext_paths.push(ntp.display().to_string());
        }
        if !ext_paths.is_empty() {
            args.push("--disable-features=DisableLoadExtensionCommandLineSwitch".to_string());
            args.push(format!("--load-extension={}", ext_paths.join(",")));
        }
        if matches!(
            profile.fingerprint_mode,
            BrowserFingerprintMode::IsolatedFingerprint
        ) {
            let sw = profile.fingerprint.screen_width.clamp(800, 3840);
            let sh = profile.fingerprint.screen_height.clamp(600, 2160);
            args.push(format!("--window-size={sw},{sh}"));
            if let Some(ua) = clean_ua {
                args.push(format!("--user-agent={ua}"));
            }
        }
    }

    if let Some(port) = cdp_port {
        args.push(format!("--remote-debugging-port={port}"));
        args.push("--remote-debugging-address=127.0.0.1".to_string());
    }

    args.push(target_url.to_string());
    args
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

        // 4. Flat archive without top-level folder keeps root files intact
        let flat_zip = base.join("flat.zip");
        {
            let f = File::create(&flat_zip).unwrap();
            let mut zw = zip::ZipWriter::new(f);
            zw.start_file("chrome.exe", zip::write::SimpleFileOptions::default())
                .unwrap();
            zw.write_all(b"MZ").unwrap();
            zw.start_file("locales/zh-CN.pak", zip::write::SimpleFileOptions::default())
                .unwrap();
            zw.write_all(b"pak").unwrap();
            zw.finish().unwrap();
        }
        let flat_target = base.join("out-flat");
        extract_chromium_zip_safe(&flat_zip, &flat_target).unwrap();
        assert!(flat_target.join("chrome.exe").exists());
        assert!(flat_target.join("locales").join("zh-CN.pak").exists());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn fingerprint_seed_and_accept_languages_are_deterministic() {
        let s1 = compute_fingerprint_seed_u32("ng-seed-001");
        let s2 = compute_fingerprint_seed_u32("ng-seed-001");
        let s3 = compute_fingerprint_seed_u32("ng-seed-002");
        assert_eq!(s1, s2);
        assert_ne!(s1, s3);
        assert!(s1 >= 1 && s1 <= i32::MAX as u32);
        assert!(compute_fingerprint_seed_u32("") >= 1);

        assert_eq!(build_accept_languages("en-US"), "en-US,en");
        assert_eq!(build_accept_languages("ko-KR"), "ko-KR,ko,en-US,en");
        assert_eq!(build_accept_languages("ja-JP"), "ja-JP,ja,en-US,en");
    }

    #[test]
    fn allowed_fp_chromium_and_cws_urls_strictly_validate_repos() {
        assert!(is_allowed_fp_chromium_url(FP_CHROMIUM_FALLBACK_URL));
        assert!(is_allowed_cws_url(CWS_CRX_URL));
        assert!(!is_allowed_fp_chromium_url(
            "https://github.com/evil/repo/releases/download/1.0/x.zip"
        ));
        assert!(!is_allowed_fp_chromium_url("http://github.com/adryfish/fingerprint-chromium/releases/download/1/a.zip"));
        assert!(!is_allowed_cws_url(
            "https://example.com/Chromium.Web.Store.crx"
        ));
    }

    #[test]
    fn extract_crx3_safe_unpacks_valid_crx_and_rejects_bad_headers_and_traversal() {
        let base = std::env::temp_dir().join("ng-crx3-sec-test");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        let make_crx3 = |files: &[(&str, &[u8])]| -> Vec<u8> {
            let mut zip_buf = Cursor::new(Vec::<u8>::new());
            {
                let mut zw = zip::ZipWriter::new(&mut zip_buf);
                for (name, data) in files {
                    zw.start_file(*name, zip::write::SimpleFileOptions::default())
                        .unwrap();
                    zw.write_all(data).unwrap();
                }
                zw.finish().unwrap();
            }
            let header = b"dummy-pb-header";
            let mut out = Vec::new();
            out.extend_from_slice(b"Cr24");
            out.extend_from_slice(&3u32.to_le_bytes());
            out.extend_from_slice(&(header.len() as u32).to_le_bytes());
            out.extend_from_slice(header);
            out.extend_from_slice(&zip_buf.into_inner());
            out
        };

        let target = base.join("cws-out");
        let valid_crx = make_crx3(&[
            ("manifest.json", br#"{"manifest_version":3,"name":"CWS","version":"1.5.5.4"}"#),
            ("scripts/inject.js", b"console.log('ok');"),
        ]);
        extract_crx3_safe(&valid_crx, &target).unwrap();
        assert!(target.join("manifest.json").exists());
        assert!(target.join("scripts").join("inject.js").exists());

        // Reject bad magic
        let mut bad_magic = valid_crx.clone();
        bad_magic[0] = b'X';
        assert!(extract_crx3_safe(&bad_magic, &target).is_err());

        // Reject traversal inside CRX3 ZIP
        let evil_crx = make_crx3(&[
            ("manifest.json", br#"{"manifest_version":3}"#),
            ("../pwn.js", b"alert(1)"),
        ]);
        assert!(extract_crx3_safe(&evil_crx, &base.join("evil-out")).is_err());
        assert!(!base.join("pwn.js").exists());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn build_browser_launch_args_sets_native_fp_flags_and_chinese_ui() {
        let prof_dir = PathBuf::from(r"C:\Temp\bp-test");
        let cws_dir = PathBuf::from(r"C:\Temp\cws-ext");
        let ntp_dir = PathBuf::from(r"C:\Temp\ntp-ext");
        let legacy_dir = PathBuf::from(r"C:\Temp\legacy-ext");

        let mut clean_profile = default_browser_profiles().into_iter().next().unwrap();
        clean_profile.fingerprint_mode = BrowserFingerprintMode::CleanAlign;
        clean_profile.fingerprint.noise_seed = "seed-claude-main".into();

        let clean_args = build_browser_launch_args(
            true,
            &clean_profile,
            &prof_dir,
            "socks5://127.0.0.1:17891",
            "Asia/Seoul",
            "ko-KR",
            true,
            Some(&cws_dir),
            Some(&ntp_dir),
            None,
            Some(19555),
            "https://claude.ai",
        );
        assert!(clean_args.contains(&"--lang=zh-CN".to_string()));
        assert!(clean_args.contains(
            &"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1 , EXCLUDE localhost , EXCLUDE ::1".to_string()
        ));
        assert!(clean_args.contains(&"--accept-lang=ko-KR,ko,en-US,en".to_string()));
        assert!(clean_args.contains(&"--timezone=Asia/Seoul".to_string()));
        assert!(clean_args.contains(&"--fingerprint-brand=Chrome".to_string()));
        assert!(clean_args.contains(&"--fingerprint-platform=windows".to_string()));
        assert!(clean_args.contains(&"--disable-non-proxied-udp".to_string()));
        assert!(clean_args.contains(&"--disable-spoofing=font,audio,canvas,clientrects,gpu".to_string()));
        assert!(clean_args.iter().any(|a| a.starts_with("--fingerprint=")));
        assert!(clean_args.contains(&format!(
            "--load-extension={},{}",
            cws_dir.display(),
            ntp_dir.display()
        )));
        assert!(clean_args.contains(&"--extension-mime-request-handling=always-prompt-for-install".to_string()));
        assert!(clean_args.contains(&"--remote-debugging-port=19555".to_string()));
        assert!(clean_args.contains(&"--remote-debugging-address=127.0.0.1".to_string()));

        let mut iso_profile = clean_profile.clone();
        iso_profile.id = "bp-jp-01".into();
        iso_profile.fingerprint_mode = BrowserFingerprintMode::IsolatedFingerprint;
        iso_profile.fingerprint.hardware_concurrency = 12;
        iso_profile.fingerprint.screen_width = 1680;
        iso_profile.fingerprint.screen_height = 1050;

        let iso_args = build_browser_launch_args(
            true,
            &iso_profile,
            &prof_dir,
            "socks5://127.0.0.1:10808",
            "Asia/Tokyo",
            "ja-JP",
            true,
            Some(&cws_dir),
            Some(&ntp_dir),
            None,
            None,
            "https://accounts.google.com/",
        );
        assert!(!iso_args.iter().any(|a| a.starts_with("--disable-spoofing=")));
        assert!(iso_args.contains(&"--fingerprint-hardware-concurrency=12".to_string()));
        assert!(iso_args.contains(&"--window-size=1680,1050".to_string()));
        assert!(iso_args.contains(&"--lang=zh-CN".to_string()));

        // Legacy Chromium still uses Simplified Chinese UI + legacy align ext + CWS + NTP
        let leg_args = build_browser_launch_args(
            false,
            &iso_profile,
            &prof_dir,
            "socks5://127.0.0.1:17891",
            "Asia/Tokyo",
            "ja-JP",
            true,
            Some(&cws_dir),
            Some(&ntp_dir),
            Some(&legacy_dir),
            None,
            "https://claude.ai",
        );
        assert!(leg_args.contains(&"--lang=zh-CN".to_string()));
        assert!(!leg_args.iter().any(|a| a.starts_with("--fingerprint=")));
        assert!(leg_args.contains(&format!(
            "--load-extension={},{},{}",
            legacy_dir.display(),
            cws_dir.display(),
            ntp_dir.display()
        )));
    }

    #[test]
    fn chrome_newtab_extension_writes_clean_zero_permission_mv3() {
        let base = std::env::temp_dir().join(format!(
            "ai-netguard-ntp-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let written = write_chrome_newtab_extension_to(&base).unwrap();
        assert_eq!(written, base);

        let manifest_raw = fs::read_to_string(base.join("manifest.json")).unwrap();
        let manifest: Value = serde_json::from_str(&manifest_raw).unwrap();
        assert_eq!(manifest["manifest_version"], json!(3));
        assert_eq!(
            manifest["chrome_url_overrides"]["newtab"],
            json!("newtab.html")
        );
        assert!(manifest.get("permissions").is_none());
        assert!(manifest.get("host_permissions").is_none());
        assert!(manifest.get("content_scripts").is_none());

        let html = fs::read_to_string(base.join("newtab.html")).unwrap();
        assert!(!html.contains("<script>"));
        assert!(html.contains(r#"<script defer src="newtab.js"></script>"#));
        assert!(base.join("newtab.css").exists());
        assert!(base.join("newtab.js").exists());

        let _ = fs::remove_dir_all(&base);
    }
}
