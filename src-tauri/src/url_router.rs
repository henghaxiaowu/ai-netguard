use crate::app_env::build_clean_base_env;
use crate::models::{app_data_dir, load_config, UrlRouterConfig, UrlRouterMode};
use chrono::Local;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
    RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_OPTION_NON_VOLATILE,
    REG_SZ, REG_VALUE_TYPE,
};
use windows::Win32::UI::Shell::{SHChangeNotify, ShellExecuteW, SHCNE_ASSOCCHANGED, SHCNF_IDLIST};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

pub const PROG_ID: &str = "AINetGuardURL";
const APP_REG_NAME: &str = "AI NetGuard";
const CLIENT_KEY: &str = r"Software\Clients\StartMenuInternet\AI NetGuard";
const REGISTERED_APPS_KEY: &str = r"Software\RegisteredApplications";
const IPC_FILE_NAME: &str = "url-router-ipc.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UrlRouterStatus {
    pub registered: bool,
    pub registered_exe_matches: bool,
    pub is_default_http: bool,
    pub is_default_https: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_http_prog_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_https_prog_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_browser_path: Option<String>,
    pub current_exe_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PendingUrlPick {
    pub id: String,
    pub url: String,
    pub display_url: String,
    pub host: String,
    pub reason: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UrlRouteEvent {
    pub time: String,
    pub host: String,
    pub display_url: String,
    pub action: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlRouteDecision {
    DirectToEdge { reason: String },
    PromptPicker { reason: String },
}

pub enum UrlCliOutcome {
    NotUrlInvocation,
    HandledAndExit(i32),
    BootWithPicker(PendingUrlPick),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RouterIpcState {
    port: u16,
    token: String,
    pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RouterIpcMessage {
    token: String,
    url: String,
    reason: String,
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide_nul(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn reg_read_sz(root: HKEY, subkey: &str, value_name: &str) -> Option<String> {
    unsafe {
        let mut hkey = HKEY::default();
        let sub_w = to_wide(subkey);
        if RegOpenKeyExW(root, PCWSTR(sub_w.as_ptr()), 0, KEY_READ, &mut hkey) != ERROR_SUCCESS {
            return None;
        }
        let val_w = to_wide(value_name);
        let mut kind = REG_VALUE_TYPE::default();
        let mut size: u32 = 0;
        let q1 = RegQueryValueExW(
            hkey,
            PCWSTR(val_w.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut size),
        );
        if q1 != ERROR_SUCCESS || size == 0 || kind != REG_SZ {
            let _ = RegCloseKey(hkey);
            return None;
        }
        let mut buf = vec![0u16; (size as usize).div_ceil(2) + 1];
        let q2 = RegQueryValueExW(
            hkey,
            PCWSTR(val_w.as_ptr()),
            None,
            Some(&mut kind),
            Some(buf.as_mut_ptr() as *mut u8),
            Some(&mut size),
        );
        let _ = RegCloseKey(hkey);
        if q2 != ERROR_SUCCESS {
            return None;
        }
        let out = from_wide_nul(&buf).trim().to_string();
        (!out.is_empty()).then_some(out)
    }
}

fn reg_write_sz(root: HKEY, subkey: &str, value_name: Option<&str>, value: &str) -> Result<(), String> {
    unsafe {
        let mut hkey = HKEY::default();
        let sub_w = to_wide(subkey);
        let err = RegCreateKeyExW(
            root,
            PCWSTR(sub_w.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        );
        if err != ERROR_SUCCESS {
            return Err(format!("创建注册表项 {subkey} 失败 (WIN32 {})", err.0));
        }
        let name_w = value_name.map(to_wide);
        let name_ptr = name_w
            .as_ref()
            .map(|v| PCWSTR(v.as_ptr()))
            .unwrap_or(PCWSTR::null());
        let data_w = to_wide(value);
        let bytes = std::slice::from_raw_parts(data_w.as_ptr() as *const u8, data_w.len() * 2);
        let set_err = RegSetValueExW(hkey, name_ptr, 0, REG_SZ, Some(bytes));
        let _ = RegCloseKey(hkey);
        if set_err != ERROR_SUCCESS {
            return Err(format!("写入注册表值 {subkey} 失败 (WIN32 {})", set_err.0));
        }
        Ok(())
    }
}

pub fn validate_routable_url(raw: &str) -> Result<url::Url, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("URL 不能为空".into());
    }
    if trimmed.len() > 8192 {
        return Err("URL 长度超过限制".into());
    }
    if trimmed.starts_with('-') {
        return Err("URL 不能以命令行开关 '-' 开头".into());
    }
    if trimmed
        .bytes()
        .any(|b| b < 0x20 || b == 0x7f)
    {
        return Err("URL 包含非法控制字符".into());
    }
    let parsed = url::Url::parse(trimmed).map_err(|e| format!("URL 解析失败: {e}"))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(format!("安全限制：仅支持路由 http/https 链接 ({scheme})"));
    }
    let host = parsed.host_str().map(str::trim).unwrap_or("");
    if host.is_empty() {
        return Err("URL 缺少有效主机名".into());
    }
    Ok(parsed)
}

pub fn sanitize_url_for_display(url: &url::Url) -> String {
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or("");
    let port_part = match url.port() {
        Some(p) => format!(":{p}"),
        None => String::new(),
    };
    let path = url.path();
    let mut path_short: String = path.chars().take(120).collect();
    if path.chars().count() > 120 {
        path_short.push_str("...");
    }
    format!("{scheme}://{host}{port_part}{path_short}")
}

fn normalize_domain_pattern(raw: &str) -> String {
    let mut s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return String::new();
    }
    if s.contains("://") {
        if let Ok(u) = url::Url::parse(&s) {
            if let Some(h) = u.host_str() {
                s = h.to_ascii_lowercase();
            }
        }
    } else if let Some((head, _)) = s.split_once('/') {
        s = head.to_string();
    }
    if let Some((host_only, port_candidate)) = s.rsplit_once(':') {
        if !host_only.starts_with('[') && port_candidate.chars().all(|c| c.is_ascii_digit()) {
            s = host_only.to_string();
        }
    }
    let trimmed = s
        .trim_matches(|c| c == '[' || c == ']')
        .trim_start_matches("*.")
        .trim_matches('.');
    trimmed.to_string()
}

pub fn domain_matches(host: &str, pattern: &str) -> bool {
    let clean_host = host
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let clean_pat = normalize_domain_pattern(pattern);
    if clean_host.is_empty() || clean_pat.is_empty() {
        return false;
    }
    if clean_host == clean_pat {
        return true;
    }
    clean_host
        .strip_suffix(&clean_pat)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

pub fn is_loopback_oauth_url(url: &url::Url) -> bool {
    const REDIRECT_KEYS: [&str; 6] = [
        "redirect_uri",
        "redirect_url",
        "return_to",
        "callback",
        "continue",
        "next",
    ];
    for (k, v) in url.query_pairs() {
        if !REDIRECT_KEYS
            .iter()
            .any(|cand| cand.eq_ignore_ascii_case(k.as_ref()))
        {
            continue;
        }
        let target = v.trim();
        if let Ok(inner) = url::Url::parse(target) {
            let host = inner
                .host_str()
                .unwrap_or("")
                .trim_matches(|c| c == '[' || c == ']')
                .to_ascii_lowercase();
            if host == "127.0.0.1" || host == "localhost" || host == "::1" {
                return true;
            }
        }
    }
    false
}

pub fn is_domestic_or_local_host(host: &str) -> bool {
    let h = host
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if h.is_empty() {
        return false;
    }
    if h == "localhost"
        || h == "::1"
        || h.ends_with(".cn")
        || h.ends_with(".local")
        || h.ends_with(".internal")
        || h == "local"
    {
        return true;
    }
    if let Ok(ip) = h.parse::<Ipv4Addr>() {
        return ip.is_loopback() || ip.is_private() || ip.is_link_local();
    }
    false
}

pub fn evaluate_url_route(url: &url::Url, cfg: &UrlRouterConfig) -> UrlRouteDecision {
    let host = url.host_str().unwrap_or("");
    for pat in &cfg.edge_bypass_domains {
        if domain_matches(host, pat) {
            return UrlRouteDecision::DirectToEdge {
                reason: format!("命中 Edge 直通白名单 ({pat})"),
            };
        }
    }

    let oauth_loopback = cfg.intercept_loopback_oauth && is_loopback_oauth_url(url);

    match cfg.mode {
        UrlRouterMode::InterceptList => {
            for pat in &cfg.intercept_domains {
                if domain_matches(host, pat) {
                    return UrlRouteDecision::PromptPicker {
                        reason: format!("命中拦截规则 ({pat})"),
                    };
                }
            }
            if oauth_loopback {
                return UrlRouteDecision::PromptPicker {
                    reason: "检测到本地 OAuth 登录回调 (redirect_uri)".into(),
                };
            }
            UrlRouteDecision::DirectToEdge {
                reason: "未命中敏感拦截名单，静默转交 Edge".into(),
            }
        }
        UrlRouterMode::AllowEdgeList => {
            for pat in &cfg.intercept_domains {
                if domain_matches(host, pat) {
                    return UrlRouteDecision::PromptPicker {
                        reason: format!("命中敏感域名 ({pat})"),
                    };
                }
            }
            if is_domestic_or_local_host(host) {
                return UrlRouteDecision::DirectToEdge {
                    reason: "国内 (.cn) 或局域网地址，静默转交 Edge".into(),
                };
            }
            UrlRouteDecision::PromptPicker {
                reason: if oauth_loopback {
                    "检测到本地 OAuth 登录回调 (redirect_uri)".into()
                } else {
                    "非 Edge 直通白名单外链（白名单防漏模式）".into()
                },
            }
        }
        UrlRouterMode::AlwaysAsk => UrlRouteDecision::PromptPicker {
            reason: if oauth_loopback {
                "检测到本地 OAuth 登录回调 (redirect_uri)".into()
            } else {
                "全部外部链接弹窗询问模式".into()
            },
        },
    }
}

fn is_safe_fallback_browser_exe(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let name_lower = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if name_lower == "ai-netguard.exe" || name_lower == "ai_netguard.exe" {
        return false;
    }
    if let Ok(cur_exe) = std::env::current_exe() {
        let cand_canon = path.canonicalize().ok();
        let cur_canon = cur_exe.canonicalize().ok();
        if cand_canon.is_some() && cand_canon == cur_canon {
            return false;
        }
    }
    true
}

pub fn resolve_fallback_browser_exe(cfg: &UrlRouterConfig) -> Option<PathBuf> {
    if let Some(custom) = cfg
        .fallback_browser_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let p = PathBuf::from(custom);
        if is_safe_fallback_browser_exe(&p) {
            return Some(p);
        }
    }

    let pf_x86 = PathBuf::from(
        std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".into()),
    );
    let pf = PathBuf::from(
        std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into()),
    );
    let local = PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_default());

    let candidates = [
        pf_x86.join("Microsoft").join("Edge").join("Application").join("msedge.exe"),
        pf.join("Microsoft").join("Edge").join("Application").join("msedge.exe"),
        local.join("Microsoft").join("Edge").join("Application").join("msedge.exe"),
        pf.join("Google").join("Chrome").join("Application").join("chrome.exe"),
        pf_x86.join("Google").join("Chrome").join("Application").join("chrome.exe"),
        local.join("Google").join("Chrome").join("Application").join("chrome.exe"),
    ];

    candidates
        .into_iter()
        .find(|p| is_safe_fallback_browser_exe(p))
}

pub fn open_url_in_fallback_browser(url: &url::Url, cfg: &UrlRouterConfig) -> Result<String, String> {
    let exe = resolve_fallback_browser_exe(cfg).ok_or_else(|| {
        "未找到兜底日常浏览器 (msedge.exe / chrome.exe)，请在「默认浏览器分流」设置中手动指定".to_string()
    })?;
    let clean_env = build_clean_base_env();
    let mut cmd = Command::new(&exe);
    cmd.env_clear();
    for (k, v) in &clean_env {
        cmd.env(k, v);
    }
    cmd.arg(url.as_str())
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    cmd.spawn()
        .map_err(|e| format!("启动日常浏览器 {} 失败: {e}", exe.display()))?;
    Ok(exe
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "Edge".into()))
}

fn read_active_url_prog_id(scheme: &str) -> Option<String> {
    let latest_key = format!(
        r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\{scheme}\UserChoiceLatest\ProgId"
    );
    reg_read_sz(HKEY_CURRENT_USER, &latest_key, "ProgId").or_else(|| {
        let legacy_key = format!(
            r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\{scheme}\UserChoice"
        );
        reg_read_sz(HKEY_CURRENT_USER, &legacy_key, "ProgId")
    })
}

pub fn inspect_router_status(cfg: &UrlRouterConfig) -> UrlRouterStatus {
    let cur_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let expected_cmd = format!("\"{cur_exe}\" --open-url \"%1\"");

    let reg_cap = reg_read_sz(HKEY_CURRENT_USER, REGISTERED_APPS_KEY, APP_REG_NAME);
    let open_cmd = reg_read_sz(
        HKEY_CURRENT_USER,
        &format!(r"Software\Classes\{PROG_ID}\shell\open\command"),
        "",
    );
    let registered = reg_cap.is_some() && open_cmd.is_some();
    let registered_exe_matches = open_cmd
        .as_deref()
        .is_some_and(|c| c.eq_ignore_ascii_case(&expected_cmd));

    let http_prog = read_active_url_prog_id("http");
    let https_prog = read_active_url_prog_id("https");
    let is_default_http = http_prog.as_deref() == Some(PROG_ID);
    let is_default_https = https_prog.as_deref() == Some(PROG_ID);

    let fallback_browser_path =
        resolve_fallback_browser_exe(cfg).map(|p| p.to_string_lossy().to_string());

    UrlRouterStatus {
        registered,
        registered_exe_matches,
        is_default_http,
        is_default_https,
        current_http_prog_id: http_prog,
        current_https_prog_id: https_prog,
        fallback_browser_path,
        current_exe_path: cur_exe,
    }
}

pub fn register_as_windows_browser() -> Result<String, String> {
    let cur_exe = std::env::current_exe()
        .map_err(|e| format!("无法获取当前程序路径: {e}"))?;
    let exe_str = cur_exe.to_string_lossy().to_string();
    let icon_val = format!("\"{exe_str}\",0");
    let open_url_cmd = format!("\"{exe_str}\" --open-url \"%1\"");
    let launch_cmd = format!("\"{exe_str}\"");
    let desc = "按域名与 OAuth 规则智能分流网页链接：国内与日常工作静默进 Edge，敏感 AI 与登录跳转弹窗选指纹环境";

    // 1. Custom ProgID for URL handling
    let prog_root = format!(r"Software\Classes\{PROG_ID}");
    reg_write_sz(HKEY_CURRENT_USER, &prog_root, None, "AI NetGuard URL")?;
    reg_write_sz(HKEY_CURRENT_USER, &prog_root, Some("URL Protocol"), "")?;
    reg_write_sz(
        HKEY_CURRENT_USER,
        &format!(r"{prog_root}\Application"),
        Some("ApplicationName"),
        "AI NetGuard 链接分流器",
    )?;
    reg_write_sz(
        HKEY_CURRENT_USER,
        &format!(r"{prog_root}\Application"),
        Some("ApplicationDescription"),
        desc,
    )?;
    reg_write_sz(
        HKEY_CURRENT_USER,
        &format!(r"{prog_root}\Application"),
        Some("ApplicationIcon"),
        &icon_val,
    )?;
    reg_write_sz(
        HKEY_CURRENT_USER,
        &format!(r"{prog_root}\DefaultIcon"),
        None,
        &icon_val,
    )?;
    reg_write_sz(
        HKEY_CURRENT_USER,
        &format!(r"{prog_root}\shell\open\command"),
        None,
        &open_url_cmd,
    )?;

    // 2. StartMenuInternet registration for Windows Settings -> Default Apps
    reg_write_sz(
        HKEY_CURRENT_USER,
        CLIENT_KEY,
        None,
        "AI NetGuard 链接分流器",
    )?;
    reg_write_sz(
        HKEY_CURRENT_USER,
        &format!(r"{CLIENT_KEY}\Capabilities"),
        Some("ApplicationName"),
        "AI NetGuard 链接分流器",
    )?;
    reg_write_sz(
        HKEY_CURRENT_USER,
        &format!(r"{CLIENT_KEY}\Capabilities"),
        Some("ApplicationDescription"),
        desc,
    )?;
    reg_write_sz(
        HKEY_CURRENT_USER,
        &format!(r"{CLIENT_KEY}\Capabilities"),
        Some("ApplicationIcon"),
        &icon_val,
    )?;
    reg_write_sz(
        HKEY_CURRENT_USER,
        &format!(r"{CLIENT_KEY}\Capabilities\URLAssociations"),
        Some("http"),
        PROG_ID,
    )?;
    reg_write_sz(
        HKEY_CURRENT_USER,
        &format!(r"{CLIENT_KEY}\Capabilities\URLAssociations"),
        Some("https"),
        PROG_ID,
    )?;
    reg_write_sz(
        HKEY_CURRENT_USER,
        &format!(r"{CLIENT_KEY}\DefaultIcon"),
        None,
        &icon_val,
    )?;
    reg_write_sz(
        HKEY_CURRENT_USER,
        &format!(r"{CLIENT_KEY}\shell\open\command"),
        None,
        &launch_cmd,
    )?;

    // 3. RegisteredApplications pointer
    reg_write_sz(
        HKEY_CURRENT_USER,
        REGISTERED_APPS_KEY,
        Some(APP_REG_NAME),
        &format!(r"{CLIENT_KEY}\Capabilities"),
    )?;

    unsafe {
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None);
    }

    Ok("已注册为 Windows 可选默认浏览器（HKCU）；请在系统「默认应用」中选择「AI NetGuard 链接分流器」".into())
}

pub fn unregister_from_windows_browser() -> Result<String, String> {
    unsafe {
        let mut hkey = HKEY::default();
        let reg_apps_w = to_wide(REGISTERED_APPS_KEY);
        if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(reg_apps_w.as_ptr()), 0, KEY_WRITE, &mut hkey)
            == ERROR_SUCCESS
        {
            let name_w = to_wide(APP_REG_NAME);
            let _ = RegDeleteValueW(hkey, PCWSTR(name_w.as_ptr()));
            let _ = RegCloseKey(hkey);
        }

        let client_w = to_wide(CLIENT_KEY);
        let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(client_w.as_ptr()));

        let prog_w = to_wide(&format!(r"Software\Classes\{PROG_ID}"));
        let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(prog_w.as_ptr()));

        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None);
    }

    Ok("已移除 AI NetGuard 在 HKCU 的默认浏览器注册项（如当前仍被设为默认，请顺手在系统设置中切回 Edge）".into())
}

pub fn open_windows_default_apps_settings() -> Result<(), String> {
    let h = unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            w!("ms-settings:defaultapps"),
            None,
            None,
            SW_SHOWNORMAL,
        )
    };
    if (h.0 as isize) <= 32 {
        return Err("打开 Windows 默认应用设置失败，请手动前往 设置 -> 应用 -> 默认应用".into());
    }
    Ok(())
}

fn ipc_file_path() -> PathBuf {
    app_data_dir().join(IPC_FILE_NAME)
}

fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn build_pending_pick(url: &url::Url, reason: impl Into<String>) -> PendingUrlPick {
    let mut rand_bytes = [0u8; 6];
    OsRng.fill_bytes(&mut rand_bytes);
    PendingUrlPick {
        id: format!("pick-{}", hex::encode(rand_bytes)),
        url: url.as_str().to_string(),
        display_url: sanitize_url_for_display(url),
        host: url.host_str().unwrap_or("").to_string(),
        reason: reason.into(),
        created_at: Local::now().format("%H:%M:%S").to_string(),
    }
}

pub fn start_ipc_server<F>(on_pick: F)
where
    F: Fn(PendingUrlPick) + Send + Sync + 'static,
{
    let ipc_path = ipc_file_path();
    let _ = start_ipc_server_with_path(ipc_path, on_pick);
}

fn start_ipc_server_with_path<F>(ipc_path: PathBuf, on_pick: F) -> Option<u16>
where
    F: Fn(PendingUrlPick) + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").ok()?;
    let port = listener.local_addr().ok()?.port();
    let mut token_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);

    let state = RouterIpcState {
        port,
        token: token.clone(),
        pid: std::process::id(),
    };
    if let Ok(json) = serde_json::to_string(&state) {
        let _ = std::fs::write(&ipc_path, json);
    }

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_millis(800)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(800)));
            let mut reader = BufReader::new(&stream);
            let mut line = String::new();
            let read_res = reader.by_ref().take(16 * 1024).read_line(&mut line);
            if read_res.is_err() || line.trim().is_empty() {
                continue;
            }
            let Ok(msg) = serde_json::from_str::<RouterIpcMessage>(line.trim()) else {
                continue;
            };
            if !ct_eq_bytes(msg.token.as_bytes(), token.as_bytes()) {
                let _ = stream.write_all(b"ERR\n");
                continue;
            }
            let Ok(parsed) = validate_routable_url(&msg.url) else {
                let _ = stream.write_all(b"ERR\n");
                continue;
            };
            let pick = build_pending_pick(&parsed, msg.reason);
            on_pick(pick);
            let _ = stream.write_all(b"OK\n");
        }
    });

    Some(port)
}

pub fn cleanup_ipc_file() {
    let path = ipc_file_path();
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return;
    };
    let Ok(st) = serde_json::from_str::<RouterIpcState>(&raw) else {
        return;
    };
    if st.pid == std::process::id() {
        let _ = std::fs::remove_file(path);
    }
}

pub fn try_dispatch_to_running_instance(pick: &PendingUrlPick, retry_ms: u64) -> bool {
    try_dispatch_to_path(&ipc_file_path(), pick, retry_ms)
}

fn try_dispatch_to_path(ipc_path: &Path, pick: &PendingUrlPick, retry_ms: u64) -> bool {
    let deadline = Instant::now() + Duration::from_millis(retry_ms);
    loop {
        if let Ok(raw) = std::fs::read_to_string(ipc_path) {
            if let Ok(st) = serde_json::from_str::<RouterIpcState>(&raw) {
                let addr = SocketAddr::from(([127, 0, 0, 1], st.port));
                if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(350))
                {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(600)));
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(600)));
                    let payload = RouterIpcMessage {
                        token: st.token,
                        url: pick.url.clone(),
                        reason: pick.reason.clone(),
                    };
                    if let Ok(mut line) = serde_json::to_string(&payload) {
                        line.push('\n');
                        if stream.write_all(line.as_bytes()).is_ok() {
                            let mut ack = String::new();
                            let mut reader = BufReader::new(stream);
                            if reader.read_line(&mut ack).is_ok() && ack.trim() == "OK" {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(120));
    }
}

pub fn try_handle_cli_open_url() -> UrlCliOutcome {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut raw_url: Option<String> = None;
    let mut explicit_flag = false;

    let mut idx = 0usize;
    while idx < args.len() {
        if args[idx] == "--open-url" {
            explicit_flag = true;
            raw_url = args.get(idx + 1).cloned();
            break;
        }
        idx += 1;
    }

    if !explicit_flag && args.len() == 1 {
        let lower = args[0].trim().to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            raw_url = Some(args[0].clone());
        }
    }

    let Some(raw) = raw_url else {
        if explicit_flag {
            return UrlCliOutcome::HandledAndExit(1);
        }
        return UrlCliOutcome::NotUrlInvocation;
    };

    let Ok(parsed) = validate_routable_url(&raw) else {
        return UrlCliOutcome::HandledAndExit(1);
    };

    let cfg = load_config();
    match evaluate_url_route(&parsed, &cfg.url_router) {
        UrlRouteDecision::DirectToEdge { .. } => {
            match open_url_in_fallback_browser(&parsed, &cfg.url_router) {
                Ok(_) => UrlCliOutcome::HandledAndExit(0),
                Err(_) => UrlCliOutcome::HandledAndExit(1),
            }
        }
        UrlRouteDecision::PromptPicker { reason } => {
            let pick = build_pending_pick(&parsed, reason);
            if try_dispatch_to_running_instance(&pick, 0) {
                UrlCliOutcome::HandledAndExit(0)
            } else {
                UrlCliOutcome::BootWithPicker(pick)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn domain_matching_enforces_label_boundaries() {
        assert!(domain_matches("accounts.google.com", "accounts.google.com"));
        assert!(domain_matches("SUB.Accounts.Google.COM.", "*.accounts.google.com"));
        assert!(domain_matches("app.claude.ai", "claude.ai"));
        assert!(!domain_matches("evilgoogle.com", "google.com"));
        assert!(!domain_matches("myclaude.ai", "claude.ai"));
        assert!(!domain_matches("", "claude.ai"));
    }

    #[test]
    fn validate_and_sanitize_urls_safely() {
        assert!(validate_routable_url("file:///C:/Windows/win.ini").is_err());
        assert!(validate_routable_url("javascript:alert(1)").is_err());
        assert!(validate_routable_url("--proxy-server=http://evil").is_err());
        assert!(validate_routable_url("https://claude.ai\r\nHost: evil").is_err());

        let parsed = validate_routable_url(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id=123&code=SECRET#frag",
        )
        .unwrap();
        let display = sanitize_url_for_display(&parsed);
        assert_eq!(display, "https://accounts.google.com/o/oauth2/v2/auth");
        assert!(!display.contains("SECRET"));
        assert!(!display.contains("frag"));
    }

    #[test]
    fn evaluate_url_route_respects_modes_bypass_and_loopback_oauth() {
        let mut cfg = UrlRouterConfig::default();

        // Domestic bypass in InterceptList
        let baidu = validate_routable_url("https://www.baidu.com/s?wd=test").unwrap();
        assert!(matches!(
            evaluate_url_route(&baidu, &cfg),
            UrlRouteDecision::DirectToEdge { .. }
        ));

        // Direct AI site intercepted in InterceptList
        let claude = validate_routable_url("https://claude.ai/chats").unwrap();
        assert!(matches!(
            evaluate_url_route(&claude, &cfg),
            UrlRouteDecision::PromptPicker { .. }
        ));

        // Loopback OAuth redirect intercepted even on unlisted auth host
        let custom_oauth = validate_routable_url(
            "https://sso.example.org/authorize?redirect_uri=http%3A%2F%2F127.0.0.1%3A51234%2Fcb",
        )
        .unwrap();
        assert!(matches!(
            evaluate_url_route(&custom_oauth, &cfg),
            UrlRouteDecision::PromptPicker { .. }
        ));

        // Edge bypass takes precedence even when redirect_uri is present
        let feishu = validate_routable_url(
            "https://open.feishu.cn/open-apis/authen?redirect_uri=http%3A%2F%2F127.0.0.1%3A8080",
        )
        .unwrap();
        assert!(matches!(
            evaluate_url_route(&feishu, &cfg),
            UrlRouteDecision::DirectToEdge { .. }
        ));

        // Ordinary unknown .org site goes to Edge in InterceptList, but prompts in AllowEdgeList
        let docs = validate_routable_url("https://example.org/docs").unwrap();
        assert!(matches!(
            evaluate_url_route(&docs, &cfg),
            UrlRouteDecision::DirectToEdge { .. }
        ));
        cfg.mode = UrlRouterMode::AllowEdgeList;
        assert!(matches!(
            evaluate_url_route(&docs, &cfg),
            UrlRouteDecision::PromptPicker { .. }
        ));

        // Domestic .cn goes to Edge in AllowEdgeList
        let gov_cn = validate_routable_url("https://www.gov.cn/").unwrap();
        assert!(matches!(
            evaluate_url_route(&gov_cn, &cfg),
            UrlRouteDecision::DirectToEdge { .. }
        ));

        // AlwaysAsk prompts everything non-bypassed
        cfg.mode = UrlRouterMode::AlwaysAsk;
        assert!(matches!(
            evaluate_url_route(&gov_cn, &cfg),
            UrlRouteDecision::PromptPicker { .. }
        ));
    }

    #[test]
    fn loopback_ipc_validates_token_and_delivers_pick() {
        let temp_dir = std::env::temp_dir().join(format!(
            "ai-netguard-url-ipc-test-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let ipc_path = temp_dir.join(IPC_FILE_NAME);
        let received: Arc<Mutex<Vec<PendingUrlPick>>> = Arc::new(Mutex::new(Vec::new()));
        let rec_clone = received.clone();

        let port = start_ipc_server_with_path(ipc_path.clone(), move |pick| {
            rec_clone.lock().unwrap().push(pick);
        })
        .expect("ipc server should bind");

        let parsed = validate_routable_url("https://claude.ai/login?state=secret").unwrap();
        let pick = build_pending_pick(&parsed, "test");

        // Wrong token must be rejected
        {
            let mut st: RouterIpcState =
                serde_json::from_str(&std::fs::read_to_string(&ipc_path).unwrap()).unwrap();
            let real_token = st.token.clone();
            st.token = "0000".into();
            let wrong_path = temp_dir.join("wrong.json");
            std::fs::write(&wrong_path, serde_json::to_string(&st).unwrap()).unwrap();
            assert!(!try_dispatch_to_path(&wrong_path, &pick, 0));
            assert!(received.lock().unwrap().is_empty());
            let _ = real_token;
        }

        // Valid token succeeds
        assert!(port > 0);
        assert!(try_dispatch_to_path(&ipc_path, &pick, 500));
        let got = received.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].host, "claude.ai");
        assert_eq!(got[0].display_url, "https://claude.ai/login");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn inspect_router_status_reads_active_win11_prog_id() {
        let st = inspect_router_status(&UrlRouterConfig::default());
        assert!(!st.current_exe_path.is_empty());
        assert!(read_active_url_prog_id("https").is_some());
    }
}
