use crate::accounts::{discover_clash_verge_nodes, ClashVergeNodesSnapshot};
use crate::launcher::ProcessLauncher;
use crate::models::{
    AppConfig, AppEnvSnapshot, AppProxyMode, EnvVarHealth, LogBuffer, ManagedAppConfig,
    ManagedAppRuntimeStatus, SystemProxyStatus,
};
use chrono::Local;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::c_void;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_WIN32,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    PROCESS_VM_READ,
};
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONWARNING, MB_OK};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

const PROXY_ENV_KEYS: [&str; 4] = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];

#[repr(C)]
struct ProcessBasicInformation {
    reserved1: *mut c_void,
    peb_base_address: usize,
    reserved2: [*mut c_void; 2],
    unique_process_id: usize,
    reserved3: *mut c_void,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        process_handle: HANDLE,
        process_information_class: u32,
        process_information: *mut c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide_nul(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn is_proxy_key(key: &str) -> bool {
    PROXY_ENV_KEYS
        .iter()
        .any(|k| k.eq_ignore_ascii_case(key.trim()))
}

/// Extract `host:port` from proxy URLs like `http://127.0.0.1:17890`, `socks5h://127.0.0.1:7897`,
/// or bare WinINET strings like `127.0.0.1:7897` or `http=127.0.0.1:7897;https=127.0.0.1:7897`.
pub fn extract_proxy_host_port(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Handle WinINET per-scheme format: "http=127.0.0.1:7897;https=127.0.0.1:7897"
    let candidate = if trimmed.contains(';') || trimmed.contains('=') {
        trimmed
            .split(';')
            .map(str::trim)
            .find_map(|part| {
                if let Some((_, rhs)) = part.split_once('=') {
                    let r = rhs.trim();
                    if !r.is_empty() {
                        Some(r)
                    } else {
                        None
                    }
                } else if !part.is_empty() {
                    Some(part)
                } else {
                    None
                }
            })
            .unwrap_or(trimmed)
    } else {
        trimmed
    };

    let with_scheme = if candidate.contains("://") {
        candidate.to_string()
    } else {
        format!("http://{candidate}")
    };

    if let Ok(parsed) = url::Url::parse(&with_scheme) {
        if let Some(host) = parsed.host_str() {
            let port = parsed.port_or_known_default().unwrap_or(80);
            return Some(format!("{host}:{port}"));
        }
    }
    None
}

pub fn is_tcp_host_port_alive(host_port: &str) -> bool {
    let mut cache = HashMap::new();
    probe_tcp_alive(host_port, &mut cache)
}

fn probe_tcp_alive(host_port: &str, cache: &mut HashMap<String, bool>) -> bool {
    if let Some(&cached) = cache.get(host_port) {
        return cached;
    }
    let alive = host_port
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| {
            // Prefer IPv4 loopback first when resolving localhost
            let addrs: Vec<SocketAddr> = it.by_ref().take(4).collect();
            for addr in &addrs {
                if addr.is_ipv4()
                    && TcpStream::connect_timeout(addr, Duration::from_millis(250)).is_ok()
                {
                    return Some(true);
                }
            }
            for addr in &addrs {
                if !addr.is_ipv4()
                    && TcpStream::connect_timeout(addr, Duration::from_millis(250)).is_ok()
                {
                    return Some(true);
                }
            }
            Some(false)
        })
        .unwrap_or(false);
    cache.insert(host_port.to_string(), alive);
    alive
}

fn reg_read_string(root: HKEY, subkey: &str, value_name: &str) -> Option<String> {
    unsafe {
        let mut hkey = HKEY::default();
        let sub_w = to_wide(subkey);
        if RegOpenKeyExW(root, PCWSTR(sub_w.as_ptr()), 0, KEY_READ, &mut hkey) != ERROR_SUCCESS {
            return None;
        }
        let val_w = to_wide(value_name);
        let mut kind = REG_VALUE_TYPE::default();
        let mut size: u32 = 0;
        let query1 = RegQueryValueExW(
            hkey,
            PCWSTR(val_w.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut size),
        );
        if query1 != ERROR_SUCCESS || size == 0 || (kind != REG_SZ && kind != REG_EXPAND_SZ) {
            let _ = RegCloseKey(hkey);
            return None;
        }
        let mut buf = vec![0u16; (size as usize).div_ceil(2) + 1];
        let query2 = RegQueryValueExW(
            hkey,
            PCWSTR(val_w.as_ptr()),
            None,
            Some(&mut kind),
            Some(buf.as_mut_ptr() as *mut u8),
            Some(&mut size),
        );
        let _ = RegCloseKey(hkey);
        if query2 != ERROR_SUCCESS {
            return None;
        }
        let s = from_wide_nul(&buf).trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

fn reg_read_dword(root: HKEY, subkey: &str, value_name: &str) -> Option<u32> {
    unsafe {
        let mut hkey = HKEY::default();
        let sub_w = to_wide(subkey);
        if RegOpenKeyExW(root, PCWSTR(sub_w.as_ptr()), 0, KEY_READ, &mut hkey) != ERROR_SUCCESS {
            return None;
        }
        let val_w = to_wide(value_name);
        let mut kind = REG_VALUE_TYPE::default();
        let mut data: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;
        let query = RegQueryValueExW(
            hkey,
            PCWSTR(val_w.as_ptr()),
            None,
            Some(&mut kind),
            Some(&mut data as *mut u32 as *mut u8),
            Some(&mut size),
        );
        let _ = RegCloseKey(hkey);
        if query == ERROR_SUCCESS && kind == REG_DWORD {
            Some(data)
        } else {
            None
        }
    }
}

fn reg_enum_env_vars(root: HKEY, subkey: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    unsafe {
        let mut hkey = HKEY::default();
        let sub_w = to_wide(subkey);
        if RegOpenKeyExW(root, PCWSTR(sub_w.as_ptr()), 0, KEY_READ, &mut hkey) != ERROR_SUCCESS {
            return out;
        }
        let mut idx: u32 = 0;
        loop {
            let mut name_buf = vec![0u16; 512];
            let mut name_len = name_buf.len() as u32;
            let mut kind: u32 = 0;
            let mut data_buf = vec![0u8; 8192];
            let mut data_len = data_buf.len() as u32;
            let res = RegEnumValueW(
                hkey,
                idx,
                windows::core::PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                Some(&mut kind),
                Some(data_buf.as_mut_ptr()),
                Some(&mut data_len),
            );
            if res == ERROR_NO_MORE_ITEMS {
                break;
            }
            idx += 1;
            if res != ERROR_SUCCESS {
                continue;
            }
            let rtype = REG_VALUE_TYPE(kind);
            if rtype != REG_SZ && rtype != REG_EXPAND_SZ {
                continue;
            }
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let u16_len = (data_len as usize) / 2;
            let mut u16s = Vec::with_capacity(u16_len);
            for chunk in data_buf[..u16_len * 2].chunks_exact(2) {
                u16s.push(u16::from_le_bytes([chunk[0], chunk[1]]));
            }
            let val = from_wide_nul(&u16s);
            out.push((name, val));
        }
        let _ = RegCloseKey(hkey);
    }
    out
}

pub fn inspect_system_proxy(cache: &mut HashMap<String, bool>) -> SystemProxyStatus {
    let subkey = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    let enabled = reg_read_dword(HKEY_CURRENT_USER, subkey, "ProxyEnable").unwrap_or(0) != 0;
    let server = reg_read_string(HKEY_CURRENT_USER, subkey, "ProxyServer");
    let auto_config_url = reg_read_string(HKEY_CURRENT_USER, subkey, "AutoConfigURL");
    let host_port = server.as_deref().and_then(extract_proxy_host_port);
    let alive = if enabled {
        host_port
            .as_deref()
            .map(|hp| probe_tcp_alive(hp, cache))
            .unwrap_or(false)
    } else {
        false
    };
    SystemProxyStatus {
        enabled,
        server,
        host_port,
        alive,
        auto_config_url,
    }
}

pub fn inspect_registry_proxy_vars(cache: &mut HashMap<String, bool>) -> Vec<EnvVarHealth> {
    let mut results = Vec::new();
    let scopes = [
        ("user", HKEY_CURRENT_USER, r"Environment"),
        (
            "machine",
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        ),
    ];
    for (scope, root, subkey) in scopes {
        for (k, v) in reg_enum_env_vars(root, subkey) {
            if !is_proxy_key(&k) {
                continue;
            }
            let trimmed = v.trim();
            if trimmed.is_empty() {
                continue;
            }
            let is_no_proxy = k.eq_ignore_ascii_case("NO_PROXY");
            let host_port = if is_no_proxy {
                None
            } else {
                extract_proxy_host_port(trimmed)
            };
            let alive = host_port.as_deref().map(|hp| probe_tcp_alive(hp, cache));
            results.push(EnvVarHealth {
                scope: scope.to_string(),
                key: k.to_ascii_uppercase(),
                value: trimmed.to_string(),
                host_port,
                alive,
            });
        }
    }
    results
}

/// Parse UTF-16LE NUL-separated Windows PEB environment block and return ONLY proxy-related vars.
pub fn parse_peb_utf16_proxy_vars(u16_block: &[u16]) -> Vec<(String, String)> {
    let mut vars = Vec::new();
    let mut start = 0;
    while start < u16_block.len() {
        let Some(rel_end) = u16_block[start..].iter().position(|&c| c == 0) else {
            break;
        };
        if rel_end == 0 {
            // Double-NUL terminator reached
            break;
        }
        let entry = String::from_utf16_lossy(&u16_block[start..start + rel_end]);
        if let Some((k, v)) = entry.split_once('=') {
            if !k.is_empty() && is_proxy_key(k) {
                let trimmed = v.trim();
                if !trimmed.is_empty() {
                    vars.push((k.to_ascii_uppercase(), trimmed.to_string()));
                }
            }
        }
        start += rel_end + 1;
    }
    vars
}

/// Read live proxy environment variables directly from a running 64-bit Windows process PEB.
pub fn read_process_proxy_env(pid: u32) -> Option<Vec<(String, String)>> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;

        let result = (|| -> Option<Vec<(String, String)>> {
            let mut pbi = std::mem::zeroed::<ProcessBasicInformation>();
            let mut ret_len: u32 = 0;
            let status = NtQueryInformationProcess(
                handle,
                0, // ProcessBasicInformation
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut ret_len,
            );
            if status != 0 || pbi.peb_base_address == 0 {
                return None;
            }

            // x64 PEB.ProcessParameters is at offset 0x20
            let mut params_addr: usize = 0;
            let mut bytes_read: usize = 0;
            ReadProcessMemory(
                handle,
                (pbi.peb_base_address + 0x20) as *const c_void,
                &mut params_addr as *mut _ as *mut c_void,
                std::mem::size_of::<usize>(),
                Some(&mut bytes_read),
            )
            .ok()?;
            if params_addr == 0 {
                return None;
            }

            // x64 RTL_USER_PROCESS_PARAMETERS.Environment is at offset 0x80
            let mut env_addr: usize = 0;
            ReadProcessMemory(
                handle,
                (params_addr + 0x80) as *const c_void,
                &mut env_addr as *mut _ as *mut c_void,
                std::mem::size_of::<usize>(),
                Some(&mut bytes_read),
            )
            .ok()?;
            if env_addr == 0 {
                return None;
            }

            // Try reading RTL_USER_PROCESS_PARAMETERS.EnvironmentSize at offset 0x3F0 (Win7+)
            let mut env_size: usize = 0;
            let _ = ReadProcessMemory(
                handle,
                (params_addr + 0x3F0) as *const c_void,
                &mut env_size as *mut _ as *mut c_void,
                std::mem::size_of::<usize>(),
                Some(&mut bytes_read),
            );

            let max_bytes: usize = if (4..=262_144).contains(&env_size) {
                env_size
            } else {
                131_072
            };

            let mut raw = Vec::<u16>::new();
            let chunk_bytes = 4096usize;
            let mut offset = 0usize;
            let mut chunk = vec![0u8; chunk_bytes];
            while offset < max_bytes {
                let to_read = (max_bytes - offset).min(chunk_bytes);
                let mut nread: usize = 0;
                if ReadProcessMemory(
                    handle,
                    (env_addr + offset) as *const c_void,
                    chunk.as_mut_ptr() as *mut c_void,
                    to_read,
                    Some(&mut nread),
                )
                .is_err()
                    || nread < 2
                {
                    break;
                }
                let words = nread / 2;
                let prev_len = raw.len();
                for pair in chunk[..words * 2].chunks_exact(2) {
                    raw.push(u16::from_le_bytes([pair[0], pair[1]]));
                }
                // Stop early once we see double-NUL terminator
                let check_from = prev_len.saturating_sub(1);
                if raw[check_from..].windows(2).any(|w| w[0] == 0 && w[1] == 0) {
                    break;
                }
                offset += nread;
            }

            Some(parse_peb_utf16_proxy_vars(&raw))
        })();

        let _ = CloseHandle(handle);
        result
    }
}

#[derive(Clone)]
struct RunningProcInfo {
    pid: u32,
    exe_name: String,
    full_path: Option<String>,
}

fn query_process_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(handle);
        if ok && len > 0 {
            Some(String::from_utf16_lossy(&buf[..len as usize]))
        } else {
            None
        }
    }
}

fn snapshot_running_processes() -> Vec<RunningProcInfo> {
    let mut procs = Vec::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return procs;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let exe_name = from_wide_nul(&entry.szExeFile);
                procs.push(RunningProcInfo {
                    pid: entry.th32ProcessID,
                    exe_name,
                    full_path: None,
                });
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    procs
}

fn find_windowsapps_chatgpt() -> Option<PathBuf> {
    let program_files = std::env::var_os("ProgramFiles")?;
    let wa = PathBuf::from(program_files).join("WindowsApps");
    let entries = std::fs::read_dir(wa).ok()?;
    let mut matches: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        if name.starts_with("openai.codex_") || name.starts_with("openai.chatgpt_") {
            let cand = entry.path().join("app").join("ChatGPT.exe");
            if cand.exists() {
                matches.push(cand);
            }
        }
    }
    matches.sort();
    matches.pop()
}

fn resolve_managed_app_path(
    app: &ManagedAppConfig,
    cfg: &AppConfig,
    launcher: &ProcessLauncher,
    running_procs: &[RunningProcInfo],
) -> Option<PathBuf> {
    if let Some(custom) = app
        .exe_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let p = PathBuf::from(custom);
        if p.exists() {
            return Some(p);
        }
    }

    if app.id == "claude-desktop" {
        if let Some(p) = launcher.resolve_claude_desktop_path(cfg) {
            return Some(p);
        }
    }

    // Check if any matching running process already tells us its exact executable path
    for p in running_procs {
        let primary_match = app
            .process_names
            .first()
            .map(|n| p.exe_name.eq_ignore_ascii_case(n))
            .unwrap_or(false);
        if primary_match {
            if let Some(full) = p.full_path.as_deref().or_else(|| None) {
                let pb = PathBuf::from(full);
                if pb.exists() {
                    return Some(pb);
                }
            }
            if let Some(full) = query_process_path(p.pid) {
                let pb = PathBuf::from(full);
                if pb.exists() {
                    return Some(pb);
                }
            }
        }
    }

    let local = PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_default());
    let pf = PathBuf::from(std::env::var("ProgramFiles").unwrap_or_default());

    match app.id.as_str() {
        "antigravity" => {
            let cands = [
                local
                    .join("Programs")
                    .join("antigravity")
                    .join("Antigravity.exe"),
                pf.join("Antigravity").join("Antigravity.exe"),
            ];
            cands.into_iter().find(|p| p.exists())
        }
        "chatgpt" => {
            if let Some(p) = find_windowsapps_chatgpt() {
                return Some(p);
            }
            let cands = [
                local.join("Programs").join("ChatGPT").join("ChatGPT.exe"),
                local.join("ChatGPT").join("ChatGPT.exe"),
            ];
            cands.into_iter().find(|p| p.exists())
        }
        "cockpit-tools" => {
            let cands = [
                local
                    .join("Programs")
                    .join("Cockpit Tools")
                    .join("cockpit-tools.exe"),
                local
                    .join("Programs")
                    .join("cockpit-tools")
                    .join("cockpit-tools.exe"),
                pf.join("Cockpit Tools").join("cockpit-tools.exe"),
            ];
            cands.into_iter().find(|p| p.exists())
        }
        _ => None,
    }
}

fn describe_clash_port(host_port: &str, clash: &ClashVergeNodesSnapshot) -> Option<String> {
    let (host, port_str) = host_port.trim().rsplit_once(':')?;
    let host_clean = host.trim_matches(|c| c == '[' || c == ']');
    if !host_clean.eq_ignore_ascii_case("127.0.0.1")
        && !host_clean.eq_ignore_ascii_case("localhost")
        && host_clean != "::1"
    {
        return None;
    }
    let port: u16 = port_str.parse().ok()?;
    if let Some(listener) = clash.listeners.iter().find(|l| l.port == port) {
        return Some(listener.name.clone());
    }
    if clash.mixed_port == Some(port) {
        return Some("Clash 混合端口".to_string());
    }
    None
}

fn classify_app_health(
    app: &ManagedAppConfig,
    running: bool,
    env_vars: &[EnvVarHealth],
    cfg: &AppConfig,
    gateway_running: bool,
    sys_proxy: &SystemProxyStatus,
    clash: &ClashVergeNodesSnapshot,
) -> (String, String, bool) {
    let is_external = matches!(app.proxy_mode, AppProxyMode::ExternalManaged);
    if !running {
        if is_external {
            let msg = if app.id == "antigravity" {
                "未运行；由 Cockpit Tools 按账号代理托管启动，AI NetGuard 仅执行 PEB 巡检"
            } else {
                "未运行；由外部工具托管启动，AI NetGuard 仅执行 PEB 巡检"
            };
            return ("stopped".into(), msg.into(), false);
        }
        return (
            "stopped".into(),
            "未运行；点击“干净启动”将以无污染环境拉起".into(),
            false,
        );
    }

    // 1. Highest priority: ANY proxy env var pointing to a dead/unlistening port!
    let dead_vars: Vec<&EnvVarHealth> = env_vars
        .iter()
        .filter(|v| !v.key.eq_ignore_ascii_case("NO_PROXY") && v.alive == Some(false))
        .collect();
    if !dead_vars.is_empty() {
        let dead_desc: Vec<String> = dead_vars
            .iter()
            .map(|v| format!("{}={}", v.key, v.value))
            .collect();
        let sys_note = if sys_proxy.enabled && sys_proxy.alive {
            format!(
                "（Windows 系统代理 {} 实际在线，属于进程继承了失效环境变量导致误判/断网）",
                sys_proxy
                    .host_port
                    .as_deref()
                    .or(sys_proxy.server.as_deref())
                    .unwrap_or("已启用")
            )
        } else {
            "（目标代理端口无人监听，会导致该应用及子服务全部请求失败）".into()
        };
        let parent_hint = if is_external {
            "（请通过外部托管工具如 Cockpit Tools 重新切号/重启）"
        } else if app.id == "cockpit-tools" {
            " —— 建议先检查 Clash 端口状态或重启 Cockpit Tools（Antigravity 已走独立账号隔离环境）"
        } else {
            ""
        };
        return (
            "dead_proxy".into(),
            format!(
                "进程内存继承了失效代理: {}{}{}",
                dead_desc.join(", "),
                sys_note,
                parent_hint
            ),
            !is_external,
        );
    }

    // 2. Policy vs actual live process env check
    let active_proxies: Vec<&EnvVarHealth> = env_vars
        .iter()
        .filter(|v| !v.key.eq_ignore_ascii_case("NO_PROXY"))
        .collect();
    let ng_cli_hp = format!("127.0.0.1:{}", cfg.cli_port);
    let ng_browser_hp = format!("127.0.0.1:{}", cfg.browser_port);

    match app.proxy_mode {
        AppProxyMode::Netguard => {
            if !gateway_running {
                return (
                    "mismatch".into(),
                    "策略为走 AI NetGuard 独享出口，但网关尚未启动".into(),
                    false,
                );
            }
            let points_to_ng = active_proxies.iter().any(|v| {
                v.host_port
                    .as_deref()
                    .map(|hp| hp == ng_cli_hp || hp == ng_browser_hp)
                    .unwrap_or(false)
            });
            if points_to_ng || (app.id == "claude-desktop" && cfg.wfp_lock_enabled) {
                (
                    "clean".into(),
                    format!("运行正常：已接入 AI NetGuard 隔离通道 (:{})", cfg.cli_port),
                    false,
                )
            } else {
                (
                    "mismatch".into(),
                    "当前运行实例未携带 AI NetGuard 隔离代理变量，建议“干净重启”重新接管".into(),
                    true,
                )
            }
        }
        AppProxyMode::ExternalManaged => {
            let owner = if app.id == "antigravity" {
                "Cockpit Tools"
            } else {
                "外部托管工具"
            };
            if let Some(ng_hp) = active_proxies.iter().find_map(|v| {
                let hp = v.host_port.as_deref()?;
                (hp == ng_cli_hp || hp == ng_browser_hp).then_some(hp)
            }) {
                return (
                    "mismatch".into(),
                    format!(
                        "进程误挂在 AI NetGuard 专属端口 ({ng_hp})，关掉 AI NetGuard 后会断网；请通过 {owner} 重新启动"
                    ),
                    false,
                );
            }

            if !active_proxies.is_empty() {
                let mut seen: HashSet<String> = HashSet::new();
                let mut targets: Vec<String> = Vec::new();
                for v in &active_proxies {
                    let raw_target = v.host_port.as_deref().unwrap_or(v.value.as_str());
                    if seen.insert(raw_target.to_string()) {
                        let annotated = match v
                            .host_port
                            .as_deref()
                            .and_then(|hp| describe_clash_port(hp, clash))
                        {
                            Some(tag) => format!("{raw_target} ({tag})"),
                            None => raw_target.to_string(),
                        };
                        targets.push(annotated);
                    }
                }
                return (
                    "clean".into(),
                    format!(
                        "外部托管正常：当前代理 {} 在线（由 {owner} 托管，AI NetGuard 仅巡检不接管重启）",
                        targets.join(", ")
                    ),
                    false,
                );
            }

            let sys_hp = sys_proxy
                .host_port
                .as_deref()
                .or(sys_proxy.server.as_deref())
                .unwrap_or("系统代理");
            if app.id == "antigravity" {
                if !sys_proxy.enabled {
                    (
                        "mismatch".into(),
                        "未检测到进程代理变量且 Windows 系统代理未启用（当前处于直连状态，存在跨号直连风险）；建议通过 Cockpit Tools 按账号代理重启".into(),
                        false,
                    )
                } else if sys_proxy.alive {
                    (
                        "mismatch".into(),
                        format!(
                            "未携带独立账号代理变量（正跟随系统代理 {sys_hp}）；若需按账号隔离出口，建议通过 Cockpit Tools 重启"
                        ),
                        false,
                    )
                } else {
                    (
                        "dead_proxy".into(),
                        format!(
                            "未携带进程代理变量，且系统代理 {sys_hp} 当前不可达；请通过 Cockpit Tools 重启并检查 Clash"
                        ),
                        false,
                    )
                }
            } else if sys_proxy.enabled && !sys_proxy.alive {
                (
                    "dead_proxy".into(),
                    format!("外部托管运行中，但系统代理 {sys_hp} 当前不可达"),
                    false,
                )
            } else if sys_proxy.enabled && sys_proxy.alive {
                (
                    "clean".into(),
                    format!("外部托管运行中：无进程代理变量，正跟随在线系统代理 ({sys_hp})"),
                    false,
                )
            } else {
                (
                    "clean".into(),
                    "外部托管运行中：无进程代理变量（跟随系统默认网络）".into(),
                    false,
                )
            }
        }
        AppProxyMode::SystemProxy => {
            if active_proxies.is_empty() {
                let detail = if sys_proxy.enabled && sys_proxy.alive {
                    format!(
                        "进程环境干净，正跟随系统代理 ({})",
                        sys_proxy
                            .host_port
                            .as_deref()
                            .or(sys_proxy.server.as_deref())
                            .unwrap_or("已启用")
                    )
                } else if sys_proxy.enabled && !sys_proxy.alive {
                    format!(
                        "进程环境干净，但系统代理 {} 当前不可达（请检查 Clash 等代理软件）",
                        sys_proxy
                            .host_port
                            .as_deref()
                            .or(sys_proxy.server.as_deref())
                            .unwrap_or("未知")
                    )
                } else {
                    "进程环境干净（无残留代理变量，直连系统默认网络）".into()
                };
                return ("clean".into(), detail, false);
            }
            // If every active proxy env var matches the live Windows System Proxy (e.g. Cockpit Tools
            // explicitly propagating 127.0.0.1:7897), treat it as clean instead of a false warning.
            if sys_proxy.enabled && sys_proxy.alive {
                if let Some(ref sys_hp) = sys_proxy.host_port {
                    let all_match_sys = active_proxies
                        .iter()
                        .all(|v| v.host_port.as_deref() == Some(sys_hp.as_str()));
                    if all_match_sys {
                        return (
                            "clean".into(),
                            format!("运行正常：进程环境变量与当前在线系统代理 ({sys_hp}) 一致"),
                            false,
                        );
                    }
                }
            }
            // Running process has live proxy env vars pointing elsewhere (e.g. still pointing to 17890)
            let vars_str: Vec<String> = active_proxies
                .iter()
                .map(|v| format!("{}={}", v.key, v.value))
                .collect();
            let extra = if active_proxies
                .iter()
                .any(|v| v.host_port.as_deref() == Some(ng_cli_hp.as_str()))
            {
                "（当前仍挂在 17890，关掉 AI NetGuard 后会立即断网；建议“干净重启”剥离）"
            } else {
                "（与“跟随系统网络（无环境变量）”策略不一致，建议“干净重启”或改用「指定代理 / 外部托管」）"
            };
            (
                "mismatch".into(),
                format!("进程携带环境变量: {}{}", vars_str.join(", "), extra),
                true,
            )
        }
        AppProxyMode::Direct => {
            if active_proxies.is_empty() {
                ("clean".into(), "进程环境干净，直连模式运行中".into(), false)
            } else {
                let vars_str: Vec<String> = active_proxies
                    .iter()
                    .map(|v| format!("{}={}", v.key, v.value))
                    .collect();
                (
                    "mismatch".into(),
                    format!("策略为直连，但进程仍带代理变量: {}", vars_str.join(", ")),
                    true,
                )
            }
        }
        AppProxyMode::CustomProxy => {
            let expected_hp = app
                .custom_proxy_url
                .as_deref()
                .and_then(extract_proxy_host_port);
            if active_proxies.is_empty() && sys_proxy.enabled && sys_proxy.alive {
                if let (Some(exp), Some(sys_hp)) = (expected_hp.as_deref(), sys_proxy.host_port.as_deref()) {
                    if exp == sys_hp {
                        return (
                            "clean".into(),
                            format!(
                                "运行正常：进程环境干净，正通过在线系统代理 ({sys_hp}) 访问指定目标"
                            ),
                            false,
                        );
                    }
                }
            }
            let matches = expected_hp.as_deref().is_some_and(|exp| {
                active_proxies
                    .iter()
                    .any(|v| v.host_port.as_deref() == Some(exp))
            });
            if matches {
                let exp_label = expected_hp
                    .as_deref()
                    .map(|hp| match describe_clash_port(hp, clash) {
                        Some(tag) => format!("{hp} · {tag}"),
                        None => hp.to_string(),
                    })
                    .unwrap_or_default();
                (
                    "clean".into(),
                    format!("运行正常：已指向指定代理 ({exp_label})"),
                    false,
                )
            } else {
                (
                    "mismatch".into(),
                    "进程当前代理环境变量与指定代理配置不一致，建议“干净重启”".into(),
                    true,
                )
            }
        }
    }
}

pub fn resolve_managed_app_exe(
    app: &ManagedAppConfig,
    cfg: &AppConfig,
    launcher: &ProcessLauncher,
) -> Option<PathBuf> {
    let running_procs = snapshot_running_processes();
    resolve_managed_app_path(app, cfg, launcher, &running_procs)
}

pub fn inspect_all_apps_env(
    cfg: &AppConfig,
    launcher: &ProcessLauncher,
    gateway_running: bool,
) -> AppEnvSnapshot {
    let mut tcp_cache: HashMap<String, bool> = HashMap::new();
    let system_proxy = inspect_system_proxy(&mut tcp_cache);
    let registry_proxy_vars = inspect_registry_proxy_vars(&mut tcp_cache);
    let running_procs = snapshot_running_processes();
    let clash_snapshot = discover_clash_verge_nodes();

    let mut apps = Vec::with_capacity(cfg.managed_apps.len());
    let mut polluted_count = 0usize;

    for app in &cfg.managed_apps {
        let resolved = resolve_managed_app_path(app, cfg, launcher, &running_procs);
        let match_names: Vec<String> = if !app.process_names.is_empty() {
            app.process_names.clone()
        } else if let Some(ref p) = resolved {
            p.file_name()
                .map(|n| vec![n.to_string_lossy().to_string()])
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let matching_pids: Vec<u32> = running_procs
            .iter()
            .filter(|p| {
                match_names
                    .iter()
                    .any(|name| p.exe_name.eq_ignore_ascii_case(name))
            })
            .map(|p| p.pid)
            .collect();

        // Sample PEB env from up to 6 matching processes (covers main Electron + Go language server)
        let mut seen_kv: HashSet<(String, String)> = HashSet::new();
        let mut env_vars: Vec<EnvVarHealth> = Vec::new();
        for &pid in matching_pids.iter().take(6) {
            if let Some(vars) = read_process_proxy_env(pid) {
                for (k, v) in vars {
                    if seen_kv.insert((k.clone(), v.clone())) {
                        let is_no_proxy = k.eq_ignore_ascii_case("NO_PROXY");
                        let host_port = if is_no_proxy {
                            None
                        } else {
                            extract_proxy_host_port(&v)
                        };
                        let alive = host_port
                            .as_deref()
                            .map(|hp| probe_tcp_alive(hp, &mut tcp_cache));
                        env_vars.push(EnvVarHealth {
                            scope: "process".into(),
                            key: k,
                            value: v,
                            host_port,
                            alive,
                        });
                    }
                }
            }
        }

        let running = !matching_pids.is_empty();
        let (health, diagnosis, needs_clean_relaunch) = classify_app_health(
            app,
            running,
            &env_vars,
            cfg,
            gateway_running,
            &system_proxy,
            &clash_snapshot,
        );
        if health == "dead_proxy" || health == "mismatch" {
            polluted_count += 1;
        }

        apps.push(ManagedAppRuntimeStatus {
            id: app.id.clone(),
            name: app.name.clone(),
            builtin: app.builtin,
            installed: resolved.is_some(),
            resolved_path: resolved.map(|p| p.to_string_lossy().to_string()),
            running,
            pids: matching_pids,
            proxy_mode: app.proxy_mode.clone(),
            wfp_lock: app.wfp_lock,
            health,
            diagnosis,
            env_vars,
            needs_clean_relaunch,
        });
    }

    AppEnvSnapshot {
        system_proxy,
        registry_proxy_vars,
        apps,
        polluted_count,
        scanned_at: Local::now().format("%H:%M:%S").to_string(),
    }
}

/// Build a clean-room Windows environment map: starts from current process env (to retain essential
/// session variables like USERPROFILE, LOCALAPPDATA, SystemRoot, PATH) overlaid with fresh HKLM/HKCU
/// registry values, then strips ALL proxy variables (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY`).
pub fn build_clean_base_env() -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let mut canonical_keys: HashMap<String, String> = HashMap::new();

    let mut insert_ci = |k: String, v: String| {
        if is_proxy_key(&k) {
            return;
        }
        let lower = k.to_ascii_lowercase();
        if let Some(prev) = canonical_keys.get(&lower).cloned() {
            env.remove(&prev);
        }
        canonical_keys.insert(lower, k.clone());
        env.insert(k, v);
    };

    for (k, v) in std::env::vars() {
        insert_ci(k, v);
    }

    // Refresh non-PATH variables from HKCU so cleared user vars don't linger
    let mut hklm_path = String::new();
    let mut hkcu_path = String::new();
    for (k, v) in reg_enum_env_vars(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
    ) {
        if k.eq_ignore_ascii_case("PATH") {
            hklm_path = v;
        } else if !is_proxy_key(&k) && !v.contains('%') {
            insert_ci(k, v);
        }
    }
    for (k, v) in reg_enum_env_vars(HKEY_CURRENT_USER, r"Environment") {
        if k.eq_ignore_ascii_case("PATH") {
            hkcu_path = v;
        } else if !is_proxy_key(&k) && !v.contains('%') {
            insert_ci(k, v);
        }
    }
    if !hklm_path.is_empty() && !hkcu_path.is_empty() && !hklm_path.contains('%') && !hkcu_path.contains('%') {
        insert_ci("PATH".into(), format!("{hklm_path};{hkcu_path}"));
    }

    env
}

fn terminate_matching_processes(process_names: &[String], timeout: Duration) {
    if process_names.is_empty() {
        return;
    }
    let procs = snapshot_running_processes();
    for p in procs {
        if process_names
            .iter()
            .any(|name| p.exe_name.eq_ignore_ascii_case(name))
        {
            unsafe {
                if let Ok(h) = OpenProcess(PROCESS_TERMINATE, false, p.pid) {
                    let _ = TerminateProcess(h, 0);
                    let _ = CloseHandle(h);
                }
            }
        }
    }
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let still_alive = snapshot_running_processes().iter().any(|p| {
            process_names
                .iter()
                .any(|name| p.exe_name.eq_ignore_ascii_case(name))
        });
        if !still_alive {
            break;
        }
        std::thread::sleep(Duration::from_millis(120));
    }
}

pub fn launch_managed_app_with_clean_env(
    app: &ManagedAppConfig,
    cfg: &AppConfig,
    launcher: &mut ProcessLauncher,
    pac_port: u16,
    gateway_running: bool,
    relaunch: bool,
    logs: Arc<LogBuffer>,
) -> Result<String, String> {
    // Pre-flight checks
    match app.proxy_mode {
        AppProxyMode::ExternalManaged => {
            return Err(format!(
                "{} 当前为「外部托管 · 仅巡检」模式，请通过对应托管工具（如 Cockpit Tools）启动或重启",
                app.name
            ));
        }
        AppProxyMode::Netguard => {
            if !gateway_running {
                return Err(format!(
                    "无法以 AI NetGuard 隔离模式启动 {}：安全网关未运行，请先启动安全网关",
                    app.name
                ));
            }
        }
        AppProxyMode::CustomProxy => {
            let url = app
                .custom_proxy_url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| format!("{} 未配置自定义代理地址", app.name))?;
            let hp = extract_proxy_host_port(url)
                .ok_or_else(|| format!("自定义代理地址格式无效: {url}"))?;
            let mut cache = HashMap::new();
            if !probe_tcp_alive(&hp, &mut cache) {
                return Err(format!(
                    "自定义代理端口 {hp} 当前无人监听，已中止启动 {} 防止断网",
                    app.name
                ));
            }
        }
        AppProxyMode::SystemProxy | AppProxyMode::Direct => {}
    }

    // Claude Desktop in Netguard mode uses the battle-tested PAC + Squirrel launcher
    if app.id == "claude-desktop" && matches!(app.proxy_mode, AppProxyMode::Netguard) {
        return launcher.launch_claude_desktop(cfg, pac_port, logs);
    }

    let running_procs = snapshot_running_processes();
    let exe = resolve_managed_app_path(app, cfg, launcher, &running_procs)
        .ok_or_else(|| format!("未检测到 {} 的可执行文件，请在该卡片中手动指定路径", app.name))?;

    let kill_names: Vec<String> = if !app.process_names.is_empty() {
        app.process_names.clone()
    } else {
        exe.file_name()
            .map(|n| vec![n.to_string_lossy().to_string()])
            .unwrap_or_default()
    };

    if relaunch {
        terminate_matching_processes(&kill_names, Duration::from_secs(3));
    }

    let mut clean_env = build_clean_base_env();
    let mode_desc = match app.proxy_mode {
        AppProxyMode::Netguard => {
            let http = format!("http://127.0.0.1:{}", cfg.cli_port);
            let socks = format!("socks5h://127.0.0.1:{}", cfg.cli_port);
            clean_env.insert("HTTP_PROXY".into(), http.clone());
            clean_env.insert("HTTPS_PROXY".into(), http);
            clean_env.insert("ALL_PROXY".into(), socks);
            clean_env.insert("NO_PROXY".into(), cfg.extra_no_proxy.clone());
            format!("AI NetGuard 独享出口 (127.0.0.1:{})", cfg.cli_port)
        }
        AppProxyMode::SystemProxy => {
            // Proxy env vars stay stripped so Electron/Chromium/Go cleanly follow Windows System Proxy
            "干净环境 · 跟随系统代理".into()
        }
        AppProxyMode::Direct => {
            clean_env.insert("NO_PROXY".into(), "*".into());
            "干净环境 · 直连无代理".into()
        }
        AppProxyMode::CustomProxy => {
            let url = app.custom_proxy_url.as_deref().unwrap_or("").trim().to_string();
            clean_env.insert("HTTP_PROXY".into(), url.clone());
            clean_env.insert("HTTPS_PROXY".into(), url.clone());
            clean_env.insert("ALL_PROXY".into(), url.clone());
            clean_env.insert("NO_PROXY".into(), cfg.extra_no_proxy.clone());
            format!("指定代理 ({url})")
        }
        AppProxyMode::ExternalManaged => {
            return Err(format!(
                "{} 当前为「外部托管 · 仅巡检」模式",
                app.name
            ));
        }
    };

    let mut cmd = Command::new(&exe);
    cmd.env_clear();
    for (k, v) in &clean_env {
        cmd.env(k, v);
    }
    if let Some(parent) = exe.parent() {
        cmd.current_dir(parent);
    }
    if matches!(app.proxy_mode, AppProxyMode::Direct) && app.id != "claude-desktop" {
        cmd.arg("--no-proxy-server");
    }
    if matches!(app.proxy_mode, AppProxyMode::CustomProxy)
        && !matches!(app.id.as_str(), "claude-desktop" | "cockpit-tools")
    {
        let already_has_proxy_arg = app
            .extra_args
            .iter()
            .any(|a| a.trim().starts_with("--proxy-server"));
        let already_has_bypass_arg = app
            .extra_args
            .iter()
            .any(|a| a.trim().starts_with("--proxy-bypass-list"));
        if !already_has_proxy_arg {
            let proxy_url = app.custom_proxy_url.as_deref().unwrap_or("").trim();
            if !proxy_url.is_empty() {
                cmd.arg(format!("--proxy-server={proxy_url}"));
                if !already_has_bypass_arg {
                    cmd.arg("--proxy-bypass-list=<-loopback>;localhost;127.0.0.1");
                }
            }
        }
    }
    for arg in &app.extra_args {
        let a = arg.trim();
        if !a.is_empty() {
            cmd.arg(a);
        }
    }
    cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);

    let spawn_res = cmd.spawn();
    if let Err(err) = spawn_res {
        // Fallback for WindowsApps MSIX packages (e.g. OpenAI.Codex / ChatGPT) when direct exec hits ACL
        let exe_lower = exe.to_string_lossy().to_lowercase();
        if app.id == "chatgpt" && exe_lower.contains("\\windowsapps\\") {
            let mut fallback = Command::new("explorer.exe");
            fallback
                .env_clear()
                .envs(&clean_env)
                .arg("shell:AppsFolder\\OpenAI.Codex_2p2nqsd0c76g0!App")
                .creation_flags(CREATE_NO_WINDOW);
            fallback
                .spawn()
                .map_err(|e2| format!("启动 {} 失败 ({err}; MSIX 回退失败: {e2})", app.name))?;
        } else {
            return Err(format!("启动 {} 失败: {err}", app.name));
        }
    }

    let verb = if relaunch { "干净重启" } else { "干净启动" };
    let msg = format!("已{verb} {} ({mode_desc})", app.name);
    logs.push(format!("[应用环境] {msg} -> {}", Path::new(&exe).display()));
    Ok(msg)
}

fn sanitize_filename_part(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || c.is_control() {
                '-'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim().trim_matches('.');
    if trimmed.is_empty() {
        "AI-App".into()
    } else {
        trimmed.to_string()
    }
}

/// Create a Windows Desktop `.lnk` shortcut pointing to `ai-netguard.exe --launch-app <app_id>`
/// while preserving the target AI application's native icon.
pub fn create_desktop_shortcut_for_app(
    app: &ManagedAppConfig,
    cfg: &AppConfig,
    launcher: &ProcessLauncher,
) -> Result<String, String> {
    if matches!(app.proxy_mode, AppProxyMode::ExternalManaged) {
        return Err(format!(
            "{} 当前为「外部托管 · 仅巡检」模式，无需通过 AI NetGuard 创建启动快捷方式",
            app.name
        ));
    }
    let self_exe =
        std::env::current_exe().map_err(|e| format!("无法获取 AI NetGuard 程序路径: {e}"))?;
    let resolved_target = resolve_managed_app_exe(app, cfg, launcher)
        .ok_or_else(|| format!("未检测到 {} 的可执行文件，请先在卡片中指定路径", app.name))?;

    let user_profile = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .ok_or("无法读取 USERPROFILE 目录")?;
    let desktop_dir = user_profile.join("Desktop");
    if !desktop_dir.exists() {
        return Err(format!("桌面目录不存在: {}", desktop_dir.display()));
    }

    let safe_name = sanitize_filename_part(&app.name);
    let lnk_path = desktop_dir.join(format!("{safe_name} (NetGuard).lnk"));
    let args = format!("--launch-app {}", app.id);
    let icon_loc = format!("{},0", resolved_target.to_string_lossy());
    let desc = format!("通过 AI NetGuard 干净环境启动 {}", app.name);

    // Static PowerShell script reading strictly from process env vars (zero command interpolation).
    let ps_static = "$ws = New-Object -ComObject WScript.Shell; \
        $sc = $ws.CreateShortcut($env:NG_SC_LNK); \
        $sc.TargetPath = $env:NG_SC_TARGET; \
        $sc.Arguments = $env:NG_SC_ARGS; \
        $sc.WorkingDirectory = $env:NG_SC_WORKDIR; \
        $sc.IconLocation = $env:NG_SC_ICON; \
        $sc.Description = $env:NG_SC_DESC; \
        $sc.Save()";

    let work_dir = self_exe
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let out = Command::new("powershell.exe")
        .args(["-NoLogo", "-NoProfile", "-Command", ps_static])
        .env("NG_SC_LNK", &lnk_path)
        .env("NG_SC_TARGET", &self_exe)
        .env("NG_SC_ARGS", &args)
        .env("NG_SC_WORKDIR", &work_dir)
        .env("NG_SC_ICON", &icon_loc)
        .env("NG_SC_DESC", &desc)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("创建桌面快捷方式失败: {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("创建桌面快捷方式失败: {}", stderr.trim()));
    }

    Ok(format!(
        "已在桌面创建快捷方式：{}（双击即可按当前配置启动，无需打开 AI NetGuard 窗口）",
        lnk_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
    ))
}

fn show_native_warning_box(title: &str, message: &str) {
    let title_w = to_wide(title);
    let msg_w = to_wide(message);
    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR(msg_w.as_ptr()),
            PCWSTR(title_w.as_ptr()),
            MB_OK | MB_ICONWARNING,
        );
    }
}

/// Fast headless CLI entrypoint: `ai-netguard.exe --launch-app <app_id>`.
/// Returns `Some(exit_code)` when handled, or `None` for normal GUI startup.
pub fn try_handle_cli_launch() -> Option<i32> {
    let mut args = std::env::args().skip(1);
    let mut target_app_id: Option<String> = None;
    let mut relaunch = false;
    while let Some(arg) = args.next() {
        if arg == "--launch-app" {
            target_app_id = args.next();
        } else if arg == "--relaunch" {
            relaunch = true;
        }
    }
    let app_id = target_app_id?;

    let cfg = crate::models::load_config();
    let Some(app) = cfg
        .managed_apps
        .iter()
        .find(|a| a.id == app_id)
        .cloned()
    else {
        show_native_warning_box(
            "AI NetGuard 启动失败",
            &format!("未在配置中找到应用 ID：{app_id}"),
        );
        return Some(1);
    };

    let mut tcp_cache = HashMap::new();
    let gateway_running = probe_tcp_alive(&format!("127.0.0.1:{}", cfg.cli_port), &mut tcp_cache);
    let mut launcher = ProcessLauncher::new();
    let logs = Arc::new(LogBuffer::new());

    match launch_managed_app_with_clean_env(
        &app,
        &cfg,
        &mut launcher,
        crate::pac::PAC_PORT,
        gateway_running,
        relaunch,
        logs,
    ) {
        Ok(_) => Some(0),
        Err(err) => {
            show_native_warning_box("AI NetGuard 启动失败", &err);
            Some(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_proxy_host_port_handles_urls_and_wininet_formats() {
        assert_eq!(
            extract_proxy_host_port("http://127.0.0.1:17890"),
            Some("127.0.0.1:17890".into())
        );
        assert_eq!(
            extract_proxy_host_port("socks5h://127.0.0.1:7897"),
            Some("127.0.0.1:7897".into())
        );
        assert_eq!(
            extract_proxy_host_port("127.0.0.1:7897"),
            Some("127.0.0.1:7897".into())
        );
        assert_eq!(
            extract_proxy_host_port("http=127.0.0.1:7897;https=127.0.0.1:7897"),
            Some("127.0.0.1:7897".into())
        );
        assert_eq!(extract_proxy_host_port(""), None);
    }

    #[test]
    fn parse_peb_utf16_env_extracts_only_proxy_vars() {
        let mut raw: Vec<u16> = Vec::new();
        for item in [
            "PATH=C:\\Windows\\System32",
            "SECRET_API_KEY=sk-ant-do-not-leak",
            "http_proxy=http://127.0.0.1:17890",
            "HTTPS_PROXY=http://127.0.0.1:17890",
            "NO_PROXY=localhost,127.0.0.1",
        ] {
            raw.extend(item.encode_utf16());
            raw.push(0);
        }
        raw.push(0);

        let parsed = parse_peb_utf16_proxy_vars(&raw);
        assert_eq!(
            parsed,
            vec![
                ("HTTP_PROXY".into(), "http://127.0.0.1:17890".into()),
                ("HTTPS_PROXY".into(), "http://127.0.0.1:17890".into()),
                ("NO_PROXY".into(), "localhost,127.0.0.1".into()),
            ]
        );
    }

    #[test]
    fn read_own_process_peb_succeeds_on_windows_x64() {
        let pid = std::process::id();
        let vars = read_process_proxy_env(pid);
        assert!(
            vars.is_some(),
            "expected PEB ReadProcessMemory to succeed on current process"
        );
    }

    #[test]
    fn classify_detects_dead_proxy_even_when_system_proxy_is_healthy() {
        let cfg = AppConfig::default();
        let app = ManagedAppConfig {
            id: "antigravity".into(),
            name: "Antigravity".into(),
            builtin: true,
            exe_path: None,
            process_names: vec!["Antigravity.exe".into()],
            proxy_mode: AppProxyMode::SystemProxy,
            custom_proxy_url: None,
            wfp_lock: false,
            extra_args: Vec::new(),
        };
        let sys = SystemProxyStatus {
            enabled: true,
            server: Some("127.0.0.1:7897".into()),
            host_port: Some("127.0.0.1:7897".into()),
            alive: true,
            auto_config_url: None,
        };
        let env_vars = vec![EnvVarHealth {
            scope: "process".into(),
            key: "HTTP_PROXY".into(),
            value: "http://127.0.0.1:17890".into(),
            host_port: Some("127.0.0.1:17890".into()),
            alive: Some(false),
        }];
        let clash = ClashVergeNodesSnapshot::default();
        let (health, diag, needs_relaunch) =
            classify_app_health(&app, true, &env_vars, &cfg, false, &sys, &clash);
        assert_eq!(health, "dead_proxy");
        assert!(needs_relaunch);
        assert!(diag.contains("127.0.0.1:7897"));
        assert!(diag.contains("127.0.0.1:17890"));
    }

    #[test]
    fn build_clean_base_env_strips_proxy_variables() {
        let env = build_clean_base_env();
        for k in env.keys() {
            assert!(
                !is_proxy_key(k),
                "clean base env must not contain proxy key {k}"
            );
        }
    }

    #[test]
    fn classify_treats_live_system_proxy_env_as_clean_in_system_proxy_mode() {
        let cfg = AppConfig::default();
        let app = ManagedAppConfig {
            id: "cockpit-tools".into(),
            name: "Cockpit Tools".into(),
            builtin: true,
            exe_path: None,
            process_names: vec!["cockpit-tools.exe".into()],
            proxy_mode: AppProxyMode::SystemProxy,
            custom_proxy_url: None,
            wfp_lock: false,
            extra_args: Vec::new(),
        };
        let sys = SystemProxyStatus {
            enabled: true,
            server: Some("127.0.0.1:7897".into()),
            host_port: Some("127.0.0.1:7897".into()),
            alive: true,
            auto_config_url: None,
        };
        let env_vars = vec![
            EnvVarHealth {
                scope: "process".into(),
                key: "HTTP_PROXY".into(),
                value: "http://127.0.0.1:7897".into(),
                host_port: Some("127.0.0.1:7897".into()),
                alive: Some(true),
            },
            EnvVarHealth {
                scope: "process".into(),
                key: "HTTPS_PROXY".into(),
                value: "http://127.0.0.1:7897".into(),
                host_port: Some("127.0.0.1:7897".into()),
                alive: Some(true),
            },
        ];
        let clash = ClashVergeNodesSnapshot::default();
        let (health, _diag, needs_relaunch) =
            classify_app_health(&app, true, &env_vars, &cfg, true, &sys, &clash);
        assert_eq!(health, "clean");
        assert!(!needs_relaunch);
    }

    #[test]
    fn classify_treats_clean_env_matching_live_system_proxy_as_clean_in_custom_proxy_mode() {
        let cfg = AppConfig::default();
        let app = ManagedAppConfig {
            id: "antigravity".into(),
            name: "Antigravity".into(),
            builtin: true,
            exe_path: None,
            process_names: vec!["Antigravity.exe".into()],
            proxy_mode: AppProxyMode::CustomProxy,
            custom_proxy_url: Some("http://127.0.0.1:7897".into()),
            wfp_lock: false,
            extra_args: Vec::new(),
        };
        let sys = SystemProxyStatus {
            enabled: true,
            server: Some("127.0.0.1:7897".into()),
            host_port: Some("127.0.0.1:7897".into()),
            alive: true,
            auto_config_url: None,
        };
        let clash = ClashVergeNodesSnapshot::default();
        let (health, diag, needs_relaunch) =
            classify_app_health(&app, true, &[], &cfg, true, &sys, &clash);
        assert_eq!(health, "clean");
        assert!(!needs_relaunch);
        assert!(diag.contains("127.0.0.1:7897"));
    }

    #[test]
    fn external_managed_antigravity_health_and_refusal_rules() {
        let cfg = AppConfig::default();
        let app = ManagedAppConfig {
            id: "antigravity".into(),
            name: "Antigravity".into(),
            builtin: true,
            exe_path: None,
            process_names: vec!["Antigravity.exe".into()],
            proxy_mode: AppProxyMode::ExternalManaged,
            custom_proxy_url: None,
            wfp_lock: false,
            extra_args: Vec::new(),
        };
        let sys_off = SystemProxyStatus {
            enabled: false,
            server: None,
            host_port: None,
            alive: false,
            auto_config_url: None,
        };
        let clash = ClashVergeNodesSnapshot {
            detected: true,
            source_path: None,
            mixed_port: Some(7897),
            listeners: vec![crate::accounts::ClashVergeListenerItem {
                name: "adspower-japan".into(),
                listener_type: "mixed".into(),
                port: 10809,
                proxy: "JP".into(),
            }],
            groups: Vec::new(),
            proxies: Vec::new(),
        };

        // 1. Live Clash listener port -> clean + annotated listener name + no relaunch
        let live_10809 = vec![EnvVarHealth {
            scope: "process".into(),
            key: "HTTPS_PROXY".into(),
            value: "http://127.0.0.1:10809".into(),
            host_port: Some("127.0.0.1:10809".into()),
            alive: Some(true),
        }];
        let (h1, d1, r1) =
            classify_app_health(&app, true, &live_10809, &cfg, false, &sys_off, &clash);
        assert_eq!(h1, "clean");
        assert!(!r1);
        assert!(d1.contains("adspower-japan"), "diag={d1}");

        // 2. Empty env + disabled system proxy -> mismatch warning (bare direct risk)
        let (h2, d2, r2) = classify_app_health(&app, true, &[], &cfg, false, &sys_off, &clash);
        assert_eq!(h2, "mismatch");
        assert!(!r2);
        assert!(d2.contains("直连"), "diag={d2}");

        // 3. Accidentally pointing to AI NetGuard port 17890 -> mismatch warning
        let live_17890 = vec![EnvVarHealth {
            scope: "process".into(),
            key: "HTTP_PROXY".into(),
            value: "http://127.0.0.1:17890".into(),
            host_port: Some("127.0.0.1:17890".into()),
            alive: Some(true),
        }];
        let (h3, d3, r3) =
            classify_app_health(&app, true, &live_17890, &cfg, true, &sys_off, &clash);
        assert_eq!(h3, "mismatch");
        assert!(!r3);
        assert!(d3.contains("17890"), "diag={d3}");

        // 4. Dead port :10810 -> dead_proxy alert, never takeover relaunch
        let dead_10810 = vec![EnvVarHealth {
            scope: "process".into(),
            key: "ALL_PROXY".into(),
            value: "http://127.0.0.1:10810".into(),
            host_port: Some("127.0.0.1:10810".into()),
            alive: Some(false),
        }];
        let (h4, _d4, r4) =
            classify_app_health(&app, true, &dead_10810, &cfg, false, &sys_off, &clash);
        assert_eq!(h4, "dead_proxy");
        assert!(!r4);

        // 5. Launch and shortcut creation must refuse ExternalManaged
        let mut launcher = ProcessLauncher::new();
        let logs = Arc::new(LogBuffer::new());
        let launch_res =
            launch_managed_app_with_clean_env(&app, &cfg, &mut launcher, 17898, false, false, logs);
        assert!(launch_res.is_err());
        let sc_res = create_desktop_shortcut_for_app(&app, &cfg, &launcher);
        assert!(sc_res.is_err());
    }
}
