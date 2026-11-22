mod accounts;
mod adspower;
mod app_env;
mod healthcheck;
mod ipc_client;
mod launcher;
mod models;
mod network;
mod pac;
mod singbox;
mod uri_parser;

use accounts::{
    default_env_presets, discover_clash_verge_nodes, load_accounts, load_env_presets,
    normalize_account, normalize_env_presets, reorder_account_list, save_accounts,
    save_env_presets, AccountBrowserKind, AccountEnvPreset, AccountNodeSource, AccountRecord,
    ClashVergeNodesSnapshot,
};
use adspower::{AdsPowerConfigStatus, AdsPowerProfilesSnapshot, AdsPowerSettingsDisk};

use guard_protocol::{GuardRequest, ProtectedTarget};
use ipc_client::GuardClient;
use launcher::{download_and_install_browser, ProcessLauncher};
use models::{
    default_browser_homepage, default_browser_profiles, effective_outbound_mode,
    extract_loopback_port, load_config, save_config_to_disk, ActiveAccountSession, AppConfig,
    AppEnvSnapshot, AppProxyMode, BrowserFingerprintConfig, BrowserFingerprintMode,
    BrowserProfile, DiagnosticCheck, ExitIpInfo, GatewayStatus, KillSwitchMode, LogBuffer,
    NodeProfile, OutboundMode,
};
use network::{
    detect_physical_nic, detect_running_vpn_conflicts, probe_exit_ip, probe_exit_ip_fast,
    probe_exit_ip_via_proxy, resolve_server_ipv4,
};
use pac::{PacServer, PAC_PORT};
use singbox::{send_kill_switch_http, SingBoxManager};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{
    menu::{MenuBuilder, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, State, WindowEvent,
};

struct InnerState {
    config: AppConfig,
    singbox: SingBoxManager,
    pac: PacServer,
    guard: GuardClient,
    launcher: ProcessLauncher,
    last_exit_ip: Option<ExitIpInfo>,
    verified_geo_cache: HashMap<String, ExitIpInfo>,
    active_secondary_ports: BTreeMap<String, u16>,
    active_account_session: Option<ActiveAccountSession>,
    running_adspower_ids: HashSet<String>,
    extra_wfp_targets: Vec<ProtectedTarget>,
    manual_kill_switch: bool,
    starting_gateway: bool,
    active_nic_name: Option<String>,
    active_gateway_ip: Option<String>,
}

struct StartingResetGuard(Arc<AppState>);

impl Drop for StartingResetGuard {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.0.inner.lock() {
            inner.starting_gateway = false;
        }
    }
}

pub struct AppState {
    inner: Mutex<InnerState>,
    accounts: Mutex<Vec<AccountRecord>>,
    account_envs: Mutex<Vec<AccountEnvPreset>>,
    logs: Arc<LogBuffer>,
}

impl AppState {
    fn new() -> Self {
        let mut cfg = load_config();
        ensure_default_browser_profile(&mut cfg);
        let browser_port = cfg.browser_port;
        let logs = Arc::new(LogBuffer::new());
        let accounts = match load_accounts() {
            Ok(list) => list,
            Err(err) => {
                logs.push(format!("[账号库] 读取加密库失败: {err}"));
                Vec::new()
            }
        };
        let account_envs = match load_env_presets() {
            Ok(list) => list,
            Err(err) => {
                logs.push(format!("[账号库] 读取启动环境列表失败: {err}"));
                default_env_presets()
            }
        };
        Self {
            inner: Mutex::new(InnerState {
                config: cfg,
                singbox: SingBoxManager::new(),
                pac: PacServer::new(browser_port),
                guard: GuardClient::new(),
                launcher: ProcessLauncher::new(),
                last_exit_ip: None,
                verified_geo_cache: HashMap::new(),
                active_secondary_ports: BTreeMap::new(),
                active_account_session: None,
                running_adspower_ids: HashSet::new(),
                extra_wfp_targets: Vec::new(),
                manual_kill_switch: false,
                starting_gateway: false,
                active_nic_name: None,
                active_gateway_ip: None,
            }),
            accounts: Mutex::new(accounts),
            account_envs: Mutex::new(account_envs),
            logs,
        }
    }

    fn allowed_ports(cfg: &AppConfig) -> Vec<u16> {
        vec![cfg.cli_port, cfg.browser_port, PAC_PORT]
    }

    fn allowed_browser_ports(inner: &InnerState) -> Vec<u16> {
        let mut ports = Self::allowed_ports(&inner.config);
        for &p in SingBoxManager::secondary_node_port_map(&inner.config).values() {
            if !ports.contains(&p) {
                ports.push(p);
            }
        }
        for &p in inner.active_secondary_ports.values() {
            if !ports.contains(&p) {
                ports.push(p);
            }
        }
        for p in inner
            .config
            .browser_profiles
            .iter()
            .filter_map(|bp| bp.custom_proxy_url.as_deref())
            .filter_map(extract_loopback_port)
        {
            if !ports.contains(&p) {
                ports.push(p);
            }
        }
        ports
    }

    fn build_desktop_wfp_targets(inner: &InnerState, allow_proxy_ports: bool) -> Vec<ProtectedTarget> {
        let ports = if allow_proxy_ports {
            Self::allowed_ports(&inner.config)
        } else {
            Vec::new()
        };
        inner
            .launcher
            .resolve_claude_desktop_wfp_paths(&inner.config)
            .into_iter()
            .map(|p| ProtectedTarget {
                exe_path: p.to_string_lossy().to_string(),
                allow_private_lan: false,
                allowed_loopback_ports: ports.clone(),
            })
            .collect()
    }

    fn build_wfp_targets(inner: &InnerState) -> Vec<ProtectedTarget> {
        let browser_ports = Self::allowed_browser_ports(inner);
        let mut targets = Vec::new();
        if let Some(browser) = inner.launcher.resolve_browser_path(&inner.config) {
            targets.push(ProtectedTarget {
                exe_path: browser.to_string_lossy().to_string(),
                allow_private_lan: false,
                allowed_loopback_ports: browser_ports,
            });
        }
        targets.extend(Self::build_desktop_wfp_targets(inner, true));
        for app in &inner.config.managed_apps {
            if app.id != "claude-desktop"
                && app.wfp_lock
                && matches!(app.proxy_mode, AppProxyMode::Netguard)
            {
                if let Some(exe) =
                    app_env::resolve_managed_app_exe(app, &inner.config, &inner.launcher)
                {
                    let exe_str = exe.to_string_lossy().to_string();
                    if !targets
                        .iter()
                        .any(|t| t.exe_path.eq_ignore_ascii_case(&exe_str))
                    {
                        targets.push(ProtectedTarget {
                            exe_path: exe_str,
                            allow_private_lan: false,
                            allowed_loopback_ports: vec![inner.config.cli_port],
                        });
                    }
                }
            }
        }
        for extra in &inner.extra_wfp_targets {
            if !targets.iter().any(|t| t.exe_path == extra.exe_path) {
                targets.push(extra.clone());
            }
        }
        targets
    }

    fn snapshot_status(&self) -> GatewayStatus {
        let mut inner = self.inner.lock().expect("state lock poisoned");
        let running = inner.singbox.is_running();
        let blocked = inner.singbox.is_blocked();
        let kill_reason = inner.singbox.kill_reason();
        let running_browser_profiles = inner.launcher.running_browser_profile_ids();
        let browser_running = !running_browser_profiles.is_empty();
        let mut running_adspower_profiles: Vec<String> =
            inner.running_adspower_ids.iter().cloned().collect();
        running_adspower_profiles.sort();
        let browser_path = inner.launcher.resolve_browser_path(&inner.config);
        let desktop_path = inner.launcher.resolve_claude_desktop_path(&inner.config);
        let cli_found = inner.launcher.detect_claude_cli().is_some();
        let nic = detect_physical_nic();
        let conflicts = detect_running_vpn_conflicts();
        let guard_connected = inner.guard.is_connected();
        let guard_st = inner.guard.last_status().clone();
        let secondary_node_ports = if running {
            inner.active_secondary_ports.clone()
        } else {
            BTreeMap::new()
        };

        GatewayStatus {
            running,
            blocked_by_kill_switch: blocked,
            kill_switch_reason: kill_reason,
            guard_connected,
            guard_elevated: guard_connected,
            wfp_active: guard_connected && guard_st.wfp_active,
            wfp_filter_count: if guard_connected {
                guard_st.filter_count
            } else {
                0
            },
            persistent_claude_lock_active: guard_connected && guard_st.persistent_lock_active,
            persistent_claude_filter_count: if guard_connected {
                guard_st.persistent_filter_count
            } else {
                0
            },
            bypass_route_active: guard_connected && guard_st.bypass_route_active,
            browser_running,
            browser_installed: browser_path.is_some(),
            browser_path: browser_path.map(|p| p.to_string_lossy().to_string()),
            claude_desktop_found: desktop_path.is_some(),
            claude_desktop_path: desktop_path.map(|p| p.to_string_lossy().to_string()),
            claude_cli_found: cli_found,
            detected_physical_nic: nic.as_ref().map(|n| n.name.clone()),
            detected_physical_gateway: nic.map(|n| n.gateway_ip),
            detected_conflicts: conflicts,
            exit_ip: inner.last_exit_ip.clone(),
            running_browser_profiles,
            running_adspower_profiles,
            secondary_node_ports,
            active_account_session: inner.active_account_session.clone(),
            logs: self.logs.snapshot(),
        }
    }
}

fn ensure_default_browser_profile(cfg: &mut AppConfig) {
    if !cfg.browser_profiles.iter().any(|p| p.id == "default") {
        if let Some(def) = default_browser_profiles().into_iter().next() {
            cfg.browser_profiles.insert(0, def);
        }
    }
}

fn has_country_code(info: &ExitIpInfo) -> bool {
    info.country_code
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty())
}

fn merge_cached_geo_for_same_ip(mut fresh: ExitIpInfo, cached: Option<&ExitIpInfo>) -> ExitIpInfo {
    if !has_country_code(&fresh) {
        if let Some(c) = cached {
            if c.ip == fresh.ip && has_country_code(c) {
                fresh.country = fresh.country.or_else(|| c.country.clone());
                fresh.country_code = c.country_code.clone();
                fresh.region = fresh.region.or_else(|| c.region.clone());
                fresh.city = fresh.city.or_else(|| c.city.clone());
                fresh.latitude = fresh.latitude.or(c.latitude);
                fresh.longitude = fresh.longitude.or(c.longitude);
                fresh.timezone = fresh.timezone.or_else(|| c.timezone.clone());
                fresh.isp = fresh.isp.or_else(|| c.isp.clone());
                fresh.org = fresh.org.or_else(|| c.org.clone());
                fresh.asn = fresh.asn.or_else(|| c.asn.clone());
            }
        }
    }
    fresh
}

fn collect_physical_bypass_target_ips(cfg: &AppConfig) -> Vec<String> {
    let mut ips = Vec::new();
    let sec_map = SingBoxManager::secondary_node_port_map(cfg);
    for node in &cfg.nodes {
        let is_active = node.id == cfg.active_node_id || sec_map.contains_key(&node.id);
        if !is_active || node.server.trim().is_empty() {
            continue;
        }
        if matches!(effective_outbound_mode(cfg, node), OutboundMode::PhysicalBypass) {
            if let Ok(ip) = resolve_server_ipv4(&node.server) {
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
    }
    ips
}

#[tauri::command]
fn get_config(state: State<'_, Arc<AppState>>) -> AppConfig {
    state.inner.lock().unwrap().config.clone()
}

#[tauri::command]
fn save_config(
    state: State<'_, Arc<AppState>>,
    mut config: AppConfig,
) -> Result<AppConfig, String> {
    ensure_default_browser_profile(&mut config);
    save_config_to_disk(&config)?;
    let mut inner = state.inner.lock().unwrap();
    inner.config = config.clone();
    if inner.guard.is_connected() {
        if inner.config.wfp_lock_enabled {
            let targets = AppState::build_wfp_targets(&inner);
            let _ = inner.guard.call(GuardRequest::ApplyWfpLock { targets });
        } else {
            let _ = inner.guard.call(GuardRequest::ClearWfpLock);
        }
    }
    state.logs.push("已保存配置");
    Ok(config)
}

#[tauri::command]
fn parse_node_uri(uri: String) -> Result<NodeProfile, String> {
    uri_parser::parse_node_uri(&uri)
}

#[tauri::command]
fn generate_vps_script(protocol: String, port: u16) -> String {
    uri_parser::generate_vps_script(&protocol, port)
}

#[tauri::command]
fn get_status(state: State<'_, Arc<AppState>>) -> GatewayStatus {
    state.snapshot_status()
}

#[tauri::command]
async fn connect_guard(state: State<'_, Arc<AppState>>) -> Result<GatewayStatus, String> {
    {
        let mut inner = state.inner.lock().unwrap();
        inner.guard.ensure_started()?;
        let targets = AppState::build_wfp_targets(&inner);
        if inner.config.wfp_lock_enabled && !targets.is_empty() {
            inner
                .guard
                .call(GuardRequest::ApplyWfpLock { targets })?;
        }
        state.logs.push("已连接提权 Guard 并应用 WFP 保护规则");
    }
    Ok(state.snapshot_status())
}

#[tauri::command]
async fn start_gateway(state: State<'_, Arc<AppState>>) -> Result<GatewayStatus, String> {
    let nic = detect_physical_nic();
    let conflicts = detect_running_vpn_conflicts();
    {
        let mut inner = state.inner.lock().unwrap();
        if inner.starting_gateway {
            return Err("安全网关正在启动".into());
        }
        if inner.singbox.is_running() {
            drop(inner);
            return Ok(state.snapshot_status());
        }
        if let Err(err) = SingBoxManager::check_listen_ports(&inner.config) {
            state.logs.push(&err);
            return Err(err);
        }
        inner.starting_gateway = true;
        inner.last_exit_ip = None;
        inner.verified_geo_cache.clear();
        inner.active_secondary_ports.clear();
    }
    let _reset_guard = StartingResetGuard(state.inner().clone());

    let (probe_port, api_secret, active_node, cfg_copy) = {
        let mut inner = state.inner.lock().unwrap();
        let cfg = inner.config.clone();
        let nic_name = nic.as_ref().map(|n| n.name.as_str());

        // Elevate Guard, apply WFP locks, and inject /32 bypass routes BEFORE starting sing-box
        // so sing-box's first outbound handshake already sees all /32 bypass routes & monitor won't race UAC.
        let bypass_ips = collect_physical_bypass_target_ips(&cfg);
        let need_bypass_route = !bypass_ips.is_empty() && !conflicts.is_empty() && nic.is_some();

        if cfg.wfp_lock_enabled || cfg.require_netguard_for_claude || need_bypass_route {
            match inner.guard.ensure_started() {
                Ok(()) => {
                    if cfg.wfp_lock_enabled {
                        let targets = AppState::build_wfp_targets(&inner);
                        if !targets.is_empty() {
                            if let Err(e) = inner.guard.call(GuardRequest::ApplyWfpLock { targets }) {
                                inner.singbox.stop();
                                return Err(format!("WFP 防泄漏规则下发失败，已中止启动: {e}"));
                            }
                        }
                    }
                    if cfg.require_netguard_for_claude {
                        let desktop_targets = AppState::build_desktop_wfp_targets(&inner, true);
                        if !desktop_targets.is_empty() {
                            if let Err(e) = inner
                                .guard
                                .call(GuardRequest::InstallPersistentLock { targets: desktop_targets })
                            {
                                state.logs.push(format!("Claude 离线硬锁下发警告: {e}"));
                            } else {
                                state.logs.push(
                                    "已激活 Claude Desktop 离线硬锁（未开启 NetGuard 且仅限专属端口，已屏蔽 Clash 7897）",
                                );
                            }
                        }
                    }
                    if !bypass_ips.is_empty() {
                        if let Some(n) = nic.as_ref() {
                            if let Err(e) = inner.guard.call(GuardRequest::SetBypassRoutes {
                                target_ips: bypass_ips.clone(),
                                gateway_ip: n.gateway_ip.clone(),
                                interface_index: n.if_index,
                            }) {
                                state.logs.push(format!("物理网卡 /32 旁路路由提示: {e}"));
                            } else {
                                state.logs.push(format!(
                                    "已注入 /32 物理网卡旁路路由: {} -> {} ({})",
                                    bypass_ips.join(", "),
                                    n.gateway_ip,
                                    n.name
                                ));
                            }
                        }
                    }
                }
                Err(e) => {
                    if cfg.wfp_lock_enabled {
                        inner.singbox.stop();
                        return Err(format!("安全要求启用 WFP 硬锁，但提权失败: {e}"));
                    }
                    state.logs.push(format!("未连接提权 Guard: {e}"));
                }
            }
        }

        inner.pac.ensure_started(cfg.browser_port)?;
        inner.singbox.start(&cfg, nic_name, state.logs.clone())?;
        let sec_ports = SingBoxManager::secondary_node_port_map(&cfg);
        inner.active_secondary_ports = sec_ports.clone();
        if !sec_ports.is_empty() {
            let desc: Vec<String> = sec_ports
                .iter()
                .filter_map(|(nid, port)| {
                    cfg.nodes
                        .iter()
                        .find(|n| &n.id == nid)
                        .map(|n| format!("{}(:{port})", n.name))
                })
                .collect();
            state
                .logs
                .push(format!("已并发激活 {} 个独立浏览器节点端口: {}", desc.len(), desc.join(", ")));
        }
        // Keep selector in default ai_block state until initial exit verification passes.
        inner
            .singbox
            .mark_kill_switch(true, Some("正在核验安全出口，完成前保持阻断".into()));
        inner.active_nic_name = nic.as_ref().map(|n| n.name.clone());
        inner.active_gateway_ip = nic.as_ref().map(|n| n.gateway_ip.clone());

        let node = cfg.nodes.iter().find(|n| n.id == cfg.active_node_id).cloned();
        let secret = inner.singbox.api_secret();
        let p_port = SingBoxManager::probe_port(&cfg);
        (p_port, secret, node, cfg)
    };

    tokio::time::sleep(Duration::from_millis(600)).await;
    if !state.inner.lock().unwrap().singbox.is_running() {
        let err = "sing-box 在启动时退出，详情请查看内核运行日志";
        state.logs.push(err);
        return Err(err.into());
    }

    // Initial exit IP verification via isolated in_probe (1 retry for cold TLS/Reality handshake)
    let probe_res = match probe_exit_ip(probe_port).await {
        Ok(exit) => Ok(exit),
        Err(first_err) => {
            state.logs.push(format!("首次冷启动出口探测重试中: {first_err}"));
            tokio::time::sleep(Duration::from_millis(800)).await;
            probe_exit_ip(probe_port).await
        }
    };

    match probe_res {
        Ok(exit) => {
            let mismatch = active_node
                .as_ref()
                .and_then(|node| check_node_expectation(node, &exit));
            {
                let mut inner = state.inner.lock().unwrap();
                if has_country_code(&exit) {
                    inner
                        .verified_geo_cache
                        .insert(exit.ip.clone(), exit.clone());
                }
                inner.last_exit_ip = Some(exit.clone());
            }
            if let Some(reason) = mismatch {
                state.logs.push(format!("出口核验异常: {reason}"));
                if matches!(cfg_copy.kill_switch, KillSwitchMode::FailClosed) {
                    let _ = send_kill_switch_http(&api_secret, true).await;
                    let mut inner = state.inner.lock().unwrap();
                    inner.singbox.mark_kill_switch(true, Some(reason));
                } else if send_kill_switch_http(&api_secret, false).await.is_ok() {
                    let mut inner = state.inner.lock().unwrap();
                    inner.singbox.mark_kill_switch(false, None);
                }
            } else {
                match send_kill_switch_http(&api_secret, false).await {
                    Ok(()) => {
                        let mut inner = state.inner.lock().unwrap();
                        inner.singbox.mark_kill_switch(false, None);
                        state.logs.push(format!(
                            "出口核验通过，已解锁安全出站: {} ({})",
                            exit.ip,
                            exit.country_code.as_deref().unwrap_or("--")
                        ));
                    }
                    Err(e) => {
                        state.logs.push(format!("解锁安全选择器失败，维持阻断并停止网关: {e}"));
                        let mut inner = state.inner.lock().unwrap();
                        inner.singbox.stop();
                    }
                }
            }
        }
        Err(e) => {
            state.logs.push(format!("初始出口探测失败: {e}"));
            if matches!(cfg_copy.kill_switch, KillSwitchMode::FailClosed) {
                let _ = send_kill_switch_http(&api_secret, true).await;
                let mut inner = state.inner.lock().unwrap();
                inner
                    .singbox
                    .mark_kill_switch(true, Some(format!("出口探测失败，保持熔断阻断: {e}")));
            } else if send_kill_switch_http(&api_secret, false).await.is_ok() {
                let mut inner = state.inner.lock().unwrap();
                inner.singbox.mark_kill_switch(false, None);
            }
        }
    }

    // Auto-launch Safe Browser (and optional Claude Desktop) when exit IP passed cleanly
    let exit_ok_and_unblocked = {
        let inner = state.inner.lock().unwrap();
        inner.last_exit_ip.is_some() && !inner.singbox.is_blocked()
    };
    if exit_ok_and_unblocked {
        let mut inner = state.inner.lock().unwrap();
        if cfg_copy.auto_launch_browser
            && inner.launcher.resolve_browser_path(&cfg_copy).is_some()
            && !inner.launcher.is_browser_running()
        {
            if let Err(e) =
                inner
                    .launcher
                    .launch_browser_url(&cfg_copy, "https://claude.ai", state.logs.clone())
            {
                state.logs.push(format!("自动弹出安全浏览器失败: {e}"));
            }
        }
        if cfg_copy.auto_launch_claude_desktop
            && inner.launcher.resolve_claude_desktop_path(&cfg_copy).is_some()
        {
            if let Err(e) = inner
                .launcher
                .launch_claude_desktop(&cfg_copy, PAC_PORT, state.logs.clone())
            {
                state.logs.push(format!("自动启动 Claude Desktop 失败: {e}"));
            }
        }
    }

    Ok(state.snapshot_status())
}

#[tauri::command]
fn stop_gateway(state: State<'_, Arc<AppState>>) -> GatewayStatus {
    {
        let mut inner = state.inner.lock().unwrap();
        if inner.guard.is_connected() {
            let _ = inner.guard.call(GuardRequest::ClearBypassRoute);
            let _ = inner.guard.call(GuardRequest::ClearWfpLock);
            if inner.config.require_netguard_for_claude {
                let offline_targets = AppState::build_desktop_wfp_targets(&inner, false);
                if !offline_targets.is_empty() {
                    let _ = inner.guard.call(GuardRequest::InstallPersistentLock {
                        targets: offline_targets,
                    });
                }
            }
        }
        inner.singbox.stop();
        inner.last_exit_ip = None;
        inner.verified_geo_cache.clear();
        inner.active_secondary_ports.clear();
        inner.manual_kill_switch = false;
        inner.active_nic_name = None;
        inner.active_gateway_ip = None;
        state.logs.push("已停止安全网关并收紧离线 WFP 防护（关闭未使用的回环放行端口）");
    }
    state.snapshot_status()
}

#[tauri::command]
async fn run_diagnostics(state: State<'_, Arc<AppState>>) -> Result<Vec<DiagnosticCheck>, String> {
    let (running, browser_port, cfg) = {
        let mut inner = state.inner.lock().unwrap();
        (
            inner.singbox.is_running(),
            inner.config.browser_port,
            inner.config.clone(),
        )
    };

    if running {
        if let Ok(raw_exit) = probe_exit_ip(browser_port).await {
            let mut inner = state.inner.lock().unwrap();
            let exit = if has_country_code(&raw_exit) {
                inner
                    .verified_geo_cache
                    .insert(raw_exit.ip.clone(), raw_exit.clone());
                raw_exit
            } else {
                let cached = inner.verified_geo_cache.get(&raw_exit.ip).cloned();
                merge_cached_geo_for_same_ip(raw_exit, cached.as_ref())
            };
            inner.last_exit_ip = Some(exit);
        }
    }

    let st = state.snapshot_status();
    Ok(healthcheck::run_eight_checks(&cfg, &st).await)
}

#[tauri::command]
async fn fix_diagnostic(state: State<'_, Arc<AppState>>, action: String) -> Result<String, String> {
    if action == "connect_guard" {
        let _ = connect_guard(state).await?;
        return Ok("已连接提权 Guard 并刷新 WFP / 旁路路由".into());
    }
    let cfg = state.inner.lock().unwrap().config.clone();
    healthcheck::apply_fix_action(&action, &cfg)
}

#[tauri::command]
async fn install_browser(app: AppHandle, state: State<'_, Arc<AppState>>) -> Result<String, String> {
    let msg = download_and_install_browser(app, state.logs.clone()).await?;
    // Refresh WFP rules if guard is already active so newly installed chrome.exe gets locked
    let mut inner = state.inner.lock().unwrap();
    if inner.guard.is_connected() && inner.config.wfp_lock_enabled {
        let targets = AppState::build_wfp_targets(&inner);
        let _ = inner.guard.call(GuardRequest::ApplyWfpLock { targets });
    }
    Ok(msg)
}

#[tauri::command]
fn launch_browser(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    launch_browser_url(state, "https://claude.ai".into())
}

#[tauri::command]
fn launch_browser_url(state: State<'_, Arc<AppState>>, url: String) -> Result<String, String> {
    launch_browser_profile(state, "default".into(), Some(url))
}

#[tauri::command]
fn launch_browser_profile(
    state: State<'_, Arc<AppState>>,
    profile_id: String,
    url: Option<String>,
) -> Result<String, String> {
    let mut inner = state.inner.lock().unwrap();
    let profile: BrowserProfile = if let Some(found) = inner
        .config
        .browser_profiles
        .iter()
        .find(|p| p.id == profile_id)
        .cloned()
    {
        found
    } else if profile_id == "default" {
        default_browser_profiles().into_iter().next().unwrap()
    } else {
        return Err(format!("未找到浏览器环境配置: {profile_id}"));
    };

    let (proxy_server_url, node_label, effective_tz, effective_locale) = if let Some(custom_url) =
        profile
            .custom_proxy_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    {
        let hp = app_env::extract_proxy_host_port(custom_url)
            .ok_or_else(|| format!("浏览器环境绑定的代理地址格式无效: {custom_url}"))?;
        if !app_env::is_tcp_host_port_alive(&hp) {
            return Err(format!(
                "环境绑定的本地代理端口 {hp} 未在监听（请确认 Clash Verge 等代理软件已启动）"
            ));
        }
        let tz = profile
            .fingerprint
            .timezone
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("Asia/Tokyo")
            .to_string();
        let locale = profile
            .fingerprint
            .locale
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("ja-JP")
            .to_string();
        (
            custom_url.to_string(),
            format!("独立代理 ({hp})"),
            tz,
            locale,
        )
    } else {
        if !inner.singbox.is_running() {
            return Err("请先启动安全网关".into());
        }
        if inner.starting_gateway {
            return Err("安全网关正在启动，请稍候再打开浏览器".into());
        }

        let target_node_id = profile
            .node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(inner.config.active_node_id.as_str())
            .to_string();

        let is_primary = target_node_id == inner.config.active_node_id;
        let socks_port = if is_primary {
            if inner.singbox.is_blocked() {
                return Err("安全主网关处于熔断阻断状态，请等待核验完成或解除熔断后再打开主出口浏览器".into());
            }
            inner.config.browser_port
        } else if let Some(&sec_port) = inner.active_secondary_ports.get(&target_node_id) {
            sec_port
        } else {
            return Err("该浏览器环境绑定的备用节点端口尚未激活（可能为启动网关后新添加或服务器地址为空），请先保存配置并重启安全网关".into());
        };

        let bound_node = inner
            .config
            .nodes
            .iter()
            .find(|n| n.id == target_node_id)
            .cloned();
        let label = bound_node
            .as_ref()
            .map(|n| n.name.clone())
            .unwrap_or_else(|| target_node_id.clone());
        let tz = profile
            .fingerprint
            .timezone
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                bound_node
                    .as_ref()
                    .and_then(|n| n.timezone.as_deref())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or("Asia/Seoul")
            .to_string();
        let locale = profile
            .fingerprint
            .locale
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                bound_node
                    .as_ref()
                    .and_then(|n| n.locale.as_deref())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or("ko-KR")
            .to_string();
        (
            format!("socks5://127.0.0.1:{socks_port}"),
            label,
            tz,
            locale,
        )
    };

    if inner.config.wfp_lock_enabled {
        inner.guard.ensure_started()?;
        let targets = AppState::build_wfp_targets(&inner);
        inner
            .guard
            .call(GuardRequest::ApplyWfpLock { targets })?;
    }

    let target_url = url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let hp = profile.homepage.trim();
            if hp.is_empty() { "https://claude.ai" } else { hp }
        })
        .to_string();

    let cfg = inner.config.clone();
    inner.launcher.launch_browser_profile(
        &cfg,
        &profile,
        &proxy_server_url,
        &node_label,
        &effective_tz,
        &effective_locale,
        &target_url,
        state.logs.clone(),
    )
}

#[tauri::command]
fn close_browser_profile(
    state: State<'_, Arc<AppState>>,
    profile_id: String,
) -> Result<GatewayStatus, String> {
    let closed = {
        let mut inner = state.inner.lock().unwrap();
        inner.launcher.close_browser_profile(&profile_id)
    };
    if closed {
        state
            .logs
            .push(format!("已关闭浏览器环境窗口: {profile_id}"));
    }
    Ok(state.snapshot_status())
}

#[tauri::command]
async fn probe_node_exit(
    state: State<'_, Arc<AppState>>,
    node_id: String,
) -> Result<ExitIpInfo, String> {
    let probe_port = {
        let mut inner = state.inner.lock().unwrap();
        if !inner.singbox.is_running() {
            return Err("安全网关未启动，无法探测节点出口".into());
        }
        if node_id == inner.config.active_node_id {
            SingBoxManager::probe_port(&inner.config)
        } else {
            inner
                .active_secondary_ports
                .get(&node_id)
                .copied()
                .ok_or_else(|| "该节点本地代理端口尚未激活，请先保存配置并重启网关".to_string())?
        }
    };
    probe_exit_ip(probe_port).await
}

#[derive(Clone, Debug)]
struct ResolvedAccountProxy {
    node_source: String,
    node_name: String,
    local_port: u16,
    http_proxy_url: String,
    browser_proxy_url: String,
    probe_proxy_url: String,
    netguard_node: Option<NodeProfile>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountLaunchOutcome {
    message: String,
    config: AppConfig,
    accounts: Vec<AccountRecord>,
    status: GatewayStatus,
    session: ActiveAccountSession,
}

fn resolve_account_proxy_target(
    account: &AccountRecord,
    cfg: &AppConfig,
    gateway_running: bool,
    gateway_starting: bool,
    gateway_blocked: bool,
    active_secondary_ports: &BTreeMap<String, u16>,
    clash: &ClashVergeNodesSnapshot,
) -> Result<ResolvedAccountProxy, String> {
    match account.linked_node_source {
        AccountNodeSource::None => Err(
            "该账号尚未绑定出口节点，为防止默认系统代理造成 IP 污染已拒绝启动；请先点击「编辑」绑定节点".into(),
        ),
        AccountNodeSource::Netguard => {
            if !gateway_running {
                return Err("该账号绑定了 AI NetGuard 节点，但安全网关尚未启动，已拒绝拉起".into());
            }
            if gateway_starting {
                return Err("AI NetGuard 安全网关正在启动中，请稍候再试".into());
            }
            let target_id = account
                .linked_node_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let node = target_id
                .and_then(|id| cfg.nodes.iter().find(|n| n.id == id))
                .or_else(|| {
                    account
                        .linked_node_name
                        .as_deref()
                        .map(str::trim)
                        .and_then(|name| cfg.nodes.iter().find(|n| n.name == name))
                })
                .cloned()
                .ok_or_else(|| {
                    format!(
                        "未在 AI NetGuard 节点列表找到账号绑定的节点（{}）",
                        account
                            .linked_node_name
                            .as_deref()
                            .or(target_id)
                            .unwrap_or("未知")
                    )
                })?;

            let port = if node.id == cfg.active_node_id {
                if gateway_blocked {
                    return Err(format!(
                        "安全主节点 [{}] 当前处于 Fail-Closed 熔断阻断状态，已拒绝拉起防泄漏保护",
                        node.name
                    ));
                }
                cfg.browser_port
            } else {
                active_secondary_ports
                    .get(&node.id)
                    .copied()
                    .ok_or_else(|| {
                        format!(
                            "备用节点 [{}] 尚未分配本地端口（请保存配置并重启网关后再拉起）",
                            node.name
                        )
                    })?
            };

            Ok(ResolvedAccountProxy {
                node_source: "netguard".into(),
                node_name: node.name.clone(),
                local_port: port,
                http_proxy_url: format!("http://127.0.0.1:{port}"),
                browser_proxy_url: format!("socks5://127.0.0.1:{port}"),
                probe_proxy_url: format!("socks5h://127.0.0.1:{port}"),
                netguard_node: Some(node),
            })
        }
        AccountNodeSource::ClashVerge => {
            let node_name = account
                .linked_node_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or("Clash Verge 节点名称为空，无法确定本地代理端口")?
                .to_string();

            let matched_listener = if let Some(override_port) = account.linked_proxy_port.filter(|&p| p > 0) {
                clash.listeners.iter().find(|l| l.port == override_port)
            } else {
                clash.listeners.iter().find(|l| {
                    l.proxy.eq_ignore_ascii_case(&node_name)
                        || l.name.eq_ignore_ascii_case(&node_name)
                })
            };

            let port = account
                .linked_proxy_port
                .filter(|&p| p > 0)
                .or_else(|| matched_listener.map(|l| l.port))
                .or(clash.mixed_port)
                .unwrap_or(7897);

            let is_http_only = matched_listener
                .map(|l| l.listener_type.eq_ignore_ascii_case("http"))
                .unwrap_or(false);
            let is_socks_only = matched_listener
                .map(|l| l.listener_type.to_ascii_lowercase().starts_with("socks"))
                .unwrap_or(false);

            let http_proxy_url = if is_socks_only {
                format!("socks5://127.0.0.1:{port}")
            } else {
                format!("http://127.0.0.1:{port}")
            };
            let browser_proxy_url = if is_http_only {
                format!("http://127.0.0.1:{port}")
            } else {
                format!("socks5://127.0.0.1:{port}")
            };
            let probe_proxy_url = if is_http_only {
                format!("http://127.0.0.1:{port}")
            } else {
                format!("socks5h://127.0.0.1:{port}")
            };

            Ok(ResolvedAccountProxy {
                node_source: "clash_verge".into(),
                node_name,
                local_port: port,
                http_proxy_url,
                browser_proxy_url,
                probe_proxy_url,
                netguard_node: None,
            })
        }
        AccountNodeSource::Custom => {
            let raw_name = account
                .linked_node_name
                .as_deref()
                .map(str::trim)
                .unwrap_or("");
            if raw_name.eq_ignore_ascii_case("direct") || raw_name == "直连" {
                return Err(
                    "「直连」模式无隔离代理端口；为防止本地真实 IP 串号污染，请改为绑定代理节点或指定本地代理端口".into(),
                );
            }
            if let Some(hp) = app_env::extract_proxy_host_port(raw_name) {
                let port = extract_loopback_port(&hp)
                    .or_else(|| hp.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()))
                    .unwrap_or(account.linked_proxy_port.unwrap_or(0));
                let full_url = if raw_name.contains("://") {
                    raw_name.to_string()
                } else {
                    format!("http://{hp}")
                };
                let probe_url = if let Some(rest) = full_url.strip_prefix("socks5://") {
                    format!("socks5h://{rest}")
                } else {
                    full_url.clone()
                };
                return Ok(ResolvedAccountProxy {
                    node_source: "custom".into(),
                    node_name: raw_name.to_string(),
                    local_port: port,
                    http_proxy_url: full_url.clone(),
                    browser_proxy_url: full_url,
                    probe_proxy_url: probe_url,
                    netguard_node: None,
                });
            }
            if let Some(port) = account.linked_proxy_port.filter(|&p| p > 0) {
                let label = if raw_name.is_empty() {
                    format!("自定义代理 :{port}")
                } else {
                    raw_name.to_string()
                };
                return Ok(ResolvedAccountProxy {
                    node_source: "custom".into(),
                    node_name: label,
                    local_port: port,
                    http_proxy_url: format!("http://127.0.0.1:{port}"),
                    browser_proxy_url: format!("http://127.0.0.1:{port}"),
                    probe_proxy_url: format!("http://127.0.0.1:{port}"),
                    netguard_node: None,
                });
            }
            Err("自定义代理节点未填有效代理地址 (如 http://127.0.0.1:10809) 或端口号".into())
        }
    }
}

fn infer_locale_for_country(cc: Option<&str>) -> (&'static str, &'static str) {
    match cc
        .map(str::trim)
        .unwrap_or("")
        .to_ascii_uppercase()
        .as_str()
    {
        "JP" => ("Asia/Tokyo", "ja-JP"),
        "KR" => ("Asia/Seoul", "ko-KR"),
        "GB" | "UK" => ("Europe/London", "en-GB"),
        "DE" => ("Europe/Berlin", "de-DE"),
        "SG" => ("Asia/Singapore", "en-SG"),
        "HK" => ("Asia/Hong_Kong", "zh-HK"),
        "TW" => ("Asia/Taipei", "zh-TW"),
        "CA" => ("America/Toronto", "en-CA"),
        "AU" => ("Australia/Sydney", "en-AU"),
        "FR" => ("Europe/Paris", "fr-FR"),
        _ => ("America/Los_Angeles", "en-US"),
    }
}

fn default_homepage_for_provider(provider: &str) -> String {
    let p = provider.trim().to_ascii_lowercase();
    if p.contains("claude") || p.contains("anthropic") {
        "https://claude.ai".into()
    } else if p.contains("google") || p.contains("gemini") {
        "https://accounts.google.com/".into()
    } else if p.contains("openai") || p.contains("chatgpt") {
        "https://chatgpt.com/".into()
    } else if p.contains("github") {
        "https://github.com/".into()
    } else {
        default_browser_homepage()
    }
}

fn random_isolated_fingerprint(tz: String, locale: String) -> BrowserFingerprintConfig {
    const GPUS: [(&str, &str); 5] = [
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 6700 XT Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 770 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ];
    const SCREENS: [(u32, u32, f64); 4] = [
        (1920, 1080, 1.0),
        (1920, 1080, 1.25),
        (2560, 1440, 1.0),
        (1680, 1050, 1.0),
    ];
    let gpu = GPUS[(rand::random::<u32>() as usize) % GPUS.len()];
    let scr = SCREENS[(rand::random::<u32>() as usize) % SCREENS.len()];
    let cpus = [4u32, 8, 12, 16];
    let mems = [8u32, 16, 32];
    let cpu = cpus[(rand::random::<u32>() as usize) % cpus.len()];
    let mem = mems[(rand::random::<u32>() as usize) % mems.len()];
    let seed = format!("acc-{:012x}", rand::random::<u64>() & 0xffff_ffff_ffff);
    BrowserFingerprintConfig {
        timezone: Some(tz),
        locale: Some(locale),
        screen_width: scr.0,
        screen_height: scr.1,
        device_pixel_ratio: scr.2,
        hardware_concurrency: cpu,
        device_memory: mem,
        webgl_vendor: gpu.0.into(),
        webgl_renderer: gpu.1.into(),
        user_agent: None,
        noise_seed: seed,
    }
}

async fn resolve_and_verify_account_proxy(
    state: &Arc<AppState>,
    account: &AccountRecord,
) -> Result<(ResolvedAccountProxy, ExitIpInfo), String> {
    let clash = discover_clash_verge_nodes();
    let resolved = {
        let mut inner = state.inner.lock().unwrap();
        let running = inner.singbox.is_running();
        let starting = inner.starting_gateway;
        let blocked = inner.singbox.is_blocked();
        let cfg = inner.config.clone();
        let sec_ports = inner.active_secondary_ports.clone();
        resolve_account_proxy_target(
            account,
            &cfg,
            running,
            starting,
            blocked,
            &sec_ports,
            &clash,
        )?
    };

    if resolved.node_source != "netguard" {
        let hp = app_env::extract_proxy_host_port(&resolved.http_proxy_url)
            .ok_or_else(|| format!("代理地址格式无效: {}", resolved.http_proxy_url))?;
        if !app_env::is_tcp_host_port_alive(&hp) {
            return Err(format!(
                "账号 [{}] 绑定的代理端口 {} 当前无人监听（请确认 Clash Verge 已运行且对应监听端口已开启），已拒绝启动",
                if account.label.trim().is_empty() { &account.email } else { &account.label },
                hp
            ));
        }
    }

    let verified_exit = probe_exit_ip_via_proxy(&resolved.probe_proxy_url)
        .await
        .map_err(|e| format!("启动前出口 IP 核验失败（已阻止启动以防 IP 污染）: {e}"))?;

    if let Some(ref ng_node) = resolved.netguard_node {
        if let Some(reason) = check_node_expectation(ng_node, &verified_exit) {
            return Err(format!(
                "出口 IP 核验不通过（已阻止启动以防污染）: {reason}"
            ));
        }
    }

    Ok((resolved, verified_exit))
}

#[tauri::command]
async fn launch_account_antigravity(
    state: State<'_, Arc<AppState>>,
    account_id: String,
) -> Result<AccountLaunchOutcome, String> {
    let account = {
        let guard = state
            .accounts
            .lock()
            .map_err(|_| "账号库状态锁定失败".to_string())?;
        guard
            .iter()
            .find(|a| a.id == account_id.trim())
            .cloned()
            .ok_or_else(|| "未找到指定账号记录".to_string())?
    };

    let (resolved, verified_exit) = resolve_and_verify_account_proxy(state.inner(), &account).await?;

    let display_label = if account.label.trim().is_empty() {
        account.email.clone()
    } else {
        account.label.clone()
    };

    let (msg, next_cfg, session) = {
        let mut inner = state.inner.lock().unwrap();
        if let Some(app) = inner
            .config
            .managed_apps
            .iter_mut()
            .find(|a| a.id == "antigravity")
        {
            app.proxy_mode = AppProxyMode::CustomProxy;
            app.custom_proxy_url = Some(resolved.http_proxy_url.clone());
        } else {
            return Err("未找到 Antigravity 受控应用配置".into());
        }
        save_config_to_disk(&inner.config)?;

        let app_cfg = inner
            .config
            .managed_apps
            .iter()
            .find(|a| a.id == "antigravity")
            .cloned()
            .unwrap();
        let cfg_clone = inner.config.clone();
        let gateway_ok = inner.singbox.is_running() && !inner.singbox.is_blocked();
        let _ = inner.pac.ensure_started(cfg_clone.browser_port);
        let launch_msg = app_env::launch_managed_app_with_clean_env(
            &app_cfg,
            &cfg_clone,
            &mut inner.launcher,
            PAC_PORT,
            gateway_ok,
            true,
            state.logs.clone(),
        )?;

        let prev_same = inner
            .active_account_session
            .as_ref()
            .filter(|s| s.account_id == account.id);
        let existing_browser_id = prev_same
            .and_then(|s| s.browser_profile_id.clone())
            .or_else(|| account.linked_browser_profile_id.clone());
        let (acc_uid, acc_sn, acc_adspower_label) = resolve_account_adspower_target(&account);
        let effective_kind = prev_same
            .map(|s| s.browser_kind.clone())
            .unwrap_or_else(|| match account.browser_kind {
                AccountBrowserKind::Adspower => "adspower".to_string(),
                AccountBrowserKind::Netguard => "netguard".to_string(),
            });
        let effective_adspower_uid = prev_same
            .and_then(|s| s.adspower_user_id.clone())
            .or(acc_uid)
            .or(acc_sn);
        let effective_adspower_label = prev_same
            .and_then(|s| s.adspower_profile_label.clone())
            .or(acc_adspower_label);

        let sess = ActiveAccountSession {
            account_id: account.id.clone(),
            account_label: display_label.clone(),
            email: account.email.clone(),
            node_source: resolved.node_source.clone(),
            node_name: resolved.node_name.clone(),
            proxy_url: resolved.http_proxy_url.clone(),
            local_port: resolved.local_port,
            verified_exit_ip: Some(verified_exit.clone()),
            antigravity_launched: true,
            browser_kind: effective_kind,
            browser_profile_id: existing_browser_id,
            adspower_user_id: effective_adspower_uid,
            adspower_profile_label: effective_adspower_label,
            activated_at: chrono::Local::now().format("%H:%M:%S").to_string(),
        };
        inner.active_account_session = Some(sess.clone());
        state.logs.push(format!(
            "[账号切换] 已验证出口 {} ({}) 并以 [{}] 环境干净重启 Antigravity -> {}",
            verified_exit.ip,
            verified_exit.country_code.as_deref().unwrap_or("--"),
            display_label,
            resolved.http_proxy_url
        ));
        (launch_msg, cfg_clone, sess)
    };

    let accounts = state
        .accounts
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    let status = state.snapshot_status();
    Ok(AccountLaunchOutcome {
        message: format!(
            "已切换账号 [{display_label}] ({}, IP {}) -> {msg}",
            resolved.node_name, verified_exit.ip
        ),
        config: next_cfg,
        accounts,
        status,
        session,
    })
}

fn resolve_account_adspower_target(
    account: &AccountRecord,
) -> (Option<String>, Option<String>, Option<String>) {
    let uid = account
        .adspower_user_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let mut sn = account
        .adspower_serial_number
        .as_deref()
        .map(|s| s.trim().trim_start_matches('#').trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if uid.is_none() && sn.is_none() {
        sn = account
            .environment_profile
            .as_deref()
            .map(|s| s.trim().trim_start_matches('#').trim())
            .filter(|s| !s.is_empty())
            .map(str::to_string);
    }
    let label = account
        .adspower_profile_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| sn.as_ref().map(|s| format!("#{s}")))
        .or_else(|| uid.clone());
    (uid, sn, label)
}

#[tauri::command]
async fn launch_account_browser(
    state: State<'_, Arc<AppState>>,
    account_id: String,
    url: Option<String>,
) -> Result<AccountLaunchOutcome, String> {
    let account = {
        let guard = state
            .accounts
            .lock()
            .map_err(|_| "账号库状态锁定失败".to_string())?;
        guard
            .iter()
            .find(|a| a.id == account_id.trim())
            .cloned()
            .ok_or_else(|| "未找到指定账号记录".to_string())?
    };

    let display_label = if account.label.trim().is_empty() {
        account.email.clone()
    } else {
        account.label.clone()
    };

    if account.browser_kind == AccountBrowserKind::Adspower {
        let (uid, sn, adspower_label) = resolve_account_adspower_target(&account);
        if uid.is_none() && sn.is_none() {
            return Err(
                "该账号已设为 AdsPower 模式，但尚未绑定 AdsPower 环境 user_id 或窗口序号，请先点击「编辑」选择或填写 AdsPower 环境".into(),
            );
        }

        // Preserve AdsPower's existing per-profile proxy & fingerprint intact; only run
        // pre-launch exit IP verification if the user also bound a local port/node here.
        let (node_source, node_name, proxy_url, local_port, verified_exit) =
            if account.linked_node_source != AccountNodeSource::None {
                let (res, exit) = resolve_and_verify_account_proxy(state.inner(), &account).await?;
                (
                    res.node_source,
                    res.node_name,
                    res.http_proxy_url,
                    res.local_port,
                    Some(exit),
                )
            } else {
                (
                    "adspower_internal".to_string(),
                    "AdsPower 环境内置代理".to_string(),
                    String::new(),
                    0u16,
                    None,
                )
            };

        let settings = adspower::load_settings()?;
        let start_res = adspower::start_browser(&settings, uid.as_deref(), sn.as_deref()).await?;
        let track_key = start_res
            .user_id
            .clone()
            .or_else(|| uid.clone())
            .or_else(|| sn.clone())
            .unwrap_or_else(|| account.id.clone());

        let (next_cfg, next_accounts, session) = {
            let mut inner = state.inner.lock().unwrap();
            let accounts_list = state
                .accounts
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();
            inner.running_adspower_ids.insert(track_key.clone());
            let prev_antigravity = inner
                .active_account_session
                .as_ref()
                .filter(|s| s.account_id == account.id)
                .is_some_and(|s| s.antigravity_launched);
            let sess = ActiveAccountSession {
                account_id: account.id.clone(),
                account_label: display_label.clone(),
                email: account.email.clone(),
                node_source: node_source.clone(),
                node_name: node_name.clone(),
                proxy_url,
                local_port,
                verified_exit_ip: verified_exit.clone(),
                antigravity_launched: prev_antigravity,
                browser_kind: "adspower".to_string(),
                browser_profile_id: None,
                adspower_user_id: Some(track_key.clone()),
                adspower_profile_label: adspower_label.clone(),
                activated_at: chrono::Local::now().format("%H:%M:%S").to_string(),
            };
            inner.active_account_session = Some(sess.clone());
            state.logs.push(format!(
                "[账号切换] 已通过 AdsPower Local API 拉起 [{display_label}] ({})",
                adspower_label.as_deref().unwrap_or(&track_key),
            ));
            (inner.config.clone(), accounts_list, sess)
        };

        let status = state.snapshot_status();
        let target_desc = adspower_label.unwrap_or(track_key);
        let message = if let Some(ref exit) = verified_exit {
            format!(
                "已核验出口 {} ({}) 并拉起 [{display_label}] AdsPower 环境「{target_desc}」（保持 AdsPower 原代理设置）",
                exit.ip,
                exit.country_code.as_deref().unwrap_or("--")
            )
        } else {
            format!("已直接拉起 [{display_label}] AdsPower 环境「{target_desc}」（使用 AdsPower 原代理设置）")
        };

        return Ok(AccountLaunchOutcome {
            message,
            config: next_cfg,
            accounts: next_accounts,
            status,
            session,
        });
    }

    let (resolved, verified_exit) = resolve_and_verify_account_proxy(state.inner(), &account).await?;

    let (msg, next_cfg, next_accounts, session) = {
        let mut inner = state.inner.lock().unwrap();
        let mut accounts_guard = state
            .accounts
            .lock()
            .map_err(|_| "账号库状态锁定失败".to_string())?;

        let (fallback_tz, fallback_loc) =
            infer_locale_for_country(verified_exit.country_code.as_deref());
        let resolved_tz = resolved
            .netguard_node
            .as_ref()
            .and_then(|n| n.timezone.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| {
                verified_exit
                    .timezone
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| fallback_tz.to_string());
        let resolved_loc = resolved
            .netguard_node
            .as_ref()
            .and_then(|n| n.locale.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| fallback_loc.to_string());

        let requested_profile_id = account
            .linked_browser_profile_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let existing_idx = requested_profile_id.as_ref().and_then(|pid| {
            inner
                .config
                .browser_profiles
                .iter()
                .position(|p| &p.id == pid)
        });

        let mut cfg_changed = false;
        let profile = if let Some(idx) = existing_idx {
            let mut prof = inner.config.browser_profiles[idx].clone();
            if prof.id.starts_with("bp-acc-") {
                let desired_node_id = resolved.netguard_node.as_ref().map(|n| n.id.clone());
                let desired_custom_proxy = if resolved.netguard_node.is_none() {
                    Some(resolved.browser_proxy_url.clone())
                } else {
                    None
                };
                if prof.node_id != desired_node_id
                    || prof.custom_proxy_url != desired_custom_proxy
                    || prof.fingerprint.timezone.as_deref() != Some(resolved_tz.as_str())
                    || prof.fingerprint.locale.as_deref() != Some(resolved_loc.as_str())
                {
                    prof.node_id = desired_node_id;
                    prof.custom_proxy_url = desired_custom_proxy;
                    prof.fingerprint.timezone = Some(resolved_tz.clone());
                    prof.fingerprint.locale = Some(resolved_loc.clone());
                    inner.config.browser_profiles[idx] = prof.clone();
                    cfg_changed = true;
                }
            }
            prof
        } else {
            let safe_suffix: String = account
                .id
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .take(48)
                .collect();
            let mut candidate_id = if safe_suffix.is_empty() {
                format!("bp-acc-{}", chrono::Utc::now().timestamp_millis())
            } else {
                format!("bp-acc-{safe_suffix}")
            };
            while inner
                .config
                .browser_profiles
                .iter()
                .any(|p| p.id == candidate_id)
            {
                candidate_id = format!("bp-acc-{:08x}", rand::random::<u32>());
            }

            let is_claude = account.provider.to_ascii_lowercase().contains("claude")
                || account.provider.to_ascii_lowercase().contains("anthropic");
            let fp_mode = if is_claude {
                BrowserFingerprintMode::CleanAlign
            } else {
                BrowserFingerprintMode::IsolatedFingerprint
            };
            let fp_cfg = if is_claude {
                BrowserFingerprintConfig {
                    timezone: Some(resolved_tz.clone()),
                    locale: Some(resolved_loc.clone()),
                    ..BrowserFingerprintConfig::default()
                }
            } else {
                random_isolated_fingerprint(resolved_tz.clone(), resolved_loc.clone())
            };

            let created = BrowserProfile {
                id: candidate_id.clone(),
                name: format!("{display_label} · 专属"),
                builtin: false,
                node_id: resolved.netguard_node.as_ref().map(|n| n.id.clone()),
                custom_proxy_url: if resolved.netguard_node.is_none() {
                    Some(resolved.browser_proxy_url.clone())
                } else {
                    None
                },
                homepage: default_homepage_for_provider(&account.provider),
                fingerprint_mode: fp_mode,
                fingerprint: fp_cfg,
                notes: Some(format!("由账号 [{}] 自动创建并绑定独立目录", account.email)),
            };
            inner.config.browser_profiles.push(created.clone());
            cfg_changed = true;

            if let Some(acc_mut) = accounts_guard.iter_mut().find(|a| a.id == account.id) {
                acc_mut.linked_browser_profile_id = Some(candidate_id);
                save_accounts(&accounts_guard)?;
            }
            created
        };

        if cfg_changed {
            save_config_to_disk(&inner.config)?;
        }

        if inner.config.wfp_lock_enabled && inner.guard.is_connected() {
            let targets = AppState::build_wfp_targets(&inner);
            inner
                .guard
                .call(GuardRequest::ApplyWfpLock { targets })?;
        }

        let eff_tz = profile
            .fingerprint
            .timezone
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| resolved_tz.clone());
        let eff_loc = profile
            .fingerprint
            .locale
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| resolved_loc.clone());
        let target_url = url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                let hp = profile.homepage.trim();
                if hp.is_empty() { "https://accounts.google.com/" } else { hp }
            })
            .to_string();

        let cfg_clone = inner.config.clone();
        let launch_msg = inner.launcher.launch_browser_profile(
            &cfg_clone,
            &profile,
            &resolved.browser_proxy_url,
            &resolved.node_name,
            &eff_tz,
            &eff_loc,
            &target_url,
            state.logs.clone(),
        )?;

        let prev_antigravity = inner
            .active_account_session
            .as_ref()
            .filter(|s| s.account_id == account.id)
            .is_some_and(|s| s.antigravity_launched);
        let sess = ActiveAccountSession {
            account_id: account.id.clone(),
            account_label: display_label.clone(),
            email: account.email.clone(),
            node_source: resolved.node_source.clone(),
            node_name: resolved.node_name.clone(),
            proxy_url: resolved.browser_proxy_url.clone(),
            local_port: resolved.local_port,
            verified_exit_ip: Some(verified_exit.clone()),
            antigravity_launched: prev_antigravity,
            browser_kind: "netguard".to_string(),
            browser_profile_id: Some(profile.id.clone()),
            adspower_user_id: None,
            adspower_profile_label: None,
            activated_at: chrono::Local::now().format("%H:%M:%S").to_string(),
        };
        inner.active_account_session = Some(sess.clone());
        (launch_msg, cfg_clone, accounts_guard.clone(), sess)
    };

    let status = state.snapshot_status();
    Ok(AccountLaunchOutcome {
        message: format!(
            "已核验出口 {} ({}) 并拉起 [{display_label}] 专属浏览器 -> {msg}",
            verified_exit.ip,
            verified_exit.country_code.as_deref().unwrap_or("--")
        ),
        config: next_cfg,
        accounts: next_accounts,
        status,
        session,
    })
}

#[tauri::command]
async fn clear_active_account_session(
    state: State<'_, Arc<AppState>>,
    close_browser: bool,
) -> Result<GatewayStatus, String> {
    let adspower_target = {
        let mut inner = state.inner.lock().unwrap();
        let mut stop_ads: Option<String> = None;
        let mut stop_ng_pid: Option<String> = None;
        if close_browser {
            if let Some(sess) = inner.active_account_session.as_ref() {
                if sess.browser_kind == "adspower" {
                    stop_ads = sess.adspower_user_id.clone();
                } else if let Some(pid) = sess.browser_profile_id.as_deref() {
                    stop_ng_pid = Some(pid.to_string());
                }
            }
        }
        if let Some(pid) = stop_ng_pid {
            inner.launcher.close_browser_profile(&pid);
        }
        inner.active_account_session = None;
        stop_ads
    };
    if let Some(target) = adspower_target {
        if let Ok(settings) = adspower::load_settings() {
            let is_digits = target.chars().all(|c| c.is_ascii_digit());
            let _ = if is_digits {
                adspower::stop_browser(&settings, None, Some(&target)).await
            } else {
                adspower::stop_browser(&settings, Some(&target), None).await
            };
        }
        let mut inner = state.inner.lock().unwrap();
        inner.running_adspower_ids.remove(&target);
    }
    Ok(state.snapshot_status())
}

#[tauri::command]
fn get_adspower_config() -> Result<AdsPowerConfigStatus, String> {
    let settings = adspower::load_settings()?;
    Ok(adspower::to_config_status(&settings))
}

#[tauri::command]
fn save_adspower_config(
    state: State<'_, Arc<AppState>>,
    base_url: String,
    api_key: Option<String>,
    clear_api_key: bool,
) -> Result<AdsPowerConfigStatus, String> {
    let current = adspower::load_settings()?;
    let next_key = if clear_api_key {
        String::new()
    } else if let Some(k) = api_key {
        let trimmed = k.trim();
        if trimmed.is_empty() {
            current.api_key
        } else {
            trimmed.to_string()
        }
    } else {
        current.api_key
    };
    let saved = adspower::save_settings(&AdsPowerSettingsDisk {
        base_url,
        api_key: next_key,
    })?;
    let status = adspower::to_config_status(&saved);
    state.logs.push(format!(
        "[AdsPower] 已更新 Local API 配置 ({}, {})",
        status.base_url,
        if status.has_api_key {
            "API Key 已通过 DPAPI 加密保存"
        } else {
            "未配置 API Key"
        }
    ));
    Ok(status)
}

#[tauri::command]
async fn test_adspower_connection() -> Result<String, String> {
    let settings = adspower::load_settings()?;
    adspower::test_connection(&settings).await
}

#[tauri::command]
async fn list_adspower_profiles() -> Result<AdsPowerProfilesSnapshot, String> {
    let settings = adspower::load_settings()?;
    let display_base = adspower::normalize_base_url(&settings.base_url)
        .unwrap_or_else(|_| adspower::DEFAULT_ADSPOWER_BASE_URL.to_string());
    match adspower::list_profiles(&settings).await {
        Ok(snap) => Ok(snap),
        Err(err) => Ok(AdsPowerProfilesSnapshot {
            connected: false,
            base_url: display_base,
            profiles: Vec::new(),
            error: Some(err),
        }),
    }
}

#[tauri::command]
async fn close_adspower_profile(
    state: State<'_, Arc<AppState>>,
    user_id: Option<String>,
    serial_number: Option<String>,
) -> Result<GatewayStatus, String> {
    let settings = adspower::load_settings()?;
    let clean_uid = user_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let clean_sn = serial_number
        .as_deref()
        .map(|s| s.trim().trim_start_matches('#').trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    adspower::stop_browser(&settings, clean_uid.as_deref(), clean_sn.as_deref()).await?;
    {
        let mut inner = state.inner.lock().unwrap();
        if let Some(ref uid) = clean_uid {
            inner.running_adspower_ids.remove(uid);
        }
        if let Some(ref sn) = clean_sn {
            inner.running_adspower_ids.remove(sn);
        }
    }
    Ok(state.snapshot_status())
}

#[tauri::command]
async fn toggle_kill_switch(
    state: State<'_, Arc<AppState>>,
    block: bool,
) -> Result<GatewayStatus, String> {
    let (running, api_secret) = {
        let mut inner = state.inner.lock().unwrap();
        (inner.singbox.is_running(), inner.singbox.api_secret())
    };
    if !running {
        return Err("网关未启动".into());
    }
    send_kill_switch_http(&api_secret, block).await?;
    {
        let mut inner = state.inner.lock().unwrap();
        inner.manual_kill_switch = block;
        inner.singbox.mark_kill_switch(
            block,
            block.then(|| "已手动触发紧急熔断：AI 出站已锁定为 block".into()),
        );
        state.logs.push(if block {
            "[紧急熔断] 用户手动阻断全部 AI 出站"
        } else {
            "[解除熔断] 用户手动恢复 AI 出站"
        });
    }
    Ok(state.snapshot_status())
}

#[tauri::command]
async fn toggle_persistent_claude_lock(
    state: State<'_, Arc<AppState>>,
    enable: bool,
) -> Result<GatewayStatus, String> {
    {
        let mut inner = state.inner.lock().unwrap();
        inner.guard.ensure_started()?;
        if enable {
            let allow_ports = inner.singbox.is_running();
            let desktop_targets = AppState::build_desktop_wfp_targets(&inner, allow_ports);
            inner
                .guard
                .call(GuardRequest::InstallPersistentLock {
                    targets: desktop_targets,
                })?;
            state.logs.push("已开启 Claude Desktop 离线硬锁：未启动 NetGuard 时完全断网");
        } else {
            inner.guard.call(GuardRequest::RemovePersistentLock)?;
            state.logs.push("已移除 Claude Desktop 离线硬锁：恢复系统默认联网");
        }
        inner.config.require_netguard_for_claude = enable;
        let _ = save_config_to_disk(&inner.config);
    }
    Ok(state.snapshot_status())
}

#[tauri::command]
fn launch_claude_desktop(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    let mut inner = state.inner.lock().unwrap();
    if !inner.singbox.is_running() {
        return Err("请先启动安全网关".into());
    }
    if inner.starting_gateway || inner.singbox.is_blocked() {
        return Err("安全网关仍在核验出口节点或处于阻断状态，请等待首页显示出口 IP 并解锁后再启动 Claude Desktop".into());
    }
    let cfg = inner.config.clone();
    inner.pac.ensure_started(cfg.browser_port)?;
    if cfg.wfp_lock_enabled {
        inner.guard.ensure_started()?;
        let targets = AppState::build_wfp_targets(&inner);
        inner
            .guard
            .call(GuardRequest::ApplyWfpLock { targets })?;
    }
    inner
        .launcher
        .launch_claude_desktop(&cfg, PAC_PORT, state.logs.clone())
}

#[tauri::command]
fn launch_claude_terminal(
    state: State<'_, Arc<AppState>>,
    work_dir: String,
    strict_wfp: bool,
) -> Result<String, String> {
    let mut inner = state.inner.lock().unwrap();
    if !inner.singbox.is_running() {
        return Err("请先启动安全网关".into());
    }
    if inner.starting_gateway || inner.singbox.is_blocked() {
        return Err("安全网关正在核验出口或处于阻断状态，请等待解锁后再启动安全终端".into());
    }
    if strict_wfp {
        let (shim, _) = inner.launcher.ensure_strict_cli_shim()?;
        let shim_str = shim.to_string_lossy().to_string();
        let cli_ports = vec![inner.config.cli_port];
        if let Some(existing) = inner
            .extra_wfp_targets
            .iter_mut()
            .find(|t| t.exe_path == shim_str)
        {
            existing.allowed_loopback_ports = cli_ports;
        } else {
            inner.extra_wfp_targets.push(ProtectedTarget {
                exe_path: shim_str,
                allow_private_lan: true,
                allowed_loopback_ports: cli_ports,
            });
        }
        inner.guard.ensure_started()?;
        let targets = AppState::build_wfp_targets(&inner);
        inner
            .guard
            .call(GuardRequest::ApplyWfpLock { targets })?;
    }
    let cfg = inner.config.clone();
    inner
        .launcher
        .launch_claude_terminal(&cfg, &work_dir, strict_wfp, state.logs.clone())
}

#[tauri::command]
fn clear_logs(state: State<'_, Arc<AppState>>) {
    state.logs.clear();
}

#[tauri::command]
fn inspect_apps_env(state: State<'_, Arc<AppState>>) -> Result<AppEnvSnapshot, String> {
    let mut inner = state.inner.lock().unwrap();
    let gateway_running = inner.singbox.is_running() && !inner.singbox.is_blocked();
    Ok(app_env::inspect_all_apps_env(
        &inner.config,
        &inner.launcher,
        gateway_running,
    ))
}

#[tauri::command]
fn launch_managed_app(
    state: State<'_, Arc<AppState>>,
    app_id: String,
    relaunch: bool,
) -> Result<String, String> {
    let mut inner = state.inner.lock().unwrap();
    let app = inner
        .config
        .managed_apps
        .iter()
        .find(|a| a.id == app_id)
        .cloned()
        .ok_or_else(|| format!("未找到受控应用配置: {app_id}"))?;
    let gateway_running = inner.singbox.is_running() && !inner.singbox.is_blocked();
    if app.wfp_lock
        && matches!(app.proxy_mode, AppProxyMode::Netguard)
        && inner.config.wfp_lock_enabled
        && inner.guard.is_connected()
    {
        let targets = AppState::build_wfp_targets(&inner);
        inner.guard.call(GuardRequest::ApplyWfpLock { targets })?;
    }
    let cfg = inner.config.clone();
    let _ = inner.pac.ensure_started(cfg.browser_port);
    let pac_port = PAC_PORT;
    app_env::launch_managed_app_with_clean_env(
        &app,
        &cfg,
        &mut inner.launcher,
        pac_port,
        gateway_running,
        relaunch,
        state.logs.clone(),
    )
}

#[tauri::command]
fn clean_registry_proxy_env(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    let cfg = state.inner.lock().unwrap().config.clone();
    let msg = healthcheck::apply_fix_action("fix_claude_env", &cfg)?;
    state.logs.push(format!("[应用环境] {msg}"));
    Ok(msg)
}

#[tauri::command]
fn create_managed_app_shortcut(
    state: State<'_, Arc<AppState>>,
    app_id: String,
) -> Result<String, String> {
    let inner = state.inner.lock().unwrap();
    let app = inner
        .config
        .managed_apps
        .iter()
        .find(|a| a.id == app_id)
        .cloned()
        .ok_or_else(|| format!("未找到受控应用配置: {app_id}"))?;
    let msg = app_env::create_desktop_shortcut_for_app(&app, &inner.config, &inner.launcher)?;
    state.logs.push(format!("[应用环境] {msg}"));
    Ok(msg)
}

#[tauri::command]
fn list_accounts(state: State<'_, Arc<AppState>>) -> Result<Vec<AccountRecord>, String> {
    let list = state
        .accounts
        .lock()
        .map_err(|_| "账号库状态锁定失败".to_string())?;
    Ok(list.clone())
}

#[tauri::command]
fn upsert_account(
    state: State<'_, Arc<AppState>>,
    account: AccountRecord,
) -> Result<Vec<AccountRecord>, String> {
    let mut guard = state
        .accounts
        .lock()
        .map_err(|_| "账号库状态锁定失败".to_string())?;
    let existing_idx = (!account.id.trim().is_empty())
        .then(|| guard.iter().position(|a| a.id == account.id.trim()))
        .flatten();
    let existing = existing_idx.and_then(|idx| guard.get(idx));
    let normalized = normalize_account(account, existing)?;
    let summary_email = normalized.email.clone();

    let mut next = guard.clone();
    if let Some(idx) = existing_idx {
        next[idx] = normalized;
    } else {
        next.insert(0, normalized);
    }
    save_accounts(&next)?;
    *guard = next.clone();
    state.logs.push(format!("[账号库] 已保存账号记录: {summary_email}"));
    Ok(next)
}

#[tauri::command]
fn delete_account(state: State<'_, Arc<AppState>>, id: String) -> Result<Vec<AccountRecord>, String> {
    let mut guard = state
        .accounts
        .lock()
        .map_err(|_| "账号库状态锁定失败".to_string())?;
    let target_id = id.trim();
    let mut next = guard.clone();
    let before = next.len();
    next.retain(|a| a.id != target_id);
    let removed = before.saturating_sub(next.len());
    if removed > 0 {
        save_accounts(&next)?;
        *guard = next.clone();
        state.logs.push(format!("[账号库] 已删除 {removed} 条账号记录"));
    }
    Ok(next)
}

#[tauri::command]
fn delete_accounts(
    state: State<'_, Arc<AppState>>,
    ids: Vec<String>,
) -> Result<Vec<AccountRecord>, String> {
    let id_set: std::collections::HashSet<String> = ids
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mut guard = state
        .accounts
        .lock()
        .map_err(|_| "账号库状态锁定失败".to_string())?;
    if id_set.is_empty() {
        return Ok(guard.clone());
    }
    let mut next = guard.clone();
    let before = next.len();
    next.retain(|a| !id_set.contains(&a.id));
    let removed = before.saturating_sub(next.len());
    if removed > 0 {
        save_accounts(&next)?;
        *guard = next.clone();
        state.logs.push(format!("[账号库] 已批量删除 {removed} 条账号记录"));
    }
    Ok(next)
}

#[tauri::command]
fn import_accounts(
    state: State<'_, Arc<AppState>>,
    accounts: Vec<AccountRecord>,
    replace: bool,
) -> Result<Vec<AccountRecord>, String> {
    let mut guard = state
        .accounts
        .lock()
        .map_err(|_| "账号库状态锁定失败".to_string())?;
    let imported_count = accounts.len();
    let mut next: Vec<AccountRecord> = if replace {
        Vec::new()
    } else {
        guard.clone()
    };

    for item in accounts {
        let trimmed_id = item.id.trim().to_string();
        let trimmed_email = item.email.trim().to_lowercase();
        let trimmed_provider = {
            let p = item.provider.trim();
            if p.is_empty() { "google".to_string() } else { p.to_lowercase() }
        };

        let match_idx = next.iter().position(|existing| {
            (!trimmed_id.is_empty() && existing.id == trimmed_id)
                || (existing.email.trim().to_lowercase() == trimmed_email
                    && existing.provider.trim().to_lowercase() == trimmed_provider)
        });

        let existing = match_idx.and_then(|idx| next.get(idx));
        let mut normalized = normalize_account(item, existing)?;
        if let Some(prev) = existing {
            if !prev.id.trim().is_empty() {
                normalized.id = prev.id.clone();
            }
        }
        if let Some(idx) = match_idx {
            next[idx] = normalized;
        } else {
            next.push(normalized);
        }
    }

    save_accounts(&next)?;
    *guard = next.clone();
    state.logs.push(format!(
        "[账号库] 已{}导入 {imported_count} 条账号记录（当前共 {} 条）",
        if replace { "覆盖" } else { "合并" },
        next.len()
    ));
    Ok(next)
}

#[tauri::command]
fn list_account_environments(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<AccountEnvPreset>, String> {
    let list = state
        .account_envs
        .lock()
        .map_err(|_| "环境列表锁定失败".to_string())?;
    Ok(list.clone())
}

#[tauri::command]
fn save_account_environments(
    state: State<'_, Arc<AppState>>,
    presets: Vec<AccountEnvPreset>,
) -> Result<Vec<AccountEnvPreset>, String> {
    let mut guard = state
        .account_envs
        .lock()
        .map_err(|_| "环境列表锁定失败".to_string())?;
    let normalized = normalize_env_presets(presets);
    save_env_presets(&normalized)?;
    *guard = normalized.clone();
    Ok(normalized)
}

#[tauri::command]
fn list_clash_verge_nodes() -> ClashVergeNodesSnapshot {
    discover_clash_verge_nodes()
}

#[tauri::command]
fn reorder_accounts(
    state: State<'_, Arc<AppState>>,
    ordered_ids: Vec<String>,
) -> Result<Vec<AccountRecord>, String> {
    let mut guard = state
        .accounts
        .lock()
        .map_err(|_| "账号库状态锁定失败".to_string())?;
    let next = reorder_account_list(&guard, &ordered_ids);
    save_accounts(&next)?;
    *guard = next.clone();
    Ok(next)
}

fn check_node_expectation(node: &NodeProfile, exit: &ExitIpInfo) -> Option<String> {
    if let Some(exp_ip) = node.expected_ip.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if exp_ip != exit.ip {
            return Some(format!("出口 IP 漂移: 预期 {exp_ip}, 实测 {}", exit.ip));
        }
    }
    if let Some(exp_cc) = node
        .expected_country
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        match exit
            .country_code
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(actual_cc) if !actual_cc.eq_ignore_ascii_case(exp_cc) => {
                return Some(format!(
                    "出口地区异常: 预期 {exp_cc}, 实测 {actual_cc}"
                ));
            }
            None => {
                return Some(format!(
                    "出口地区无法核验（探针未返回国家字段，预期 {exp_cc}）"
                ));
            }
            _ => {}
        }
    }
    None
}

fn spawn_monitor_loop(app: AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let mut fail_streak = 0u8;
        let mut probe_tick = 0u64;
        let mut last_full_geo_at: Option<Instant> = None;
        loop {
            tokio::time::sleep(Duration::from_secs(4)).await;
            let live_nic = detect_physical_nic();
            let (
                running,
                starting,
                probe_port,
                api_secret,
                cfg,
                manual_locked,
                wfp_guard_lost,
                was_blocked_now,
                has_cached_geo,
            ) = {
                let mut inner = state.inner.lock().unwrap();
                if inner.starting_gateway {
                    (
                        false,
                        true,
                        0,
                        String::new(),
                        inner.config.clone(),
                        false,
                        false,
                        false,
                        false,
                    )
                } else {
                    let mut is_running = inner.singbox.is_running();
                    let need_bypass = !collect_physical_bypass_target_ips(&inner.config).is_empty();
                    if is_running && need_bypass {
                        if let Some(ref cur_nic) = live_nic {
                            let nic_changed =
                                inner.active_nic_name.as_deref() != Some(cur_nic.name.as_str());
                            let gw_changed = inner.active_gateway_ip.as_deref()
                                != Some(cur_nic.gateway_ip.as_str());
                            if nic_changed || gw_changed {
                                let cfg_clone = inner.config.clone();
                                if inner.guard.is_connected() {
                                    let bypass_ips = collect_physical_bypass_target_ips(&cfg_clone);
                                    if !bypass_ips.is_empty() {
                                        let _ = inner.guard.call(GuardRequest::SetBypassRoutes {
                                            target_ips: bypass_ips,
                                            gateway_ip: cur_nic.gateway_ip.clone(),
                                            interface_index: cur_nic.if_index,
                                        });
                                    }
                                }
                                if nic_changed {
                                    state.logs.push(format!(
                                        "[自适应] 检测到物理网卡切换 ({} -> {})，自动重启 sing-box 绑定新网卡",
                                        inner.active_nic_name.as_deref().unwrap_or("无"),
                                        cur_nic.name
                                    ));
                                    if inner
                                        .singbox
                                        .start(&cfg_clone, Some(cur_nic.name.as_str()), state.logs.clone())
                                        .is_ok()
                                    {
                                        inner.singbox.mark_kill_switch(
                                            true,
                                            Some("网卡切换重新核验出口中".into()),
                                        );
                                        inner.active_secondary_ports =
                                            SingBoxManager::secondary_node_port_map(&cfg_clone);
                                        inner.verified_geo_cache.clear();
                                        fail_streak = 0;
                                        last_full_geo_at = None;
                                    } else {
                                        inner.singbox.stop();
                                        inner.active_secondary_ports.clear();
                                        is_running = false;
                                    }
                                }
                                inner.active_nic_name = Some(cur_nic.name.clone());
                                inner.active_gateway_ip = Some(cur_nic.gateway_ip.clone());
                            }
                        }
                    }

                    let mut guard_lost = false;
                    if inner.guard.is_connected() {
                        match inner.guard.call(GuardRequest::WfpStatus) {
                            Ok(st) => {
                                let expected_targets = AppState::build_wfp_targets(&inner);
                                if is_running
                                    && inner.config.wfp_lock_enabled
                                    && !expected_targets.is_empty()
                                    && !st.wfp_active
                                {
                                    guard_lost = true;
                                }
                            }
                            Err(_) => {
                                if is_running && inner.config.wfp_lock_enabled {
                                    guard_lost = true;
                                }
                            }
                        }
                    }
                    if guard_lost && matches!(inner.config.kill_switch, KillSwitchMode::FailClosed) {
                        inner.singbox.stop();
                        inner.last_exit_ip = None;
                        inner.verified_geo_cache.clear();
                        inner.active_secondary_ports.clear();
                    }
                    let cached_geo_ok = inner
                        .last_exit_ip
                        .as_ref()
                        .is_some_and(|last| {
                            has_country_code(last)
                                && inner
                                    .verified_geo_cache
                                    .get(&last.ip)
                                    .is_some_and(has_country_code)
                        });
                    (
                        is_running && !guard_lost,
                        false,
                        SingBoxManager::probe_port(&inner.config),
                        inner.singbox.api_secret(),
                        inner.config.clone(),
                        inner.manual_kill_switch,
                        guard_lost,
                        inner.singbox.is_blocked(),
                        cached_geo_ok,
                    )
                }
            };

            if starting {
                continue;
            }

            if wfp_guard_lost {
                state.logs.push("[安全告警] 检测到 Guard 守护进程退出或 WFP 规则失效，已触发 Fail-Closed 停机保护");
                let _ = app.emit("gateway-status-updated", state.snapshot_status());
                fail_streak = 0;
                probe_tick = 0;
                last_full_geo_at = None;
                continue;
            }

            if !running {
                fail_streak = 0;
                probe_tick = 0;
                last_full_geo_at = None;
                let _ = app.emit("gateway-status-updated", state.snapshot_status());
                continue;
            }

            probe_tick = probe_tick.saturating_add(1);
            let should_probe_net = was_blocked_now || probe_tick % 3 == 0;
            if !should_probe_net {
                let _ = app.emit("gateway-status-updated", state.snapshot_status());
                continue;
            }

            let need_full_geo = was_blocked_now
                || !has_cached_geo
                || last_full_geo_at.is_none_or(|t| t.elapsed() >= Duration::from_secs(300));

            let probe_res: Result<(ExitIpInfo, bool), String> = if need_full_geo {
                probe_exit_ip(probe_port).await.map(|info| (info, true))
            } else {
                match probe_exit_ip_fast(probe_port).await {
                    Ok((fast_ip, latency_ms)) => {
                        let cached = {
                            let inner = state.inner.lock().unwrap();
                            inner.verified_geo_cache.get(&fast_ip).cloned()
                        };
                        if let Some(c) = cached.filter(has_country_code) {
                            Ok((
                                ExitIpInfo {
                                    ip: fast_ip,
                                    country: c.country,
                                    country_code: c.country_code,
                                    region: c.region,
                                    city: c.city,
                                    latitude: c.latitude,
                                    longitude: c.longitude,
                                    timezone: c.timezone,
                                    isp: c.isp,
                                    org: c.org,
                                    asn: c.asn,
                                    latency_ms: Some(latency_ms),
                                    verified_at: chrono::Local::now().format("%H:%M:%S").to_string(),
                                },
                                false,
                            ))
                        } else {
                            // IP changed or uncached -> run immediate full GeoIP verification
                            probe_exit_ip(probe_port).await.map(|info| (info, true))
                        }
                    }
                    Err(e) => Err(e),
                }
            };

            let active_node = cfg.nodes.iter().find(|n| n.id == cfg.active_node_id);
            match probe_res {
                Ok((raw_exit, was_full_geo)) => {
                    fail_streak = 0;
                    let (exit, was_blocked) = {
                        let mut inner = state.inner.lock().unwrap();
                        let resolved_exit = if has_country_code(&raw_exit) {
                            if was_full_geo {
                                last_full_geo_at = Some(Instant::now());
                            }
                            inner
                                .verified_geo_cache
                                .insert(raw_exit.ip.clone(), raw_exit.clone());
                            raw_exit
                        } else {
                            let cached = inner.verified_geo_cache.get(&raw_exit.ip).cloned();
                            merge_cached_geo_for_same_ip(raw_exit, cached.as_ref())
                        };
                        inner.last_exit_ip = Some(resolved_exit.clone());
                        (resolved_exit, inner.singbox.is_blocked())
                    };
                    let mismatch = active_node.and_then(|n| check_node_expectation(n, &exit));
                    if let Some(reason) = mismatch {
                        if matches!(cfg.kill_switch, KillSwitchMode::FailClosed) && !was_blocked {
                            state.logs.push(format!("[实时熔断] {reason}"));
                            let switched = send_kill_switch_http(&api_secret, true).await.is_ok();
                            let mut inner = state.inner.lock().unwrap();
                            if switched {
                                inner.singbox.mark_kill_switch(true, Some(reason));
                            } else {
                                inner.singbox.stop();
                            }
                        }
                    } else if was_blocked
                        && !manual_locked
                        && send_kill_switch_http(&api_secret, false).await.is_ok()
                    {
                        state.logs.push("[恢复] 出口探针恢复正常，自动解除阻断");
                        let mut inner = state.inner.lock().unwrap();
                        inner.singbox.mark_kill_switch(false, None);
                    }
                }
                Err(e) => {
                    fail_streak = fail_streak.saturating_add(1);
                    let was_blocked = state.inner.lock().unwrap().singbox.is_blocked();
                    // Require 2 consecutive probe failures before killing active Claude streams
                    // on transient WiFi roaming blips, while IP/country mismatch remains 0-tolerance.
                    if fail_streak >= 2
                        && matches!(cfg.kill_switch, KillSwitchMode::FailClosed)
                        && !was_blocked
                    {
                        state.logs.push(format!("[实时熔断] 出口探针连续两次失败，已切为 block: {e}"));
                        let switched = send_kill_switch_http(&api_secret, true).await.is_ok();
                        let mut inner = state.inner.lock().unwrap();
                        if switched {
                            inner
                                .singbox
                                .mark_kill_switch(true, Some("出口检测连续失败，已实时熔断".into()));
                        } else {
                            inner.singbox.stop();
                        }
                    }
                }
            }

            let _ = app.emit("gateway-status-updated", state.snapshot_status());
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Headless fast-path for desktop shortcuts: `ai-netguard.exe --launch-app <app_id>`
    if let Some(exit_code) = app_env::try_handle_cli_launch() {
        std::process::exit(exit_code);
    }

    let _single_instance = unsafe {
        use windows::core::w;
        use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
        use windows::Win32::System::Threading::CreateMutexW;
        use windows::Win32::UI::WindowsAndMessaging::{
            FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE,
        };
        let mutex = CreateMutexW(None, false, w!("Local\\AI-NetGuard-SingleInstance"));
        if GetLastError() == ERROR_ALREADY_EXISTS {
            if let Ok(hwnd) = FindWindowW(
                None,
                w!("AI NetGuard — 本地零泄漏 AI 安全网关"),
            ) {
                let _ = ShowWindow(hwnd, SW_RESTORE);
                let _ = SetForegroundWindow(hwnd);
            }
            return;
        }
        mutex
    };

    let state = Arc::new(AppState::new());
    let state_for_setup = state.clone();

    tauri::Builder::default()
        .manage(state.clone())
        .setup(move |app| {
            let show_item = MenuItem::with_id(app, "show", "打开控制台", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "退出并清理护盾", true, None::<&str>)?;
            let menu = MenuBuilder::new(app)
                .item(&show_item)
                .separator()
                .item(&quit_item)
                .build()?;

            let tray_state = state_for_setup.clone();
            let _tray = TrayIconBuilder::with_id("main-tray")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("AI NetGuard — 本地零泄漏 AI 安全网关")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "quit" => {
                        {
                            let mut inner = tray_state.inner.lock().unwrap();
                            inner.guard.try_shutdown();
                            inner.singbox.stop();
                        }
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                })
                .build(app)?;

            spawn_monitor_loop(app.handle().clone(), state_for_setup);
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_config,
            save_config,
            parse_node_uri,
            generate_vps_script,
            get_status,
            connect_guard,
            start_gateway,
            stop_gateway,
            run_diagnostics,
            fix_diagnostic,
            install_browser,
            launch_browser,
            launch_browser_url,
            launch_browser_profile,
            close_browser_profile,
            probe_node_exit,
            launch_account_antigravity,
            launch_account_browser,
            clear_active_account_session,
            toggle_kill_switch,
            toggle_persistent_claude_lock,
            launch_claude_desktop,
            launch_claude_terminal,
            inspect_apps_env,
            launch_managed_app,
            clean_registry_proxy_env,
            create_managed_app_shortcut,
            list_accounts,
            upsert_account,
            delete_account,
            delete_accounts,
            import_accounts,
            list_account_environments,
            save_account_environments,
            list_clash_verge_nodes,
            reorder_accounts,
            get_adspower_config,
            save_adspower_config,
            test_adspower_connection,
            list_adspower_profiles,
            close_adspower_profile,
            clear_logs,
        ])
        .run(tauri::generate_context!())
        .expect("error while running AI NetGuard");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_exit(country_code: Option<&str>) -> ExitIpInfo {
        ExitIpInfo {
            ip: "1.2.3.4".into(),
            country: country_code.map(|s| s.to_string()),
            country_code: country_code.map(|s| s.to_string()),
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            timezone: None,
            isp: None,
            org: None,
            asn: None,
            latency_ms: Some(15),
            verified_at: "12:00:00".into(),
        }
    }

    #[test]
    fn check_node_expectation_rejects_missing_country_when_expected() {
        let mut node = AppConfig::default().nodes[0].clone();
        node.expected_ip = None;
        node.expected_country = Some("KR".into());

        assert!(check_node_expectation(&node, &sample_exit(Some("KR"))).is_none());
        assert!(check_node_expectation(&node, &sample_exit(Some("US"))).is_some());
        assert!(check_node_expectation(&node, &sample_exit(None)).is_some());

        node.expected_country = None;
        assert!(check_node_expectation(&node, &sample_exit(None)).is_none());
    }

    #[test]
    fn cached_geo_reuses_same_verified_ip_and_rejects_drifted_ip() {
        let mut node = AppConfig::default().nodes[0].clone();
        node.expected_ip = None;
        node.expected_country = Some("KR".into());

        let verified = sample_exit(Some("KR"));
        let mut same_ip_ipify = sample_exit(None);
        same_ip_ipify.ip = verified.ip.clone();
        let merged_same = merge_cached_geo_for_same_ip(same_ip_ipify, Some(&verified));
        assert_eq!(merged_same.country_code.as_deref(), Some("KR"));
        assert!(check_node_expectation(&node, &merged_same).is_none());

        let mut drifted_ip_ipify = sample_exit(None);
        drifted_ip_ipify.ip = "9.9.9.9".into();
        let merged_drift = merge_cached_geo_for_same_ip(drifted_ip_ipify, Some(&verified));
        assert!(merged_drift.country_code.is_none());
        assert!(check_node_expectation(&node, &merged_drift).is_some());
    }

    #[test]
    fn build_wfp_targets_grants_secondary_ports_to_chrome_not_claude() {
        let mut cfg = AppConfig::default();
        cfg.nodes[0].server = "61.111.253.124".into();
        cfg.nodes.push(NodeProfile {
            id: "jp-home".into(),
            name: "日本家宽".into(),
            protocol: crate::models::ProxyProtocol::Socks,
            server: "212.68.187.81".into(),
            port: 50101,
            uuid: None,
            flow: None,
            security: None,
            sni: None,
            fingerprint: None,
            public_key: None,
            short_id: None,
            method: None,
            password: None,
            username: None,
            obfs: None,
            obfs_password: None,
            allow_insecure: None,
            certificate_sha256: None,
            expected_ip: Some("212.68.187.81".into()),
            expected_country: Some("JP".into()),
            timezone: Some("Asia/Tokyo".into()),
            locale: Some("ja-JP".into()),
            outbound_mode: None,
        });

        cfg.browser_profiles.push(BrowserProfile {
            id: "clash-ext-browser".into(),
            name: "Clash 测试环境".into(),
            builtin: false,
            node_id: None,
            custom_proxy_url: Some("socks5://127.0.0.1:10809".into()),
            homepage: "https://claude.ai".into(),
            fingerprint_mode: BrowserFingerprintMode::CleanAlign,
            fingerprint: BrowserFingerprintConfig::default(),
            notes: None,
        });

        let inner = InnerState {
            config: cfg.clone(),
            singbox: SingBoxManager::new(),
            pac: PacServer::new(cfg.browser_port),
            guard: GuardClient::new(),
            launcher: ProcessLauncher::new(),
            last_exit_ip: None,
            verified_geo_cache: HashMap::new(),
            active_secondary_ports: [("jp-home".to_string(), 17901)].into_iter().collect(),
            active_account_session: None,
            running_adspower_ids: HashSet::new(),
            extra_wfp_targets: Vec::new(),
            manual_kill_switch: false,
            starting_gateway: false,
            active_nic_name: None,
            active_gateway_ip: None,
        };

        let browser_ports = AppState::allowed_browser_ports(&inner);
        assert!(browser_ports.contains(&17901));
        assert!(browser_ports.contains(&10809));
        assert!(browser_ports.contains(&cfg.browser_port));

        let desktop_targets = AppState::build_desktop_wfp_targets(&inner, true);
        for dt in desktop_targets {
            assert!(
                !dt.allowed_loopback_ports.contains(&17901),
                "claude.exe must never receive secondary browser port 17901"
            );
            assert!(
                !dt.allowed_loopback_ports.contains(&10809),
                "claude.exe must never receive Clash browser port 10809"
            );
            assert!(dt.allowed_loopback_ports.contains(&cfg.browser_port));
        }
    }

    #[test]
    fn resolve_account_proxy_rejects_unbound_and_matches_clash_listener() {
        let mut cfg = AppConfig::default();
        cfg.active_node_id = "seoul-vps".into();
        let sec_ports: BTreeMap<String, u16> = [("node-jp".into(), 17901)].into_iter().collect();
        let clash = ClashVergeNodesSnapshot {
            detected: true,
            source_path: None,
            mixed_port: Some(7897),
            listeners: vec![accounts::ClashVergeListenerItem {
                name: "adspower-japan".into(),
                listener_type: "mixed".into(),
                port: 10809,
                proxy: "🇯🇵 日本Z10 | IEPL".into(),
            }],
            groups: Vec::new(),
            proxies: Vec::new(),
        };

        let mut acc = AccountRecord {
            id: "a1".into(),
            label: "主力".into(),
            provider: "Google".into(),
            email: "main@gmail.com".into(),
            password: "pw".into(),
            totp_secret: None,
            recovery_codes: None,
            recovery_email: None,
            env_type: accounts::AccountEnvType::Custom,
            environment_name: String::new(),
            environment_profile: None,
            browser_kind: AccountBrowserKind::Netguard,
            adspower_user_id: None,
            adspower_serial_number: None,
            adspower_profile_name: None,
            linked_node_source: AccountNodeSource::None,
            linked_node_id: None,
            linked_node_name: None,
            linked_browser_profile_id: None,
            linked_proxy_port: None,
            purpose: String::new(),
            tags: Vec::new(),
            status: accounts::AccountStatus::Active,
            notes: None,
            created_at: String::new(),
            updated_at: String::new(),
        };

        // 1. Unbound account MUST fail closed
        assert!(resolve_account_proxy_target(&acc, &cfg, true, false, false, &sec_ports, &clash).is_err());

        // 2. Clash Verge node auto-matches listener port 10809
        acc.linked_node_source = AccountNodeSource::ClashVerge;
        acc.linked_node_name = Some("🇯🇵 日本Z10 | IEPL".into());
        let clash_res =
            resolve_account_proxy_target(&acc, &cfg, false, false, false, &sec_ports, &clash).unwrap();
        assert_eq!(clash_res.local_port, 10809);
        assert_eq!(clash_res.http_proxy_url, "http://127.0.0.1:10809");
        assert_eq!(clash_res.probe_proxy_url, "socks5h://127.0.0.1:10809");

        // 3. Explicit NetGuard blocked primary fails closed even when gateway running
        acc.linked_node_source = AccountNodeSource::Netguard;
        acc.linked_node_id = Some("seoul-vps".into());
        assert!(resolve_account_proxy_target(&acc, &cfg, true, false, true, &sec_ports, &clash).is_err());
    }
}
