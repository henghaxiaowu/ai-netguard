use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocol {
    Vless,
    Shadowsocks,
    Trojan,
    Hysteria2,
    Socks,
    Http,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutboundMode {
    PhysicalBypass,
    UpstreamDetour,
    DefaultRoute,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchMode {
    FailClosed,
    MonitorOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppProxyMode {
    Netguard,
    SystemProxy,
    Direct,
    CustomProxy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedAppConfig {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub builtin: bool,
    #[serde(default)]
    pub exe_path: Option<String>,
    #[serde(default)]
    pub process_names: Vec<String>,
    pub proxy_mode: AppProxyMode,
    #[serde(default)]
    pub custom_proxy_url: Option<String>,
    #[serde(default)]
    pub wfp_lock: bool,
    #[serde(default)]
    pub extra_args: Vec<String>,
}

pub fn default_managed_apps() -> Vec<ManagedAppConfig> {
    vec![
        ManagedAppConfig {
            id: "claude-desktop".into(),
            name: "Claude Desktop".into(),
            builtin: true,
            exe_path: None,
            process_names: vec!["claude.exe".into()],
            proxy_mode: AppProxyMode::Netguard,
            custom_proxy_url: None,
            wfp_lock: true,
            extra_args: Vec::new(),
        },
        ManagedAppConfig {
            id: "antigravity".into(),
            name: "Antigravity".into(),
            builtin: true,
            exe_path: None,
            process_names: vec![
                "Antigravity.exe".into(),
                "language_server_windows_x64.exe".into(),
            ],
            proxy_mode: AppProxyMode::SystemProxy,
            custom_proxy_url: None,
            wfp_lock: false,
            extra_args: Vec::new(),
        },
        ManagedAppConfig {
            id: "chatgpt".into(),
            name: "ChatGPT / Codex".into(),
            builtin: true,
            exe_path: None,
            process_names: vec!["ChatGPT.exe".into()],
            proxy_mode: AppProxyMode::SystemProxy,
            custom_proxy_url: None,
            wfp_lock: false,
            extra_args: Vec::new(),
        },
        ManagedAppConfig {
            id: "cockpit-tools".into(),
            name: "Cockpit Tools".into(),
            builtin: true,
            exe_path: None,
            process_names: vec!["cockpit-tools.exe".into()],
            proxy_mode: AppProxyMode::SystemProxy,
            custom_proxy_url: None,
            wfp_lock: false,
            extra_args: Vec::new(),
        },
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeProfile {
    pub id: String,
    pub name: String,
    pub protocol: ProxyProtocol,
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub security: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub short_id: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(default)]
    pub obfs_password: Option<String>,
    #[serde(default)]
    pub allow_insecure: Option<bool>,
    #[serde(default)]
    pub certificate_sha256: Option<String>,
    #[serde(default)]
    pub expected_ip: Option<String>,
    #[serde(default)]
    pub expected_country: Option<String>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub locale: Option<String>,
    #[serde(default)]
    pub outbound_mode: Option<OutboundMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFingerprintMode {
    #[default]
    CleanAlign,
    IsolatedFingerprint,
}

fn default_screen_width() -> u32 {
    1920
}
fn default_screen_height() -> u32 {
    1080
}
fn default_dpr() -> f64 {
    1.0
}
fn default_hw_concurrency() -> u32 {
    8
}
fn default_device_mem() -> u32 {
    8
}
fn default_webgl_vendor() -> String {
    "Google Inc. (NVIDIA)".into()
}
fn default_webgl_renderer() -> String {
    "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)".into()
}
fn default_noise_seed() -> String {
    "ng-default-seed".into()
}
pub fn default_browser_homepage() -> String {
    "https://claude.ai".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFingerprintConfig {
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub locale: Option<String>,
    #[serde(default = "default_screen_width")]
    pub screen_width: u32,
    #[serde(default = "default_screen_height")]
    pub screen_height: u32,
    #[serde(default = "default_dpr")]
    pub device_pixel_ratio: f64,
    #[serde(default = "default_hw_concurrency")]
    pub hardware_concurrency: u32,
    #[serde(default = "default_device_mem")]
    pub device_memory: u32,
    #[serde(default = "default_webgl_vendor")]
    pub webgl_vendor: String,
    #[serde(default = "default_webgl_renderer")]
    pub webgl_renderer: String,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default = "default_noise_seed")]
    pub noise_seed: String,
}

impl Default for BrowserFingerprintConfig {
    fn default() -> Self {
        Self {
            timezone: None,
            locale: None,
            screen_width: default_screen_width(),
            screen_height: default_screen_height(),
            device_pixel_ratio: default_dpr(),
            hardware_concurrency: default_hw_concurrency(),
            device_memory: default_device_mem(),
            webgl_vendor: default_webgl_vendor(),
            webgl_renderer: default_webgl_renderer(),
            user_agent: None,
            noise_seed: default_noise_seed(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserProfile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub builtin: bool,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub custom_proxy_url: Option<String>,
    #[serde(default = "default_browser_homepage")]
    pub homepage: String,
    #[serde(default)]
    pub fingerprint_mode: BrowserFingerprintMode,
    #[serde(default)]
    pub fingerprint: BrowserFingerprintConfig,
    #[serde(default)]
    pub notes: Option<String>,
}

pub fn default_browser_profiles() -> Vec<BrowserProfile> {
    vec![BrowserProfile {
        id: "default".into(),
        name: "默认安全浏览器 (主出口)".into(),
        builtin: true,
        node_id: None,
        custom_proxy_url: None,
        homepage: default_browser_homepage(),
        fingerprint_mode: BrowserFingerprintMode::CleanAlign,
        fingerprint: BrowserFingerprintConfig::default(),
        notes: Some("默认跟随活跃主出口节点，使用纯净时区与语言对齐（对 Claude / hCaptcha 最安全）".into()),
    }]
}

fn default_browser_kind_str() -> String {
    "netguard".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveAccountSession {
    pub account_id: String,
    pub account_label: String,
    pub email: String,
    pub node_source: String,
    pub node_name: String,
    pub proxy_url: String,
    pub local_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_exit_ip: Option<ExitIpInfo>,
    pub antigravity_launched: bool,
    #[serde(default = "default_browser_kind_str")]
    pub browser_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adspower_user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adspower_profile_label: Option<String>,
    pub activated_at: String,
}

pub fn extract_loopback_port(raw_url: &str) -> Option<u16> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    let parsed = url::Url::parse(&with_scheme).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    if host != "127.0.0.1" && host != "localhost" {
        return None;
    }
    let port = parsed.port()?;
    (port > 1024).then_some(port)
}

pub fn effective_outbound_mode(cfg: &AppConfig, node: &NodeProfile) -> OutboundMode {
    node.outbound_mode
        .clone()
        .unwrap_or_else(|| cfg.outbound_mode.clone())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamProxyConfig {
    pub enabled: bool,
    pub protocol: String,
    pub server: String,
    pub port: u16,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub active_node_id: String,
    pub nodes: Vec<NodeProfile>,
    pub outbound_mode: OutboundMode,
    #[serde(default)]
    pub physical_interface_name: Option<String>,
    pub upstream_proxy: UpstreamProxyConfig,
    pub kill_switch: KillSwitchMode,
    pub browser_port: u16,
    pub cli_port: u16,
    #[serde(default)]
    pub custom_browser_path: Option<String>,
    #[serde(default)]
    pub claude_desktop_path: Option<String>,
    pub extra_no_proxy: String,
    pub align_fingerprint: bool,
    pub wfp_lock_enabled: bool,
    pub strict_cli_wfp_enabled: bool,
    #[serde(default = "default_true")]
    pub auto_start_gateway: bool,
    #[serde(default = "default_true")]
    pub auto_launch_browser: bool,
    #[serde(default)]
    pub auto_launch_claude_desktop: bool,
    #[serde(default = "default_true")]
    pub require_netguard_for_claude: bool,
    pub ai_domains: Vec<String>,
    #[serde(default = "default_managed_apps")]
    pub managed_apps: Vec<ManagedAppConfig>,
    #[serde(default = "default_browser_profiles")]
    pub browser_profiles: Vec<BrowserProfile>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            active_node_id: "seoul-vps".into(),
            nodes: vec![NodeProfile {
                id: "seoul-vps".into(),
                name: "首尔 VPS 独享出口".into(),
                protocol: ProxyProtocol::Vless,
                server: String::new(),
                port: 443,
                uuid: Some(String::new()),
                flow: Some("xtls-rprx-vision".into()),
                security: Some("reality".into()),
                sni: Some("www.microsoft.com".into()),
                fingerprint: Some("chrome".into()),
                public_key: Some(String::new()),
                short_id: Some(String::new()),
                method: None,
                password: None,
                username: None,
                obfs: None,
                obfs_password: None,
                allow_insecure: Some(false),
                certificate_sha256: None,
                expected_ip: None,
                expected_country: Some("KR".into()),
                timezone: Some("Asia/Seoul".into()),
                locale: Some("ko-KR".into()),
                outbound_mode: None,
            }],
            outbound_mode: OutboundMode::PhysicalBypass,
            physical_interface_name: None,
            upstream_proxy: UpstreamProxyConfig {
                enabled: false,
                protocol: "socks".into(),
                server: "127.0.0.1".into(),
                port: 7890,
            },
            kill_switch: KillSwitchMode::FailClosed,
            browser_port: 17891,
            cli_port: 17890,
            custom_browser_path: None,
            claude_desktop_path: None,
            extra_no_proxy: "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16".into(),
            align_fingerprint: true,
            wfp_lock_enabled: true,
            strict_cli_wfp_enabled: false,
            auto_start_gateway: true,
            auto_launch_browser: true,
            auto_launch_claude_desktop: false,
            require_netguard_for_claude: true,
            ai_domains: vec![
                "anthropic.com".into(),
                "claude.ai".into(),
                "claude.com".into(),
                "statsig.anthropic.com".into(),
                "sentry.io".into(),
                "auth0.com".into(),
                "stripe.com".into(),
                "challenges.cloudflare.com".into(),
                "openai.com".into(),
                "chatgpt.com".into(),
                "gemini.google.com".into(),
                "ip.net.coffee".into(),
                "fuck-claude.vercel.app".into(),
            ],
            managed_apps: default_managed_apps(),
            browser_profiles: default_browser_profiles(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticCheck {
    pub id: String,
    pub title: String,
    pub category: String,
    pub status: String,
    pub summary: String,
    pub detail: String,
    pub fixable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExitIpInfo {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    pub verified_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayStatus {
    pub running: bool,
    pub blocked_by_kill_switch: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kill_switch_reason: Option<String>,
    pub guard_connected: bool,
    pub guard_elevated: bool,
    pub wfp_active: bool,
    pub wfp_filter_count: usize,
    pub persistent_claude_lock_active: bool,
    pub persistent_claude_filter_count: usize,
    pub bypass_route_active: bool,
    pub browser_running: bool,
    pub browser_installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_path: Option<String>,
    pub claude_desktop_found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claude_desktop_path: Option<String>,
    pub claude_cli_found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected_physical_nic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected_physical_gateway: Option<String>,
    pub detected_conflicts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_ip: Option<ExitIpInfo>,
    #[serde(default)]
    pub running_browser_profiles: Vec<String>,
    #[serde(default)]
    pub running_adspower_profiles: Vec<String>,
    #[serde(default)]
    pub secondary_node_ports: std::collections::BTreeMap<String, u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_account_session: Option<ActiveAccountSession>,
    pub logs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadProgress {
    pub stage: String,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvVarHealth {
    pub scope: String, // "user" | "machine" | "process"
    pub key: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alive: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemProxyStatus {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_port: Option<String>,
    pub alive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_config_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedAppRuntimeStatus {
    pub id: String,
    pub name: String,
    pub builtin: bool,
    pub installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_path: Option<String>,
    pub running: bool,
    pub pids: Vec<u32>,
    pub proxy_mode: AppProxyMode,
    pub wfp_lock: bool,
    pub health: String, // "clean" | "dead_proxy" | "mismatch" | "stopped"
    pub diagnosis: String,
    pub env_vars: Vec<EnvVarHealth>,
    pub needs_clean_relaunch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppEnvSnapshot {
    pub system_proxy: SystemProxyStatus,
    pub registry_proxy_vars: Vec<EnvVarHealth>,
    pub apps: Vec<ManagedAppRuntimeStatus>,
    pub polluted_count: usize,
    pub scanned_at: String,
}

pub fn app_data_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join("AI-NetGuard");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn load_config() -> AppConfig {
    let path = app_data_dir().join("config.json");
    if let Ok(raw) = std::fs::read_to_string(&path) {
        if let Ok(cfg) = serde_json::from_str::<AppConfig>(&raw) {
            return cfg;
        }
    }
    let def = AppConfig::default();
    let _ = save_config_to_disk(&def);
    def
}

pub fn save_config_to_disk(cfg: &AppConfig) -> Result<(), String> {
    let path = app_data_dir().join("config.json");
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| e.to_string())
}

pub struct LogBuffer {
    lines: Mutex<VecDeque<String>>,
}

impl LogBuffer {
    pub fn new() -> Self {
        Self {
            lines: Mutex::new(VecDeque::with_capacity(400)),
        }
    }

    pub fn push(&self, msg: impl AsRef<str>) {
        let ts = chrono::Local::now().format("%H:%M:%S");
        let entry = format!("[{ts}] {}", msg.as_ref());
        if let Ok(mut guard) = self.lines.lock() {
            if guard.len() >= 400 {
                guard.pop_front();
            }
            guard.push_back(entry);
        }
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.lines
            .lock()
            .map(|g| g.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn clear(&self) {
        if let Ok(mut guard) = self.lines.lock() {
            guard.clear();
        }
    }
}
