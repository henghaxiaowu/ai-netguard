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
