use crate::launcher::KillOnCloseJob;
use crate::models::{app_data_dir, AppConfig, LogBuffer, NodeProfile, OutboundMode, ProxyProtocol};
use crate::pac::PAC_PORT;
use crate::uri_parser::normalize_spki_sha256_base64;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, ErrorKind};
use std::net::{Ipv4Addr, TcpListener};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const CLASH_API_PORT: u16 = 17899;

pub struct SingBoxManager {
    process: Option<SingBoxProcess>,
    api_secret: String,
    killed_by_switch: bool,
    kill_reason: Option<String>,
}

struct SingBoxProcess {
    child: Child,
    job: KillOnCloseJob,
}

impl SingBoxManager {
    pub fn new() -> Self {
        Self {
            process: None,
            api_secret: format!("ng-{:016x}", rand::random::<u64>()),
            killed_by_switch: false,
            kill_reason: None,
        }
    }

    pub fn is_running(&mut self) -> bool {
        let Some(process) = &mut self.process else {
            return false;
        };
        if matches!(process.child.try_wait(), Ok(None)) {
            return true;
        }
        self.stop();
        false
    }

    pub fn is_blocked(&self) -> bool {
        self.killed_by_switch
    }

    pub fn kill_reason(&self) -> Option<String> {
        self.kill_reason.clone()
    }

    pub fn find_binary() -> Result<PathBuf, String> {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                for name in ["sing-box.exe", "sing-box-x86_64-pc-windows-msvc.exe"] {
                    let cand = dir.join(name);
                    if cand.exists() {
                        return Ok(cand);
                    }
                }
            }
        }
        #[cfg(any(debug_assertions, test))]
        {
            let dev_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("binaries")
                .join("sing-box-x86_64-pc-windows-msvc.exe");
            if dev_path.exists() {
                return Ok(dev_path);
            }
        }
        Err("未找到 sing-box 内核二进制文件".into())
    }

    pub fn probe_port(cfg: &AppConfig) -> u16 {
        let mut cand = cfg.browser_port.saturating_add(1);
        for _ in 0..16 {
            if cand != cfg.cli_port
                && cand != cfg.browser_port
                && cand != PAC_PORT
                && cand != CLASH_API_PORT
                && cand > 1024
            {
                return cand;
            }
            cand = cand.saturating_add(1);
        }
        17892
    }

    pub fn check_listen_ports(cfg: &AppConfig) -> Result<(), String> {
        let ports = [
            cfg.cli_port,
            cfg.browser_port,
            Self::probe_port(cfg),
            CLASH_API_PORT,
        ];
        for (index, &port) in ports.iter().enumerate() {
            if port == 0 || port == PAC_PORT || ports[..index].contains(&port) {
                return Err(format!("网关监听端口 {port} 无效或与其他网关端口重复"));
            }
            TcpListener::bind((Ipv4Addr::LOCALHOST, port)).map_err(|err| {
                if err.kind() == ErrorKind::AddrInUse {
                    format!("本地端口 127.0.0.1:{port} 已被占用，请退出占用端口的程序后再启动网关")
                } else {
                    format!("无法绑定网关监听端口 127.0.0.1:{port}: {err}")
                }
            })?;
        }
        Ok(())
    }

    pub fn generate_config(
        &self,
        cfg: &AppConfig,
        physical_nic: Option<&str>,
    ) -> Result<Value, String> {
        let node = cfg
            .nodes
            .iter()
            .find(|n| n.id == cfg.active_node_id)
            .ok_or("未找到选中的出口节点")?;

        if node.server.trim().is_empty() {
            return Err("出口节点服务器地址为空，请先在“出口与共存路由”中填写或导入节点".into());
        }

        let mut exit_outbound = build_node_outbound(node)?;
        let mut outbounds: Vec<Value> = Vec::new();

        match cfg.outbound_mode {
            OutboundMode::PhysicalBypass => {
                if let Some(nic) = physical_nic {
                    exit_outbound["bind_interface"] = json!(nic);
                }
            }
            OutboundMode::UpstreamDetour => {
                let up_type = if cfg.upstream_proxy.protocol == "http" {
                    "http"
                } else {
                    "socks"
                };
                outbounds.push(json!({
                    "type": up_type,
                    "tag": "upstream_detour",
                    "server": cfg.upstream_proxy.server,
                    "server_port": cfg.upstream_proxy.port
                }));
                exit_outbound["detour"] = json!("upstream_detour");
            }
            OutboundMode::DefaultRoute => {}
        }

        outbounds.insert(
            0,
            json!({
                "type": "selector",
                "tag": "ai_selector",
                "outbounds": ["ai_block", "ai_exit"],
                "default": "ai_block",
                "interrupt_exist_connections": true
            }),
        );
        outbounds.insert(1, exit_outbound);
        outbounds.push(json!({ "type": "block", "tag": "ai_block" }));
        outbounds.push(json!({ "type": "direct", "tag": "direct" }));

        let mut rules = vec![
            json!({ "action": "sniff" }),
            json!({ "protocol": "quic", "action": "reject" }),
            json!({ "ip_cidr": ["::/0"], "action": "reject" }),
            json!({ "inbound": ["in_probe"], "outbound": "ai_exit" }),
            json!({ "inbound": ["in_browser"], "outbound": "ai_selector" }),
        ];

        let mut route_domains: Vec<String> = Vec::new();
        for domain in cfg
            .ai_domains
            .iter()
            .map(String::as_str)
            .chain([
                "hcaptcha.com",
                "challenges.cloudflare.com",
                "accounts.google.com",
                "googleapis.com",
                "gstatic.com",
            ])
        {
            let trimmed = domain.trim();
            if !trimmed.is_empty() && !route_domains.iter().any(|d| d.eq_ignore_ascii_case(trimmed))
            {
                route_domains.push(trimmed.to_string());
            }
        }

        if !route_domains.is_empty() {
            rules.push(json!({
                "domain_suffix": route_domains,
                "outbound": "ai_selector"
            }));
        }

        // For CLI traffic that does not match AI domains: use upstream clash if configured, else direct.
        let cli_final = if cfg.upstream_proxy.enabled
            && matches!(cfg.outbound_mode, OutboundMode::UpstreamDetour)
        {
            "upstream_detour"
        } else {
            "direct"
        };

        let local_dns = match (&cfg.outbound_mode, physical_nic) {
            (OutboundMode::PhysicalBypass, Some(nic)) => json!({
                "tag": "dns_local",
                "type": "udp",
                "server": "223.5.5.5",
                "bind_interface": nic
            }),
            _ => json!({ "tag": "dns_local", "type": "local" }),
        };

        Ok(json!({
            "log": { "level": "info", "timestamp": true },
            "experimental": {
                "clash_api": {
                    "external_controller": format!("127.0.0.1:{CLASH_API_PORT}"),
                    "secret": self.api_secret
                }
            },
            "dns": {
                "servers": [
                    { "tag": "dns_remote", "type": "https", "server": "1.1.1.1", "detour": "ai_selector" },
                    local_dns
                ],
                "rules": [
                    { "domain_suffix": route_domains, "server": "dns_remote" }
                ],
                "final": "dns_local",
                "strategy": "ipv4_only"
            },
            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "in_cli",
                    "listen": "127.0.0.1",
                    "listen_port": cfg.cli_port
                },
                {
                    "type": "socks",
                    "tag": "in_browser",
                    "listen": "127.0.0.1",
                    "listen_port": cfg.browser_port
                },
                {
                    "type": "socks",
                    "tag": "in_probe",
                    "listen": "127.0.0.1",
                    "listen_port": Self::probe_port(cfg)
                }
            ],
            "outbounds": outbounds,
            "route": {
                "default_domain_resolver": "dns_local",
                "rules": rules,
                "final": cli_final
            }
        }))
    }

    pub fn start(
        &mut self,
        cfg: &AppConfig,
        physical_nic: Option<&str>,
        logs: Arc<LogBuffer>,
    ) -> Result<(), String> {
        self.stop();

        let bin = Self::find_binary()?;
        let config_json = self.generate_config(cfg, physical_nic)?;
        let cfg_path = app_data_dir().join("sing-box.json");
        let pretty = serde_json::to_string_pretty(&config_json).map_err(|e| e.to_string())?;
        std::fs::write(&cfg_path, pretty).map_err(|e| e.to_string())?;

        // Validate config before launching
        let check = Command::new(&bin)
            .args(["check", "-c", &cfg_path.to_string_lossy()])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("执行 sing-box check 失败: {e}"))?;
        if !check.status.success() {
            let err_text = String::from_utf8_lossy(&check.stderr);
            return Err(format!("sing-box 配置校验未通过: {err_text}"));
        }

        let job = KillOnCloseJob::new().map_err(|e| format!("创建 sing-box 进程作业失败: {e}"))?;
        let mut child = Command::new(&bin)
            .args(["run", "-c", &cfg_path.to_string_lossy()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| format!("启动 sing-box 失败: {e}"))?;
        if let Err(err) = job.assign(&child) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("绑定 sing-box 进程作业失败，已中止启动: {err}"));
        }

        if let Some(stdout) = child.stdout.take() {
            let l = logs.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    l.push(format!("[sing-box] {line}"));
                }
            });
        }
        if let Some(stderr) = child.stderr.take() {
            let l = logs.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    l.push(format!("[sing-box] {line}"));
                }
            });
        }

        self.process = Some(SingBoxProcess { child, job });
        self.killed_by_switch = false;
        self.kill_reason = None;
        logs.push(format!(
            "sing-box 已启动 (CLI :{}, 专用浏览器 :{})",
            cfg.cli_port, cfg.browser_port
        ));
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(SingBoxProcess { mut child, job }) = self.process.take() {
            drop(job);
            let _ = child.wait();
        }
        self.killed_by_switch = false;
        self.kill_reason = None;
    }

    pub fn api_secret(&self) -> String {
        self.api_secret.clone()
    }

    pub fn mark_kill_switch(&mut self, block: bool, reason: Option<String>) {
        self.killed_by_switch = block;
        self.kill_reason = if block { reason } else { None };
    }
}

pub async fn send_kill_switch_http(api_secret: &str, block: bool) -> Result<(), String> {
    let target = if block { "ai_block" } else { "ai_exit" };
    let client = reqwest::Client::new();
    let resp = client
        .put(format!("http://127.0.0.1:{CLASH_API_PORT}/proxies/ai_selector"))
        .bearer_auth(api_secret)
        .json(&json!({ "name": target }))
        .send()
        .await
        .map_err(|e| format!("调用 sing-box 熔断控制 API 失败: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("sing-box selector 切换失败: HTTP {}", resp.status()));
    }
    Ok(())
}

impl Drop for SingBoxManager {
    fn drop(&mut self) {
        self.stop();
    }
}

fn build_node_outbound(node: &NodeProfile) -> Result<Value, String> {
    let base = match node.protocol {
        ProxyProtocol::Vless => {
            let uuid = node.uuid.as_deref().unwrap_or("").trim();
            if uuid.is_empty() {
                return Err("VLESS 节点缺少 UUID".into());
            }
            let mut obj = json!({
                "type": "vless",
                "tag": "ai_exit",
                "server": node.server.trim(),
                "server_port": node.port,
                "uuid": uuid
            });
            if let Some(flow) = node.flow.as_deref().filter(|s| !s.is_empty()) {
                obj["flow"] = json!(flow);
            }
            if let Some(tls) = build_tls(node)? {
                obj["tls"] = tls;
            }
            obj
        }
        ProxyProtocol::Trojan => {
            let pass = node.password.as_deref().unwrap_or("");
            let mut obj = json!({
                "type": "trojan",
                "tag": "ai_exit",
                "server": node.server.trim(),
                "server_port": node.port,
                "password": pass
            });
            if let Some(tls) = build_tls(node)? {
                obj["tls"] = tls;
            }
            obj
        }
        ProxyProtocol::Hysteria2 => {
            let pass = node.password.as_deref().unwrap_or("");
            let mut tls = json!({
                "enabled": true,
                "server_name": node.sni.clone().unwrap_or_else(|| node.server.clone()),
                "insecure": node.allow_insecure.unwrap_or(false)
            });
            apply_tls_cert_pinning(&mut tls, node)?;
            let mut obj = json!({
                "type": "hysteria2",
                "tag": "ai_exit",
                "server": node.server.trim(),
                "server_port": node.port,
                "password": pass,
                "tls": tls
            });
            if let (Some(obfs), Some(obfs_pw)) = (&node.obfs, &node.obfs_password) {
                if !obfs.is_empty() {
                    obj["obfs"] = json!({ "type": obfs, "password": obfs_pw });
                }
            }
            obj
        }
        ProxyProtocol::Shadowsocks => json!({
            "type": "shadowsocks",
            "tag": "ai_exit",
            "server": node.server.trim(),
            "server_port": node.port,
            "method": node.method.as_deref().unwrap_or("aes-256-gcm"),
            "password": node.password.as_deref().unwrap_or("")
        }),
        ProxyProtocol::Socks => {
            let mut obj = json!({
                "type": "socks",
                "tag": "ai_exit",
                "server": node.server.trim(),
                "server_port": node.port,
                "version": "5"
            });
            if let Some(u) = node.username.as_deref().filter(|s| !s.is_empty()) {
                obj["username"] = json!(u);
                obj["password"] = json!(node.password.as_deref().unwrap_or(""));
            }
            obj
        }
        ProxyProtocol::Http => {
            let mut obj = json!({
                "type": "http",
                "tag": "ai_exit",
                "server": node.server.trim(),
                "server_port": node.port
            });
            if let Some(u) = node.username.as_deref().filter(|s| !s.is_empty()) {
                obj["username"] = json!(u);
                obj["password"] = json!(node.password.as_deref().unwrap_or(""));
            }
            if node.security.as_deref() == Some("tls") {
                let mut tls = json!({
                    "enabled": true,
                    "insecure": node.allow_insecure.unwrap_or(false)
                });
                apply_tls_cert_pinning(&mut tls, node)?;
                obj["tls"] = tls;
            }
            obj
        }
    };

    if base.is_null() {
        return Err("节点构造失败".into());
    }
    Ok(base)
}

fn apply_tls_cert_pinning(tls: &mut Value, node: &NodeProfile) -> Result<(), String> {
    if let Some(raw_pin) = node
        .certificate_sha256
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let normalized = normalize_spki_sha256_base64(raw_pin)?;
        tls["insecure"] = json!(false);
        tls["certificate_public_key_sha256"] = json!([normalized]);
    }
    Ok(())
}

fn build_tls(node: &NodeProfile) -> Result<Option<Value>, String> {
    let sec = node.security.as_deref().unwrap_or("none");
    if sec == "none" {
        return Ok(None);
    }
    let mut tls = json!({
        "enabled": true,
        "server_name": node.sni.clone().unwrap_or_else(|| node.server.clone()),
        "insecure": node.allow_insecure.unwrap_or(false),
        "utls": {
            "enabled": true,
            "fingerprint": node.fingerprint.clone().unwrap_or_else(|| "chrome".into())
        }
    });
    if sec == "reality" {
        tls["reality"] = json!({
            "enabled": true,
            "public_key": node.public_key.as_deref().unwrap_or(""),
            "short_id": node.short_id.as_deref().unwrap_or("")
        });
    }
    apply_tls_cert_pinning(&mut tls, node)?;
    Ok(Some(tls))
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::UpstreamProxyConfig;
    use std::time::{Duration, Instant};

    #[test]
    fn rejects_an_occupied_port_before_gateway_startup() {
        let holder = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = holder.local_addr().unwrap().port();
        let mut cfg = AppConfig::default();
        cfg.cli_port = port;
        let err = SingBoxManager::check_listen_ports(&cfg).unwrap_err();
        assert!(err.contains(&format!("127.0.0.1:{port}")), "{err}");
    }

    #[test]
    fn closing_job_terminates_child_while_its_stdin_is_open() {
        let job = KillOnCloseJob::new().unwrap();
        let mut child = Command::new("cmd.exe")
            .args(["/d", "/c", "set /p netguard_test="])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap();
        assert!(child.try_wait().unwrap().is_none());
        if let Err(err) = job.assign(&child) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("failed to attach test process: {err}");
        }

        drop(job);
        let deadline = Instant::now() + Duration::from_secs(3);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("test process survived closing the job");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn generated_configs_pass_real_singbox_check() {
        let bin = SingBoxManager::find_binary().expect("sing-box binary present");
        let mgr = SingBoxManager::new();

        let mut cfg = AppConfig::default();
        cfg.nodes[0].server = "1.2.3.4".into();
        cfg.nodes[0].uuid = Some("11111111-2222-3333-4444-555555555555".into());
        cfg.nodes[0].public_key = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
        cfg.nodes[0].short_id = Some("1234abcd".into());

        // Test PhysicalBypass mode
        let json1 = mgr.generate_config(&cfg, Some("Ethernet")).unwrap();
        let dns_domains: Vec<&str> = json1["dns"]["rules"][0]["domain_suffix"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(dns_domains.contains(&"hcaptcha.com"));
        assert!(dns_domains.contains(&"accounts.google.com"));
        let p1 = std::env::temp_dir().join("ng-test-bypass.json");
        std::fs::write(&p1, serde_json::to_string_pretty(&json1).unwrap()).unwrap();
        let out1 = Command::new(&bin)
            .args(["check", "-c", &p1.to_string_lossy()])
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&p1);
        assert!(
            out1.status.success(),
            "bypass config check failed: {}",
            String::from_utf8_lossy(&out1.stderr)
        );

        // Test UpstreamDetour mode
        cfg.outbound_mode = OutboundMode::UpstreamDetour;
        cfg.upstream_proxy = UpstreamProxyConfig {
            enabled: true,
            protocol: "socks".into(),
            server: "127.0.0.1".into(),
            port: 7890,
        };
        let json2 = mgr.generate_config(&cfg, None).unwrap();
        let p2 = std::env::temp_dir().join("ng-test-detour.json");
        std::fs::write(&p2, serde_json::to_string_pretty(&json2).unwrap()).unwrap();
        let out2 = Command::new(&bin)
            .args(["check", "-c", &p2.to_string_lossy()])
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&p2);
        assert!(
            out2.status.success(),
            "detour config check failed: {}",
            String::from_utf8_lossy(&out2.stderr)
        );
        assert_eq!(json1["outbounds"][0]["default"], "ai_block");
        assert_eq!(json1["outbounds"][0]["interrupt_exist_connections"], true);
        assert_eq!(json1["inbounds"][2]["tag"], "in_probe");
        assert_eq!(json1["route"]["rules"][3]["inbound"][0], "in_probe");
        assert_eq!(json1["route"]["rules"][3]["outbound"], "ai_exit");

        // Test Hysteria2 with SPKI SHA-256 pinning
        cfg.outbound_mode = OutboundMode::DefaultRoute;
        cfg.nodes[0].protocol = ProxyProtocol::Hysteria2;
        cfg.nodes[0].password = Some("secret".into());
        cfg.nodes[0].allow_insecure = Some(true);
        cfg.nodes[0].certificate_sha256 =
            Some("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into());
        let json3 = mgr.generate_config(&cfg, None).unwrap();
        assert_eq!(json3["outbounds"][1]["tls"]["insecure"], false);
        assert_eq!(
            json3["outbounds"][1]["tls"]["certificate_public_key_sha256"][0],
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
        let p3 = std::env::temp_dir().join("ng-test-hy2-pin.json");
        std::fs::write(&p3, serde_json::to_string_pretty(&json3).unwrap()).unwrap();
        let out3 = Command::new(&bin)
            .args(["check", "-c", &p3.to_string_lossy()])
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&p3);
        assert!(
            out3.status.success(),
            "hy2 pinned config check failed: {}",
            String::from_utf8_lossy(&out3.stderr)
        );
    }
}
