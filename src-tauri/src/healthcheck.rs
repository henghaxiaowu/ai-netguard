use crate::models::{app_data_dir, AppConfig, DiagnosticCheck, GatewayStatus};
use crate::network::check_anthropic_via_http_proxy;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub async fn run_eight_checks(cfg: &AppConfig, status: &GatewayStatus) -> Vec<DiagnosticCheck> {
    let active_node = cfg.nodes.iter().find(|n| n.id == cfg.active_node_id);

    // 1. Exit IP check
    let c1 = match (&status.exit_ip, active_node) {
        (Some(exit), Some(node)) => {
            let expected_ip_ok = node
                .expected_ip
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|exp| exp == exit.ip)
                .unwrap_or(true);
            let expected_cc_ok = node
                .expected_country
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|exp| {
                    exit.country_code
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(|cc| cc.eq_ignore_ascii_case(exp))
                        .unwrap_or(false)
                })
                .unwrap_or(true);

            if expected_ip_ok && expected_cc_ok {
                DiagnosticCheck {
                    id: "exit_ip".into(),
                    title: "1. 远端干净出口 IP 核验".into(),
                    category: "core".into(),
                    status: "pass".into(),
                    summary: format!("出口 IP {} 验证通过", exit.ip),
                    detail: format!(
                        "{} {} | 延迟 {}ms | 校验于 {}",
                        exit.country_code.as_deref().unwrap_or("--"),
                        exit.asn.as_deref().unwrap_or(""),
                        exit.latency_ms.unwrap_or(0),
                        exit.verified_at
                    ),
                    fixable: false,
                    fix_action: None,
                }
            } else {
                DiagnosticCheck {
                    id: "exit_ip".into(),
                    title: "1. 远端干净出口 IP 核验".into(),
                    category: "core".into(),
                    status: "fail".into(),
                    summary: format!("出口 IP {} 与节点预期不符！", exit.ip),
                    detail: format!(
                        "预期 IP: {:?}, 预期国家: {:?}; 实测: {} ({:?})",
                        node.expected_ip, node.expected_country, exit.ip, exit.country_code
                    ),
                    fixable: false,
                    fix_action: None,
                }
            }
        }
        _ => DiagnosticCheck {
            id: "exit_ip".into(),
            title: "1. 远端干净出口 IP 核验".into(),
            category: "core".into(),
            status: if status.running { "fail" } else { "pending" }.into(),
            summary: if status.running {
                "代理出口探针未通"
            } else {
                "网关尚未启动"
            }
            .into(),
            detail: "请确认节点服务器、端口与凭据正确且防火墙放行".into(),
            fixable: false,
            fix_action: None,
        },
    };

    // 2. Coexistence bypass / detour check
    let c2 = if status.detected_conflicts.is_empty() {
        DiagnosticCheck {
            id: "coexistence".into(),
            title: "2. 并发梯子 / 公司 VPN 共存检测".into(),
            category: "coexistence".into(),
            status: "pass".into(),
            summary: "未检测到其他并发代理/VPN，无冲突风险".into(),
            detail: format!(
                "物理网卡: {} (网关 {})",
                status.detected_physical_nic.as_deref().unwrap_or("未知"),
                status.detected_physical_gateway.as_deref().unwrap_or("--")
            ),
            fixable: false,
            fix_action: None,
        }
    } else if status.bypass_route_active
        || matches!(cfg.outbound_mode, crate::models::OutboundMode::UpstreamDetour)
    {
        DiagnosticCheck {
            id: "coexistence".into(),
            title: "2. 并发梯子 / 公司 VPN 共存检测".into(),
            category: "coexistence".into(),
            status: "pass".into(),
            summary: format!("已隔离共存 ({})", status.detected_conflicts.join(", ")),
            detail: if status.bypass_route_active {
                "已注入物理网卡 /32 主机旁路路由，隧道直奔目标节点".into()
            } else {
                "当前按配置经上游代理串联出站".into()
            },
            fixable: false,
            fix_action: None,
        }
    } else {
        DiagnosticCheck {
            id: "coexistence".into(),
            title: "2. 并发梯子 / 公司 VPN 共存检测".into(),
            category: "coexistence".into(),
            status: "warn".into(),
            summary: format!("检测到并发工具: {}", status.detected_conflicts.join(", ")),
            detail: "建议开启 WFP 提权 Guard 以自动写入物理网卡 /32 绕过路由，防止被其他 TUN 抢占".into(),
            fixable: true,
            fix_action: Some("connect_guard".into()),
        }
    };

    // 3. DNS leak protection check
    let prefs_ok = browser_prefs_hardened();
    let c3 = DiagnosticCheck {
        id: "dns_leak".into(),
        title: "3. DNS 防泄漏校验 (远端解析 + 禁 DoH)".into(),
        category: "security".into(),
        status: if status.running && prefs_ok { "pass" } else { "warn" }.into(),
        summary: if prefs_ok {
            "浏览器本地解析与 DoH 已强制关闭"
        } else {
            "浏览器防泄漏 Profile 尚未初始化"
        }
        .into(),
        detail: "启动 参数含 --host-resolver-rules=MAP * ~NOTFOUND 且 sing-box 使用远端 DoH + 策略 ipv4_only".into(),
        fixable: !prefs_ok,
        fix_action: (!prefs_ok).then(|| "harden_browser_prefs".into()),
    };

    // 4. IPv6 leak check
    let c4 = DiagnosticCheck {
        id: "ipv6_leak".into(),
        title: "4. IPv6 泄漏阻断校验".into(),
        category: "security".into(),
        status: if status.running && status.wfp_active {
            "pass"
        } else if status.running {
            "warn"
        } else {
            "pending"
        }
        .into(),
        summary: if status.wfp_active {
            "内核 WFP IPv6 层 + sing-box 双重阻断已生效"
        } else {
            "仅 sing-box 规则丢弃 ::/0，尚未加 WFP 内核硬锁"
        }
        .into(),
        detail: "FWPM_LAYER_ALE_AUTH_CONNECT_V6 拦截非回环流量".into(),
        fixable: !status.wfp_active && status.running,
        fix_action: Some("connect_guard".into()),
    };

    // 5. WebRTC / QUIC check
    let c5 = DiagnosticCheck {
        id: "webrtc_quic".into(),
        title: "5. WebRTC UDP / QUIC 穿透拦截".into(),
        category: "security".into(),
        status: if status.browser_installed { "pass" } else { "warn" }.into(),
        summary: if status.browser_installed {
            "已配置 disable_non_proxied_udp + --disable-quic"
        } else {
            "专属防泄漏浏览器尚未下载安装"
        }
        .into(),
        detail: "sing-box route 同时显式 reject 所有 QUIC (UDP 443) 报文".into(),
        fixable: false,
        fix_action: None,
    };

    // 6. WFP Kernel Kill-Switch check
    let c6 = DiagnosticCheck {
        id: "wfp_lock".into(),
        title: "6. Windows WFP 内核防火墙硬锁".into(),
        category: "security".into(),
        status: if !cfg.wfp_lock_enabled {
            "warn"
        } else if status.wfp_active {
            "pass"
        } else {
            "fail"
        }
        .into(),
        summary: if status.wfp_active {
            format!("已注入 {} 条动态 WFP 规则", status.wfp_filter_count)
        } else if !cfg.wfp_lock_enabled {
            "用户主动关闭了 WFP 硬锁开关".into()
        } else {
            "WFP 硬锁未激活（需启动提权 Guard）".into()
        },
        detail: "仅允许受控 AI 进程访问 127.0.0.1 回环，断网/崩溃绝不裸奔".into(),
        fixable: cfg.wfp_lock_enabled && !status.wfp_active,
        fix_action: Some("connect_guard".into()),
    };

    // 7. Kill-switch status
    let c7 = DiagnosticCheck {
        id: "kill_switch".into(),
        title: "7. 异常断网熔断机制 (Fail-Closed)".into(),
        category: "core".into(),
        status: if status.blocked_by_kill_switch {
            "fail"
        } else if matches!(cfg.kill_switch, crate::models::KillSwitchMode::FailClosed) {
            "pass"
        } else {
            "warn"
        }
        .into(),
        summary: if status.blocked_by_kill_switch {
            status
                .kill_switch_reason
                .clone()
                .unwrap_or_else(|| "当前正处于熔断阻断状态".into())
        } else if matches!(cfg.kill_switch, crate::models::KillSwitchMode::FailClosed) {
            "已就绪：出口异常或漂移时秒切 block 黑洞".into()
        } else {
            "当前为仅告警模式，异常时不自动阻断".into()
        },
        detail: "后台每 4 秒核验一次隧道可达性与出口 IP".into(),
        fixable: false,
        fix_action: None,
    };

    // 8. Claude Code CLI & environment check
    let env_conflicts = inspect_user_proxy_env(cfg.cli_port);
    let anthropic_probe = if status.running && !status.blocked_by_kill_switch {
        check_anthropic_via_http_proxy(cfg.cli_port).await.ok()
    } else {
        None
    };

    let c8 = if !env_conflicts.is_empty() {
        DiagnosticCheck {
            id: "claude_code".into(),
            title: "8. Claude Code CLI 链路与环境变量检测".into(),
            category: "cli".into(),
            status: "warn".into(),
            summary: format!("用户环境变量存在旧代理指向: {}", env_conflicts.join(", ")),
            detail: "建议清理全局残留或使用“一键修正”，改由安全终端局部注入".into(),
            fixable: true,
            fix_action: Some("fix_claude_env".into()),
        }
    } else if status.running && anthropic_probe.is_none() {
        DiagnosticCheck {
            id: "claude_code".into(),
            title: "8. Claude Code CLI 链路与环境变量检测".into(),
            category: "cli".into(),
            status: "fail".into(),
            summary: format!("经本地 CLI 端口 {} 访问 api.anthropic.com 失败", cfg.cli_port),
            detail: "请检查节点连通性或本地防火墙设置".into(),
            fixable: false,
            fix_action: None,
        }
    } else {
        DiagnosticCheck {
            id: "claude_code".into(),
            title: "8. Claude Code CLI 链路与环境变量检测".into(),
            category: "cli".into(),
            status: if status.running { "pass" } else { "pending" }.into(),
            summary: match anthropic_probe {
                Some(code) => format!("api.anthropic.com 连通正常 (HTTP {code})"),
                None => "环境变量干净，等待启动网关后验证 Anthropic 握手".into(),
            },
            detail: format!(
                "Claude CLI: {}",
                if status.claude_cli_found { "已安装" } else { "未在 PATH 找到" }
            ),
            fixable: false,
            fix_action: None,
        }
    };

    vec![c1, c2, c3, c4, c5, c6, c7, c8]
}

fn browser_prefs_hardened() -> bool {
    let pref = app_data_dir()
        .join("browser-profile")
        .join("Default")
        .join("Preferences");
    if let Ok(raw) = std::fs::read_to_string(pref) {
        return raw.contains("disable_non_proxied_udp");
    }
    false
}

fn inspect_user_proxy_env(expected_port: u16) -> Vec<String> {
    let expected = format!("127.0.0.1:{expected_port}");
    let mut bad = Vec::new();
    for key in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
        if let Ok(val) = std::env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() && !trimmed.contains(&expected) {
                bad.push(format!("{key}={trimmed}"));
            }
        }
    }
    bad
}

#[cfg(test)]
pub fn escape_ps_single_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            continue;
        }
        // PowerShell treats ASCII ' plus Unicode smart single quotes (U+2018..U+201B) as string delimiters.
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            out.push(c);
            out.push(c);
        } else {
            out.push(c);
        }
    }
    out
}

pub fn encode_powershell_encoded_command(script: &str) -> String {
    let mut utf16le = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        utf16le.extend_from_slice(&unit.to_le_bytes());
    }
    STANDARD.encode(utf16le)
}

pub fn encode_utf8_b64(s: &str) -> String {
    STANDARD.encode(s.as_bytes())
}

pub fn apply_fix_action(action: &str, cfg: &AppConfig) -> Result<String, String> {
    match action {
        "fix_claude_env" => {
            let http_val = format!("http://127.0.0.1:{}", cfg.cli_port);
            let socks_val = format!("socks5h://127.0.0.1:{}", cfg.cli_port);
            let clean_no_proxy: String = cfg
                .extra_no_proxy
                .chars()
                .filter(|c| !c.is_control())
                .collect();
            let ps_static = "[Environment]::SetEnvironmentVariable('HTTP_PROXY', $env:NG_FIX_HTTP, 'User'); \
                 [Environment]::SetEnvironmentVariable('HTTPS_PROXY', $env:NG_FIX_HTTP, 'User'); \
                 [Environment]::SetEnvironmentVariable('ALL_PROXY', $env:NG_FIX_SOCKS, 'User'); \
                 [Environment]::SetEnvironmentVariable('NO_PROXY', $env:NG_FIX_NO_PROXY, 'User')";
            let out = Command::new("powershell.exe")
                .args(["-NoLogo", "-NoProfile", "-Command", ps_static])
                .env("NG_FIX_HTTP", &http_val)
                .env("NG_FIX_SOCKS", &socks_val)
                .env("NG_FIX_NO_PROXY", &clean_no_proxy)
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .map_err(|e| format!("写入用户环境变量失败: {e}"))?;
            if !out.status.success() {
                return Err(String::from_utf8_lossy(&out.stderr).to_string());
            }
            // Update current process env too so immediate re-check sees it
            std::env::set_var("HTTP_PROXY", &http_val);
            std::env::set_var("HTTPS_PROXY", &http_val);
            std::env::set_var("ALL_PROXY", &socks_val);
            std::env::set_var("NO_PROXY", &clean_no_proxy);
            Ok(format!("已将当前用户环境变量修正为 127.0.0.1:{}", cfg.cli_port))
        }
        "harden_browser_prefs" => {
            let default_dir = app_data_dir().join("browser-profile").join("Default");
            std::fs::create_dir_all(&default_dir).map_err(|e| e.to_string())?;
            let pref = default_dir.join("Preferences");
            let val = serde_json::json!({
                "dns_over_https": { "mode": "off" },
                "webrtc": { "ip_handling_policy": "disable_non_proxied_udp" },
                "net": { "network_prediction_options": 2 }
            });
            std::fs::write(pref, serde_json::to_string_pretty(&val).unwrap())
                .map_err(|e| e.to_string())?;
            Ok("已初始化防泄漏浏览器 Preferences".into())
        }
        other => Err(format!("未知修复操作: {other}")),
    }
}

#[allow(dead_code)]
fn _unused_path_ref(_p: PathBuf) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps_single_quote_escaping_blocks_injection() {
        let malicious = "localhost'; Start-Process calc.exe;\r\n '127.0.0.1";
        let escaped = escape_ps_single_quoted(malicious);
        assert_eq!(escaped, "localhost''; Start-Process calc.exe; ''127.0.0.1");
        assert!(!escaped.contains('\r'));
        assert!(!escaped.contains('\n'));

        let unicode_malicious = "localhost\u{2019}; calc; \u{2018}127.0.0.1";
        let unicode_escaped = escape_ps_single_quoted(unicode_malicious);
        assert_eq!(
            unicode_escaped,
            "localhost\u{2019}\u{2019}; calc; \u{2018}\u{2018}127.0.0.1"
        );
    }

    #[tokio::test]
    async fn exit_check_fails_when_expected_country_missing() {
        let mut cfg = AppConfig::default();
        cfg.nodes[0].expected_country = Some("KR".into());
        let mut status = GatewayStatus::default();
        status.running = true;
        status.exit_ip = Some(crate::models::ExitIpInfo {
            ip: "1.2.3.4".into(),
            country: None,
            country_code: None,
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            timezone: None,
            isp: None,
            org: None,
            asn: None,
            latency_ms: Some(12),
            verified_at: "12:00:00".into(),
        });
        let checks = run_eight_checks(&cfg, &status).await;
        assert_eq!(checks[0].id, "exit_ip");
        assert_eq!(checks[0].status, "fail");
    }
}
