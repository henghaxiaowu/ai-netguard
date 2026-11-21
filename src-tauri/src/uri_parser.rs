use crate::models::{NodeProfile, ProxyProtocol};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use std::collections::HashMap;
use url::Url;

fn decode_b64(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    for engine in [&URL_SAFE_NO_PAD, &URL_SAFE, &STANDARD] {
        if let Ok(bytes) = engine.decode(trimmed) {
            if let Ok(text) = String::from_utf8(bytes) {
                return Ok(text);
            }
        }
    }
    Err("Invalid base64 payload".into())
}

/// Normalize a Hysteria2/TLS SPKI SHA-256 fingerprint (`sha256/<b64>`, raw `<b64>`,
/// `sha256:<hex>`, or colon-separated hex) into sing-box's raw standard base64 format.
pub fn normalize_spki_sha256_base64(input: &str) -> Result<String, String> {
    let mut s = input.trim();
    if s.is_empty() {
        return Err("空的证书指纹".into());
    }
    for prefix in ["sha256/", "sha-256/", "sha256:", "sha-256:"] {
        if s.len() > prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
            s = &s[prefix.len()..];
            break;
        }
    }
    let compact_hex: String = s
        .chars()
        .filter(|&c| c != ':' && c != '-' && !c.is_whitespace())
        .collect();
    if compact_hex.len() == 64 && compact_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = hex::decode(&compact_hex)
            .map_err(|e| format!("证书 SHA-256 Hex 解析失败: {e}"))?;
        return Ok(STANDARD.encode(bytes));
    }
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(s) {
            if bytes.len() == 32 {
                return Ok(STANDARD.encode(bytes));
            }
        }
    }
    Err("证书 SPKI SHA-256 格式无效（需为 32 字节 Base64 或 64 位 Hex）".into())
}

fn query_map(url: &Url) -> HashMap<String, String> {
    url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn query_ci<'a>(q: &'a HashMap<String, String>, key: &str) -> Option<&'a String> {
    q.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v)
}

pub fn parse_node_uri(raw: &str) -> Result<NodeProfile, String> {
    let trimmed = raw.trim();
    let url = Url::parse(trimmed).map_err(|e| format!("URI 解析失败: {e}"))?;
    let scheme = url.scheme().to_lowercase();
    let q = query_map(&url);
    let fragment_name = url
        .fragment()
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let id = format!("node-{}", chrono::Utc::now().timestamp_millis());
    let server = url
        .host_str()
        .ok_or("URI 缺少服务器地址")?
        .trim_matches(['[', ']'])
        .to_string();

    let pin_sha256 = query_ci(&q, "pinSHA256")
        .or_else(|| query_ci(&q, "pin"))
        .map(|v| normalize_spki_sha256_base64(v))
        .transpose()?;

    match scheme.as_str() {
        "vless" => {
            let port = url.port().unwrap_or(443);
            let uuid = url.username().to_string();
            if uuid.is_empty() {
                return Err("VLESS URI 缺少 UUID".into());
            }
            let sec = q.get("security").cloned().unwrap_or_else(|| "none".into());
            Ok(NodeProfile {
                id,
                name: fragment_name.unwrap_or_else(|| format!("VLESS {server}:{port}")),
                protocol: ProxyProtocol::Vless,
                server,
                port,
                uuid: Some(uuid),
                flow: q.get("flow").filter(|s| !s.is_empty()).cloned(),
                security: Some(sec),
                sni: q.get("sni").cloned(),
                fingerprint: q.get("fp").cloned().or_else(|| Some("chrome".into())),
                public_key: q.get("pbk").cloned(),
                short_id: q.get("sid").cloned(),
                method: None,
                password: None,
                username: None,
                obfs: None,
                obfs_password: None,
                allow_insecure: Some(q.get("allowInsecure").map(|v| v == "1").unwrap_or(false)),
                certificate_sha256: pin_sha256,
                expected_ip: None,
                expected_country: None,
                timezone: Some("Asia/Seoul".into()),
                locale: Some("ko-KR".into()),
                outbound_mode: None,
            })
        }
        "trojan" => {
            let port = url.port().unwrap_or(443);
            let password = url.username().to_string();
            Ok(NodeProfile {
                id,
                name: fragment_name.unwrap_or_else(|| format!("Trojan {server}:{port}")),
                protocol: ProxyProtocol::Trojan,
                server,
                port,
                uuid: None,
                flow: None,
                security: Some("tls".into()),
                sni: q.get("sni").cloned(),
                fingerprint: q.get("fp").cloned().or_else(|| Some("chrome".into())),
                public_key: None,
                short_id: None,
                method: None,
                password: Some(password),
                username: None,
                obfs: None,
                obfs_password: None,
                allow_insecure: Some(q.get("allowInsecure").map(|v| v == "1").unwrap_or(false)),
                certificate_sha256: pin_sha256,
                expected_ip: None,
                expected_country: None,
                timezone: None,
                locale: None,
                outbound_mode: None,
            })
        }
        "hy2" | "hysteria2" => {
            let port = url.port().unwrap_or(443);
            let password = url.username().to_string();
            Ok(NodeProfile {
                id,
                name: fragment_name.unwrap_or_else(|| format!("Hysteria2 {server}:{port}")),
                protocol: ProxyProtocol::Hysteria2,
                server,
                port,
                uuid: None,
                flow: None,
                security: Some("tls".into()),
                sni: q.get("sni").cloned(),
                fingerprint: None,
                public_key: None,
                short_id: None,
                method: None,
                password: Some(password),
                username: None,
                obfs: q.get("obfs").cloned(),
                obfs_password: q.get("obfs-password").cloned(),
                allow_insecure: Some(q.get("insecure").map(|v| v == "1").unwrap_or(false)),
                certificate_sha256: pin_sha256,
                expected_ip: None,
                expected_country: None,
                timezone: None,
                locale: None,
                outbound_mode: None,
            })
        }
        "ss" => parse_ss_uri(trimmed, id, fragment_name),
        "socks" | "socks5" | "socks5h" => {
            let port = url.port().unwrap_or(1080);
            let user = (!url.username().is_empty()).then(|| url.username().to_string());
            let pass = url.password().map(str::to_string);
            Ok(NodeProfile {
                id,
                name: fragment_name.unwrap_or_else(|| format!("SOCKS5 {server}:{port}")),
                protocol: ProxyProtocol::Socks,
                server,
                port,
                uuid: None,
                flow: None,
                security: None,
                sni: None,
                fingerprint: None,
                public_key: None,
                short_id: None,
                method: None,
                password: pass,
                username: user,
                obfs: None,
                obfs_password: None,
                allow_insecure: None,
                certificate_sha256: None,
                expected_ip: None,
                expected_country: None,
                timezone: None,
                locale: None,
                outbound_mode: None,
            })
        }
        "http" | "https" => {
            let port = url.port().unwrap_or(if scheme == "https" { 443 } else { 8080 });
            let user = (!url.username().is_empty()).then(|| url.username().to_string());
            let pass = url.password().map(str::to_string);
            Ok(NodeProfile {
                id,
                name: fragment_name.unwrap_or_else(|| format!("HTTP {server}:{port}")),
                protocol: ProxyProtocol::Http,
                server,
                port,
                uuid: None,
                flow: None,
                security: (scheme == "https").then(|| "tls".into()),
                sni: None,
                fingerprint: None,
                public_key: None,
                short_id: None,
                method: None,
                password: pass,
                username: user,
                obfs: None,
                obfs_password: None,
                allow_insecure: Some(false),
                certificate_sha256: pin_sha256,
                expected_ip: None,
                expected_country: None,
                timezone: None,
                locale: None,
                outbound_mode: None,
            })
        }
        other => Err(format!("暂不支持的协议: {other}")),
    }
}

fn parse_ss_uri(raw: &str, id: String, fragment_name: Option<String>) -> Result<NodeProfile, String> {
    let without_prefix = raw.strip_prefix("ss://").ok_or("Invalid ss:// URI")?;
    let before_frag = without_prefix.split('#').next().unwrap_or(without_prefix);
    let before_query = before_frag.split('?').next().unwrap_or(before_frag);

    let (method, password, server, port) = if let Some((left, right)) = before_query.split_once('@') {
        let decoded = decode_b64(left).unwrap_or_else(|_| left.to_string());
        let (m, p) = decoded
            .split_once(':')
            .ok_or("SS userinfo 格式错误，应为 method:password")?;
        let (host, port_str) = right
            .rsplit_once(':')
            .ok_or("SS server:port 格式错误")?;
        let port: u16 = port_str.parse().map_err(|_| "SS 端口无效")?;
        (m.to_string(), p.to_string(), host.trim_matches(['[', ']']).to_string(), port)
    } else {
        let decoded = decode_b64(before_query)?;
        let (cred, hostport) = decoded
            .rsplit_once('@')
            .ok_or("SS 解码内容缺少 @")?;
        let (m, p) = cred.split_once(':').ok_or("SS 解码缺少 method:password")?;
        let (host, port_str) = hostport.rsplit_once(':').ok_or("SS 解码缺少 port")?;
        let port: u16 = port_str.parse().map_err(|_| "SS 端口无效")?;
        (m.to_string(), p.to_string(), host.trim_matches(['[', ']']).to_string(), port)
    };

    Ok(NodeProfile {
        id,
        name: fragment_name.unwrap_or_else(|| format!("SS {server}:{port}")),
        protocol: ProxyProtocol::Shadowsocks,
        server,
        port,
        uuid: None,
        flow: None,
        security: None,
        sni: None,
        fingerprint: None,
        public_key: None,
        short_id: None,
        method: Some(method),
        password: Some(password),
        username: None,
        obfs: None,
        obfs_password: None,
        allow_insecure: None,
        certificate_sha256: None,
        expected_ip: None,
        expected_country: None,
        timezone: None,
        locale: None,
        outbound_mode: None,
    })
}

pub fn generate_vps_script(protocol: &str, port: u16) -> String {
    if protocol == "hysteria2" {
        return format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
bash <(curl -fsSL https://sing-box.app/deb-install.sh)
PASS=$(openssl rand -hex 16)
mkdir -p /etc/sing-box
openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
  -keyout /etc/sing-box/hy2.key -out /etc/sing-box/hy2.crt \
  -subj "/CN=bing.com" -days 3650
cat >/etc/sing-box/config.json <<EOF
{{
  "inbounds": [{{
    "type": "hysteria2",
    "listen": "::",
    "listen_port": {port},
    "users": [{{ "password": "$PASS" }}],
    "tls": {{
      "enabled": true,
      "certificate_path": "/etc/sing-box/hy2.crt",
      "key_path": "/etc/sing-box/hy2.key"
    }}
  }}],
  "outbounds": [{{ "type": "direct" }}]
}}
EOF
systemctl enable --now sing-box
IP=$(curl -4 -fsSL https://api.ipify.org)
PIN=$(openssl x509 -in /etc/sing-box/hy2.crt -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64 -w0)
echo "=== 导入到 AI NetGuard 的节点链接 ==="
echo "hy2://$PASS@$IP:{port}?sni=bing.com&pinSHA256=sha256/$PIN#Seoul-Hy2"
"#
        );
    }

    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail
bash <(curl -fsSL https://sing-box.app/deb-install.sh)
UUID=$(sing-box generate uuid)
KEYS=$(sing-box generate reality-keypair)
PRIV=$(echo "$KEYS" | awk '/PrivateKey/ {{print $2}}')
PUB=$(echo "$KEYS" | awk '/PublicKey/ {{print $2}}')
SID=$(openssl rand -hex 4)
mkdir -p /etc/sing-box
cat >/etc/sing-box/config.json <<EOF
{{
  "inbounds": [{{
    "type": "vless",
    "listen": "::",
    "listen_port": {port},
    "users": [{{ "uuid": "$UUID", "flow": "xtls-rprx-vision" }}],
    "tls": {{
      "enabled": true,
      "server_name": "www.microsoft.com",
      "reality": {{
        "enabled": true,
        "handshake": {{ "server": "www.microsoft.com", "server_port": 443 }},
        "private_key": "$PRIV",
        "short_id": ["$SID"]
      }}
    }}
  }}],
  "outbounds": [{{ "type": "direct" }}]
}}
EOF
systemctl enable --now sing-box
IP=$(curl -4 -fsSL https://api.ipify.org)
echo "=== 导入到 AI NetGuard 的节点链接 ==="
echo "vless://$UUID@$IP:{port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=$PUB&sid=$SID#Seoul-Reality"
"#
    )
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vless_reality_and_socks() {
        let vless = parse_node_uri(
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality&flow=xtls-rprx-vision&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=abcd#Seoul",
        )
        .unwrap();
        assert_eq!(vless.name, "Seoul");
        assert_eq!(vless.protocol, ProxyProtocol::Vless);
        assert_eq!(vless.server, "1.2.3.4");
        assert_eq!(vless.port, 443);
        assert_eq!(vless.public_key.as_deref(), Some("PUBKEY"));
        assert_eq!(vless.short_id.as_deref(), Some("abcd"));

        let socks = parse_node_uri("socks5://user1:pass1@9.8.7.6:1080#StaticISP").unwrap();
        assert_eq!(socks.protocol, ProxyProtocol::Socks);
        assert_eq!(socks.username.as_deref(), Some("user1"));
        assert_eq!(socks.password.as_deref(), Some("pass1"));

        let hy2 = parse_node_uri("hy2://secret@5.6.7.8:8443?sni=bing.com&insecure=1#Hy2").unwrap();
        assert_eq!(hy2.protocol, ProxyProtocol::Hysteria2);
        assert_eq!(hy2.allow_insecure, Some(true));

        let hy2_pinned = parse_node_uri(
            "hy2://secret@5.6.7.8:8443?sni=bing.com&pinSHA256=sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=#Hy2Pin",
        )
        .unwrap();
        assert_eq!(hy2_pinned.allow_insecure, Some(false));
        assert_eq!(
            hy2_pinned.certificate_sha256.as_deref(),
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        );

        let vps = generate_vps_script("hysteria2", 8443);
        assert!(!vps.contains("insecure=1"));
        assert!(vps.contains("pinSHA256=sha256/$PIN"));
    }
}
