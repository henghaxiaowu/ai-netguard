use crate::models::ExitIpInfo;
use reqwest::Proxy;
use serde::Deserialize;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

#[derive(Debug, Clone)]
pub struct PhysicalNicInfo {
    pub name: String,
    pub if_index: u32,
    pub gateway_ip: String,
    pub metric: u32,
}

const VIRTUAL_KEYWORDS: &[&str] = &[
    "wintun",
    "wireguard",
    "clash",
    "mihomo",
    "sing-box",
    "tap-windows",
    "openvpn",
    "tailscale",
    "anyconnect",
    "fortinet",
    "globalprotect",
    "hyper-v",
    "vethernet",
    "vmware",
    "virtualbox",
    "loopback",
    "pseudo",
];

pub fn detect_physical_nic() -> Option<PhysicalNicInfo> {
    unsafe {
        let mut size: u32 = 16 * 1024;
        let mut buf: Vec<u8> = vec![0; size as usize];
        let mut ret = GetAdaptersAddresses(
            AF_INET.0 as u32,
            GAA_FLAG_INCLUDE_GATEWAYS,
            None,
            Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
            &mut size,
        );

        if ret == ERROR_BUFFER_OVERFLOW.0 {
            buf.resize(size as usize, 0);
            ret = GetAdaptersAddresses(
                AF_INET.0 as u32,
                GAA_FLAG_INCLUDE_GATEWAYS,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            );
        }

        if ret != ERROR_SUCCESS.0 {
            return None;
        }

        let mut candidates = Vec::new();
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            let adapter = &*cur;
            if adapter.OperStatus == IfOperStatusUp {
                let name = adapter.FriendlyName.to_string().unwrap_or_default();
                let desc = adapter.Description.to_string().unwrap_or_default();
                let combined_lower = format!("{} {}", name.to_lowercase(), desc.to_lowercase());
                let is_virtual = VIRTUAL_KEYWORDS.iter().any(|kw| combined_lower.contains(kw));

                if !is_virtual && !adapter.FirstGatewayAddress.is_null() {
                    let gw_addr = &*adapter.FirstGatewayAddress;
                    if !gw_addr.Address.lpSockaddr.is_null()
                        && (*gw_addr.Address.lpSockaddr).sa_family == AF_INET
                    {
                        let sin = &*(gw_addr.Address.lpSockaddr as *const SOCKADDR_IN);
                        let bytes = sin.sin_addr.S_un.S_addr.to_ne_bytes();
                        let gw_ip = Ipv4Addr::from(bytes);
                        if !gw_ip.is_unspecified() {
                            candidates.push(PhysicalNicInfo {
                                name,
                                if_index: adapter.Anonymous1.Anonymous.IfIndex,
                                gateway_ip: gw_ip.to_string(),
                                metric: adapter.Ipv4Metric,
                            });
                        }
                    }
                }
            }
            cur = adapter.Next;
        }

        candidates.sort_by_key(|c| c.metric);
        candidates.into_iter().next()
    }
}

pub fn detect_running_vpn_conflicts() -> Vec<String> {
    let known = [
        ("clash-verge.exe", "Clash Verge"),
        ("clash-verge-service.exe", "Clash Verge Service"),
        ("mihomo.exe", "Mihomo"),
        ("clash.exe", "Clash"),
        ("v2rayn.exe", "v2rayN"),
        ("xray.exe", "Xray"),
        ("nekoray.exe", "NekoRay"),
        ("wireguard.exe", "WireGuard"),
        ("openvpn.exe", "OpenVPN"),
        ("vpnui.exe", "Cisco AnyConnect"),
        ("pangpa.exe", "GlobalProtect"),
        ("tailscaled.exe", "Tailscale"),
    ];

    let mut found = Vec::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return found;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let end = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let exe = String::from_utf16_lossy(&entry.szExeFile[..end]).to_lowercase();
                for (proc_name, label) in known {
                    if exe == proc_name && !found.iter().any(|x| x == label) {
                        found.push(label.to_string());
                    }
                }
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    found
}

pub fn resolve_server_ipv4(host: &str) -> Result<String, String> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip.to_string());
    }
    let addrs = (host, 0)
        .to_socket_addrs()
        .map_err(|e| format!("无法解析服务器域名 {host}: {e}"))?;
    for addr in addrs {
        if let std::net::IpAddr::V4(v4) = addr.ip() {
            let oct = v4.octets();
            let is_clash_fake_ip = oct[0] == 198 && (oct[1] == 18 || oct[1] == 19);
            if !is_clash_fake_ip {
                return Ok(v4.to_string());
            }
        }
    }
    Err(format!(
        "解析 {host} 仅获取到虚拟 Fake-IP (198.18.0.0/15)，建议节点直接填写服务器 IP"
    ))
}

#[derive(Deserialize)]
struct IpWhoisResp {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    ip: String,
    country: Option<String>,
    country_code: Option<String>,
    region: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    timezone: Option<IpWhoisTz>,
    connection: Option<IpWhoisConn>,
}

#[derive(Deserialize)]
struct IpApiCoResp {
    ip: String,
    country_name: Option<String>,
    country_code: Option<String>,
    region: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    timezone: Option<String>,
    org: Option<String>,
    asn: Option<String>,
}

#[derive(Deserialize)]
struct IpSbResp {
    ip: String,
    country: Option<String>,
    country_code: Option<String>,
    region: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    timezone: Option<String>,
    isp: Option<String>,
    organization: Option<String>,
    asn: Option<u64>,
}

#[derive(Deserialize)]
struct IpWhoisTz {
    id: Option<String>,
}

#[derive(Deserialize)]
struct IpWhoisConn {
    asn: Option<u64>,
    org: Option<String>,
    isp: Option<String>,
}

#[derive(Deserialize)]
struct IpifyResp {
    ip: String,
}

pub async fn probe_exit_ip(socks_port: u16) -> Result<ExitIpInfo, String> {
    let proxy = Proxy::all(format!("socks5h://127.0.0.1:{socks_port}"))
        .map_err(|e| format!("构造代理探针失败: {e}"))?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("构建 HTTP 探针客户端失败: {e}"))?;

    let started = Instant::now();
    if let Ok(resp) = client.get("https://ipwho.is/").send().await {
        if resp.status().is_success() {
            if let Ok(parsed) = resp.json::<IpWhoisResp>().await {
                if parsed.success.unwrap_or(true) && !parsed.ip.trim().is_empty() {
                    return Ok(ExitIpInfo {
                        ip: parsed.ip,
                        country: parsed.country,
                        country_code: parsed.country_code,
                        region: parsed.region,
                        city: parsed.city,
                        latitude: parsed.latitude,
                        longitude: parsed.longitude,
                        timezone: parsed.timezone.and_then(|t| t.id),
                        isp: parsed.connection.as_ref().and_then(|c| c.isp.clone()),
                        org: parsed.connection.as_ref().and_then(|c| c.org.clone()),
                        asn: parsed
                            .connection
                            .as_ref()
                            .and_then(|c| c.asn.map(|a| format!("AS{a}"))),
                        latency_ms: Some(started.elapsed().as_millis() as u64),
                        verified_at: chrono::Local::now().format("%H:%M:%S").to_string(),
                    });
                }
            }
        }
    }

    let started_geo2 = Instant::now();
    if let Ok(resp) = client.get("https://api.ip.sb/geoip").send().await {
        if resp.status().is_success() {
            if let Ok(parsed) = resp.json::<IpSbResp>().await {
                if !parsed.ip.trim().is_empty() {
                    return Ok(ExitIpInfo {
                        ip: parsed.ip,
                        country: parsed.country,
                        country_code: parsed.country_code,
                        region: parsed.region,
                        city: parsed.city,
                        latitude: parsed.latitude,
                        longitude: parsed.longitude,
                        timezone: parsed.timezone,
                        isp: parsed.isp,
                        org: parsed.organization,
                        asn: parsed.asn.map(|a| format!("AS{a}")),
                        latency_ms: Some(started_geo2.elapsed().as_millis() as u64),
                        verified_at: chrono::Local::now().format("%H:%M:%S").to_string(),
                    });
                }
            }
        }
    }

    let started_geo3 = Instant::now();
    if let Ok(resp) = client.get("https://ipapi.co/json/").send().await {
        if resp.status().is_success() {
            if let Ok(parsed) = resp.json::<IpApiCoResp>().await {
                if !parsed.ip.trim().is_empty() {
                    return Ok(ExitIpInfo {
                        ip: parsed.ip,
                        country: parsed.country_name,
                        country_code: parsed.country_code,
                        region: parsed.region,
                        city: parsed.city,
                        latitude: parsed.latitude,
                        longitude: parsed.longitude,
                        timezone: parsed.timezone,
                        isp: parsed.org.clone(),
                        org: parsed.org,
                        asn: parsed.asn,
                        latency_ms: Some(started_geo3.elapsed().as_millis() as u64),
                        verified_at: chrono::Local::now().format("%H:%M:%S").to_string(),
                    });
                }
            }
        }
    }

    let started2 = Instant::now();
    let resp = client
        .get("https://api.ipify.org?format=json")
        .send()
        .await
        .map_err(|e| format!("代理出口探测超时或被阻断: {e}"))?;
    let parsed = resp
        .json::<IpifyResp>()
        .await
        .map_err(|e| format!("出口 IP 解析失败: {e}"))?;
    Ok(ExitIpInfo {
        ip: parsed.ip,
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
        latency_ms: Some(started2.elapsed().as_millis() as u64),
        verified_at: chrono::Local::now().format("%H:%M:%S").to_string(),
    })
}

pub async fn check_anthropic_via_http_proxy(http_port: u16) -> Result<u16, String> {
    let proxy = Proxy::all(format!("http://127.0.0.1:{http_port}"))
        .map_err(|e| format!("HTTP 代理初始化失败: {e}"))?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(7))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get("https://api.anthropic.com/")
        .send()
        .await
        .map_err(|e| format!("通过本地端口 {http_port} 访问 Anthropic 失败: {e}"))?;
    Ok(resp.status().as_u16())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_nic_detection_runs_cleanly() {
        let nic = detect_physical_nic();
        let conflicts = detect_running_vpn_conflicts();
        println!("NIC={nic:?}, conflicts={conflicts:?}");
        assert!(nic.is_some(), "expected at least one active physical adapter");
    }

    #[test]
    fn ipwhois_response_parses_coordinates() {
        let sample = r#"{
            "ip": "203.0.113.10",
            "country": "South Korea",
            "country_code": "KR",
            "region": "Seoul",
            "city": "Seoul",
            "latitude": 37.566535,
            "longitude": 126.9779692,
            "timezone": { "id": "Asia/Seoul" },
            "connection": { "asn": 64512, "org": "Example Transit", "isp": "Example Transit" }
        }"#;
        let parsed: IpWhoisResp = serde_json::from_str(sample).unwrap();
        assert_eq!(parsed.ip, "203.0.113.10");
        assert!((parsed.latitude.unwrap() - 37.566535).abs() < 1e-6);
        assert!((parsed.longitude.unwrap() - 126.9779692).abs() < 1e-6);
    }
}
