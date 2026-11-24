use crate::launcher::pick_free_loopback_port;
use crate::models::{AppConfig, BrowserProfile};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MAX_WS_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BrowserCookieRecord {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<f64>,
    pub http_only: bool,
    pub secure: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
    pub host_only: bool,
    pub session: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CookieDeleteTarget {
    pub name: String,
    pub domain: String,
    pub path: String,
    #[serde(default)]
    pub secure: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileCookiesSnapshot {
    pub profile_id: String,
    pub live_mode: bool,
    pub cookies: Vec<BrowserCookieRecord>,
    pub export_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CookieImportOutcome {
    pub imported_count: usize,
    pub skipped_count: usize,
    pub live_mode: bool,
    pub total_count: usize,
    pub cookies: Vec<BrowserCookieRecord>,
    pub export_json: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CookieParamInput {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawJsonCookie {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default, alias = "expirationDate")]
    expires: Option<f64>,
    #[serde(default, alias = "http_only")]
    http_only: Option<bool>,
    #[serde(default)]
    secure: Option<bool>,
    #[serde(default, alias = "same_site")]
    same_site: Option<String>,
    #[serde(default)]
    session: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct WrappedCookiesObject {
    cookies: Vec<RawJsonCookie>,
}

fn normalize_same_site(raw: Option<&str>) -> Option<String> {
    let s = raw?.trim().to_ascii_lowercase();
    match s.as_str() {
        "lax" => Some("Lax".to_string()),
        "strict" => Some("Strict".to_string()),
        "none" | "no_restriction" => Some("None".to_string()),
        _ => None,
    }
}

fn normalize_expiry_seconds(raw_exp: Option<f64>, is_session: bool) -> Option<f64> {
    if is_session {
        return None;
    }
    let exp = raw_exp?;
    if !exp.is_finite() || exp <= 0.0 {
        return None;
    }
    if exp > 1_000_000_000_000.0 {
        Some(exp / 1000.0)
    } else {
        Some(exp)
    }
}

fn normalize_cookie_param(
    name_raw: &str,
    value_raw: &str,
    domain_raw: Option<&str>,
    url_raw: Option<&str>,
    path_raw: Option<&str>,
    expires_raw: Option<f64>,
    http_only: bool,
    mut secure: bool,
    same_site_raw: Option<&str>,
    session: bool,
) -> Option<CookieParamInput> {
    let name = name_raw.trim().to_string();
    if name.is_empty() {
        return None;
    }
    let mut domain = domain_raw.unwrap_or("").trim().to_string();
    if domain.is_empty() {
        if let Some(u) = url_raw.and_then(|raw| url::Url::parse(raw.trim()).ok()) {
            if let Some(h) = u.host_str() {
                domain = h.to_string();
            }
        }
    }
    if domain.is_empty() {
        return None;
    }
    let mut path = path_raw
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("/")
        .to_string();
    if !path.starts_with('/') {
        path = format!("/{path}");
    }

    let same_site = normalize_same_site(same_site_raw);
    if same_site.as_deref() == Some("None") {
        secure = true;
    }
    if name.starts_with("__Host-") {
        secure = true;
        path = "/".to_string();
        domain = domain.trim_start_matches('.').to_string();
    } else if name.starts_with("__Secure-") {
        secure = true;
    }

    let expires = normalize_expiry_seconds(expires_raw, session);
    Some(CookieParamInput {
        name,
        value: value_raw.to_string(),
        domain,
        path,
        expires,
        http_only: Some(http_only),
        secure: Some(secure),
        same_site,
    })
}

pub fn parse_cookies_input(raw: &str) -> Result<Vec<CookieParamInput>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("请先粘贴 Cookie 内容（支持 AdsPower / EditThisCookie JSON 或 Netscape 格式）".into());
    }

    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        let items: Vec<RawJsonCookie> = if trimmed.starts_with('[') {
            serde_json::from_str(trimmed)
                .map_err(|e| format!("Cookie JSON 数组解析失败: {e}"))?
        } else if let Ok(wrapped) = serde_json::from_str::<WrappedCookiesObject>(trimmed) {
            wrapped.cookies
        } else {
            let single = serde_json::from_str::<RawJsonCookie>(trimmed)
                .map_err(|e| format!("Cookie JSON 解析失败: {e}"))?;
            vec![single]
        };

        let parsed: Vec<CookieParamInput> = items
            .into_iter()
            .filter_map(|item| {
                normalize_cookie_param(
                    item.name.as_deref().unwrap_or(""),
                    item.value.as_deref().unwrap_or(""),
                    item.domain.as_deref(),
                    item.url.as_deref(),
                    item.path.as_deref(),
                    item.expires,
                    item.http_only.unwrap_or(false),
                    item.secure.unwrap_or(false),
                    item.same_site.as_deref(),
                    item.session.unwrap_or(false),
                )
            })
            .collect();

        if parsed.is_empty() {
            return Err("JSON 中未解析到包含有效 name 和 domain 的 Cookie 条目".into());
        }
        return Ok(parsed);
    }

    // Netscape cookies.txt (tab-separated, 7 columns; supports #HttpOnly_ prefix)
    let mut out = Vec::new();
    for line in trimmed.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        let (http_only_prefix, body) = if let Some(rest) = l.strip_prefix("#HttpOnly_") {
            (true, rest)
        } else {
            if l.starts_with('#') {
                continue;
            }
            (false, l)
        };
        let cols: Vec<&str> = body.split('\t').collect();
        if cols.len() < 7 {
            continue;
        }
        let domain = cols[0].trim();
        let path = cols[2].trim();
        let secure = cols[3].trim().eq_ignore_ascii_case("true");
        let expires_raw = cols[4].trim().parse::<f64>().ok();
        let name = cols[5].trim();
        let value = cols[6];
        if let Some(c) = normalize_cookie_param(
            name,
            value,
            Some(domain),
            None,
            Some(path),
            expires_raw,
            http_only_prefix,
            secure,
            None,
            expires_raw.map(|v| v <= 0.0).unwrap_or(false),
        ) {
            out.push(c);
        }
    }

    if out.is_empty() {
        return Err(
            "未识别到有效 Cookie（请粘贴 AdsPower/EditThisCookie 的 JSON 数组，或标准 Netscape 7 列格式）"
                .into(),
        );
    }
    Ok(out)
}

pub fn format_cookies_export_json(cookies: &[BrowserCookieRecord]) -> String {
    let exported: Vec<Value> = cookies
        .iter()
        .map(|c| {
            let same_site_val = match c.same_site.as_deref() {
                Some("None") => Value::String("no_restriction".into()),
                Some("Lax") => Value::String("lax".into()),
                Some("Strict") => Value::String("strict".into()),
                _ => Value::String("unspecified".into()),
            };
            let mut obj = serde_json::Map::new();
            obj.insert("domain".into(), Value::String(c.domain.clone()));
            if let Some(exp) = c.expires {
                obj.insert("expirationDate".into(), json!(exp));
            }
            obj.insert("hostOnly".into(), Value::Bool(c.host_only));
            obj.insert("httpOnly".into(), Value::Bool(c.http_only));
            obj.insert("name".into(), Value::String(c.name.clone()));
            obj.insert("path".into(), Value::String(c.path.clone()));
            obj.insert("sameSite".into(), same_site_val);
            obj.insert("secure".into(), Value::Bool(c.secure));
            obj.insert("session".into(), Value::Bool(c.session));
            obj.insert("value".into(), Value::String(c.value.clone()));
            Value::Object(obj)
        })
        .collect();
    serde_json::to_string_pretty(&exported).unwrap_or_else(|_| "[]".into())
}

fn cdp_value_to_cookie_records(val: &Value) -> Vec<BrowserCookieRecord> {
    let mut records: Vec<BrowserCookieRecord> = val
        .get("cookies")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let name = item.get("name")?.as_str()?.to_string();
                    let value = item.get("value").and_then(Value::as_str).unwrap_or("").to_string();
                    let domain = item.get("domain")?.as_str()?.to_string();
                    let path = item.get("path").and_then(Value::as_str).unwrap_or("/").to_string();
                    let raw_exp = item.get("expires").and_then(Value::as_f64);
                    let session = item
                        .get("session")
                        .and_then(Value::as_bool)
                        .unwrap_or_else(|| raw_exp.map(|e| e <= 0.0).unwrap_or(true));
                    let expires = if session {
                        None
                    } else {
                        raw_exp.filter(|&e| e > 0.0)
                    };
                    let http_only = item.get("httpOnly").and_then(Value::as_bool).unwrap_or(false);
                    let secure = item.get("secure").and_then(Value::as_bool).unwrap_or(false);
                    let same_site = item
                        .get("sameSite")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    let host_only = !domain.starts_with('.');
                    Some(BrowserCookieRecord {
                        name,
                        value,
                        domain,
                        path,
                        expires,
                        http_only,
                        secure,
                        same_site,
                        host_only,
                        session,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    records.sort_by(|a, b| {
        a.domain
            .cmp(&b.domain)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.path.cmp(&b.path))
    });
    records
}

/// Pure-Rust SHA-1 (RFC 3174) strictly for RFC 6455 Sec-WebSocket-Accept handshake.
pub(crate) fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn read_http_response(stream: &mut TcpStream) -> Result<(String, Vec<u8>, Vec<u8>), String> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 64 * 1024 {
            return Err("本地 CDP HTTP 响应头过长".into());
        }
        let n = stream
            .read(&mut tmp)
            .map_err(|e| format!("读取本地 CDP HTTP 响应失败: {e}"))?;
        if n == 0 {
            return Err("本地 CDP HTTP 连接提前关闭".into());
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let header_str = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut remainder = buf[header_end + 4..].to_vec();

    let content_length = header_str
        .lines()
        .find_map(|line| {
            let (k, v) = line.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("content-length") {
                v.trim().parse::<usize>().ok()
            } else {
                None
            }
        });

    let mut body = Vec::new();
    if let Some(len) = content_length {
        if len > MAX_WS_MESSAGE_BYTES {
            return Err("本地 CDP HTTP 响应体过大".into());
        }
        if remainder.len() >= len {
            body.extend_from_slice(&remainder[..len]);
            remainder = remainder[len..].to_vec();
        } else {
            body.extend_from_slice(&remainder);
            remainder.clear();
            while body.len() < len {
                let n = stream
                    .read(&mut tmp)
                    .map_err(|e| format!("读取本地 CDP HTTP 响应体失败: {e}"))?;
                if n == 0 {
                    break;
                }
                let need = (len - body.len()).min(n);
                body.extend_from_slice(&tmp[..need]);
            }
        }
    }

    Ok((header_str, body, remainder))
}

fn fetch_cdp_browser_ws_url(port: u16) -> Result<String, String> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .map_err(|e| format!("连接本地 CDP 端口 127.0.0.1:{port} 失败: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let req = format!(
        "GET /json/version HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("发送 /json/version 请求失败: {e}"))?;

    let (headers, body, _) = read_http_response(&mut stream)?;
    let status_line = headers.lines().next().unwrap_or("");
    if !status_line.contains("200") {
        return Err(format!("本地 CDP /json/version 返回异常: {status_line}"));
    }
    let val: Value = serde_json::from_slice(&body)
        .map_err(|e| format!("解析 /json/version JSON 失败: {e}"))?;
    let ws_url = val
        .get("webSocketDebuggerUrl")
        .and_then(Value::as_str)
        .ok_or_else(|| "CDP /json/version 缺少 webSocketDebuggerUrl".to_string())?;
    Ok(ws_url.to_string())
}

struct LoopbackWsClient {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl LoopbackWsClient {
    fn connect(ws_url_str: &str, expected_port: u16) -> Result<Self, String> {
        let parsed = url::Url::parse(ws_url_str)
            .map_err(|e| format!("无效的 CDP WebSocket URL: {e}"))?;
        if parsed.scheme() != "ws" {
            return Err("CDP WebSocket URL 仅允许 ws:// 协议".into());
        }
        let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
        if host != "127.0.0.1" && host != "localhost" {
            return Err(format!("拒绝连接非回环 CDP WebSocket 主机: {host}"));
        }
        let port = parsed.port().unwrap_or(expected_port);
        if port != expected_port {
            return Err(format!("CDP WebSocket 端口不匹配: 预期 {expected_port}, 实际 {port}"));
        }

        let mut path = parsed.path().to_string();
        if path.is_empty() {
            path = "/".to_string();
        }
        if let Some(q) = parsed.query() {
            path.push('?');
            path.push_str(q);
        }

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
            .map_err(|e| format!("连接 CDP WebSocket 127.0.0.1:{port} 失败: {e}"))?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(12)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(12)));

        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let key_b64 = STANDARD.encode(nonce);

        let handshake = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key_b64}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        stream
            .write_all(handshake.as_bytes())
            .map_err(|e| format!("发送 WebSocket 握手失败: {e}"))?;

        let (headers, _, remainder) = read_http_response(&mut stream)?;
        let status_line = headers.lines().next().unwrap_or("");
        if !status_line.contains("101") {
            return Err(format!("CDP WebSocket 握手未返回 101: {status_line}"));
        }

        let expected_accept = STANDARD.encode(sha1_digest(format!("{key_b64}{WS_GUID}").as_bytes()));
        let accept_ok = headers.lines().any(|line| {
            line.split_once(':').is_some_and(|(k, v)| {
                k.trim().eq_ignore_ascii_case("sec-websocket-accept")
                    && v.trim() == expected_accept
            })
        });
        if !accept_ok {
            return Err("CDP WebSocket Sec-WebSocket-Accept 校验失败".into());
        }

        Ok(Self {
            stream,
            buf: remainder,
        })
    }

    fn read_exact_buffered(&mut self, len: usize) -> Result<Vec<u8>, String> {
        let mut tmp = [0u8; 4096];
        while self.buf.len() < len {
            let n = self
                .stream
                .read(&mut tmp)
                .map_err(|e| format!("读取 WebSocket 数据失败: {e}"))?;
            if n == 0 {
                return Err("CDP WebSocket 连接意外断开".into());
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
        let out: Vec<u8> = self.buf.drain(..len).collect();
        Ok(out)
    }

    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x80 | (opcode & 0x0F));
        let len = payload.len();
        if len <= 125 {
            frame.push(0x80 | (len as u8));
        } else if len <= u16::MAX as usize {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let mut mask = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut mask);
        frame.extend_from_slice(&mask);
        for (i, &b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i % 4]);
        }
        self.stream
            .write_all(&frame)
            .map_err(|e| format!("发送 CDP WebSocket 帧失败: {e}"))?;
        let _ = self.stream.flush();
        Ok(())
    }

    fn send_text(&mut self, text: &str) -> Result<(), String> {
        self.send_frame(0x1, text.as_bytes())
    }

    fn read_text_message(&mut self) -> Result<String, String> {
        let mut assembled: Vec<u8> = Vec::new();
        let mut in_text_fragments = false;

        loop {
            let hdr = self.read_exact_buffered(2)?;
            let fin = (hdr[0] & 0x80) != 0;
            let opcode = hdr[0] & 0x0F;
            let masked = (hdr[1] & 0x80) != 0;
            let mut len = (hdr[1] & 0x7F) as usize;
            if len == 126 {
                let b = self.read_exact_buffered(2)?;
                len = u16::from_be_bytes([b[0], b[1]]) as usize;
            } else if len == 127 {
                let b = self.read_exact_buffered(8)?;
                let len64 = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if len64 > MAX_WS_MESSAGE_BYTES as u64 {
                    return Err("CDP 消息体超出 16MB 安全上限".into());
                }
                len = len64 as usize;
            }
            if assembled.len().saturating_add(len) > MAX_WS_MESSAGE_BYTES {
                return Err("CDP 分片消息累计超出 16MB 安全上限".into());
            }
            let mask_key = if masked {
                Some(self.read_exact_buffered(4)?)
            } else {
                None
            };
            let mut payload = self.read_exact_buffered(len)?;
            if let Some(m) = mask_key {
                for (i, b) in payload.iter_mut().enumerate() {
                    *b ^= m[i % 4];
                }
            }

            match opcode {
                0x8 => {
                    let _ = self.send_frame(0x8, &[]);
                    return Err("CDP WebSocket 会话已关闭".into());
                }
                0x9 => {
                    let _ = self.send_frame(0xA, &payload);
                }
                0xA => {}
                0x1 | 0x2 => {
                    assembled = payload;
                    in_text_fragments = true;
                    if fin {
                        return String::from_utf8(assembled)
                            .map_err(|e| format!("CDP 响应非 UTF-8 文本: {e}"));
                    }
                }
                0x0 => {
                    if !in_text_fragments {
                        return Err("收到未开始的 WebSocket 连续帧".into());
                    }
                    assembled.extend_from_slice(&payload);
                    if fin {
                        return String::from_utf8(assembled)
                            .map_err(|e| format!("CDP 响应非 UTF-8 文本: {e}"));
                    }
                }
                _ => {}
            }
        }
    }

    fn call(&mut self, id: u64, method: &str, params: Value) -> Result<Value, String> {
        let req = json!({
            "id": id,
            "method": method,
            "params": params,
        });
        self.send_text(&req.to_string())?;
        loop {
            let text = self.read_text_message()?;
            let msg: Value = serde_json::from_str(&text)
                .map_err(|e| format!("解析 CDP 响应 JSON 失败: {e}"))?;
            if msg.get("id").and_then(Value::as_u64) == Some(id) {
                if let Some(err) = msg.get("error") {
                    let err_msg = err
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("未知 CDP 错误");
                    return Err(format!("CDP 调用 {method} 失败: {err_msg}"));
                }
                return Ok(msg.get("result").cloned().unwrap_or_else(|| json!({})));
            }
        }
    }
}

fn has_cookie_db(profile_dir: &Path) -> bool {
    profile_dir.join("Default").join("Network").join("Cookies").exists()
        || profile_dir.join("Default").join("Cookies").exists()
}

pub enum CookieOp {
    Get,
    Import {
        raw_text: String,
        replace_existing: bool,
    },
    Delete {
        targets: Vec<CookieDeleteTarget>,
    },
    Clear,
}

pub enum CookieOpResult {
    Snapshot(ProfileCookiesSnapshot),
    Import(CookieImportOutcome),
}

pub fn execute_cookie_op_blocking(
    cfg: &AppConfig,
    profile: &BrowserProfile,
    exe_path: &Path,
    profile_dir: &Path,
    live_cdp_port: Option<u16>,
    op: CookieOp,
) -> Result<CookieOpResult, String> {
    let live_mode = live_cdp_port.is_some();

    // Fast path for brand-new profiles that have never launched or imported cookies yet.
    if !live_mode && !has_cookie_db(profile_dir) {
        match &op {
            CookieOp::Get | CookieOp::Clear => {
                return Ok(CookieOpResult::Snapshot(ProfileCookiesSnapshot {
                    profile_id: profile.id.clone(),
                    live_mode: false,
                    cookies: Vec::new(),
                    export_json: "[]".into(),
                }));
            }
            CookieOp::Delete { .. } => {
                return Ok(CookieOpResult::Snapshot(ProfileCookiesSnapshot {
                    profile_id: profile.id.clone(),
                    live_mode: false,
                    cookies: Vec::new(),
                    export_json: "[]".into(),
                }));
            }
            CookieOp::Import { .. } => {}
        }
    }

    let parsed_import = match &op {
        CookieOp::Import { raw_text, .. } => Some(parse_cookies_input(raw_text)?),
        _ => None,
    };

    let _unused_cfg = cfg;
    let mut headless_child = None;
    let cdp_port = if let Some(port) = live_cdp_port {
        port
    } else {
        std::fs::create_dir_all(profile_dir).map_err(|e| e.to_string())?;
        let port = pick_free_loopback_port()?;
        let mut cmd = Command::new(exe_path);
        cmd.arg(format!("--user-data-dir={}", profile_dir.display()))
            .arg("--headless=new")
            .arg("--disable-gpu")
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--disable-sync")
            .arg("--disable-background-networking")
            .arg("--disable-extensions")
            .arg("--proxy-server=http://127.0.0.1:1")
            .arg("--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1")
            .arg("--force-webrtc-ip-handling-policy")
            .arg("--webrtc-ip-handling-policy=disable_non_proxied_udp")
            .arg("--disable-quic")
            .arg(format!("--remote-debugging-port={port}"))
            .arg("--remote-debugging-address=127.0.0.1")
            .arg("about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW);

        let child = cmd.spawn().map_err(|e| {
            format!(
                "启动离线 Cookie 读写进程失败（{}）: {e}",
                exe_path.display()
            )
        })?;
        headless_child = Some(child);
        port
    };

    let op_res = (|| -> Result<CookieOpResult, String> {
        let mut ws_url = None;
        let deadline = Instant::now() + Duration::from_secs(7);
        while Instant::now() < deadline {
            if let Some(child) = headless_child.as_mut() {
                if let Ok(Some(status)) = child.try_wait() {
                    return Err(format!(
                        "离线 Cookie 进程提前退出 ({status})；请确认该环境浏览器窗口已关闭后再试"
                    ));
                }
            }
            if let Ok(url) = fetch_cdp_browser_ws_url(cdp_port) {
                ws_url = Some(url);
                break;
            }
            std::thread::sleep(Duration::from_millis(120));
        }

        let ws_url = ws_url.ok_or_else(|| {
            format!("等待本地 CDP Cookie 通道就绪超时 (127.0.0.1:{cdp_port})")
        })?;
        let mut ws = LoopbackWsClient::connect(&ws_url, cdp_port)?;
        let mut next_id = 1u64;

        let out = match op {
            CookieOp::Get => {
                let res = ws.call(next_id, "Storage.getCookies", json!({}))?;
                next_id += 1;
                let cookies = cdp_value_to_cookie_records(&res);
                let export_json = format_cookies_export_json(&cookies);
                CookieOpResult::Snapshot(ProfileCookiesSnapshot {
                    profile_id: profile.id.clone(),
                    live_mode,
                    cookies,
                    export_json,
                })
            }
            CookieOp::Clear => {
                ws.call(next_id, "Storage.clearCookies", json!({}))?;
                next_id += 1;
                let res = ws.call(next_id, "Storage.getCookies", json!({}))?;
                next_id += 1;
                let cookies = cdp_value_to_cookie_records(&res);
                let export_json = format_cookies_export_json(&cookies);
                CookieOpResult::Snapshot(ProfileCookiesSnapshot {
                    profile_id: profile.id.clone(),
                    live_mode,
                    cookies,
                    export_json,
                })
            }
            CookieOp::Delete { targets } => {
                for target in targets {
                    let clean_name = target.name.trim();
                    let clean_domain = target.domain.trim();
                    let clean_path = if target.path.trim().is_empty() {
                        "/"
                    } else {
                        target.path.trim()
                    };
                    if clean_name.is_empty() || clean_domain.is_empty() {
                        continue;
                    }
                    let need_secure = target.secure.unwrap_or(false)
                        || clean_name.starts_with("__Host-")
                        || clean_name.starts_with("__Secure-");
                    let mut cookie_obj = serde_json::Map::new();
                    cookie_obj.insert("name".into(), Value::String(clean_name.to_string()));
                    cookie_obj.insert("value".into(), Value::String(String::new()));
                    cookie_obj.insert("domain".into(), Value::String(clean_domain.to_string()));
                    cookie_obj.insert("path".into(), Value::String(clean_path.to_string()));
                    cookie_obj.insert("expires".into(), json!(1));
                    if need_secure {
                        cookie_obj.insert("secure".into(), Value::Bool(true));
                    }
                    let _ = ws.call(
                        next_id,
                        "Storage.setCookies",
                        json!({ "cookies": [Value::Object(cookie_obj)] }),
                    );
                    next_id += 1;
                }
                let res = ws.call(next_id, "Storage.getCookies", json!({}))?;
                next_id += 1;
                let cookies = cdp_value_to_cookie_records(&res);
                let export_json = format_cookies_export_json(&cookies);
                CookieOpResult::Snapshot(ProfileCookiesSnapshot {
                    profile_id: profile.id.clone(),
                    live_mode,
                    cookies,
                    export_json,
                })
            }
            CookieOp::Import {
                replace_existing, ..
            } => {
                let import_list = parsed_import.unwrap_or_default();
                if replace_existing {
                    ws.call(next_id, "Storage.clearCookies", json!({}))?;
                    next_id += 1;
                }

                let mut imported_count = 0usize;
                let mut skipped_count = 0usize;
                let mut first_warning: Option<String> = None;

                let bulk_val = serde_json::to_value(&import_list).map_err(|e| e.to_string())?;
                if ws
                    .call(next_id, "Storage.setCookies", json!({ "cookies": bulk_val }))
                    .is_ok()
                {
                    next_id += 1;
                    imported_count = import_list.len();
                } else {
                    next_id += 1;
                    for cookie in &import_list {
                        let single_val =
                            serde_json::to_value(cookie).map_err(|e| e.to_string())?;
                        match ws.call(
                            next_id,
                            "Storage.setCookies",
                            json!({ "cookies": [single_val] }),
                        ) {
                            Ok(_) => imported_count += 1,
                            Err(err) => {
                                skipped_count += 1;
                                if first_warning.is_none() {
                                    first_warning = Some(format!(
                                        "部分 Cookie ({}@{}): {err}",
                                        cookie.name, cookie.domain
                                    ));
                                }
                            }
                        }
                        next_id += 1;
                    }
                }

                let res = ws.call(next_id, "Storage.getCookies", json!({}))?;
                next_id += 1;
                let cookies = cdp_value_to_cookie_records(&res);
                let export_json = format_cookies_export_json(&cookies);
                let total_count = cookies.len();
                CookieOpResult::Import(CookieImportOutcome {
                    imported_count,
                    skipped_count,
                    live_mode,
                    total_count,
                    cookies,
                    export_json,
                    warning: first_warning,
                })
            }
        };

        if !live_mode {
            let _ = ws.call(next_id, "Browser.close", json!({}));
        } else {
            let _ = ws.send_frame(0x8, &[]);
        }
        Ok(out)
    })();

    if let Some(mut child) = headless_child {
        let exit_deadline = Instant::now() + Duration::from_secs(4);
        let mut exited = false;
        while Instant::now() < exit_deadline {
            match child.try_wait() {
                Ok(Some(_)) => {
                    exited = true;
                    break;
                }
                _ => std::thread::sleep(Duration::from_millis(80)),
            }
        }
        if !exited {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    op_res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_matches_rfc6455_websocket_accept_vector() {
        // RFC 6455 Section 1.3 official test vector
        let combined = format!("dGhlIHNhbXBsZSBub25jZQ=={WS_GUID}");
        let accept = STANDARD.encode(sha1_digest(combined.as_bytes()));
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn parse_cookies_accepts_adspower_json_and_netscape_with_httponly() {
        let json_raw = r#"[
          {
            "domain": ".google.com",
            "expirationDate": 1800000000,
            "httpOnly": true,
            "name": "SID",
            "path": "/",
            "sameSite": "no_restriction",
            "secure": false,
            "value": "val_sid"
          },
          {
            "url": "https://claude.ai/chats",
            "name": "sessionKey",
            "value": "sk-ant-123",
            "sameSite": "lax"
          }
        ]"#;
        let parsed = parse_cookies_input(json_raw).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "SID");
        assert_eq!(parsed[0].domain, ".google.com");
        assert_eq!(parsed[0].same_site.as_deref(), Some("None"));
        assert_eq!(parsed[0].secure, Some(true));
        assert_eq!(parsed[0].http_only, Some(true));
        assert_eq!(parsed[1].domain, "claude.ai");
        assert_eq!(parsed[1].same_site.as_deref(), Some("Lax"));

        let netscape_raw = "# Netscape HTTP Cookie File\n\
            #HttpOnly_.accounts.google.com\tTRUE\t/\tTRUE\t1800000100\tHSID\tabc-xyz\n\
            example.com\tFALSE\t/app\tFALSE\t0\tpref\tlight\n";
        let ns_parsed = parse_cookies_input(netscape_raw).unwrap();
        assert_eq!(ns_parsed.len(), 2);
        assert_eq!(ns_parsed[0].domain, ".accounts.google.com");
        assert_eq!(ns_parsed[0].http_only, Some(true));
        assert_eq!(ns_parsed[0].secure, Some(true));
        assert_eq!(ns_parsed[1].expires, None);
        assert_eq!(ns_parsed[1].path, "/app");
    }

    #[test]
    fn parse_cookies_normalizes_host_and_secure_prefixes_and_ms_timestamps() {
        let raw = r#"{
          "cookies": [
            {
              "name": "__Host-next-auth",
              "value": "tok",
              "domain": ".example.com",
              "path": "/custom",
              "expires": 1800000000000,
              "secure": false
            }
          ]
        }"#;
        let parsed = parse_cookies_input(raw).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].domain, "example.com");
        assert_eq!(parsed[0].path, "/");
        assert_eq!(parsed[0].secure, Some(true));
        assert_eq!(parsed[0].expires, Some(1_800_000_000.0));
    }

    #[test]
    fn format_cookies_export_json_roundtrips_cleanly() {
        let records = vec![BrowserCookieRecord {
            name: "sessionKey".into(),
            value: "secret-val".into(),
            domain: ".claude.ai".into(),
            path: "/".into(),
            expires: Some(1_850_000_000.0),
            http_only: true,
            secure: true,
            same_site: Some("Lax".into()),
            host_only: false,
            session: false,
        }];
        let json_str = format_cookies_export_json(&records);
        let reparsed = parse_cookies_input(&json_str).unwrap();
        assert_eq!(reparsed.len(), 1);
        assert_eq!(reparsed[0].name, "sessionKey");
        assert_eq!(reparsed[0].value, "secret-val");
        assert_eq!(reparsed[0].domain, ".claude.ai");
        assert_eq!(reparsed[0].same_site.as_deref(), Some("Lax"));
        assert_eq!(reparsed[0].http_only, Some(true));
    }
}
