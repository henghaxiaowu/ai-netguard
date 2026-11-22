use crate::accounts::{dpapi_decrypt, dpapi_encrypt};
use crate::models::app_data_dir;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const ADSPOWER_VAULT_FILE: &str = "adspower.vault";
const VAULT_FORMAT: &str = "dpapi-v1";
const VAULT_VERSION: u32 = 1;
pub const DEFAULT_ADSPOWER_BASE_URL: &str = "http://127.0.0.1:50325";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdsPowerSettingsDisk {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default)]
    pub api_key: String,
}

fn default_base_url() -> String {
    DEFAULT_ADSPOWER_BASE_URL.to_string()
}

impl Default for AdsPowerSettingsDisk {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_ADSPOWER_BASE_URL.to_string(),
            api_key: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdsPowerConfigStatus {
    pub base_url: String,
    pub has_api_key: bool,
    pub api_key_masked: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdsPowerProfileItem {
    pub user_id: String,
    pub serial_number: String,
    pub name: String,
    pub group_name: String,
    pub remark: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AdsPowerProfilesSnapshot {
    pub connected: bool,
    pub base_url: String,
    pub profiles: Vec<AdsPowerProfileItem>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdsPowerStartResult {
    pub user_id: Option<String>,
    pub serial_number: Option<String>,
    pub debug_port: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultEnvelope {
    version: u32,
    format: String,
    payload: String,
}

pub fn vault_path() -> PathBuf {
    app_data_dir().join(ADSPOWER_VAULT_FILE)
}

/// Restrict AdsPower Local API URL to loopback HTTP origins only so an API key
/// cannot be exfiltrated to a remote server.
pub fn normalize_base_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(DEFAULT_ADSPOWER_BASE_URL.to_string());
    }
    let parsed = url::Url::parse(trimmed).map_err(|_| {
        "AdsPower Local API 地址格式无效，应类似 http://127.0.0.1:50325".to_string()
    })?;
    if parsed.scheme() != "http" {
        return Err("安全限制：AdsPower Local API 仅支持 http:// 本机地址".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("安全限制：AdsPower 地址不得包含内嵌认证信息".into());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "AdsPower 地址缺少主机名".to_string())?
        .to_ascii_lowercase();
    if host != "127.0.0.1" && host != "localhost" && host != "local.adspower.net" {
        return Err(format!(
            "安全限制：为防止 API Key 泄漏，仅允许本机环回地址 (127.0.0.1 / localhost / local.adspower.net)，已拒绝 {host}"
        ));
    }
    let port = parsed.port().unwrap_or(50325);
    if port == 0 {
        return Err("AdsPower Local API 端口号无效".into());
    }
    Ok(format!("http://{host}:{port}"))
}

/// Resolve any allowed loopback host to `http://127.0.0.1:<port>` so local HTTP calls
/// bypass DNS resolution and never depend on external resolvers.
pub fn request_base_url(normalized: &str) -> Result<String, String> {
    let clean = normalize_base_url(normalized)?;
    let parsed = url::Url::parse(&clean).map_err(|_| "AdsPower 地址解析失败".to_string())?;
    let port = parsed.port().unwrap_or(50325);
    Ok(format!("http://127.0.0.1:{port}"))
}

pub fn mask_api_key(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() >= 10 {
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[chars.len() - 4..].iter().collect();
        Some(format!("{head}••••••{tail}"))
    } else {
        Some("••••••".to_string())
    }
}

pub fn to_config_status(settings: &AdsPowerSettingsDisk) -> AdsPowerConfigStatus {
    let base_url = normalize_base_url(&settings.base_url)
        .unwrap_or_else(|_| DEFAULT_ADSPOWER_BASE_URL.to_string());
    let key = settings.api_key.trim();
    AdsPowerConfigStatus {
        base_url,
        has_api_key: !key.is_empty(),
        api_key_masked: mask_api_key(key),
    }
}

pub fn load_settings_from_path(path: &Path) -> Result<AdsPowerSettingsDisk, String> {
    if !path.exists() {
        return Ok(AdsPowerSettingsDisk::default());
    }
    let raw = fs::read_to_string(path).map_err(|e| format!("读取 AdsPower 配置失败: {e}"))?;
    if raw.trim().is_empty() {
        return Ok(AdsPowerSettingsDisk::default());
    }
    let envelope: VaultEnvelope =
        serde_json::from_str(&raw).map_err(|e| format!("解析 AdsPower 配置信封失败: {e}"))?;
    if envelope.format != VAULT_FORMAT {
        return Err(format!("不支持的 AdsPower 加密格式: {}", envelope.format));
    }
    let encrypted = STANDARD
        .decode(envelope.payload.trim())
        .map_err(|e| format!("解码 AdsPower 密文失败: {e}"))?;
    let decrypted = dpapi_decrypt(&encrypted)?;
    let mut parsed: AdsPowerSettingsDisk =
        serde_json::from_slice(&decrypted).map_err(|e| format!("解析 AdsPower 配置内容失败: {e}"))?;
    parsed.base_url = normalize_base_url(&parsed.base_url)
        .unwrap_or_else(|_| DEFAULT_ADSPOWER_BASE_URL.to_string());
    parsed.api_key = parsed.api_key.trim().to_string();
    Ok(parsed)
}

pub fn save_settings_to_path(
    path: &Path,
    settings: &AdsPowerSettingsDisk,
) -> Result<AdsPowerSettingsDisk, String> {
    let clean = AdsPowerSettingsDisk {
        base_url: normalize_base_url(&settings.base_url)?,
        api_key: settings.api_key.trim().to_string(),
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建 AdsPower 配置目录失败: {e}"))?;
    }
    let plaintext =
        serde_json::to_vec(&clean).map_err(|e| format!("序列化 AdsPower 配置失败: {e}"))?;
    let encrypted = dpapi_encrypt(&plaintext)?;
    let envelope = VaultEnvelope {
        version: VAULT_VERSION,
        format: VAULT_FORMAT.to_string(),
        payload: STANDARD.encode(encrypted),
    };
    let json = serde_json::to_string_pretty(&envelope)
        .map_err(|e| format!("生成 AdsPower 信封失败: {e}"))?;
    let tmp_path = path.with_extension("vault.tmp");
    fs::write(&tmp_path, json).map_err(|e| format!("写入 AdsPower 临时配置失败: {e}"))?;
    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("原子保存 AdsPower 配置失败: {e}")
    })?;
    Ok(clean)
}

pub fn load_settings() -> Result<AdsPowerSettingsDisk, String> {
    load_settings_from_path(&vault_path())
}

pub fn save_settings(settings: &AdsPowerSettingsDisk) -> Result<AdsPowerSettingsDisk, String> {
    save_settings_to_path(&vault_path(), settings)
}

fn build_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|e| format!("初始化 AdsPower HTTP 客户端失败: {e}"))
}

fn apply_auth(req: reqwest::RequestBuilder, api_key: &str) -> reqwest::RequestBuilder {
    let trimmed = api_key.trim();
    if trimmed.is_empty() {
        req
    } else {
        req.bearer_auth(trimmed)
    }
}

fn is_auth_error_msg(status_code: reqwest::StatusCode, msg: &str) -> bool {
    if status_code == reqwest::StatusCode::UNAUTHORIZED || status_code == reqwest::StatusCode::FORBIDDEN
    {
        return true;
    }
    let lower = msg.to_ascii_lowercase();
    lower.contains("api key")
        || lower.contains("apikey")
        || lower.contains("unauthorized")
        || lower.contains("token")
        || msg.contains("密钥")
        || msg.contains("认证")
        || msg.contains("权限")
}

fn map_connect_error(display_base: &str, err: reqwest::Error) -> String {
    if err.is_connect() {
        format!(
            "无法连接 AdsPower Local API ({display_base})，请确认 AdsPower 客户端已打开且在设置中启用了 Local API"
        )
    } else if err.is_timeout() {
        format!("连接 AdsPower Local API ({display_base}) 超时，请检查本地客户端是否卡死或端口不一致")
    } else {
        format!("请求 AdsPower Local API ({display_base}) 失败: {err}")
    }
}

fn json_str_or_num(val: Option<&Value>) -> String {
    match val {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

pub fn parse_user_list_page(val: &Value) -> Result<(Vec<AdsPowerProfileItem>, bool), String> {
    let code = val.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 0 {
        let msg = val
            .get("msg")
            .and_then(Value::as_str)
            .unwrap_or("未知错误")
            .trim();
        if is_auth_error_msg(reqwest::StatusCode::OK, msg) {
            return Err(format!("AdsPower API Key 校验失败（{msg}），请在「AdsPower API」设置中核对密钥"));
        }
        return Err(format!("AdsPower 返回异常 (code={code}): {msg}"));
    }

    let list = val
        .get("data")
        .and_then(|d| d.get("list"))
        .and_then(Value::as_array)
        .ok_or_else(|| "AdsPower user/list 响应缺少 data.list 字段".to_string())?;

    let mut out = Vec::with_capacity(list.len());
    for item in list {
        let user_id = json_str_or_num(item.get("user_id"));
        if user_id.is_empty() {
            continue;
        }
        let serial_number = json_str_or_num(item.get("serial_number"))
            .trim_start_matches('#')
            .trim()
            .to_string();
        let name = json_str_or_num(item.get("name"));
        let group_name = json_str_or_num(item.get("group_name"));
        let remark = json_str_or_num(item.get("remark"));
        out.push(AdsPowerProfileItem {
            user_id,
            serial_number,
            name,
            group_name,
            remark,
        });
    }

    let has_more = out.len() >= 100;
    Ok((out, has_more))
}

async fn parse_adspower_json(
    resp: reqwest::Response,
    display_base: &str,
) -> Result<Value, String> {
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("读取 AdsPower ({display_base}) 响应失败: {e}"))?;
    let val: Value = serde_json::from_str(&text).map_err(|e| {
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return "AdsPower API Key 校验失败（HTTP 认证被拒），请核对「AdsPower API」中的密钥"
                .to_string();
        }
        format!("解析 AdsPower JSON 响应失败 (HTTP {}): {e}", status.as_u16())
    })?;
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        let msg = val.get("msg").and_then(Value::as_str).unwrap_or("");
        return Err(format!(
            "AdsPower API Key 校验失败（{msg}），请在「AdsPower API」设置中重新填入正确的 API Key"
        ));
    }
    Ok(val)
}

pub async fn test_connection(settings: &AdsPowerSettingsDisk) -> Result<String, String> {
    let display_base = normalize_base_url(&settings.base_url)?;
    let req_base = request_base_url(&display_base)?;
    let client = build_client()?;
    let url = format!("{req_base}/status");
    let resp = apply_auth(client.get(&url), &settings.api_key)
        .send()
        .await
        .map_err(|e| map_connect_error(&display_base, e))?;
    let val = parse_adspower_json(resp, &display_base).await?;
    let code = val.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 0 {
        let msg = val.get("msg").and_then(Value::as_str).unwrap_or("连接被拒绝");
        if is_auth_error_msg(reqwest::StatusCode::OK, msg) {
            return Err(format!(
                "AdsPower API Key 校验失败（{msg}），请检查「AdsPower -> API」里的密钥是否正确"
            ));
        }
        return Err(format!("AdsPower 状态检测失败 (code={code}): {msg}"));
    }
    Ok(format!("已连接 AdsPower Local API ({display_base})，鉴权通过"))
}

pub async fn list_profiles(
    settings: &AdsPowerSettingsDisk,
) -> Result<AdsPowerProfilesSnapshot, String> {
    let display_base = normalize_base_url(&settings.base_url)?;
    let req_base = request_base_url(&display_base)?;
    let client = build_client()?;

    let mut all = Vec::new();
    for page in 1..=5u32 {
        let url = format!("{req_base}/api/v1/user/list?page={page}&page_size=100");
        let resp = apply_auth(client.get(&url), &settings.api_key)
            .send()
            .await
            .map_err(|e| map_connect_error(&display_base, e))?;
        let val = parse_adspower_json(resp, &display_base).await?;
        let (mut items, has_more) = parse_user_list_page(&val)?;
        all.append(&mut items);
        if !has_more {
            break;
        }
        if page < 5 {
            tokio::time::sleep(Duration::from_millis(1050)).await;
        }
    }

    Ok(AdsPowerProfilesSnapshot {
        connected: true,
        base_url: display_base,
        profiles: all,
        error: None,
    })
}

pub async fn start_browser(
    settings: &AdsPowerSettingsDisk,
    user_id: Option<&str>,
    serial_number: Option<&str>,
) -> Result<AdsPowerStartResult, String> {
    let display_base = normalize_base_url(&settings.base_url)?;
    let req_base = request_base_url(&display_base)?;
    let clean_uid = user_id.map(str::trim).filter(|s| !s.is_empty());
    let clean_sn = serial_number
        .map(|s| s.trim().trim_start_matches('#').trim())
        .filter(|s| !s.is_empty());

    if clean_uid.is_none() && clean_sn.is_none() {
        return Err("未指定 AdsPower 环境 user_id 或窗口序号".into());
    }

    let mut endpoint = url::Url::parse(&format!("{req_base}/api/v1/browser/start"))
        .map_err(|e| format!("构造 AdsPower 启动 URL 失败: {e}"))?;
    {
        let mut qp = endpoint.query_pairs_mut();
        if let Some(uid) = clean_uid {
            qp.append_pair("user_id", uid);
        } else if let Some(sn) = clean_sn {
            qp.append_pair("serial_number", sn);
        }
    }

    // Never pass proxy override parameters or touch /user/update so AdsPower keeps
    // its existing per-profile proxy & fingerprint settings completely untouched.
    let client = build_client()?;
    let resp = apply_auth(client.get(endpoint), &settings.api_key)
        .send()
        .await
        .map_err(|e| map_connect_error(&display_base, e))?;
    let val = parse_adspower_json(resp, &display_base).await?;
    let code = val.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 0 {
        let msg = val.get("msg").and_then(Value::as_str).unwrap_or("启动失败");
        if is_auth_error_msg(reqwest::StatusCode::OK, msg) {
            return Err(format!(
                "AdsPower API Key 校验失败（{msg}），请在「AdsPower API」设置中核对密钥"
            ));
        }
        return Err(format!("AdsPower 启动环境失败: {msg}"));
    }

    let debug_port = val
        .get("data")
        .and_then(|d| d.get("debug_port"))
        .map(|v| json_str_or_num(Some(v)))
        .filter(|s| !s.is_empty());

    Ok(AdsPowerStartResult {
        user_id: clean_uid.map(str::to_string),
        serial_number: clean_sn.map(str::to_string),
        debug_port,
    })
}

pub async fn stop_browser(
    settings: &AdsPowerSettingsDisk,
    user_id: Option<&str>,
    serial_number: Option<&str>,
) -> Result<(), String> {
    let display_base = normalize_base_url(&settings.base_url)?;
    let req_base = request_base_url(&display_base)?;
    let clean_uid = user_id.map(str::trim).filter(|s| !s.is_empty());
    let clean_sn = serial_number
        .map(|s| s.trim().trim_start_matches('#').trim())
        .filter(|s| !s.is_empty());

    if clean_uid.is_none() && clean_sn.is_none() {
        return Err("未指定要关闭的 AdsPower 环境".into());
    }

    let mut endpoint = url::Url::parse(&format!("{req_base}/api/v1/browser/stop"))
        .map_err(|e| format!("构造 AdsPower 关闭 URL 失败: {e}"))?;
    {
        let mut qp = endpoint.query_pairs_mut();
        if let Some(uid) = clean_uid {
            qp.append_pair("user_id", uid);
        } else if let Some(sn) = clean_sn {
            qp.append_pair("serial_number", sn);
        }
    }

    let client = build_client()?;
    let resp = apply_auth(client.get(endpoint), &settings.api_key)
        .send()
        .await
        .map_err(|e| map_connect_error(&display_base, e))?;
    let val = parse_adspower_json(resp, &display_base).await?;
    let code = val.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 0 {
        let msg = val.get("msg").and_then(Value::as_str).unwrap_or("关闭失败");
        return Err(format!("关闭 AdsPower 窗口失败: {msg}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_base_url_allows_loopback_and_rejects_remote_hosts() {
        assert_eq!(normalize_base_url("").unwrap(), "http://127.0.0.1:50325");
        assert_eq!(
            normalize_base_url("http://localhost:50326/").unwrap(),
            "http://localhost:50326"
        );
        assert_eq!(
            normalize_base_url("http://local.adspower.net:50325").unwrap(),
            "http://local.adspower.net:50325"
        );
        assert_eq!(
            request_base_url("http://local.adspower.net:50325").unwrap(),
            "http://127.0.0.1:50325"
        );
        assert!(normalize_base_url("https://127.0.0.1:50325").is_err());
        assert!(normalize_base_url("http://192.168.1.50:50325").is_err());
        assert!(normalize_base_url("http://evil.example.com:50325").is_err());
        assert!(normalize_base_url("http://user:pass@127.0.0.1:50325").is_err());
    }

    #[test]
    fn adspower_vault_dpapi_roundtrip_and_masking() {
        let temp_dir = std::env::temp_dir().join(format!(
            "ai-netguard-adspower-test-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let path = temp_dir.join("adspower.vault");
        let input = AdsPowerSettingsDisk {
            base_url: "http://localhost:50325/".into(),
            api_key: "sk-adspower-secret-1234".into(),
        };
        let saved = save_settings_to_path(&path, &input).expect("save should succeed");
        assert_eq!(saved.base_url, "http://localhost:50325");

        let raw_file = fs::read_to_string(&path).unwrap();
        assert!(!raw_file.contains("sk-adspower-secret-1234"));

        let loaded = load_settings_from_path(&path).expect("load should succeed");
        assert_eq!(loaded, saved);

        let status = to_config_status(&loaded);
        assert!(status.has_api_key);
        assert_eq!(status.api_key_masked.as_deref(), Some("sk-a••••••1234"));
        assert_eq!(mask_api_key("short"), Some("••••••".into()));
        assert_eq!(mask_api_key("   "), None);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn parse_user_list_handles_string_and_numeric_serial_numbers() {
        let payload = json!({
            "code": 0,
            "msg": "success",
            "data": {
                "list": [
                    {
                        "user_id": "j82xkp41",
                        "serial_number": "42",
                        "name": "JP 主力谷歌",
                        "group_name": "Antigravity",
                        "remark": "日本 IEPL"
                    },
                    {
                        "user_id": "k91abz02",
                        "serial_number": 7,
                        "name": "KR 备用",
                        "group_name": "Default",
                        "remark": ""
                    }
                ]
            }
        });
        let (items, has_more) = parse_user_list_page(&payload).expect("parse should pass");
        assert!(!has_more);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].user_id, "j82xkp41");
        assert_eq!(items[0].serial_number, "42");
        assert_eq!(items[0].name, "JP 主力谷歌");
        assert_eq!(items[1].user_id, "k91abz02");
        assert_eq!(items[1].serial_number, "7");
    }
}
