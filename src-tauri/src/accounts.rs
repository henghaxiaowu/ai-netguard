use crate::models::app_data_dir;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

const VAULT_FILE_NAME: &str = "accounts.vault";
const ENV_PRESETS_FILE_NAME: &str = "account-environments.json";
const VAULT_FORMAT: &str = "dpapi-v1";
const VAULT_VERSION: u32 = 1;
const VAULT_ENTROPY: &[u8] = b"AI-NetGuard-AccountVault-v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    #[default]
    Active,
    Standby,
    Restricted,
    Banned,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AccountEnvType {
    #[serde(alias = "adspower", alias = "fingerprint_other")]
    Fingerprint,
    #[serde(alias = "claude_code", alias = "netguard_browser")]
    Local,
    #[default]
    Custom,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AccountNodeSource {
    #[default]
    None,
    Netguard,
    ClashVerge,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default = "default_provider")]
    pub provider: String,
    pub email: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub recovery_codes: Option<String>,
    #[serde(default)]
    pub recovery_email: Option<String>,
    #[serde(default)]
    pub env_type: AccountEnvType,
    #[serde(default)]
    pub environment_name: String,
    #[serde(default)]
    pub environment_profile: Option<String>,
    #[serde(default)]
    pub linked_node_source: AccountNodeSource,
    #[serde(default)]
    pub linked_node_id: Option<String>,
    #[serde(default)]
    pub linked_node_name: Option<String>,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub status: AccountStatus,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountEnvPreset {
    #[serde(default)]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub env_type: AccountEnvType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClashVergeNodeItem {
    pub name: String,
    pub node_type: String,
    pub is_group: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClashVergeNodesSnapshot {
    pub detected: bool,
    pub source_path: Option<String>,
    pub groups: Vec<ClashVergeNodeItem>,
    pub proxies: Vec<ClashVergeNodeItem>,
}

fn default_provider() -> String {
    "Google".to_string()
}

pub fn default_env_presets() -> Vec<AccountEnvPreset> {
    vec![
        AccountEnvPreset {
            id: "env-adspower".into(),
            name: "AdsPower".into(),
            env_type: AccountEnvType::Fingerprint,
        },
        AccountEnvPreset {
            id: "env-local-browser".into(),
            name: "本地浏览器".into(),
            env_type: AccountEnvType::Local,
        },
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultEnvelope {
    version: u32,
    format: String,
    payload: String,
}

pub fn vault_path() -> PathBuf {
    app_data_dir().join(VAULT_FILE_NAME)
}

pub fn env_presets_path() -> PathBuf {
    app_data_dir().join(ENV_PRESETS_FILE_NAME)
}

fn trim_opt(opt: Option<String>) -> Option<String> {
    opt.and_then(|s| {
        let trimmed = s.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn normalize_tags(tags: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for raw in tags {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let key = trimmed.to_lowercase();
        if seen.insert(key) {
            out.push(trimmed.to_string());
        }
    }
    out
}

/// Normalize, validate, and timestamp an account record before storing it in the encrypted vault.
pub fn normalize_account(
    mut record: AccountRecord,
    existing: Option<&AccountRecord>,
) -> Result<AccountRecord, String> {
    record.email = record.email.trim().to_string();
    if record.email.is_empty() {
        return Err("账号/邮箱不能为空".into());
    }

    record.id = record.id.trim().to_string();
    if record.id.is_empty() {
        record.id = format!(
            "acc-{}-{:08x}",
            chrono::Utc::now().timestamp_millis(),
            rand::random::<u32>()
        );
    }

    record.label = record.label.trim().to_string();

    record.provider = record.provider.trim().to_string();
    if record.provider.is_empty() {
        record.provider = default_provider();
    }

    record.totp_secret = trim_opt(record.totp_secret);
    record.recovery_codes = trim_opt(record.recovery_codes);
    record.recovery_email = trim_opt(record.recovery_email);

    record.environment_name = record.environment_name.trim().to_string();
    record.environment_profile = trim_opt(record.environment_profile);

    record.linked_node_id = trim_opt(record.linked_node_id);
    record.linked_node_name = trim_opt(record.linked_node_name);

    if record.linked_node_source == AccountNodeSource::None && record.linked_node_id.is_some() {
        record.linked_node_source = AccountNodeSource::Netguard;
    }

    match record.linked_node_source {
        AccountNodeSource::None => {
            record.linked_node_id = None;
            record.linked_node_name = None;
        }
        AccountNodeSource::Netguard => {
            if record.linked_node_id.is_none() && record.linked_node_name.is_none() {
                record.linked_node_source = AccountNodeSource::None;
            }
        }
        AccountNodeSource::ClashVerge | AccountNodeSource::Custom => {
            record.linked_node_id = None;
            if record.linked_node_name.is_none() {
                record.linked_node_source = AccountNodeSource::None;
            }
        }
    }

    record.purpose = record.purpose.trim().to_string();
    record.tags = normalize_tags(record.tags);
    record.notes = trim_opt(record.notes);

    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    record.created_at = match existing {
        Some(prev) if !prev.created_at.trim().is_empty() => prev.created_at.clone(),
        _ => {
            let trimmed = record.created_at.trim();
            if trimmed.is_empty() {
                now.clone()
            } else {
                trimmed.to_string()
            }
        }
    };
    record.updated_at = now;

    Ok(record)
}

pub fn normalize_env_presets(presets: Vec<AccountEnvPreset>) -> Vec<AccountEnvPreset> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for mut item in presets {
        item.name = item.name.trim().to_string();
        if item.name.is_empty() {
            continue;
        }
        let key = item.name.to_lowercase();
        if !seen.insert(key) {
            continue;
        }
        item.id = item.id.trim().to_string();
        if item.id.is_empty() {
            item.id = format!(
                "env-{}-{:08x}",
                chrono::Utc::now().timestamp_millis(),
                rand::random::<u32>()
            );
        }
        out.push(item);
    }
    out
}

pub fn load_env_presets_from_path(path: &Path) -> Result<Vec<AccountEnvPreset>, String> {
    if !path.exists() {
        return Ok(default_env_presets());
    }
    let raw = fs::read_to_string(path).map_err(|e| format!("读取环境预设失败: {e}"))?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let presets: Vec<AccountEnvPreset> =
        serde_json::from_str(&raw).map_err(|e| format!("解析环境预设失败: {e}"))?;
    Ok(normalize_env_presets(presets))
}

pub fn save_env_presets_to_path(path: &Path, presets: &[AccountEnvPreset]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建环境预设目录失败: {e}"))?;
    }
    let json =
        serde_json::to_string_pretty(presets).map_err(|e| format!("序列化环境预设失败: {e}"))?;
    let tmp_path = path.with_extension("json.tmp");
    fs::write(&tmp_path, json).map_err(|e| format!("写入环境预设临时文件失败: {e}"))?;
    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("原子更新环境预设失败: {e}")
    })?;
    Ok(())
}

pub fn load_env_presets() -> Result<Vec<AccountEnvPreset>, String> {
    load_env_presets_from_path(&env_presets_path())
}

pub fn save_env_presets(presets: &[AccountEnvPreset]) -> Result<(), String> {
    save_env_presets_to_path(&env_presets_path(), presets)
}

fn strip_yaml_comment(raw: &str) -> &str {
    let bytes = raw.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_single {
            if b == b'\'' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    i += 2;
                    continue;
                }
                in_single = false;
            }
        } else if in_double {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_double = false;
            }
        } else if b == b'\'' {
            in_single = true;
        } else if b == b'"' {
            in_double = true;
        } else if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return &raw[..i];
        }
        i += 1;
    }
    raw
}

fn unquote_yaml_value(raw: &str) -> String {
    let trimmed = strip_yaml_comment(raw).trim();
    if trimmed.len() >= 2 && trimmed.starts_with('\'') && trimmed.ends_with('\'') {
        return trimmed[1..trimmed.len() - 1].replace("''", "'");
    }
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        let inner = &trimmed[1..trimmed.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                    None => out.push('\\'),
                }
            } else {
                out.push(ch);
            }
        }
        return out;
    }
    trimmed.to_string()
}

fn split_yaml_kv(line: &str) -> Option<(&str, &str)> {
    let idx = line.find(':')?;
    let rest = &line[idx + 1..];
    if !rest.is_empty() && !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
        return None;
    }
    let key = line[..idx].trim();
    if key.is_empty() {
        return None;
    }
    Some((key, rest.trim()))
}

fn parse_inline_clash_flow(body: &str) -> (Option<String>, Option<String>) {
    let trimmed = body.trim();
    let inner = trimmed
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(trimmed);

    let mut pairs = Vec::new();
    let mut start = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut brace_depth = 0usize;
    let mut bracket_depth = 0usize;
    let bytes = inner.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if in_single {
            if b == b'\'' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    i += 2;
                    continue;
                }
                in_single = false;
            }
        } else if in_double {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_double = false;
            }
        } else {
            match b {
                b'\'' => in_single = true,
                b'"' => in_double = true,
                b'{' => brace_depth += 1,
                b'}' => brace_depth = brace_depth.saturating_sub(1),
                b'[' => bracket_depth += 1,
                b']' => bracket_depth = bracket_depth.saturating_sub(1),
                b',' if brace_depth == 0 && bracket_depth == 0 => {
                    pairs.push(&inner[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
        i += 1;
    }
    pairs.push(&inner[start..]);

    let mut name = None;
    let mut node_type = None;
    for pair in pairs {
        if let Some((k, v)) = split_yaml_kv(pair.trim()) {
            if k == "name" && name.is_none() {
                let parsed = unquote_yaml_value(v);
                if !parsed.is_empty() {
                    name = Some(parsed);
                }
            } else if k == "type" && node_type.is_none() {
                let parsed = unquote_yaml_value(v);
                if !parsed.is_empty() {
                    node_type = Some(parsed);
                }
            }
        }
    }
    (name, node_type)
}

/// Extract proxy groups and proxy node names/types from a Clash / Clash Verge YAML config.
/// Only `name` and `type` are extracted; credentials and server addresses are ignored.
pub fn parse_clash_yaml_nodes(yaml: &str) -> (Vec<ClashVergeNodeItem>, Vec<ClashVergeNodeItem>) {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Section {
        None,
        Proxies,
        ProxyGroups,
    }

    let mut section = Section::None;
    let mut item_indent: Option<usize> = None;
    let mut sub_block_indent: Option<usize> = None;
    let mut cur_name: Option<String> = None;
    let mut cur_type: Option<String> = None;

    let mut groups = Vec::new();
    let mut proxies = Vec::new();
    let mut seen_groups = HashSet::new();
    let mut seen_proxies = HashSet::new();

    let flush_current = |sec: Section,
                         name_opt: &mut Option<String>,
                         type_opt: &mut Option<String>,
                         groups: &mut Vec<ClashVergeNodeItem>,
                         proxies: &mut Vec<ClashVergeNodeItem>,
                         seen_groups: &mut HashSet<String>,
                         seen_proxies: &mut HashSet<String>| {
        if let Some(name) = name_opt.take() {
            let trimmed = name.trim().to_string();
            let node_type = type_opt
                .take()
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| {
                    if sec == Section::ProxyGroups {
                        "group".to_string()
                    } else {
                        "proxy".to_string()
                    }
                });
            if !trimmed.is_empty() {
                match sec {
                    Section::ProxyGroups => {
                        if seen_groups.insert(trimmed.clone()) {
                            groups.push(ClashVergeNodeItem {
                                name: trimmed,
                                node_type,
                                is_group: true,
                            });
                        }
                    }
                    Section::Proxies => {
                        if seen_proxies.insert(trimmed.clone()) {
                            proxies.push(ClashVergeNodeItem {
                                name: trimmed,
                                node_type,
                                is_group: false,
                            });
                        }
                    }
                    Section::None => {}
                }
            }
        } else {
            *type_opt = None;
        }
    };

    for raw_line in yaml.lines() {
        let line = raw_line.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let indent = line.len() - line.trim_start_matches([' ', '\t']).len();

        // Top-level YAML key (not a list item)
        if indent == 0 && !trimmed.starts_with('-') {
            flush_current(
                section,
                &mut cur_name,
                &mut cur_type,
                &mut groups,
                &mut proxies,
                &mut seen_groups,
                &mut seen_proxies,
            );
            item_indent = None;
            sub_block_indent = None;

            if let Some((key, _)) = split_yaml_kv(trimmed) {
                section = match key {
                    "proxies" => Section::Proxies,
                    "proxy-groups" => Section::ProxyGroups,
                    _ => Section::None,
                };
            } else {
                section = Section::None;
            }
            continue;
        }

        if section == Section::None {
            continue;
        }

        if let Some(after_dash) = trimmed.strip_prefix('-').and_then(|s| {
            if s.is_empty() || s.starts_with(|c: char| c.is_ascii_whitespace()) {
                Some(s.trim())
            } else {
                None
            }
        }) {
            let expected_indent = *item_indent.get_or_insert(indent);
            if indent > expected_indent {
                // Nested list item (e.g. group members under `proxies:`)
                continue;
            }
            flush_current(
                section,
                &mut cur_name,
                &mut cur_type,
                &mut groups,
                &mut proxies,
                &mut seen_groups,
                &mut seen_proxies,
            );
            sub_block_indent = None;

            if after_dash.starts_with('{') {
                let (n, t) = parse_inline_clash_flow(after_dash);
                cur_name = n;
                cur_type = t;
            } else if let Some((k, v)) = split_yaml_kv(after_dash) {
                if k == "name" {
                    let parsed = unquote_yaml_value(v);
                    if !parsed.is_empty() {
                        cur_name = Some(parsed);
                    }
                } else if k == "type" {
                    let parsed = unquote_yaml_value(v);
                    if !parsed.is_empty() {
                        cur_type = Some(parsed);
                    }
                }
            }
            continue;
        }

        if let Some(base_indent) = item_indent {
            if indent <= base_indent {
                continue;
            }
            if let Some(sub) = sub_block_indent {
                if indent >= sub {
                    continue;
                }
                sub_block_indent = None;
            }
            if let Some((k, v)) = split_yaml_kv(trimmed) {
                let clean_val = strip_yaml_comment(v).trim();
                if clean_val.is_empty() {
                    sub_block_indent = Some(indent + 1);
                } else if k == "name" && cur_name.is_none() {
                    let parsed = unquote_yaml_value(v);
                    if !parsed.is_empty() {
                        cur_name = Some(parsed);
                    }
                } else if k == "type" && cur_type.is_none() {
                    let parsed = unquote_yaml_value(v);
                    if !parsed.is_empty() {
                        cur_type = Some(parsed);
                    }
                }
            }
        }
    }

    flush_current(
        section,
        &mut cur_name,
        &mut cur_type,
        &mut groups,
        &mut proxies,
        &mut seen_groups,
        &mut seen_proxies,
    );

    (groups, proxies)
}

/// Inspect local Clash Verge configuration files for proxy groups and node names.
pub fn discover_clash_verge_nodes() -> ClashVergeNodesSnapshot {
    let Some(appdata) = std::env::var_os("APPDATA").map(PathBuf::from) else {
        return ClashVergeNodesSnapshot::default();
    };
    let candidates = [
        appdata
            .join("io.github.clash-verge-rev.clash-verge-rev")
            .join("clash-verge.yaml"),
        appdata
            .join("io.github.clash-verge-rev.clash-verge-rev")
            .join("config.yaml"),
        appdata.join("clash-verge").join("clash-verge.yaml"),
        appdata.join("clash-verge").join("config.yaml"),
    ];

    for path in candidates {
        if path.is_file() {
            if let Ok(raw) = fs::read_to_string(&path) {
                let (groups, proxies) = parse_clash_yaml_nodes(&raw);
                return ClashVergeNodesSnapshot {
                    detected: true,
                    source_path: Some(path.to_string_lossy().to_string()),
                    groups,
                    proxies,
                };
            }
        }
    }

    ClashVergeNodesSnapshot::default()
}

fn blob_from_slice(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: if bytes.is_empty() {
            std::ptr::null_mut()
        } else {
            bytes.as_ptr() as *mut u8
        },
    }
}

/// Encrypt bytes with Windows DPAPI bound to the current Windows user account.
pub fn dpapi_encrypt(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let in_blob = blob_from_slice(plaintext);
    let entropy_blob = blob_from_slice(VAULT_ENTROPY);
    let mut out_blob = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptProtectData(
            &in_blob,
            PCWSTR::null(),
            Some(&entropy_blob),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
        .map_err(|e| format!("DPAPI 加密账号库失败: {e}"))?;

        let result = if out_blob.pbData.is_null() || out_blob.cbData == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
        };

        if !out_blob.pbData.is_null() {
            let _ = LocalFree(HLOCAL(out_blob.pbData.cast()));
        }

        Ok(result)
    }
}

/// Decrypt bytes previously protected by `dpapi_encrypt`.
pub fn dpapi_decrypt(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let in_blob = blob_from_slice(ciphertext);
    let entropy_blob = blob_from_slice(VAULT_ENTROPY);
    let mut out_blob = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptUnprotectData(
            &in_blob,
            None,
            Some(&entropy_blob),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
        .map_err(|e| format!("DPAPI 解密账号库失败: {e}"))?;

        let result = if out_blob.pbData.is_null() || out_blob.cbData == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
        };

        if !out_blob.pbData.is_null() {
            let _ = LocalFree(HLOCAL(out_blob.pbData.cast()));
        }

        Ok(result)
    }
}

pub fn load_accounts_from_path(path: &Path) -> Result<Vec<AccountRecord>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(path).map_err(|e| format!("读取账号库文件失败: {e}"))?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let envelope: VaultEnvelope =
        serde_json::from_str(&raw).map_err(|e| format!("解析账号库信封失败: {e}"))?;
    if envelope.format != VAULT_FORMAT {
        return Err(format!("不支持的账号库加密格式: {}", envelope.format));
    }
    let encrypted = STANDARD
        .decode(envelope.payload.trim())
        .map_err(|e| format!("解码账号库密文失败: {e}"))?;
    let decrypted = dpapi_decrypt(&encrypted)?;
    let accounts: Vec<AccountRecord> =
        serde_json::from_slice(&decrypted).map_err(|e| format!("解析账号记录失败: {e}"))?;
    Ok(accounts)
}

pub fn save_accounts_to_path(path: &Path, accounts: &[AccountRecord]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建账号库目录失败: {e}"))?;
    }
    let plaintext =
        serde_json::to_vec(accounts).map_err(|e| format!("序列化账号记录失败: {e}"))?;
    let encrypted = dpapi_encrypt(&plaintext)?;
    let envelope = VaultEnvelope {
        version: VAULT_VERSION,
        format: VAULT_FORMAT.to_string(),
        payload: STANDARD.encode(encrypted),
    };
    let json =
        serde_json::to_string_pretty(&envelope).map_err(|e| format!("生成账号库信封失败: {e}"))?;
    let tmp_path = path.with_extension("vault.tmp");
    fs::write(&tmp_path, json).map_err(|e| format!("写入账号库临时文件失败: {e}"))?;
    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("原子更新账号库失败: {e}")
    })?;
    Ok(())
}

pub fn load_accounts() -> Result<Vec<AccountRecord>, String> {
    load_accounts_from_path(&vault_path())
}

pub fn save_accounts(accounts: &[AccountRecord]) -> Result<(), String> {
    save_accounts_to_path(&vault_path(), accounts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(id: &str, email: &str) -> AccountRecord {
        AccountRecord {
            id: id.into(),
            label: "主力 Google".into(),
            provider: "Google".into(),
            email: email.into(),
            password: "S3cure!Pass#2026".into(),
            totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            recovery_codes: Some("1111-2222\n3333-4444".into()),
            recovery_email: Some("backup@example.com".into()),
            env_type: AccountEnvType::Fingerprint,
            environment_name: "AdsPower".into(),
            environment_profile: Some("Win-042".into()),
            linked_node_source: AccountNodeSource::Netguard,
            linked_node_id: Some("seoul-vps".into()),
            linked_node_name: Some("首尔 VPS 独享出口".into()),
            purpose: "CloudCart / Google Ads 投放".into(),
            tags: vec!["Ads".into(), "KR".into()],
            status: AccountStatus::Active,
            notes: Some("韩国独享节点登录".into()),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn dpapi_roundtrip_and_tamper_rejection() {
        let payload = br#"[{"email":"alice@gmail.com","secret":"top-secret"}]"#;
        let encrypted = dpapi_encrypt(payload).expect("encrypt should succeed");
        assert_ne!(encrypted.as_slice(), payload);

        let decrypted = dpapi_decrypt(&encrypted).expect("decrypt should succeed");
        assert_eq!(decrypted, payload);

        let mut tampered = encrypted.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(dpapi_decrypt(&tampered).is_err());
    }

    #[test]
    fn vault_file_save_overwrite_and_load() {
        let temp_dir = std::env::temp_dir().join(format!(
            "ai-netguard-accounts-test-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let path = temp_dir.join("accounts.vault");

        let first = normalize_account(sample_record("acc-1", "one@gmail.com"), None).unwrap();
        save_accounts_to_path(&path, &[first.clone()]).expect("first save should succeed");

        let second = normalize_account(sample_record("acc-2", "two@gmail.com"), None).unwrap();
        save_accounts_to_path(&path, &[first.clone(), second.clone()])
            .expect("atomic overwrite save should succeed");

        let loaded = load_accounts_from_path(&path).expect("load should succeed");
        assert_eq!(loaded, vec![first, second]);

        let raw_file = fs::read_to_string(&path).unwrap();
        assert!(!raw_file.contains("S3cure!Pass#2026"));
        assert!(!raw_file.contains("JBSWY3DPEHPK3PXP"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn normalize_account_keeps_blank_env_and_migrates_legacy_fields() {
        let mut blank = sample_record("", "   ");
        assert!(normalize_account(blank.clone(), None).is_err());

        blank.email = "  user@gmail.com  ".into();
        blank.provider = "  ".into();
        blank.environment_name = "   ".into();
        blank.env_type = AccountEnvType::Custom;
        blank.linked_node_source = AccountNodeSource::None;
        blank.linked_node_id = None;
        blank.linked_node_name = None;
        blank.tags = vec![
            " CloudCart ".into(),
            "cloudcart".into(),
            "".into(),
            "Main".into(),
        ];
        blank.totp_secret = Some("   ".into());

        let created = normalize_account(blank, None).unwrap();
        assert!(created.id.starts_with("acc-"));
        assert_eq!(created.email, "user@gmail.com");
        assert_eq!(created.provider, "Google");
        assert_eq!(created.environment_name, "");
        assert_eq!(created.linked_node_source, AccountNodeSource::None);
        assert_eq!(created.tags, vec!["CloudCart", "Main"]);
        assert_eq!(created.totp_secret, None);
        assert!(!created.created_at.is_empty());

        // Legacy JSON migration: adspower -> Fingerprint, claude_code -> Local, linkedNodeId -> Netguard
        let legacy_json = r#"{
            "id": "legacy-1",
            "email": "legacy@gmail.com",
            "envType": "adspower",
            "linkedNodeId": "seoul-vps"
        }"#;
        let parsed: AccountRecord = serde_json::from_str(legacy_json).unwrap();
        let migrated = normalize_account(parsed, None).unwrap();
        assert_eq!(migrated.env_type, AccountEnvType::Fingerprint);
        assert_eq!(migrated.linked_node_source, AccountNodeSource::Netguard);
        assert_eq!(migrated.linked_node_id.as_deref(), Some("seoul-vps"));

        let legacy_local: AccountRecord = serde_json::from_str(
            r#"{"email":"cc@gmail.com","envType":"claude_code"}"#,
        )
        .unwrap();
        assert_eq!(legacy_local.env_type, AccountEnvType::Local);

        let mut existing = created.clone();
        existing.created_at = "2025-01-02 03:04:05".into();
        let mut update_input = created.clone();
        update_input.created_at = "2026-12-31 23:59:59".into();
        let updated = normalize_account(update_input, Some(&existing)).unwrap();
        assert_eq!(updated.created_at, "2025-01-02 03:04:05");
    }

    #[test]
    fn env_presets_save_empty_list_does_not_reseed_defaults() {
        let temp_dir = std::env::temp_dir().join(format!(
            "ai-netguard-env-test-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let path = temp_dir.join("account-environments.json");

        // Before file exists -> defaults
        let initial = load_env_presets_from_path(&path).unwrap();
        assert_eq!(initial.len(), 2);

        // Saving empty list persists [] and does not re-seed defaults on next load
        save_env_presets_to_path(&path, &[]).unwrap();
        let after_clear = load_env_presets_from_path(&path).unwrap();
        assert!(after_clear.is_empty());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn parse_clash_yaml_nodes_handles_block_and_inline_styles() {
        let yaml = r#"
mixed-port: 7897
proxies:
- name: "🇭🇰 香港 01"
  server: 1.2.3.4
  port: 443
  type: ss
  ws-opts:
    path: /ws
    headers:
      Host: example.com
  udp: true
- {name: '🇯🇵 日本 ''VIP'', Node', type: vless, server: 5.6.7.8, port: 443}
- name: 🇺🇸 美国直连 # comment outside quote
  type: trojan

proxy-groups:
- name: 🚀 节点选择
  type: select
  proxies:
    - ♻️ 自动选择
    - "🇭🇰 香港 01"
- { name: "♻️ 自动选择", type: url-test }

rules:
- MATCH,🚀 节点选择
"#;

        let (groups, proxies) = parse_clash_yaml_nodes(yaml);
        assert_eq!(
            groups,
            vec![
                ClashVergeNodeItem {
                    name: "🚀 节点选择".into(),
                    node_type: "select".into(),
                    is_group: true,
                },
                ClashVergeNodeItem {
                    name: "♻️ 自动选择".into(),
                    node_type: "url-test".into(),
                    is_group: true,
                },
            ]
        );
        assert_eq!(
            proxies,
            vec![
                ClashVergeNodeItem {
                    name: "🇭🇰 香港 01".into(),
                    node_type: "ss".into(),
                    is_group: false,
                },
                ClashVergeNodeItem {
                    name: "🇯🇵 日本 'VIP', Node".into(),
                    node_type: "vless".into(),
                    is_group: false,
                },
                ClashVergeNodeItem {
                    name: "🇺🇸 美国直连".into(),
                    node_type: "trojan".into(),
                    is_group: false,
                },
            ]
        );
    }
}
