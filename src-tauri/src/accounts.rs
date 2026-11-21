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
    #[default]
    Adspower,
    ClaudeCode,
    NetguardBrowser,
    Local,
    FingerprintOther,
    Custom,
}

impl AccountEnvType {
    fn default_label(self) -> &'static str {
        match self {
            Self::Adspower => "AdsPower",
            Self::ClaudeCode => "Claude Code",
            Self::NetguardBrowser => "NetGuard 安全浏览器",
            Self::Local => "本地环境",
            Self::FingerprintOther => "指纹浏览器",
            Self::Custom => "自定义环境",
        }
    }
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
    pub linked_node_id: Option<String>,
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

fn default_provider() -> String {
    "Google".to_string()
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
    if record.environment_name.is_empty() {
        record.environment_name = record.env_type.default_label().to_string();
    }

    record.environment_profile = trim_opt(record.environment_profile);
    record.linked_node_id = trim_opt(record.linked_node_id);
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
            env_type: AccountEnvType::Adspower,
            environment_name: "AdsPower".into(),
            environment_profile: Some("Win-042".into()),
            linked_node_id: Some("seoul-vps".into()),
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
    fn normalize_account_validates_email_and_preserves_created_at() {
        let mut blank = sample_record("", "   ");
        assert!(normalize_account(blank.clone(), None).is_err());

        blank.email = "  user@gmail.com  ".into();
        blank.provider = "  ".into();
        blank.environment_name = "".into();
        blank.env_type = AccountEnvType::Custom;
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
        assert_eq!(created.environment_name, "自定义环境");
        assert_eq!(created.tags, vec!["CloudCart", "Main"]);
        assert_eq!(created.totp_secret, None);
        assert!(!created.created_at.is_empty());

        let mut existing = created.clone();
        existing.created_at = "2025-01-02 03:04:05".into();
        let mut update_input = created.clone();
        update_input.created_at = "2026-12-31 23:59:59".into();
        let updated = normalize_account(update_input, Some(&existing)).unwrap();
        assert_eq!(updated.created_at, "2025-01-02 03:04:05");
    }
}
