use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedTarget {
    pub exe_path: String,
    pub allow_private_lan: bool,
    #[serde(default)]
    pub allowed_loopback_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeEnvelope {
    pub token: String,
    #[serde(default)]
    pub nonce: String,
    pub request: GuardRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum GuardRequest {
    Ping,
    ApplyWfpLock {
        targets: Vec<ProtectedTarget>,
    },
    ClearWfpLock,
    InstallPersistentLock {
        targets: Vec<ProtectedTarget>,
    },
    RemovePersistentLock,
    WfpStatus,
    SetBypassRoute {
        target_ip: String,
        gateway_ip: String,
        interface_index: u32,
    },
    ClearBypassRoute,
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardResponse {
    pub ok: bool,
    pub message: String,
    pub wfp_active: bool,
    pub filter_count: usize,
    pub persistent_lock_active: bool,
    pub persistent_filter_count: usize,
    pub bypass_route_active: bool,
    pub locked_paths: Vec<String>,
    #[serde(default)]
    pub auth_proof: String,
}

impl GuardResponse {
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: msg.into(),
            wfp_active: false,
            filter_count: 0,
            persistent_lock_active: false,
            persistent_filter_count: 0,
            bypass_route_active: false,
            locked_paths: Vec::new(),
            auth_proof: String::new(),
        }
    }

    pub fn compute_auth_proof(&self, token: &str, nonce: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"ai-netguard-guard-v1:");
        hasher.update(token.as_bytes());
        hasher.update(b":");
        hasher.update(nonce.as_bytes());
        hasher.update(b":");
        hasher.update(if self.ok { b"1" } else { b"0" });
        hasher.update(b":");
        hasher.update(if self.wfp_active { b"1" } else { b"0" });
        hasher.update(b":");
        hasher.update(self.filter_count.to_string().as_bytes());
        hasher.update(b":");
        hasher.update(if self.persistent_lock_active { b"1" } else { b"0" });
        hasher.update(b":");
        hasher.update(self.persistent_filter_count.to_string().as_bytes());
        hasher.update(b":");
        hasher.update(self.message.as_bytes());
        hex::encode(hasher.finalize())
    }
}

pub fn constant_time_eq_bytes(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in ab.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
