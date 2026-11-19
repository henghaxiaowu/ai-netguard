use sha2::{Digest, Sha256};
use std::path::Path;

fn main() {
    let guard_bin = Path::new("binaries/netguard-guard-x86_64-pc-windows-msvc.exe");
    println!("cargo:rerun-if-changed={}", guard_bin.display());

    let guard_sha256 = if guard_bin.exists() {
        let bytes = std::fs::read(guard_bin)
            .expect("failed to read binaries/netguard-guard-x86_64-pc-windows-msvc.exe");
        hex::encode(Sha256::digest(&bytes))
    } else {
        if std::env::var("PROFILE").as_deref() == Ok("release") {
            panic!(
                "Release build requires {} to exist so its SHA-256 can be pinned before build!",
                guard_bin.display()
            );
        }
        String::new()
    };

    println!("cargo:rustc-env=NETGUARD_GUARD_SHA256={guard_sha256}");
    tauri_build::build()
}
