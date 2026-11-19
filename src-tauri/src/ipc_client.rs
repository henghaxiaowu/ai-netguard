use crate::models::app_data_dir;
use guard_protocol::{constant_time_eq_bytes, GuardRequest, GuardResponse, PipeEnvelope};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::time::Duration;
use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetTokenInformation, TokenElevation, WinBuiltinAdministratorsSid,
    WinLocalSystemSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_MAX_SID_SIZE, TOKEN_ELEVATION, TOKEN_QUERY, WELL_KNOWN_SID_TYPE,
};
use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

pub struct GuardClient {
    pipe_name: String,
    token: String,
    connected: bool,
    last_status: GuardResponse,
    expected_guard_path: Option<PathBuf>,
}

impl GuardClient {
    pub fn new() -> Self {
        let pid = std::process::id();
        let pipe_rand = format!("{:016x}{:016x}", rand::random::<u64>(), rand::random::<u64>());
        let token = format!("{:016x}{:016x}", rand::random::<u64>(), rand::random::<u64>());
        Self {
            pipe_name: format!(r"\\.\pipe\ai-netguard-{pid}-{pipe_rand}"),
            token,
            connected: false,
            last_status: GuardResponse::err("Guard not started"),
            expected_guard_path: None,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub fn last_status(&self) -> &GuardResponse {
        &self.last_status
    }

    pub fn find_guard_binary() -> Result<PathBuf, String> {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                for name in [
                    "netguard-guard.exe",
                    "netguard-guard-x86_64-pc-windows-msvc.exe",
                ] {
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
                .join("..")
                .join("target")
                .join("debug")
                .join("netguard-guard.exe");
            if dev_path.exists() {
                return Ok(dev_path);
            }
        }
        Err("未找到提权守护程序 netguard-guard.exe".into())
    }

    pub fn ensure_started(&mut self) -> Result<(), String> {
        if self.connected && self.call(GuardRequest::Ping).is_ok() {
            return Ok(());
        }

        let bin = Self::find_guard_binary()?;
        verify_guard_binary(&bin)?;
        let canonical_bin = normalize_win_path(&bin);
        self.expected_guard_path = Some(canonical_bin.clone());

        let token_file = app_data_dir().join(format!("guard-{:016x}.token", rand::random::<u64>()));
        fs::write(&token_file, &self.token)
            .map_err(|e| format!("写入 Guard 令牌失败: {e}"))?;

        let pid = std::process::id();
        let args = format!(
            "--parent-pid {pid} --pipe \"{}\" --token-file \"{}\"",
            self.pipe_name,
            token_file.display()
        );

        let bin_w: Vec<u16> = canonical_bin
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let args_w: Vec<u16> = args.encode_utf16().chain(std::iter::once(0)).collect();

        let hinst = unsafe {
            ShellExecuteW(
                None,
                w!("runas"),
                PCWSTR(bin_w.as_ptr()),
                PCWSTR(args_w.as_ptr()),
                PCWSTR::null(),
                SW_HIDE,
            )
        };
        if (hinst.0 as isize) <= 32 {
            let _ = fs::remove_file(&token_file);
            return Err("未获得管理员提权授权（UAC 被取消或拒绝）".into());
        }

        let mut last_err = String::from("unknown");
        for _ in 0..40 {
            match self.call(GuardRequest::Ping) {
                Ok(_) => {
                    self.connected = true;
                    return Ok(());
                }
                Err(e) => last_err = e,
            }
            std::thread::sleep(Duration::from_millis(125));
        }

        let _ = fs::remove_file(&token_file);
        Err(format!("等待 Guard 提权助手启动超时 ({last_err})"))
    }

    pub fn call(&mut self, request: GuardRequest) -> Result<GuardResponse, String> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.pipe_name)
            .map_err(|e| {
                self.connected = false;
                format!("连接 Guard 管道失败: {e}")
            })?;

        if let Err(e) = verify_pipe_server(&file, self.expected_guard_path.as_deref()) {
            self.connected = false;
            return Err(e);
        }

        let nonce = format!("{:016x}{:016x}", rand::random::<u64>(), rand::random::<u64>());
        let env = PipeEnvelope {
            token: self.token.clone(),
            nonce: nonce.clone(),
            request,
        };
        let mut payload = serde_json::to_string(&env).map_err(|e| e.to_string())?;
        payload.push('\n');
        file.write_all(payload.as_bytes())
            .and_then(|_| file.flush())
            .map_err(|e| {
                self.connected = false;
                format!("发送 Guard 请求失败: {e}")
            })?;

        let mut line = String::new();
        BufReader::new(file)
            .read_line(&mut line)
            .map_err(|e| {
                self.connected = false;
                format!("读取 Guard 响应失败: {e}")
            })?;

        let resp: GuardResponse =
            serde_json::from_str(line.trim()).map_err(|e| {
                self.connected = false;
                format!("解析 Guard 响应失败: {e}")
            })?;
        let expected_proof = resp.compute_auth_proof(&self.token, &nonce);
        if !constant_time_eq_bytes(&resp.auth_proof, &expected_proof) {
            self.connected = false;
            return Err("Guard 管道响应签名校验失败（疑为未授权响应或令牌不匹配）".into());
        }

        self.connected = true;
        self.last_status = resp.clone();
        if !resp.ok {
            return Err(resp.message);
        }
        Ok(resp)
    }

    pub fn try_shutdown(&mut self) {
        if self.connected {
            let _ = self.call(GuardRequest::Shutdown);
            self.connected = false;
        }
    }
}

fn normalize_win_path(path: &Path) -> PathBuf {
    let canon = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let s = canon.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        canon
    }
}

fn verify_guard_binary(bin: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(bin)
        .map_err(|e| format!("无法读取 netguard-guard.exe 元数据: {e}"))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err("netguard-guard.exe 路径为符号链接或非常规文件，拒绝提权运行".into());
    }

    let bytes = fs::read(bin).map_err(|e| format!("读取 netguard-guard.exe 失败: {e}"))?;
    let actual_sha256 = hex::encode(Sha256::digest(&bytes));
    let pinned = option_env!("NETGUARD_GUARD_SHA256").unwrap_or("").trim();

    #[cfg(not(debug_assertions))]
    {
        if pinned.len() != 64 {
            return Err("Release 构建缺少内嵌 Guard SHA-256 校验值，拒绝提权运行".into());
        }
        if !constant_time_eq_bytes(&actual_sha256.to_ascii_lowercase(), &pinned.to_ascii_lowercase())
        {
            return Err("检测到 netguard-guard.exe SHA-256 校验和不匹配（可能被替换），拒绝提权运行".into());
        }
    }

    #[cfg(debug_assertions)]
    {
        let is_packaged_sidecar = bin
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.eq_ignore_ascii_case("netguard-guard-x86_64-pc-windows-msvc.exe"))
            .unwrap_or(false);
        if is_packaged_sidecar
            && pinned.len() == 64
            && !constant_time_eq_bytes(
                &actual_sha256.to_ascii_lowercase(),
                &pinned.to_ascii_lowercase(),
            )
        {
            return Err("打包版 netguard-guard.exe SHA-256 校验不匹配，拒绝提权运行".into());
        }
    }

    Ok(())
}

unsafe fn is_well_known_sid(psid: PSID, well_known: WELL_KNOWN_SID_TYPE) -> bool {
    if psid.0.is_null() {
        return false;
    }
    let mut buf = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut cb = buf.len() as u32;
    let target = PSID(buf.as_mut_ptr() as *mut _);
    CreateWellKnownSid(well_known, None, target, &mut cb).is_ok() && EqualSid(psid, target).is_ok()
}

fn verify_pipe_server(file: &fs::File, expected_guard_path: Option<&Path>) -> Result<(), String> {
    let pipe_handle = HANDLE(file.as_raw_handle() as _);
    let mut server_pid = 0u32;
    unsafe { GetNamedPipeServerProcessId(pipe_handle, &mut server_pid) }
        .map_err(|e| format!("无法查询 Guard 管道服务端 PID: {e}"))?;

    if server_pid == 0 || server_pid == std::process::id() {
        return Err("Guard 管道服务端 PID 非法".into());
    }

    // Kernel-level check: verify pipe object owner is BUILTIN\Administrators or SYSTEM.
    // A normal-privilege local process cannot forge an Administrators-owned pipe object.
    unsafe {
        let mut owner_psid = PSID::default();
        let mut sd_ptr = PSECURITY_DESCRIPTOR::default();
        let err = GetSecurityInfo(
            pipe_handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner_psid),
            None,
            None,
            None,
            Some(&mut sd_ptr),
        );
        let owner_ok = err == ERROR_SUCCESS
            && (is_well_known_sid(owner_psid, WinBuiltinAdministratorsSid)
                || is_well_known_sid(owner_psid, WinLocalSystemSid));
        if !sd_ptr.0.is_null() {
            let _ = LocalFree(HLOCAL(sd_ptr.0));
        }
        if !owner_ok {
            return Err("Guard 管道服务端非管理员权限创建（疑似本地冒充进程），已拒绝连接".into());
        }

        // Additional identity verification if caller has query access to the elevated process.
        if let Ok(proc_handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, server_pid) {
            let mut path_buf = vec![0u16; 4096];
            let mut len = path_buf.len() as u32;
            let name_ok = QueryFullProcessImageNameW(
                proc_handle,
                PROCESS_NAME_WIN32,
                PWSTR(path_buf.as_mut_ptr()),
                &mut len,
            )
            .is_ok();
            if name_ok {
                if let Some(expected) = expected_guard_path {
                    let actual_str = String::from_utf16_lossy(&path_buf[..len as usize]);
                    let actual_norm = normalize_win_path(Path::new(&actual_str));
                    if !actual_norm
                        .to_string_lossy()
                        .eq_ignore_ascii_case(&expected.to_string_lossy())
                    {
                        let _ = CloseHandle(proc_handle);
                        return Err(format!(
                            "Guard 管道服务端可执行路径不匹配 ({actual_str})，已拒绝发送令牌"
                        ));
                    }
                }
            }

            let mut tok = HANDLE::default();
            if OpenProcessToken(proc_handle, TOKEN_QUERY, &mut tok).is_ok() {
                let mut elev = TOKEN_ELEVATION::default();
                let mut ret_len = 0u32;
                let got_elev = GetTokenInformation(
                    tok,
                    TokenElevation,
                    Some(&mut elev as *mut _ as *mut _),
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut ret_len,
                )
                .is_ok();
                let _ = CloseHandle(tok);
                if got_elev && elev.TokenIsElevated == 0 {
                    let _ = CloseHandle(proc_handle);
                    return Err("Guard 管道服务端未处于管理员提权状态，拒绝连接".into());
                }
            }
            let _ = CloseHandle(proc_handle);
        }
    }

    Ok(())
}

impl Drop for GuardClient {
    fn drop(&mut self) {
        self.try_shutdown();
    }
}
