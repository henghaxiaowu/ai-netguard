#![windows_subsystem = "windows"]

mod route;
mod wfp;

use guard_protocol::{constant_time_eq_bytes, GuardRequest, GuardResponse, PipeEnvelope};
use route::RouteManager;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::mem::ManuallyDrop;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_PIPE_CONNECTED, HLOCAL, INVALID_HANDLE_VALUE,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    FlushFileBuffers, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE};
use wfp::WfpManager;

struct Args {
    parent_pid: u32,
    pipe_name: String,
    token_file: String,
}

fn parse_args() -> Result<Args, String> {
    let mut parent_pid = None;
    let mut pipe_name = None;
    let mut token_file = None;
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let val = it.next().ok_or_else(|| format!("Missing value for {flag}"))?;
        match flag.as_str() {
            "--parent-pid" => parent_pid = Some(val.parse().map_err(|_| "Invalid parent-pid")?),
            "--pipe" => pipe_name = Some(val),
            "--token-file" => token_file = Some(val),
            other => return Err(format!("Unknown argument: {other}")),
        }
    }
    Ok(Args {
        parent_pid: parent_pid.ok_or("Missing --parent-pid")?,
        pipe_name: pipe_name.ok_or("Missing --pipe")?,
        token_file: token_file.ok_or("Missing --token-file")?,
    })
}

fn spawn_parent_watcher(parent_pid: u32, running: Arc<AtomicBool>, pipe_name: String) {
    std::thread::spawn(move || unsafe {
        if let Ok(handle) = OpenProcess(PROCESS_SYNCHRONIZE, false, parent_pid) {
            WaitForSingleObject(handle, INFINITE);
            let _ = CloseHandle(handle);
        }
        running.store(false, Ordering::SeqCst);
        // Unblock ConnectNamedPipe by briefly connecting if needed
        let _ = fs::OpenOptions::new().read(true).write(true).open(&pipe_name);
    });
}

fn handle_request(
    req: GuardRequest,
    wfp: &mut WfpManager,
    routes: &mut RouteManager,
    running: &AtomicBool,
) -> GuardResponse {
    let mut err_msg: Option<String> = None;
    let mut msg = String::from("ok");

    match req {
        GuardRequest::Ping => {}
        GuardRequest::ApplyWfpLock { targets } => {
            if let Err(e) = wfp.apply_lock(&targets) {
                err_msg = Some(e);
            } else {
                msg = format!("WFP lock active ({} filters)", wfp.filter_count());
            }
        }
        GuardRequest::ClearWfpLock => {
            if let Err(e) = wfp.clear_lock() {
                err_msg = Some(e);
            } else {
                msg = "WFP lock cleared".into();
            }
        }
        GuardRequest::InstallPersistentLock { targets } => {
            if let Err(e) = wfp.install_persistent_lock(&targets) {
                err_msg = Some(e);
            } else {
                msg = format!(
                    "Persistent offline lock installed ({} filters)",
                    wfp.persistent_filter_count()
                );
            }
        }
        GuardRequest::RemovePersistentLock => {
            if let Err(e) = wfp.remove_persistent_lock() {
                err_msg = Some(e);
            } else {
                msg = "Persistent offline lock removed".into();
            }
        }
        GuardRequest::WfpStatus => {
            wfp.sync_live_status();
        }
        GuardRequest::SetBypassRoute {
            target_ip,
            gateway_ip,
            interface_index,
        } => {
            if let Err(e) = routes.set_bypass_route(&target_ip, &gateway_ip, interface_index) {
                err_msg = Some(e);
            } else {
                msg = format!("Bypass route active for {target_ip}/32 via {gateway_ip}");
            }
        }
        GuardRequest::SetBypassRoutes {
            target_ips,
            gateway_ip,
            interface_index,
        } => {
            let count = target_ips.len();
            if let Err(e) = routes.set_bypass_routes(&target_ips, &gateway_ip, interface_index) {
                err_msg = Some(e);
            } else {
                msg = format!("Bypass routes active for {count} targets via {gateway_ip}");
            }
        }
        GuardRequest::ClearBypassRoute => {
            routes.clear_bypass_route();
            msg = "Bypass route cleared".into();
        }
        GuardRequest::Shutdown => {
            routes.clear_bypass_route();
            let _ = wfp.clear_lock();
            let _ = wfp.lock_persistent_offline();
            running.store(false, Ordering::SeqCst);
            msg = "Guard shutting down".into();
        }
    }

    GuardResponse {
        ok: err_msg.is_none(),
        message: err_msg.unwrap_or(msg),
        wfp_active: wfp.is_active(),
        filter_count: wfp.filter_count(),
        persistent_lock_active: wfp.is_persistent_active(),
        persistent_filter_count: wfp.persistent_filter_count(),
        bypass_route_active: routes.is_active(),
        locked_paths: wfp.locked_paths(),
        auth_proof: String::new(),
    }
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Argument error: {e}");
            std::process::exit(2);
        }
    };

    let token = match fs::read_to_string(&args.token_file) {
        Ok(t) => {
            let _ = fs::remove_file(&args.token_file);
            t.trim().to_string()
        }
        Err(e) => {
            eprintln!("Failed to read token file: {e}");
            std::process::exit(3);
        }
    };

    let mut wfp = match WfpManager::new() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("WFP init failed (administrator required): {e}");
            std::process::exit(4);
        }
    };
    let mut routes = RouteManager::new();

    let running = Arc::new(AtomicBool::new(true));
    spawn_parent_watcher(args.parent_pid, running.clone(), args.pipe_name.clone());

    let pipe_wide: Vec<u16> = args
        .pipe_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Allow Medium-Integrity interactive client only read/write access (GRGW, not GA),
    // blocking Low-Integrity sandboxed apps and remote SMB clients.
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let sd_ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            w!("D:(A;;GRGW;;;IU)(A;;GA;;;BA)(A;;GA;;;SY)S:(ML;;NW;;;ME)"),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
    };
    if let Err(e) = sd_ok {
        eprintln!("Failed to create pipe security descriptor: {e}");
        std::process::exit(5);
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };

    // Create a single reusable pipe instance with FILE_FLAG_FIRST_PIPE_INSTANCE to reject any
    // pre-squatted pipe and eliminate reconnect race windows between requests.
    let pipe_handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(pipe_wide.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            16384,
            16384,
            0,
            Some(&sa),
        )
    };
    if pipe_handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        eprintln!("CreateNamedPipeW failed (possible pipe squat): {err:?}");
        unsafe {
            if !sd.0.is_null() {
                let _ = LocalFree(HLOCAL(sd.0));
            }
        }
        std::process::exit(6);
    }

    while running.load(Ordering::SeqCst) {
        let connected = match unsafe { ConnectNamedPipe(pipe_handle, None) } {
            Ok(()) => true,
            Err(e) => e.code() == ERROR_PIPE_CONNECTED.to_hresult(),
        };
        if !connected || !running.load(Ordering::SeqCst) {
            if connected {
                unsafe {
                    let _ = DisconnectNamedPipe(pipe_handle);
                }
            }
            if !running.load(Ordering::SeqCst) {
                break;
            }
            continue;
        }

        let mut client_pid = 0u32;
        let client_ok = unsafe { GetNamedPipeClientProcessId(pipe_handle, &mut client_pid).is_ok() }
            && client_pid == args.parent_pid;

        let mut file =
            ManuallyDrop::new(unsafe { File::from_raw_handle(pipe_handle.0 as RawHandle) });
        let mut line = String::new();
        let read_ok = if client_ok {
            let reader = BufReader::new(&*file);
            reader.take(65536).read_line(&mut line).is_ok()
        } else {
            false
        };

        let response = if !client_ok {
            GuardResponse::err("Unauthorized pipe client PID")
        } else if !read_ok || line.trim().is_empty() {
            GuardResponse::err("Empty pipe payload")
        } else {
            match serde_json::from_str::<PipeEnvelope>(&line) {
                Ok(env) if constant_time_eq_bytes(&env.token, &token) => {
                    let mut resp = handle_request(env.request, &mut wfp, &mut routes, &running);
                    resp.auth_proof = resp.compute_auth_proof(&token, &env.nonce);
                    resp
                }
                Ok(_) => GuardResponse::err("Unauthorized token"),
                Err(e) => GuardResponse::err(format!("Malformed JSON: {e}")),
            }
        };

        if let Ok(mut json) = serde_json::to_string(&response) {
            json.push('\n');
            let _ = file.write_all(json.as_bytes());
            let _ = file.flush();
        }

        unsafe {
            let _ = FlushFileBuffers(pipe_handle);
            let _ = DisconnectNamedPipe(pipe_handle);
        }
    }

    routes.clear_bypass_route();
    let _ = wfp.clear_lock();
    let _ = wfp.lock_persistent_offline();

    unsafe {
        let _ = CloseHandle(pipe_handle);
        if !sd.0.is_null() {
            let _ = LocalFree(HLOCAL(sd.0));
        }
    }
}
