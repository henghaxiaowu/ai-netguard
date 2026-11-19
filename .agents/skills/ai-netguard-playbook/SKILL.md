---
name: ai-netguard-playbook
description: >-
  Architecture, anti-leak security model, Windows WFP kernel rules, Claude Desktop
  PAC/hCaptcha workarounds, and UI/security audit runbook for AI NetGuard. Activate
  when modifying proxy routing, WFP firewall rules, browser/Claude Desktop launchers,
  fingerprint alignment, or auditing for network leaks and security vulnerabilities.
---

# AI NetGuard Development & Zero-Leak Protection Playbook

This skill documents the core engineering architecture, security invariants, and operational lessons learned while building **AI NetGuard** (`e:\net_manager`).

---

## 1. Core Security Invariants (Never Violate)

1. **Zero Global Hijack (Coexistence with Clash Verge & Tailscale)**
   - Never replace the system proxy or install a global TUN adapter that breaks the user's running Clash Verge or Tailscale.
   - Use **Physical NIC Bypass (`OutboundMode::PhysicalBypass`)**: detect the real physical adapter via `GetAdaptersAddresses` (filtering out virtual keywords: `wintun`, `wireguard`, `clash`, `mihomo`, `tailscale`, `vmware`, `hyper-v`, etc.), bind `sing-box`'s `ai_exit` outbound with `"bind_interface"`, and inject a `/32` host route (`Metric = 1`) for the VPS IP via `CreateIpForwardEntry2`.

2. **Strict Fail-Closed Enforcement & Pre-Verification Isolation**
   - `sing-box` (`src-tauri/src/singbox.rs`) starts `ai_selector` with `"default": "ai_block"` and `"interrupt_exist_connections": true`, plus an isolated loopback probe inbound (`in_probe` -> `ai_exit`) excluded from WFP client allowlists. No client packet can traverse `ai_exit` until initial `probe_exit_ip(probe_port)` + `check_node_expectation` succeed.
   - If `wfp_lock_enabled` is true and `GuardClient::ensure_started()` or `GuardRequest::ApplyWfpLock` fails during `start_gateway`, **immediately stop `sing-box` and abort startup**.
   - During the 4-second monitor loop (`spawn_monitor_loop`), actively verify both `probe_exit_ip(probe_port)` AND live Guard status (`GuardRequest::WfpStatus`, which validates active BFE filter handles via `FwpmFilterGetById0`). If Guard drops or WFP rules disappear while `FailClosed`, **immediately stop `sing-box`**; if exit IP drifts, missing `country_code` fails `expected_country` check, or probing fails, switch `ai_selector` to `ai_block` (`interrupt_exist_connections: true` terminates existing flows) or kill `sing-box` on API failure.

3. **Zero External Requests from Tauri WebView2**
   - The Tauri control-panel window (`WebView2`) runs in the host network context, not inside `sing-box`.
   - **Never** load remote fonts (e.g., Google Fonts), remote map tiles (Mapbox/OSM), or remote IP APIs directly from frontend JS.
   - Keep the strict CSP in `src-tauri/tauri.conf.json`:
     `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' ipc: http://ipc.localhost`

---

## 2. Windows WFP Kernel Hard-Lock (`guard-helper`)

Located in `guard-helper/src/wfp.rs` and `guard-helper/src/main.rs`:

- **Dual Sublayer Design**:
  1. **Dynamic Session (`FWPM_SESSION_FLAG_DYNAMIC`, weight `0xFFFF`)**: Holds runtime filters while AI NetGuard is active. Automatically purged by the Windows Base Filtering Engine (BFE) if `netguard-guard.exe` crashes or is killed.
  2. **Persistent Offline Sublayer (`FWPM_SUBLAYER_FLAG_PERSISTENT`, weight `0xFFFE`)**: Installed when `require_netguard_for_claude` is enabled. Survives app exit and OS reboot so `Claude Desktop` cannot connect directly or via Clash (`127.0.0.1:7897`) when AI NetGuard is not running.
- **Atomic Refresh & Exact Loopback Port Discipline (`FWPM_LAYER_ALE_AUTH_CONNECT_V4` & `V6`)**:
  - `apply_lock` deletes previous filter IDs and adds new filters **inside a single `FwpmTransactionBegin0..Commit0`** so refresh failures roll back cleanly without a transient gap.
  - Empty `allowed_loopback_ports` MUST emit **zero** loopback permit filters (`plan_app_filters`), resulting in 100% network block. **Never** treat empty port lists as permit-all.
  - Strict CLI shim passes `vec![cfg.cli_port]` (only port `17890`). Persistent Claude Desktop lock tightens to `vec![]` (0 open ports) whenever AI NetGuard stops, toggles offline lock while stopped, or `guard-helper` exits, opening `[cli_port, browser_port, PAC_PORT]` (`17890`, `17891`, `17898`) only while active.
  - `Weight 14` (`FWP_ACTION_PERMIT`): Optional RFC1918 private LAN (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), enabled **only** for the CLI shim (`allow_private_lan: true`), disabled (`false`) for `chrome.exe` and `claude.exe`.
  - `Weight 10` (`FWP_ACTION_BLOCK`): Blocks all other IPv4 and IPv6 outbound connections for that `ALE_APP_ID`.
- **Guard Binary Integrity & Mutual Pipe Authentication (`ipc_client.rs`, `guard-helper/src/main.rs`)**:
  - Installer uses NSIS `"installMode": "perMachine"` (`%ProgramFiles%` Admin-protected ACL). Release builds disable `CARGO_MANIFEST_DIR` path fallbacks and pin `netguard-guard.exe` against build-time `NETGUARD_GUARD_SHA256` (`src-tauri/build.rs`) before `ShellExecuteW("runas")` (true Authenticode signature verification requires an external code-signing cert).
  - Pipe name includes a 128-bit random suffix (`\\.\pipe\ai-netguard-{pid}-{rand128}`) and randomized token filename (`guard-{rand64}.token`).
  - `guard-helper` creates a single persistent handle with `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`, narrowed SDDL `D:(A;;GRGW;;;IU)(A;;GA;;;BA)(A;;GA;;;SY)S:(ML;;NW;;;ME)`, and verifies `GetNamedPipeClientProcessId == parent_pid`.
  - Before sending the token or trusting responses, `GuardClient` verifies `GetNamedPipeServerProcessId`, `GetSecurityInfo` (pipe owner is `BUILTIN\Administrators` or `SYSTEM`), `QueryFullProcessImageNameW` + `TokenElevation` when accessible, bounded 64KB reads, constant-time token comparison, and per-call nonce `auth_proof` SHA-256 verification.
  - Parent-PID watcher (`OpenProcess(PROCESS_SYNCHRONIZE)`) exits, tightens persistent lock to full offline block (`vec![]`), and cleans up dynamic WFP rules + `/32` route when `ai-netguard.exe` terminates.

---

## 3. Claude Desktop (`Anthropic.Claude`) Integration & Pitfalls

1. **Squirrel Multi-Binary Structure**
   - `%LOCALAPPDATA%\AnthropicClaude\claude.exe` (448 KB) is only a Squirrel stub.
   - The actual Electron executable lives at `%LOCALAPPDATA%\AnthropicClaude\app-<version>\claude.exe` (~247 MB), alongside `Update.exe` and `squirrel.exe`.
   - `resolve_claude_desktop_wfp_paths` must lock **all** of these binaries, and `launch_claude_desktop` must spawn the latest `app-*\claude.exe` directly (killing any untracked Start-Menu instance first so Electron's single-instance lock does not drop our proxy arguments).

2. **Command-Line Switch Refusal (`zY(process.argv)`)**
   - Claude Desktop `3.6556.2+` inspects `process.argv` at startup and exits with code 1 (`Claude: refusing to start — a debugging or network-override switch is present on the command line.`) if any of the following switches are passed:
     `--host-resolver-rules`, `--host-rules`, `--remote-debugging-port`, `--remote-debugging-pipe`, `--ignore-certificate-errors`, `--disable-web-security`, `--log-net-log`.
   - **Solution**: Serve a local PAC file on `127.0.0.1:17898/proxy.pac` (`src-tauri/src/pac.rs`) returning `SOCKS5 127.0.0.1:17891` (and `DIRECT` for `localhost`/`127.0.0.1`/`::1`), and launch Claude Desktop with `--proxy-pac-url=http://127.0.0.1:17898/proxy.pac`.

3. **Avoiding `"无法验证您的浏览器。请重试。"` (`missing_client_attestation`)**
   - Clicking **“使用电子邮箱继续”** (`POST /api/auth/send_magic_link`) runs invisible hCaptcha (`__antClientAttestationHcaptchaInvisibleReady`) with `waitOnOpenChallenge: false`.
   - **Do NOT** inject `safebrowsing: false`, `network_prediction_options: 2`, `dns_over_https: off`, `--disable-quic`, or `--lang=ko-KR` into `Claude Desktop` (`%APPDATA%\Claude\Preferences`). Because Electron cannot load the browser MV3 `align.js` extension, its native OS culture remains `zh-CN` / `Asia/Shanghai` (`utc_offset: -480`); forcing `ko-KR` or stripping Chrome safety features creates a contradictory fingerprint that triggers hCaptcha rejection.
   - `sanitize_claude_preferences_file` automatically strips those legacy overrides while keeping `webrtc.ip_handling_policy = "disable_non_proxied_udp"`.
   - Ensure `hcaptcha.com`, `challenges.cloudflare.com`, `accounts.google.com`, `googleapis.com`, and `gstatic.com` are always merged into `sing-box` `dns_remote` and `ai_selector` domain suffixes (`src-tauri/src/singbox.rs`).
   - On datacenter/VPS IPs (where invisible hCaptcha may still refuse silent minting in Electron), use **“使用 Google 继续”** + **“粘贴剪贴板 OAuth 登录链接到安全浏览器”** so OAuth & verification run inside the full `Ungoogled-Chromium` Safe Browser and callback via `claude://login/google-auth`.

---

## 4. Safe Browser (`Ungoogled-Chromium`) & Fingerprint Alignment

- Launched via `launch_browser_url` with isolated `--user-data-dir=%LOCALAPPDATA%\AI-NetGuard\browser-profile`, `--proxy-server=socks5://127.0.0.1:17891`, `--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"`, `--webrtc-ip-handling-policy=disable_non_proxied_udp`, and `--disable-quic`.
- `ensure_fingerprint_extension` generates an MV3 extension (`world: "MAIN"`, `run_at: "document_start"`, `all_frames: true`, `match_about_blank: true`) that aligns:
  - `Intl.DateTimeFormat` and `resolvedOptions().timeZone` -> node's `timezone` (e.g. `Asia/Seoul`)
  - `Date.prototype.getTimezoneOffset` -> dynamic offset computed via `shortOffset` (e.g. `-540` for `Asia/Seoul`)
  - `navigator.language` & `navigator.languages` -> node's `locale` (e.g. `["ko-KR", "ko", "en-US", "en"]`)

---

## 5. Security & UI Verification Checklist

Whenever modifying backend or frontend code, run the full verification suite:

1. **PowerShell, Installer & Transport Safety**:
   - Never interpolate `extra_no_proxy` or user strings directly into PowerShell `-Command`: use static `NG_FIX_*` process env vars (`apply_fix_action`) or UTF-8 Base64 + `-EncodedCommand` (`launch_claude_terminal`). Keep Unicode smart quote escaping (`'` and `\u{2018}`..`\u{201B}`) in `escape_ps_single_quoted`.
   - Portable Chromium downloads (`launcher.rs`) must verify archive SHA-256 (`digest` / `expanded_assets` hash or pinned fallback hash) and use `extract_chromium_zip_safe` (rejects traversal/drive prefixes before/after stripping, rejects symlinks, verifies canonical root containment, caps entries/uncompressed bytes).
   - Hysteria2 VPS script & nodes use `certificate_public_key_sha256` (`pinSHA256`) with `insecure: false` instead of `insecure=1`.
   - Country verification in both `check_node_expectation` and `healthcheck.rs` fails closed if `expected_country` is configured and `country_code` is absent.
2. **Rust Unit & Integration Tests**:
   - `$env:PATH = "$env:USERPROFILE\.cargo\bin;" + $env:PATH; cargo test --workspace`
   - Verifies URI/SPKI-pin parsing, real `sing-box check` (`ai_selector` default-block + `interrupt_exist_connections` + `in_probe` + Hysteria2 pinning), WFP zero-permit empty-port planning, ZIP path-traversal & symlink rejection, fail-closed country checks, PAC server, MV3 extension, and PowerShell escaping.
3. **Headless DOM Overlap & Clipping Audit**:
   - Start `npx vite preview --port 4179 --host 127.0.0.1` and run a headless Edge/Chromium CDP bounding-box audit across all 5 tabs at both `1160x780` (default) and `960x660` (minimum window size) to confirm `issues = 0`.
4. **Release Packaging**:
   - Stop any running `ai-netguard.exe` / `sing-box.exe` instances, then run `& ".\scripts\build-all.ps1"`.
