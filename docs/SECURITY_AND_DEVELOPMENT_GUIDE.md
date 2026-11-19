# AI NetGuard 架构设计、安全审计与防封护城河经验总结

本文档沉淀了 **AI NetGuard** 在 Windows 本地实现 **Claude 零泄漏安全隔离**、**与 Clash Verge / Tailscale 无缝共存**、**内核级 WFP 防火墙硬锁** 以及 **登录风控对抗** 的完整工程实践与最终安全审计结论。

---

## 一、核心痛点与总体架构

### 1.1 为什么常规“开梯子用 Claude”容易触发风控或封号？
1. **出口 IP 万人共用与频繁漂移**：机场订阅节点通常是百人共享机房 IP，且规则分流或节点测速自动切换会导致同一个 Claude 账号在几分钟内跨城市/跨国跳变。
2. **WebRTC / QUIC / 本地 DNS 旁路泄漏**：即使配置了 HTTP/SOCKS 代理，浏览器的 WebRTC STUN（UDP）、HTTP/3 QUIC（UDP 443）或本地 DNS 抢答仍可能绕过代理，直接向 Cloudflare / Anthropic 暴露中国大陆真实公网 IP。
3. **进程裸奔与代理崩溃 Fail-Open**：当本地代理软件未启动、崩溃或切换配置的瞬间，后台运行的 `Claude Desktop`（及其自动更新器 `Update.exe`）会直接回退走系统默认路由直连外网。
4. **多代理抢占冲突**：开发机往往需要同时挂着 **Clash Verge**（日常查阅资料）与 **Tailscale / 公司 VPN**（内网访问），传统全局 TUN 模式会互相覆盖路由表。

### 1.2 四层零泄漏隔离架构
```
[Claude Desktop / 专属 Chromium / 安全终端]
        │  1. WFP 内核硬锁 (FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6)
        │     仅放行 127.0.0.1:17890 / 17891 / 17898，封死直连与 Clash :7897
        ▼
[本地 sing-box 隔离核心 (127.0.0.1:17890 & :17891)]
        │  2. 协议清洗：全局 reject QUIC (UDP 443) 与 IPv6 (::/0)
        │     远端 DoH (1.1.1.1) 经代理隧道解析 Anthropic / Cloudflare / hCaptcha / Google
        ▼
[Windows 物理网卡旁路 (bind_interface + /32 静态主机路由 Metric=1)]
        │  3. 绕过 Clash Verge 虚拟网卡与 Tailscale，直通物理网关 (如 192.168.1.1)
        ▼
[独享静态出口节点 (如海外 VPS 203.0.113.10:443 · VLESS+Reality)]
        │  4. 后台每 4 秒探针核验 IP 与归属国，异常秒切 ai_block 黑洞或终止内核
```

---

## 二、关键技术实现与踩坑经验

### 2.1 Windows WFP 内核防火墙双层锁（`guard-helper`）
- **为什么不能只靠代理参数？**
  子进程或 Chromium 组件在网络异常时可能尝试直连，且如果用户直接从 Windows 开始菜单启动 Claude Desktop，不会带上任何代理参数。
- **动态会话 + 持久化离线锁双层设计（`guard-helper/src/wfp.rs`）**：
  - **动态层（`FWPM_SESSION_FLAG_DYNAMIC`，权重 `0xFFFF`）**：随 `netguard-guard.exe` 生命周期存在，即使进程崩溃或被强制结束，Windows BFE 内核也会自动回收规则，不会把电脑锁死。
  - **持久化离线层（`FWPM_SUBLAYER_FLAG_PERSISTENT`，权重 `0xFFFE`）**：写入系统 BFE 数据库，开机即生效。**精细限定回环端口 `[17890, 17891, 17898]`**：
    - `Weight 15 (PERMIT)`：仅允许受控 `.exe` 连接 `127.0.0.1` 的 `17890`、`17891`、`17898` 端口（这同时拦截了本机 Clash 的 `7897` 端口！）。
    - `Weight 10 (BLOCK)`：阻断该 `.exe` 的其它一切 IPv4 / IPv6 出站连接。
- **Squirrel 安装包的多进程陷阱**：
  Windows 版 Claude Desktop（`Anthropic.Claude`）采用 Squirrel 打包：
  - `%LOCALAPPDATA%\AnthropicClaude\claude.exe`（仅 448KB）只是外壳启动器；
  - 真正的 Electron 主程序在 `%LOCALAPPDATA%\AnthropicClaude\app-3.6556.2\claude.exe`（247MB），此外还有 `Update.exe` 与 `squirrel.exe`。
  - **经验**：WFP 规则必须同时绑定这 4 个二进制路径，否则外壳 `claude.exe` 拉起 `app-*\claude.exe` 后会逃出规则。

### 2.2 攻克 Claude Desktop 命令行拦截与 `无法验证您的浏览器`
1. **命令行参数黑名单（`Claude: refusing to start`）**
   - 逆向 `app.asar` 发现，Claude Desktop `3.6556.2` 在启动时会调用 `zY(process.argv)` 检查命令行，一旦发现 `--host-resolver-rules`、`--remote-debugging-port`、`--ignore-certificate-errors` 等参数就会直接退出拒绝启动。
   - **解法**：Claude Desktop 原生支持 `--proxy-pac-url`。我们在 `src-tauri/src/pac.rs` 内置了轻量级本地 PAC 服务（`127.0.0.1:17898/proxy.pac`），返回 `SOCKS5 127.0.0.1:17891`，使 Chromium 渲染进程 100% 走 SOCKS5h 隧道且完全合法合规。
2. **解决邮箱登录报错 `无法验证您的浏览器。请重试。`（`missing_client_attestation`）**
   - **根因分析**：Anthropic 的 `/api/auth/send_magic_link` 接口绑定了 **无感 hCaptcha（Invisible）**，且前端代码（`c70d7cb34-CxDPdnl3.js`）写死了 `waitOnOpenChallenge: false`——只要 hCaptcha 不予静默放行，客户端不会弹出图形验证码等待用户点击，而是直接报错 `missing_client_attestation`。
   - **三大触发点与修复**：
     1. **不要篡改 Electron 的 Chromium 安全首选项**：此前往 `%APPDATA%\Claude\Preferences` 注入 `safebrowsing: false`、`network_prediction_options: 2` 及 `--disable-quic`、`--lang=ko-KR`，与 Electron 原生上报的 Windows 系统时区（`Asia/Shanghai`、`utc_offset: -480`）和语言（`zh-CN`）形成矛盾特征。移除这些覆盖项（仅保留 `webrtc: disable_non_proxied_udp`，QUIC/IPv6 由 WFP + `sing-box` 在底层拦截）后特征恢复自然。
     2. **补全验证域名远端解析**：将 `hcaptcha.com`、`challenges.cloudflare.com`、`accounts.google.com`、`googleapis.com`、`gstatic.com` 固定并入 `sing-box` 的 `dns_remote` 与 `ai_selector` 规则。
     3. **清理历史跨代理脏 Cookie + Google OAuth 旁路登录**：清理裸连/Clash 时期残留的 `ant-did` 与 `Network/Cookies`，并通过 **“使用 Google 继续” -> 复制链接到专属防泄漏浏览器完成 OAuth -> `claude://` 回调桌面端**，即可在机房 IP（`Purity 60/100`）下一次顺利登录。

### 2.3 专属浏览器（`Ungoogled-Chromium`）MV3 时区与语言对齐
- 通过 `src-tauri/src/launcher.rs` 自动生成 Manifest V3 扩展（注入 `world: "MAIN"`, `run_at: "document_start"`, `all_frames: true`），在页面脚本执行前重写：
  - `Intl.DateTimeFormat` 默认时区与 `resolvedOptions().timeZone` -> `Asia/Seoul`
  - `Date.prototype.getTimezoneOffset()` -> `-540`（UTC+9）
  - `navigator.language` / `navigator.languages` -> `ko-KR, ko, en-US, en`
- 配合 `--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"` 与 `--webrtc-ip-handling-policy=disable_non_proxied_udp`，在 `ip.net.coffee` 与 `fuck-claude.vercel.app` 上实现零本地信号泄漏。

---

## 三、最终代码安全审计报告（漏洞排查与修复记录）

在项目收尾及同行深度静态复核阶段，对 `guard-helper`、`guard-protocol`、`src-tauri`、打包配置与前端进行了两轮全量安全审计，发现并修复了以下安全隐患：

### 3.1 第一轮安全审计修复（6 项基础安全防线）
| 编号 | 风险等级 | 位置 | 隐患描述 | 修复措施（已落地验证） |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **高危** | [healthcheck.rs](file:///e:/net_manager/src-tauri/src/healthcheck.rs) / [launcher.rs](file:///e:/net_manager/src-tauri/src/launcher.rs) | **PowerShell 引号命令注入**：`extra_no_proxy` 等字符串直接拼接至 `powershell.exe -Command`。 | 引入环境变量隔离 + UTF-16LE `-EncodedCommand`（第二轮进一步消除全部插值并防御 Unicode 弯引号）。 |
| **2** | **中高** | [lib.rs](file:///e:/net_manager/src-tauri/src/lib.rs) | **WFP 规则下发失败时 Fail-Open**：`ApplyWfpLock` 失败未中止启动。 | 改为严格 Fail-Closed：一旦失败立即停止 `sing-box` 并中止启动。 |
| **3** | **中高** | [lib.rs](file:///e:/net_manager/src-tauri/src/lib.rs) | **熔断器 API 失联兜底缺失**：`send_kill_switch_http` 失败未二次断流。 | 若 `send_kill_switch_http` 失败立即执行 `inner.singbox.stop()`。 |
| **4** | **中低** | [main.rs](file:///e:/net_manager/guard-helper/src/main.rs) | **管道读取无界及非常量比对**。 | 限制 64KB 单行读取上限（`take(65536)`）与常量时间比对 `constant_time_eq_bytes`。 |
| **5** | **低** | [tauri.conf.json](file:///e:/net_manager/src-tauri/tauri.conf.json) | **WebView2 `csp: null`**。 | 配置严格本地 CSP，禁止管理面板自身向公网发起连接。 |
| **6** | **低** | [pac.rs](file:///e:/net_manager/src-tauri/src/pac.rs) | **PAC 服务端缺少读写超时**。 | 为连接设置 500ms 读写超时，单元测试支持随机空闲端口。 |

### 3.2 第二轮深度安全加固（回应 9 项高/中风险审查发现）
| 编号 | 风险等级 | 审查问题 | 落地修复与验证方式 |
| :--- | :--- | :--- | :--- |
| **H1** | **高** | **提权助手可被普通权限进程替换**（`currentUser` 安装模式 + 未校验哈希 + Release 含开发路径回退） | 1. [tauri.conf.json](file:///e:/net_manager/src-tauri/tauri.conf.json) 改用 NSIS `"installMode": "perMachine"`（安装至受管理员 ACL 保护的 `%ProgramFiles%`）；<br>2. Release 构建关闭 `CARGO_MANIFEST_DIR` 开发路径回退；<br>3. [build.rs](file:///e:/net_manager/src-tauri/build.rs) 在编译期固化 `NETGUARD_GUARD_SHA256`，[ipc_client.rs](file:///e:/net_manager/src-tauri/src/ipc_client.rs) 提权前校验文件非常规链接且 SHA-256 严格一致。（注：真正的 Authenticode 发布者签名仍需外部代码签名证书，详见第四章边界说明） |
| **H2** | **高** | **本地进程可冒充 Guard 伪造 WFP 状态**（可预测管道名 + 发送明文令牌前未核验服务端身份） | 1. 管道名改为 `ai-netguard-{pid}-{rand128}`，令牌文件随机命名；<br>2. [main.rs](file:///e:/net_manager/guard-helper/src/main.rs) 使用 `FILE_FLAG_FIRST_PIPE_INSTANCE` 复用单一句柄消除重连时间窗，校验 `GetNamedPipeClientProcessId == parent_pid`，SDDL 缩紧 `IU` 为 `GRGW`；<br>3. [ipc_client.rs](file:///e:/net_manager/src-tauri/src/ipc_client.rs) **发送令牌前**先校验 `GetNamedPipeServerProcessId` + `GetSecurityInfo`（管道所有者必须为 `BUILTIN\Administrators` 或 `SYSTEM`）+ `QueryFullProcessImageNameW`/`TokenElevation`，并用共享 Secret+Nonce 校验响应签名 `auth_proof`。 |
| **H3** | **高** | **熔断前后流量可能继续外发**（启动默认先放行 `ai_exit` + 缺少 `interrupt_exist_connections`） | [singbox.rs](file:///e:/net_manager/src-tauri/src/singbox.rs) 与 [lib.rs](file:///e:/net_manager/src-tauri/src/lib.rs)：`ai_selector` 默认改为 `"ai_block"` 并启用 `"interrupt_exist_connections": true`；新增仅供后台探测使用的 `in_probe` SOCKS 入站直连 `ai_exit`；启动与实时巡检通过 `in_probe` 核验出口通过后才解锁 `ai_exit`，熔断时立即切断存量连接。 |
| **H4** | **高** | **WFP 规则刷新空窗期 & Guard 异常退出状态陈旧** | [wfp.rs](file:///e:/net_manager/guard-helper/src/wfp.rs) 改为单事务原子刷新（先在同事务内删除旧 ID 并写入新规则再统一提交，失败则回滚旧规则）；`WfpStatus` 实时核验 BFE 句柄（`FwpmFilterGetById0`）；[lib.rs](file:///e:/net_manager/src-tauri/src/lib.rs) 监控循环每 4 秒轮询 Guard 状态，若开启硬锁期间 Guard 离线或规则丢失则立即触发 Fail-Closed 停机。 |
| **H5** | **高** | **Chromium 安装器 ZIP 路径穿越与未校验摘要** | [launcher.rs](file:///e:/net_manager/src-tauri/src/launcher.rs)：下载前从 GitHub API `digest` 或 `expanded_assets` HTML 解析 `windows_x64.zip` 对应 SHA-256（失败仅回退带固定哈希的受信任版本）；流式校验摘要；`extract_chromium_zip_safe` 在剥离首级目录前后全段路径合法性校验、拒绝符号链接、规范化根目录逃逸检查并限制条目数与解压总字节数（已通过单测验证）。 |
| **M1** | **中** | **WFP 放行空回环列表变全通 & 离线锁在网关关闭时留空口** | [wfp.rs](file:///e:/net_manager/guard-helper/src/wfp.rs) 删除 `allowed_loopback_ports.is_empty()` 放行全部回环端口逻辑（空列表=0 放行=全阻断）；严格 CLI 仅放行 `[cli_port]`；网关停止、空闲开启离线锁或 `guard-helper` 退出时自动将持久化离线锁收紧为 `[]` 全阻断，仅在网关运行期间放行 `[cli_port, browser_port, PAC_PORT]`。 |
| **M2** | **中** | **PowerShell Unicode 弯引号绕过转义风险** | [healthcheck.rs](file:///e:/net_manager/src-tauri/src/healthcheck.rs) 转义函数覆盖 ASCII `'` 及 Unicode `\u{2018}..\u{201B}` 且过滤控制字符；`apply_fix_action` 改用静态脚本读取进程环境变量 `NG_FIX_*`；`launch_claude_terminal` 改用 UTF-16LE `-EncodedCommand` + UTF-8 Base64 参数解码，彻底消除命令插值风险。 |
| **M3** | **中** | **生成的 Hysteria2 链接默认带 `insecure=1` 关闭证书校验** | [uri_parser.rs](file:///e:/net_manager/src-tauri/src/uri_parser.rs)、[singbox.rs](file:///e:/net_manager/src-tauri/src/singbox.rs) 与前端 [NodeEditor.tsx](file:///e:/net_manager/src/components/NodeEditor.tsx)：一键部署脚本改用 `pinSHA256=sha256/$PIN` 证书公钥指纹固定，客户端生成 `"certificate_public_key_sha256"` 且强制 `insecure: false`（未固定证书且勾选 `insecure` 时 UI 明确警告）。 |
| **M4** | **中** | **出口国家字段缺失时跳过核验** | [network.rs](file:///e:/net_manager/src-tauri/src/network.rs) 在 `ipify` 前补充 `ipapi.co` / `api.ip.sb` 两级完整 GeoIP 备用探针；[lib.rs](file:///e:/net_manager/src-tauri/src/lib.rs) 与 [healthcheck.rs](file:///e:/net_manager/src-tauri/src/healthcheck.rs) 统一在配置了 `expected_country` 但未返回 `country_code` 时判为失败并触发熔断。 |

---

## 四、已知客观边界说明（日常使用必读）

1. **Authenticode 代码签名限制**：
   - 本地开发/构建产物目前通过 **NSIS `perMachine` 安装至 `%ProgramFiles%`（仅管理员可写）+ 编译期 `NETGUARD_GUARD_SHA256` 校验和固定** 防止提权助手被篡改或替换；如需面向广域公开发布以通过 Windows SmartScreen / Authenticode 强签名校验，仍需采购受信任代码签名证书对安装包、`ai-netguard.exe` 与 `netguard-guard.exe` 进行签名。
2. **本地文件读写与仿真任务无需隔离**：
   - AI NetGuard 是**网络出站防泄漏网关**，而非虚拟机/文件沙盒。你在本地运行 MATLAB/Python/C++ 仿真或让 Claude 读写本地项目文件夹不会触发 Anthropic 账号风控（Anthropic 只检测连向其服务器的网络请求）。
3. **外部子进程联网边界**：
   - WFP 规则按 `.exe` 路径精确绑定（已锁死 `claude.exe` 全家桶、便携 `chrome.exe` 及严格模式下的 `ai-node.exe`）。
   - 如果未来在 Claude Desktop 中挂载了**需要主动访问 Anthropic 接口的外部 MCP 子进程**，请确保它继承 `127.0.0.1:17890` 代理环境变量，或在 AI NetGuard 的 **“Claude Code 终端（勾选严格 WFP 锁死）”** 中运行。
4. **Claude Desktop 自动更新提示**：
   - 当 Claude Desktop 升级到新版本号（生成新的 `app-3.xxxx\claude.exe` 目录）时，只需在 AI NetGuard 中重新点一次“启动安全网关”或“安全模式启动 Claude Desktop”，WFP 持久化与动态规则就会自动扫描并锁死新版本路径。
