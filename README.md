<div align="center">

# AI NetGuard

**Windows 平台下的 AI 专属网络隔离与 WFP 内核级防泄漏安全网关**

基于 **Tauri 2 · Rust · React 18 · sing-box · Windows Filtering Platform (WFP)** 构建

[![GitHub Release](https://img.shields.io/github/v/release/henghaxiaowu/ai-netguard?style=flat-square&color=2563eb)](https://github.com/henghaxiaowu/ai-netguard/releases/tag/v0.1.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-16a34a.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64-0f172a.svg?style=flat-square)](#本地开发与从源码构建)
[![Agent Ready](https://img.shields.io/badge/AI_Agent-Ready%20%28Skill%20Included%29-7c3aed.svg?style=flat-square)](#-ai-agent-一键配置指南)

[宣传演示](#-宣传视频与展示) · [Agent 一键配置](#-ai-agent-一键配置指南) · [应用场景](#-典型应用场景) · [架构原理](#-四层零泄漏隔离架构) · [使用教程](#-手动使用教程5-分钟上手) · [常见问题](#-常见问题与排查-faq)

</div>

---

## 🎬 宣传视频与展示

https://github.com/user-attachments/assets/cf2bd7ea-e3fa-4140-a59b-066bf845f924

> ⬇️ **[下载最新 Windows x64 安装包 (v0.1.0)](https://github.com/henghaxiaowu/ai-netguard/releases/tag/v0.1.0)** · 📖 **[安全架构与逆向排查手记](docs/SECURITY_AND_DEVELOPMENT_GUIDE.md)**

---

## 🤖 AI Agent 一键配置指南

不想自己点来点去、查端口或配环境变量？你可以直接把下面对应场景的指令复制发送给你的本地 AI Agent（**Claude Code / Antigravity / Cursor / Codex / Windsurf**），让 Agent 自动帮你完成安装、节点初始化、共存检测或源码构建。

> 本仓库已内置 Agent 专属技能文档 [`.agents/skills/ai-netguard-playbook/SKILL.md`](.agents/skills/ai-netguard-playbook/SKILL.md)，主流编码 Agent 打开或读取仓库后即可掌握全部安全边界与 WFP 规则。

### 场景 1｜已下载安装包，让 Agent 一键完成安装检查与节点配置

适合下载了 `AI.NetGuard_0.1.0_x64-setup.exe` 的普通用户——把下面整段发给 Agent（替换尖括号里的节点链接即可）：

```text
请帮我配置并启动 AI NetGuard（仓库参考 https://github.com/henghaxiaowu/ai-netguard）：
1. 检查 C:\Program Files\AI NetGuard\ 是否已安装；如果我刚下载了安装包但还未安装，先帮我检查并提示关闭旧的 ai-netguard / netguard-guard / sing-box 进程后再运行安装。
2. 检查我本机是否正在运行 Clash Verge、Tailscale 或其他代理软件，判断 17890 / 17891 / 17898 端口是否被占用。
3. 读取并按需要更新我的配置文件 %LOCALAPPDATA%\AI-NetGuard\config.json（如果不存在则先启动一次 AI NetGuard 生成或按默认结构初始化）：
   - 节点信息：<在这里粘贴你的 vless:// 或 hy2:// 节点链接，或写"保留界面导入">
   - 自动匹配并核对 expectedCountry、timezone、locale（例如首尔 KR -> Asia/Seoul / ko-KR）
   - 保持 wfpLockEnabled: true、alignFingerprint: true、killSwitch: "fail_closed"
   - 如果本机有 Clash Verge / Tailscale，设置 outboundMode 为 "physical_bypass"
4. 完成后告诉我下一步在软件界面点击哪些按钮验证（包括 8 项体检与 ip.net.coffee 核验）。
```

### 场景 2｜有空白海外 VPS，让 Agent 帮我部署独享节点并导入

```text
我有一台新的海外 VPS（IP: <你的VPS_IP>，SSH 信息: <user/端口>），我想配合 AI NetGuard 使用：
1. 参考 AI NetGuard 的节点解析格式（vless:// Reality 或 hy2:// 带 pinSHA256 公钥固定，禁止生成 insecure=1），帮我在 VPS 上配置或检查服务端部署。
2. 生成标准分享链接，并帮我写入 %LOCALAPPDATA%\AI-NetGuard\config.json 中的活跃节点，同时对齐节点所在国家代码、时区与语言。
3. 如果启用了本地或服务端防火墙，确保仅放行对应代理端口并提醒我执行出口纯净度检测。
```

### 场景 3｜给本地 Agent 仓库地址，从零全自动拉取、编译与打包安装

```text
请帮我在当前 Windows 机器上从源码部署 AI NetGuard：
1. 克隆仓库 https://github.com/henghaxiaowu/ai-netguard 并进入目录。
2. 先检查 Node.js、Rust 工具链和 cargo 状态，运行 npm install。
3. 从 SagerNet/sing-box 官方 Release 获取匹配的 Windows amd64 二进制文件，校验后放置到 src-tauri/binaries/sing-box-x86_64-pc-windows-msvc.exe。
4. 运行 cargo test --workspace 确认后端测试全部通过后，执行 .\scripts\build-all.ps1 编译 guard-helper 与 Release 安装包。
5. 安装完成后引导我完成第一次 UAC 提权与安全浏览器初始化。
```

### 场景 4｜遇到断连、端口冲突或 Claude 风控：让 Agent 深度诊断

```text
请先阅读本仓库的 .agents/skills/ai-netguard-playbook/SKILL.md 和 docs/SECURITY_AND_DEVELOPMENT_GUIDE.md：
1. 检查当前系统中 ai-netguard、netguard-guard、sing-box 的运行状态以及 17890 / 17891 / 17898 端口监听情况。
2. 审查 %LOCALAPPDATA%\AI-NetGuard\config.json 中的 outboundMode、wfpLockEnabled、expectedCountry 与 aiDomains。
3. 针对我当前的问题（描述现象：<例如：启动网关失败 / Claude Desktop 提示无法验证浏览器 / Clash 开启后掉线>），给出具体根因与可执行修复方案；不要修改安全策略中的 Fail-Closed 与 WFP 防泄漏底线。
```

---

## 💡 为什么需要 AI NetGuard？

日常开发机同时使用 **Clash Verge / Mihomo、Tailscale / 公司内网 VPN** 与 **Claude Web / Claude Desktop / Claude Code CLI** 时，传统全局代理很容易引发风控：

| 常见风险 | 传统全局/机场代理的问题 | AI NetGuard 的解法 |
| :--- | :--- | :--- |
| **出口 IP 飘移** | 机场节点多人共用、规则自动测速切换导致短时间跨国跳变 | 绑定独享静态节点，每 4 秒后台巡检出口 IP 与归属国，异常秒切黑洞 |
| **底层旁路泄漏** | WebRTC STUN（UDP）、HTTP/3 QUIC（UDP 443）、IPv6 与本地 DNS 抢答暴露真实 IP | `sing-box` 协议清洗 + 远端 DoH + **Windows WFP 内核级硬锁**兜底 |
| **代理崩退裸奔** | 网关关闭或崩溃时，后台 `Claude Desktop` / `Update.exe` 自动回退直连外网 | 支持 **Fail-Closed 紧急熔断** 与 **持久化离线硬锁**，未开网关严禁联网 |
| **多代理冲突** | 全局 TUN 互相抢占路由表，导致内网/日常资料代理与 AI 链路互相打架 | **不接管系统全局代理**；支持物理网卡直通旁路（Bypass）或链式前置共存 |
| **指纹与风控冲突** | 出口在首尔/美西，浏览器却上报中文与 `Asia/Shanghai` 时区触发验证码/风控 | 内置 MV3 扩展自动对齐独立浏览器 **时区 / 语言 / WebRTC**；Electron 端原生 PAC 防篡改 |

---

## 🎯 典型应用场景

1. **Claude Web 与桌面端高纯净隔离登录**
   - 一键下载并启动独立的便携版 **Ungoogled-Chromium**（与日常 Chrome 配置完全隔离），自动注入 MV3 时区与语言对齐扩展，并可一键同时打开 `ip.net.coffee`、`fuck-claude.vercel.app`、`claude.ai` 查验出口与指纹。
   - **Claude Desktop 安全启动器**自动通过本地 PAC（`127.0.0.1:17898/proxy.pac`）接管 Electron 与 Squirrel 全家桶流量，并支持将 Google OAuth 登录链接从剪贴板一键转发到防泄漏浏览器完成认证回调。
2. **与 Clash Verge / Tailscale / 公司 VPN 无缝共存**
   - 保持你原有的系统代理、Clash 规则或 Tailscale 内网访问完全不变。
   - 通过 **物理网卡旁路模式（Physical Bypass）**，AI 流量由 `sing-box` 通过 `bind_interface` 直通物理网关出站，彻底绕开虚拟 TUN 网卡。
3. **Claude Code CLI 终端开发防泄漏**
   - 从应用内一键拉起配置好独立代理环境变量（`127.0.0.1:17890`）与 `NO_PROXY` 的 PowerShell / 终端工作区。
   - 勾选 **严格 WFP 内核锁** 后，可进一步在内核层封死 CLI 运行时 (`node.exe` / `ai-node.exe` 等) 的直连出站与绕过风险。
4. **自建独享 VPS 节点快速落地与防失误审计**
   - 支持常见代理协议导入，也内置 **VLESS + Reality** 与 **Hysteria2（带 `pinSHA256` 公钥固定）** VPS 一键部署脚本生成器。
   - 每次启动或点击体检时，实时执行 **8 项深度安全校验**，发现节点异常或规则缺失可直接一键修复或触发熔断。

---

## 🛡 四层零泄漏隔离架构

```text
[Claude Desktop / 专属 Chromium / Claude Code CLI 终端]
        │  1. Windows WFP 内核硬锁 (FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6)
        │     仅放行 127.0.0.1 的受控端口 (17890 / 17891 / 17898)，封死直连与其它本地代理端口
        ▼
[本地 sing-box 隔离核心]
        │  - 127.0.0.1:17890  CLI 混合代理入站 (HTTP / SOCKS5)
        │  - 127.0.0.1:17891  浏览器 / PAC 专用 SOCKS5 入站
        │  - 127.0.0.1:17898  轻量本地 PAC 服务 (/proxy.pac)
        │  2. 协议清洗：全局 reject QUIC (UDP 443) 与 IPv6 (::/0)
        │     远端 DoH (1.1.1.1) 经代理隧道解析 Anthropic / Cloudflare / hCaptcha / Google 等域名
        ▼
[共存与出站路由层]
        │  3. Physical Bypass：绑定物理网卡直通网关 (如 192.168.1.1) 绕过虚拟网卡
        │     Upstream Detour：经本地前置代理链路转发
        │     Default Route：跟随当前系统默认路由
        ▼
[独享静态出口节点 (如海外 VPS 203.0.113.10:443 · VLESS+Reality / Hysteria2)]
        │  4. 启动预检 + 每 4 秒后台探针核验真实出口 IP 与归属国代码，异常立即 Fail-Closed 熔断
```

---

## 📘 手动使用教程（5 分钟上手）

### 第 1 步：安装与权限准备

1. 前往 [Releases 页面](https://github.com/henghaxiaowu/ai-netguard/releases/tag/v0.1.0) 下载最新安装包 `AI.NetGuard_0.1.0_x64-setup.exe`。
2. 运行安装程序（程序安装至受系统管理员 ACL 保护的 `C:\Program Files\AI NetGuard\` 目录）。
   - ⚠️ **升级重装提示**：若本机此前已运行 AI NetGuard，请先在系统托盘右键完全退出主程序及网关后再运行安装包，避免旧进程占用 `sing-box.exe` / `netguard-guard.exe` 导致覆盖失败。
3. 启动安全网关或开启 **Windows WFP 内核锁** 时，系统会弹出 UAC 提权确认，用于拉起高权限守护进程 `netguard-guard.exe` 管理内核过滤规则。

### 第 2 步：配置独享出口节点

打开左侧菜单 **「出口与共存路由」**：

- **方式 A — 导入已有节点**：在链接输入框直接粘贴并解析分享链接，支持格式：
  - `vless://`（支持 Reality / TLS）
  - `hy2://` / `hysteria2://`（支持 `pinSHA256` 证书公钥指纹固定）
  - `ss://`、`trojan://`、`socks5://`、`http://` / `https://`
- **方式 B — 一键部署个人 VPS**：在节点编辑器底部切换 **VLESS + Reality** 或 **Hysteria2**，生成服务端一键部署脚本到你自己的海外 VPS 运行，脚本执行后会直接输出可导入的节点链接（Hysteria2 默认强制使用证书公钥固定 `pinSHA256`，关闭不安全的跳过校验）。
- **核对出口期望与指纹对齐**：
  - 建议填写 **预期出口国家代码**（如 `KR`、`US`、`JP`，默认 `KR`），并按节点所在地选择 **时区**（如 `Asia/Seoul`）与 **语言**（如 `ko-KR`）。
  - 点击右上角 **「保存」** 提交配置（配置自动持久化到 `%LOCALAPPDATA%\AI-NetGuard\config.json`）。

### 第 3 步：选择共存与路由模式

在 **「出口与共存路由」** 中根据你的本机网络环境选择出站模式：

- **物理网卡旁路 (`Physical Bypass`，默认推荐)**：直接绑定本机物理网卡出站，自动绕过 Clash Verge 虚拟网卡与 Tailscale 等软件，互不干扰。
- **上游代理链式转发 (`Upstream Detour`)**：如果你的网络环境无法直连 VPS，需要借助本地前置代理（如 `127.0.0.1:7890`）才能连上你的独享 VPS，可选择此模式实现链式转发（仍由你的独享 VPS 作为最终 AI 出口 IP）。
- **默认系统路由 (`Default Route`)**：使用操作系统当前默认路由直连出口节点。

### 第 4 步：启动网关与安全工作区

回到左侧 **「总览与安全启动」**：

1. 点击右上角 **「启动安全网关」**：
   - 后端会拉起 `netguard-guard`（写入 WFP 内核放行/阻断规则）与 `sing-box` 核心。
   - 默认策略会先通过内置探针验证节点真实出口 IP 与国家匹配，验证通过后才切通正式流量（Fail-Closed）。
2. 启动各受保护客户端：
   - **防泄漏浏览器**：首次点击 **「下载配置」** 自动从官方发布源校验 SHA-256 并解压便携版 Ungoogled-Chromium；随后点击 **「安全打开」** 或 **「全部检测页」** 核验出口纯净度与时区/语言一致性。
   - **Claude Desktop**：点击 **「安全启动」** 拉起桌面端。若在邮箱验证遇到异常，点击 **「使用 Google 继续」**，复制跳转链接后点击面板的 **「接管 OAuth」** 在防泄漏浏览器完成登录回调即可。
   - **Claude Code CLI 终端**：填入你的本地项目工作目录，按需勾选 **「严格 WFP 锁」**，点击 **「启动终端」** 即可在隔离环境中运行 `claude`。

### 第 5 步：深度体检与应急防护

- **IP 与指纹体检**：查看 **8 项实时安全审计**（`出口 IP`、`VPN 共存`、`DNS 防泄漏`、`IPv6 阻断`、`WebRTC / QUIC`、`WFP 内核锁`、`熔断策略`、`CLI 链路`），出现告警时可直接点击对应项的修复动作或点击 **「立即全面体检」**。
- **紧急熔断（Kill Switch）**：在顶部或概览区一键切换熔断状态；在 `FailClosed` 策略下，一旦出口 IP 漂移、归属国不符或 Guard 掉线，网关会自动切入 `ai_block` 黑洞并切断存量连接。
- **持久化离线硬锁**（**「隔离与规则加固」**）：开启后会在 Windows BFE 持久化过滤层写入规则——**即使尚未打开 AI NetGuard，也禁止 Claude Desktop 私自联网**，彻底杜绝开机自启或误点图标导致的直连泄漏。

---

## 🖥️ 界面功能模块一览

| 侧边栏页面 | 主要功能 |
| :--- | :--- |
| **总览与安全启动** | 网关/熔断控制、实时出口 IP 与延时波形、地理定位可视化、浏览器 / Claude Desktop / CLI 一键安全启动 |
| **IP 与指纹体检** | 按类别筛选并运行 8 项防泄漏审计与环境变量/规则一键修复 |
| **出口与共存路由** | 多节点管理、URI 链接导入、VPS 一键脚本生成、物理网卡旁路/前置链式路由配置 |
| **隔离与规则加固** | WFP 内核锁、Claude Desktop 持久化离线硬锁、本地端口 (`17890`/`17891`)、AI 域名列表与浏览器指纹开关 |
| **内核运行日志** | 按来源（`sing-box`、`WFP`、`Guard`、`熔断`、`恢复`）实时过滤与导出运行日志 |

---

## ❓ 常见问题与排查 (FAQ)

<details>
<summary><b>1. 覆盖升级安装时提示 <code>Error opening file for writing: C:\Program Files\AI NetGuard\sing-box.exe</code></b></summary>

说明旧版 `ai-netguard.exe`、`netguard-guard` 或 `sing-box.exe` 仍在后台运行并占用了安装目录文件锁。先在系统托盘右键彻底退出 AI NetGuard（或在任务管理器结束上述进程），再重新运行安装包即可。

</details>

<details>
<summary><b>2. Claude Desktop 邮箱登录提示“无法验证您的浏览器，请重试”</b></summary>

这是 Anthropic 登录接口的无感 hCaptcha 在桌面端 Electron 环境下的常见风控拦截。建议通过软件内 **「安全启动」** 拉起 Claude Desktop 后选择 **「使用 Google 继续」**，复制 OAuth 登录网址，再点击面板上的 **「接管 OAuth」** 在专属防泄漏浏览器完成登录并回调桌面端。原理详见 [安全与开发指南](docs/SECURITY_AND_DEVELOPMENT_GUIDE.md#22-攻克-claude-desktop-命令行拦截与-无法验证您的浏览器)。

</details>

<details>
<summary><b>3. 同时开着 Clash Verge / Tailscale 无法连通或节点超时怎么办？</b></summary>

- 若你的本机网络能够直连海外 VPS：请选择 **Physical Bypass（物理网卡旁路）**，让 AI 流量绕过 Clash/Tailscale 虚拟网卡直通物理网关。
- 若本机网络必须经由本地 Clash 才能连通 VPS：请切换为 **Upstream Detour（上游代理链式转发）**，填好本地前置代理端口（如 `127.0.0.1:7890` 或 `7897`），最终出口 IP 依然严格保持为你的独享 VPS。

</details>

<details>
<summary><b>4. 配置文件与便携浏览器数据保存在哪里？</b></summary>

全部运行时数据默认存储在 `%LOCALAPPDATA%\AI-NetGuard\` 目录下，包含：
- `config.json`：节点配置、出站模式、端口及加固开关
- `browser\` / `browser-profile\`：便携版 Ungoogled-Chromium 及其独立配置目录
- `fingerprint-ext\`：自动生成的 MV3 时区与语言对齐扩展

</details>

---

## 📂 目录结构

```text
.
├── .agents/skills/ai-netguard-playbook/ # AI Agent 架构规范与防泄漏审计 Playbook
├── src/                                 # React 18 + Tailwind CSS v4 + Radix UI (shadcn/ui) 前端界面
├── src-tauri/                           # Tauri 2 Rust 主后端（配置管理、sing-box 编排、健康体检、启动器）
│   └── binaries/                        # sidecar 二进制目录（放置 sing-box 与编译后的 netguard-guard）
├── guard-helper/                        # Windows WFP 内核防火墙提权守护进程 (netguard-guard.exe)
├── guard-protocol/                      # 主程序与 Guard 守护进程间的 Named Pipe IPC 协议与 HMAC 鉴权
├── scripts/build-all.ps1                # 一键 Release 编译与 NSIS 安装包打包脚本
└── docs/
    ├── media/                           # 宣传视频封面与展示素材
    └── SECURITY_AND_DEVELOPMENT_GUIDE.md # 技术架构、防风控经验与安全审计记录
```

---

## 🛠️ 本地开发与从源码构建

### 环境依赖

- Windows 10 / 11 (x64)
- Node.js 20+ & npm
- Rust stable 工具链 (`x86_64-pc-windows-msvc`)
- 在 `src-tauri/binaries/` 下准备好官方 [sing-box](https://github.com/SagerNet/sing-box/releases) Windows amd64 可执行文件，并命名为：`sing-box-x86_64-pc-windows-msvc.exe`

### 开发模式运行

```powershell
npm install
cargo build -p guard-helper
Copy-Item .\target\debug\netguard-guard.exe .\src-tauri\binaries\netguard-guard-x86_64-pc-windows-msvc.exe -Force
npm run tauri dev
```

### 运行后端单元测试

```powershell
cargo test --workspace
```

### 一键打包 Release 安装包（NSIS）

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-all.ps1
```

打包完成后可在 `target\release\bundle\nsis\` 下获得 `AI NetGuard_0.1.0_x64-setup.exe`。

---

## 🔐 安全边界与延伸阅读

- **网络边界而非本地文件沙盒**：AI NetGuard 专注于网络出站隔离与防泄漏，不会限制你在本地运行代码或读写项目文件。
- **详细技术架构与审计报告**：请参阅 [docs/SECURITY_AND_DEVELOPMENT_GUIDE.md](docs/SECURITY_AND_DEVELOPMENT_GUIDE.md)，了解双层 WFP 原子事务刷新、Hysteria2 公钥固定、Chromium ZIP 安全校验及 Guard IPC 防冒充设计。

## 📄 开源协议

本项目基于 [MIT License](LICENSE) 开源。
