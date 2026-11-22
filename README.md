<div align="center">

# AI NetGuard

**Windows 下的 AI 专属网络隔离与 WFP 内核防泄漏安全网关**

Tauri 2 · Rust · React 18 · sing-box · Windows Filtering Platform (WFP)

[![Release](https://img.shields.io/github/v/release/henghaxiaowu/ai-netguard?style=flat-square&color=2563eb)](https://github.com/henghaxiaowu/ai-netguard/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-16a34a.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64-0f172a.svg?style=flat-square)](#源码构建)

[下载安装包](https://github.com/henghaxiaowu/ai-netguard/releases/latest) · [Agent 一键配置](#-agent-一键配置) · [快速上手](#-3-步快速上手) · [架构与端口](#-架构与端口速览) · [架构与审计文档](docs/SECURITY_AND_DEVELOPMENT_GUIDE.md)

</div>

---

https://github.com/user-attachments/assets/cf2bd7ea-e3fa-4140-a59b-066bf845f924

## ✨ 核心能力

- **WFP 内核级硬锁**：提权守护进程 `netguard-guard` 在驱动层封死受保护进程直连、QUIC (UDP 443)、WebRTC STUN 与公网明文 DNS，支持 **Fail-Closed 紧急熔断** 与 **Claude Desktop 持久化离线硬锁**。
- **不改系统代理，共存不冲突（支持单节点覆盖 + Clash Meta 识别）**：通过 **Physical Bypass** 绑定真实物理网卡（自动过滤 `Meta` / `Meta Tunnel` / `utun` 等虚拟 TUN 网卡）并注入多目标 `/32` 旁路路由，支持针对单个节点覆盖出站模式（例如「首尔 VPS」强制直连绕过 Clash 全局/TUN，「备用住宅节点」按需直连或上游串联）。
- **多出口独立指纹浏览器并发多开**：在同一 `sing-box` 内核中为主出口之外的备用节点分配独立回环 SOCKS5 端口（`17901+`），WFP 仅放行 `chrome.exe`（绝不开放给 `claude.exe` 与 CLI 沙盒）；每套浏览器环境（`BrowserProfile`）拥有独立 `--user-data-dir` 与持久化一致性指纹，并支持 **`clean_align` 纯净对齐**（对 Claude / hCaptcha 最安全）与 **`isolated_fingerprint` 完整独立指纹**（持久化屏幕、CPU/内存、Direct3D11 WebGL 与固定种子 Canvas/Audio 微扰动）。
- **AI 应用启动环境管家（PEB 扫描）**：内置 `Claude Desktop` / `Antigravity` / `ChatGPT` / `Cockpit Tools` 及自定义 `.exe` 管理，实时读取活跃进程内存 (PEB) 代理变量与端口活体，支持识别跟随在线系统代理的 `CustomProxy` 策略，精准揪出失效环境变量并一键干净重启。
- **账号与环境库（Windows DPAPI 本地加密 + 账号驱动一键拉起 + 本地额度冷却台账）**：集中管理 Google 等平台账号凭据、离线 RFC 6238 2FA 动态验证码（支持 Base32 与 `otpauth://`）及备用恢复码；支持固定分栏对齐展示与 **拖拽手柄 / 上下按钮自由调序（持久化至 `accounts.vault`）**、自动匹配本地 `Clash Verge` 节点与多 Listener 端口，并提供账号级 **`⚡ Antigravity` 干净重启**（注入 `--proxy-server` 防继承全局代理污染）、**`🌐 专属防泄漏浏览器`** 及 **`AdsPower Local API` 一键拉起**（`adspower.vault` DPAPI 加密存密钥，保持 AdsPower 原有代理设置不变；绑定外部节点时启动前先强校验真实出口 IP）；支持 **每账号独立开关 `⚡ Antigravity` 与浏览器启动按钮**（`none` / `netguard` / `adspower`），并内置 **Cockpit 风格本地额度与 5h/周期冷却倒计时台账**（套餐档位、订阅到期预警、多模型分组余量与自动回满倒计时，纯本地 DPAPI 加密存储、零外部请求/不触碰 Token）。
- **防误熔断实时巡检**：内置 8 项实时核验（出口 IP、VPN 共存、DNS、IPv6、WebRTC/QUIC、WFP、熔断、CLI 链路）；后台每 4 秒核验 Guard/WFP 护盾，每 12 秒使用轻量纯 IP 探针（`ipify` / `checkip` / `ifconfig`）并在每 5 分钟或 IP 漂移时刷新全量 GeoIP（4 路兜底），避免公共 GeoIP 限流引发误熔断，同时对 IP 漂移、国家不符及未知国家严格保持 Fail-Closed 阻断。

---

## 🤖 Agent 一键配置

把下面指令直接发给你的 AI Agent（**Claude Code / Antigravity / Cursor / Codex**），自动完成配置或排障（仓库已内置 [Agent Skill](.agents/skills/ai-netguard-playbook/SKILL.md)）：

### 1. 下载安装后一键配节点 & 查共存

```text
请帮我初始化 AI NetGuard（仓库 https://github.com/henghaxiaowu/ai-netguard）：
1. 检查是否有旧版 ai-netguard / netguard-guard / sing-box 进程占用，检查 17890/17891/17898 端口及 Clash/Tailscale 共存情况。
2. 更新 %LOCALAPPDATA%\AI-NetGuard\config.json：
   - 节点：<粘贴你的 vless:// 或 hy2:// 链接，或说明需要我生成的 VPS 脚本>
   - 自动匹配 expectedCountry、timezone、locale，开启 wfpLockEnabled / alignFingerprint / fail_closed。
   - 若本机运行了 Clash 或 Tailscale，将 outboundMode 设为 "physical_bypass"。
3. 告诉我完成后在软件里需要点击哪几项验证。
```

### 2. 源码一键构建 / 异常深度排查

```text
请先阅读本仓库的 .agents/skills/ai-netguard-playbook/SKILL.md：
- 若为源码部署：克隆仓库 -> npm install -> 准备好 src-tauri/binaries/sing-box-x86_64-pc-windows-msvc.exe -> 跑 cargo test --workspace 与 .\scripts\build-all.ps1。
- 若为故障排查：检查 Guard 管道连接、%LOCALAPPDATA%\AI-NetGuard\config.json 与端口监听，针对我的报错（<描述现象>）定位根因并修复，不要放宽 Fail-Closed 或 WFP 安全策略。
```

---

## 🚀 3 步快速上手

1. **下载安装**：从 [Releases](https://github.com/henghaxiaowu/ai-netguard/releases/latest) 下载 `AI.NetGuard_0.1.9_x64-setup.exe` 安装（升级前先彻底退出托盘中的旧进程）。
2. **配置节点**：进入 **「出口与共存路由」**，粘贴 `vless://`、`hy2://`、`ss://`、`trojan://` 或 `socks5://` 链接（或用内置向导生成独享 VPS 一键脚本），填好预期国家与时区语言，按需设置单节点出站覆盖并保存。
3. **启动使用**：回到 **「总览与安全启动」** 点击 **「启动安全网关」**（首次需 UAC 提权），随后可打开默认 **防泄漏浏览器**、**Claude Desktop**、**Claude Code 终端**，或在 **「指纹浏览器」** 中按不同节点与独立指纹并发多开浏览器窗口。

---

## 🧭 架构与端口速览

```text
[主安全浏览器 / Claude Desktop / Claude Code CLI] ──▶ [主安全出口]
[独立指纹浏览器环境 #1..N (17901+)]                 ──▶ [对应绑定出口节点]
   │  WFP 内核锁严格分级隔离：claude.exe 仅限 17890/17891/17898，备用浏览器端口仅放行 chrome.exe
   ▼
[sing-box 本地核心]  ──▶  [单节点独立 Physical Bypass (/32) / Upstream Detour]
   ├─ 127.0.0.1:17890   CLI 混合代理入站 (HTTP / SOCKS5 -> 主安全出口)
   ├─ 127.0.0.1:17891   主安全浏览器 / PAC 专用混合代理入站 (HTTP / SOCKS5 -> 主安全出口)
   ├─ 127.0.0.1:17901+  多出口指纹浏览器并发混合代理入站 (HTTP / SOCKS5 -> 独立节点直达)
   └─ 127.0.0.1:17898   Claude Desktop 本地 PAC 服务 (/proxy.pac)
```

---

## ❓ 常见问题 (FAQ)

<details>
<summary><b>覆盖安装提示 <code>Error opening file for writing: sing-box.exe</code></b></summary>

说明旧版 `ai-netguard.exe`、`netguard-guard` 或 `sing-box.exe` 仍在后台运行。右键托盘彻底退出程序（或任务管理器结束上述进程）后再安装即可。

</details>

<details>
<summary><b>Claude Desktop 邮箱登录提示“无法验证您的浏览器”</b></summary>

这是无感 hCaptcha 在 Electron 端触发的风控。建议点 **「使用 Google 继续」** 后复制链接，再点击面板 **「接管 OAuth」** 在防泄漏浏览器完成授权回调。详见 [技术指南](docs/SECURITY_AND_DEVELOPMENT_GUIDE.md#22-攻克-claude-desktop-命令行拦截与-无法验证您的浏览器)。

</details>

<details>
<summary><b>配置与浏览器数据存放在哪里？</b></summary>

全部运行时数据位于 `%LOCALAPPDATA%\AI-NetGuard\`（包含 `config.json`、DPAPI 本地加密账号库 `accounts.vault`、自定义启动环境预设 `account-environments.json`、便携浏览器 `browser/` 与独立配置文件 `browser-profile/`）。

</details>

---

## 🛠️ 源码构建

需 Windows 10/11 (x64)、Node.js 20+、Rust stable，并将官方 [sing-box](https://github.com/SagerNet/sing-box/releases) amd64 二进制放置于 `src-tauri/binaries/sing-box-x86_64-pc-windows-msvc.exe`：

```powershell
npm install
cargo test --workspace
powershell -ExecutionPolicy Bypass -File .\scripts\build-all.ps1
```

更多双层 WFP 事务刷新、Guard IPC 鉴权与两轮安全审计细节见 [SECURITY_AND_DEVELOPMENT_GUIDE.md](docs/SECURITY_AND_DEVELOPMENT_GUIDE.md)。

## 📄 开源协议

[MIT License](LICENSE)
