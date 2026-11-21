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
- **不改系统代理，共存不冲突**：通过 **Physical Bypass** 绑定物理网卡直接绕过 Clash Verge / Tailscale 虚拟网卡，也可通过 **Upstream Detour** 走前置链式代理。
- **全客户端隔离工作区**：自动下载并启动独立便携版 **Ungoogled-Chromium**（带 MV3 时区/语言对齐扩展）、PAC 接管 **Claude Desktop**、环境变量/严格 WFP 启动 **Claude Code CLI**。
- **AI 应用启动环境管家（PEB 扫描）**：内置 `Claude Desktop` / `Antigravity` / `ChatGPT` / `Cockpit Tools` 及自定义 `.exe` 管理，实时读取活跃进程内存 (PEB) 代理变量与端口活体，精准揪出脏继承死端口并一键干净重启。
- **账号与环境库（Windows DPAPI 本地加密）**：集中管理 Google 等平台账号凭据、离线 RFC 6238 2FA 动态验证码（支持 Base32 与 `otpauth://`）及备用恢复码；支持固定分栏对齐展示与 **拖拽手柄 / 上下按钮自由调序（持久化至 `accounts.vault`）**、自由增删自定义启动环境预设（`指纹浏览器`/`本地`/`自定义`，可留空），以及按来源绑定 `AI NetGuard` 节点、自动读取本地 `Clash Verge` 策略组与节点（支持搜索）或自定义/直连代理，配合用途标签、状态标记（`正常`/`备用`/`受限`/`已封禁`）、批量清理封禁号及 JSON 备份导入导出。
- **实时防泄漏体检**：内置 8 项实时核验（出口 IP、VPN 共存、DNS、IPv6、WebRTC/QUIC、WFP、熔断、CLI 链路）与每 4 秒出口巡检。

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

1. **下载安装**：从 [Releases](https://github.com/henghaxiaowu/ai-netguard/releases/latest) 下载 `AI.NetGuard_0.1.6_x64-setup.exe` 安装（升级前先彻底退出托盘中的旧进程）。
2. **配置节点**：进入 **「出口与共存路由」**，粘贴 `vless://`、`hy2://`、`ss://`、`trojan://` 或 `socks5://` 链接（或用内置向导生成独享 VPS 一键脚本），填好预期国家与时区语言并保存。
3. **启动使用**：回到 **「总览与安全启动」** 点击 **「启动安全网关」**（首次需 UAC 提权），随后按需打开 **防泄漏浏览器**、**Claude Desktop** 或 **Claude Code 终端** 即可。

---

## 🧭 架构与端口速览

```text
[受保护浏览器 / Claude Desktop / Claude Code CLI]
   │  WFP 内核锁仅放行受控回环端口 (17890 / 17891 / 17898)
   ▼
[sing-box 本地核心]  ──▶  [Physical Bypass 物理网卡直通 / Upstream Detour]  ──▶  [独享静态节点]
   ├─ 127.0.0.1:17890   CLI 混合代理入站 (HTTP / SOCKS5)
   ├─ 127.0.0.1:17891   浏览器 / PAC 专用 SOCKS5 入站
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
