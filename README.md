# AI NetGuard

Windows 平台下的 AI 专属网络隔离与防泄漏安全网关（基于 **Tauri 2 + Rust + React 18 + sing-box + Windows Filtering Platform (WFP)**）。

## 宣传视频与展示

https://github.com/user-attachments/assets/cf2bd7ea-e3fa-4140-a59b-066bf845f924

**[下载最新安装包 (v0.1.0)](https://github.com/henghaxiaowu/ai-netguard/releases/tag/v0.1.0)**

## 核心特性

- **进程级与域名级分流隔离**：不接管全局系统代理，仅针对受保护的浏览器实例、Claude Desktop 与 Claude Code CLI 终端提供独立代理通道（默认本地混合端口 `127.0.0.1:10808`），与 Clash Verge、Tailscale 等共存互不干扰。
- **Windows WFP 内核级防泄漏（Guard Helper）**：
  - 提权守护服务 `netguard-guard` 通过 Named Pipe + HMAC-SHA256 鉴权。
  - 在内核层强制阻断受保护进程的直连出站、QUIC/UDP `:443`、WebRTC STUN (`:3478` / `:19302` / `:5349`) 与公网明文 DNS (`:53` / `:853`)。
  - 支持紧急熔断（Kill Switch）与 Claude Desktop 持久化离线硬锁。
- **远程 DNS 防污染与指纹对齐**：
  - AI 域名强制通过代理出口执行远程 DoH 解析，杜绝本地 Fake-IP 与 DNS 抢答泄漏。
  - 自动对齐安全浏览器的时区（`TZ`）、语言（`--lang` / `--accept-lang`）及 WebRTC 策略。
- **深度安全体检**：内置 12 项实时联通性、DNS 污染、WFP 内核锁、WebRTC 防护及环境指纹一致性审计与一键修复。

## 目录结构

- [`src/`](src/) — React 18 + Tailwind CSS v4 + Radix UI (`shadcn/ui`) 前端界面
- [`src-tauri/`](src-tauri/) — Tauri 2 Rust 核心后端（配置管理、`sing-box` 编排、深度体检、安全启动器）
- [`guard-helper/`](guard-helper/) — Windows WFP 内核防火墙提权守护进程 (`netguard-guard.exe`)
- [`guard-protocol/`](guard-protocol/) — 主程序与 Guard 守护进程间的 IPC 协议与 HMAC 鉴权定义
- [`scripts/`](scripts/) — 自动化构建脚本（自动拉取 `sing-box` 内核、编译 Guard 与打包 NSIS 安装包）
- [`docs/SECURITY_AND_DEVELOPMENT_GUIDE.md`](docs/SECURITY_AND_DEVELOPMENT_GUIDE.md) — 架构说明与安全审计手册

## 本地开发与构建

### 环境依赖

- Windows 10 / 11 (x64)
- Node.js 20+ & npm
- Rust stable 工具链 (`x86_64-pc-windows-msvc`)

### 开发调试

```powershell
npm install
npm run tauri dev
```

### 一键完整打包（含 Guard Helper、sing-box 内核与 NSIS 安装包）

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-all.ps1
```

## 开源协议

本项目基于 [MIT License](LICENSE) 开源。
