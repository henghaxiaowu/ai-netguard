import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AppConfig,
  DiagnosticCheck,
  DownloadProgress,
  GatewayStatus,
  NodeProfile,
} from "./types";

export const api = {
  getConfig: () => invoke<AppConfig>("get_config"),
  saveConfig: (config: AppConfig) => invoke<AppConfig>("save_config", { config }),
  parseNodeUri: (uri: string) => invoke<NodeProfile>("parse_node_uri", { uri }),
  getStatus: () => invoke<GatewayStatus>("get_status"),
  startGateway: () => invoke<GatewayStatus>("start_gateway"),
  stopGateway: () => invoke<GatewayStatus>("stop_gateway"),
  toggleKillSwitch: (block: boolean) =>
    invoke<GatewayStatus>("toggle_kill_switch", { block }),
  togglePersistentClaudeLock: (enable: boolean) =>
    invoke<GatewayStatus>("toggle_persistent_claude_lock", { enable }),
  runDiagnostics: () => invoke<DiagnosticCheck[]>("run_diagnostics"),
  fixDiagnostic: (action: string) => invoke<string>("fix_diagnostic", { action }),
  installBrowser: () => invoke<string>("install_browser"),
  launchBrowser: () => invoke<string>("launch_browser"),
  launchBrowserUrl: (url: string) =>
    invoke<string>("launch_browser_url", { url }),
  launchClaudeDesktop: () => invoke<string>("launch_claude_desktop"),
  launchClaudeTerminal: (workDir: string, strictWfp: boolean) =>
    invoke<string>("launch_claude_terminal", { workDir, strictWfp }),
  connectGuard: () => invoke<GatewayStatus>("connect_guard"),
  clearLogs: () => invoke<void>("clear_logs"),
  generateVpsScript: (protocol: "vless-reality" | "hysteria2", port: number) =>
    invoke<string>("generate_vps_script", { protocol, port }),
  onBrowserDownloadProgress: (
    cb: (progress: DownloadProgress) => void,
  ): Promise<UnlistenFn> =>
    listen<DownloadProgress>("browser-download-progress", (e) => cb(e.payload)),
  onStatusUpdate: (cb: (status: GatewayStatus) => void): Promise<UnlistenFn> =>
    listen<GatewayStatus>("gateway-status-updated", (e) => cb(e.payload)),
};
