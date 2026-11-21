import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AccountEnvPreset,
  AccountRecord,
  AppConfig,
  AppEnvSnapshot,
  ClashVergeNodesSnapshot,
  DiagnosticCheck,
  DownloadProgress,
  ExitIpInfo,
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
  launchBrowserProfile: (profileId: string, url?: string) =>
    invoke<string>("launch_browser_profile", {
      profileId,
      url: url ?? null,
    }),
  closeBrowserProfile: (profileId: string) =>
    invoke<GatewayStatus>("close_browser_profile", { profileId }),
  probeNodeExit: (nodeId: string) =>
    invoke<ExitIpInfo>("probe_node_exit", { nodeId }),
  launchClaudeDesktop: () => invoke<string>("launch_claude_desktop"),
  launchClaudeTerminal: (workDir: string, strictWfp: boolean) =>
    invoke<string>("launch_claude_terminal", { workDir, strictWfp }),
  inspectAppsEnv: () => invoke<AppEnvSnapshot>("inspect_apps_env"),
  launchManagedApp: (appId: string, relaunch: boolean) =>
    invoke<string>("launch_managed_app", { appId, relaunch }),
  cleanRegistryProxyEnv: () => invoke<string>("clean_registry_proxy_env"),
  createManagedAppShortcut: (appId: string) =>
    invoke<string>("create_managed_app_shortcut", { appId }),
  listAccounts: () => invoke<AccountRecord[]>("list_accounts"),
  upsertAccount: (account: AccountRecord) =>
    invoke<AccountRecord[]>("upsert_account", { account }),
  deleteAccount: (id: string) => invoke<AccountRecord[]>("delete_account", { id }),
  deleteAccounts: (ids: string[]) =>
    invoke<AccountRecord[]>("delete_accounts", { ids }),
  importAccounts: (accounts: AccountRecord[], replace: boolean) =>
    invoke<AccountRecord[]>("import_accounts", { accounts, replace }),
  listAccountEnvironments: () =>
    invoke<AccountEnvPreset[]>("list_account_environments"),
  saveAccountEnvironments: (presets: AccountEnvPreset[]) =>
    invoke<AccountEnvPreset[]>("save_account_environments", { presets }),
  listClashVergeNodes: () =>
    invoke<ClashVergeNodesSnapshot>("list_clash_verge_nodes"),
  reorderAccounts: (orderedIds: string[]) =>
    invoke<AccountRecord[]>("reorder_accounts", { orderedIds }),
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
