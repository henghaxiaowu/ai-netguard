import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AccountEnvPreset,
  AccountLaunchOutcome,
  AccountRecord,
  AdsPowerConfigStatus,
  AdsPowerProfilesSnapshot,
  AppConfig,
  AppEnvSnapshot,
  ClashVergeNodesSnapshot,
  CookieDeleteTarget,
  CookieImportOutcome,
  DiagnosticCheck,
  DownloadProgress,
  ExitIpInfo,
  GatewayStatus,
  NodeProfile,
  PendingUrlPickPayload,
  ProfileCookiesSnapshot,
  UrlRouteEvent,
  UrlRouterStatus,
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
  getProfileCookies: (profileId: string) =>
    invoke<ProfileCookiesSnapshot>("get_profile_cookies", { profileId }),
  importProfileCookies: (
    profileId: string,
    rawText: string,
    replaceExisting: boolean,
  ) =>
    invoke<CookieImportOutcome>("import_profile_cookies", {
      profileId,
      rawText,
      replaceExisting,
    }),
  deleteProfileCookies: (profileId: string, targets: CookieDeleteTarget[]) =>
    invoke<ProfileCookiesSnapshot>("delete_profile_cookies", {
      profileId,
      targets,
    }),
  clearProfileCookies: (profileId: string) =>
    invoke<ProfileCookiesSnapshot>("clear_profile_cookies", { profileId }),
  probeNodeExit: (nodeId: string) =>
    invoke<ExitIpInfo>("probe_node_exit", { nodeId }),
  probeProxyExit: (proxyUrl: string) =>
    invoke<ExitIpInfo>("probe_proxy_exit", { proxyUrl }),
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
  launchAccountBrowser: (accountId: string, url?: string | null) =>
    invoke<AccountLaunchOutcome>("launch_account_browser", {
      accountId,
      url: url ?? null,
    }),
  clearActiveAccountSession: (closeBrowser = false) =>
    invoke<GatewayStatus>("clear_active_account_session", { closeBrowser }),
  getAdsPowerConfig: () =>
    invoke<AdsPowerConfigStatus>("get_adspower_config"),
  saveAdsPowerConfig: (
    baseUrl: string,
    apiKey: string | null,
    clearApiKey = false,
  ) =>
    invoke<AdsPowerConfigStatus>("save_adspower_config", {
      baseUrl,
      apiKey,
      clearApiKey,
    }),
  testAdsPowerConnection: () =>
    invoke<string>("test_adspower_connection"),
  listAdsPowerProfiles: () =>
    invoke<AdsPowerProfilesSnapshot>("list_adspower_profiles"),
  closeAdsPowerProfile: (userId?: string | null, serialNumber?: string | null) =>
    invoke<GatewayStatus>("close_adspower_profile", {
      userId: userId ?? null,
      serialNumber: serialNumber ?? null,
    }),
  connectGuard: () => invoke<GatewayStatus>("connect_guard"),
  getUrlRouterStatus: () => invoke<UrlRouterStatus>("get_url_router_status"),
  registerUrlRouter: () => invoke<UrlRouterStatus>("register_url_router"),
  unregisterUrlRouter: () => invoke<UrlRouterStatus>("unregister_url_router"),
  openDefaultAppsSettings: () => invoke<void>("open_default_apps_settings"),
  listUrlRouteHistory: () => invoke<UrlRouteEvent[]>("list_url_route_history"),
  testUrlRouterPicker: (url: string) =>
    invoke<void>("test_url_router_picker", { url }),
  getPendingUrlPick: () =>
    invoke<PendingUrlPickPayload | null>("get_pending_url_pick"),
  resolveUrlPick: (payload: {
    pickId: string;
    action: string;
    adspowerUserId?: string | null;
    adspowerSerialNumber?: string | null;
    adspowerProfileName?: string | null;
    browserProfileId?: string | null;
    addEdgeBypassHost?: boolean;
  }) => invoke<string>("resolve_url_pick", payload),
  clearLogs: () => invoke<void>("clear_logs"),
  generateVpsScript: (protocol: "vless-reality" | "hysteria2", port: number) =>
    invoke<string>("generate_vps_script", { protocol, port }),
  onBrowserDownloadProgress: (
    cb: (progress: DownloadProgress) => void,
  ): Promise<UnlistenFn> =>
    listen<DownloadProgress>("browser-download-progress", (e) => cb(e.payload)),
  onStatusUpdate: (cb: (status: GatewayStatus) => void): Promise<UnlistenFn> =>
    listen<GatewayStatus>("gateway-status-updated", (e) => cb(e.payload)),
  onUrlPickerUpdated: (cb: () => void): Promise<UnlistenFn> =>
    listen("url-picker-updated", () => cb()),
};
