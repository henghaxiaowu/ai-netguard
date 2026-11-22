export type ProxyProtocol =
  | "vless"
  | "shadowsocks"
  | "trojan"
  | "hysteria2"
  | "socks"
  | "http";

export type OutboundMode = "physical_bypass" | "upstream_detour" | "default_route";

export type KillSwitchMode = "fail_closed" | "monitor_only";

export type AppProxyMode = "netguard" | "system_proxy" | "direct" | "custom_proxy";

export interface ManagedAppConfig {
  id: string;
  name: string;
  builtin: boolean;
  exePath?: string | null;
  processNames: string[];
  proxyMode: AppProxyMode;
  customProxyUrl?: string | null;
  wfpLock: boolean;
  extraArgs: string[];
}

export interface NodeProfile {
  id: string;
  name: string;
  protocol: ProxyProtocol;
  server: string;
  port: number;
  uuid?: string;
  flow?: string;
  security?: "none" | "tls" | "reality";
  sni?: string;
  fingerprint?: string;
  publicKey?: string;
  shortId?: string;
  method?: string;
  password?: string;
  username?: string;
  obfs?: string;
  obfsPassword?: string;
  allowInsecure?: boolean;
  certificateSha256?: string;
  expectedIp?: string;
  expectedCountry?: string;
  timezone?: string;
  locale?: string;
  outboundMode?: OutboundMode | null;
}

export type BrowserFingerprintMode = "clean_align" | "isolated_fingerprint";

export interface BrowserFingerprintConfig {
  timezone?: string | null;
  locale?: string | null;
  screenWidth: number;
  screenHeight: number;
  devicePixelRatio: number;
  hardwareConcurrency: number;
  deviceMemory: number;
  webglVendor: string;
  webglRenderer: string;
  userAgent?: string | null;
  noiseSeed: string;
}

export interface BrowserProfile {
  id: string;
  name: string;
  builtin?: boolean;
  nodeId?: string | null;
  customProxyUrl?: string | null;
  homepage: string;
  fingerprintMode: BrowserFingerprintMode;
  fingerprint: BrowserFingerprintConfig;
  notes?: string | null;
}

export interface UpstreamProxyConfig {
  enabled: boolean;
  protocol: "socks" | "http";
  server: string;
  port: number;
}

export interface AppConfig {
  activeNodeId: string;
  nodes: NodeProfile[];
  outboundMode: OutboundMode;
  physicalInterfaceName?: string;
  upstreamProxy: UpstreamProxyConfig;
  killSwitch: KillSwitchMode;
  browserPort: number;
  cliPort: number;
  customBrowserPath?: string;
  claudeDesktopPath?: string;
  extraNoProxy: string;
  alignFingerprint: boolean;
  wfpLockEnabled: boolean;
  strictCliWfpEnabled: boolean;
  autoStartGateway: boolean;
  autoLaunchBrowser: boolean;
  autoLaunchClaudeDesktop: boolean;
  requireNetguardForClaude: boolean;
  aiDomains: string[];
  managedApps: ManagedAppConfig[];
  browserProfiles?: BrowserProfile[];
}

export type CheckSeverity = "pass" | "warn" | "fail" | "pending";

export interface DiagnosticCheck {
  id: string;
  title: string;
  category: "core" | "security" | "coexistence" | "cli";
  status: CheckSeverity;
  summary: string;
  detail: string;
  fixable?: boolean;
  fixAction?: string;
}

export interface ExitIpInfo {
  ip: string;
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  isp?: string;
  org?: string;
  asn?: string;
  latencyMs?: number;
  verifiedAt: string;
}

export interface GatewayStatus {
  running: boolean;
  blockedByKillSwitch: boolean;
  killSwitchReason?: string;
  guardConnected: boolean;
  guardElevated: boolean;
  wfpActive: boolean;
  wfpFilterCount: number;
  persistentClaudeLockActive: boolean;
  persistentClaudeFilterCount: number;
  bypassRouteActive: boolean;
  browserRunning: boolean;
  browserInstalled: boolean;
  browserPath?: string;
  claudeDesktopFound: boolean;
  claudeDesktopPath?: string;
  claudeCliFound: boolean;
  detectedPhysicalNic?: string;
  detectedPhysicalGateway?: string;
  detectedConflicts: string[];
  exitIp?: ExitIpInfo;
  runningBrowserProfiles?: string[];
  runningAdspowerProfiles?: string[];
  secondaryNodePorts?: Record<string, number>;
  activeAccountSession?: ActiveAccountSession | null;
  logs: string[];
}

export interface DownloadProgress {
  stage: "downloading" | "extracting" | "done" | "error";
  downloadedBytes: number;
  totalBytes: number;
  message: string;
}

export interface EnvVarHealth {
  scope: "user" | "machine" | "process" | string;
  key: string;
  value: string;
  hostPort?: string;
  alive?: boolean;
}

export interface SystemProxyStatus {
  enabled: boolean;
  server?: string;
  hostPort?: string;
  alive: boolean;
  autoConfigUrl?: string;
}

export interface ManagedAppRuntimeStatus {
  id: string;
  name: string;
  builtin: boolean;
  installed: boolean;
  resolvedPath?: string;
  running: boolean;
  pids: number[];
  proxyMode: AppProxyMode;
  wfpLock: boolean;
  health: "clean" | "dead_proxy" | "mismatch" | "stopped";
  diagnosis: string;
  envVars: EnvVarHealth[];
  needsCleanRelaunch: boolean;
}

export interface AppEnvSnapshot {
  systemProxy: SystemProxyStatus;
  registryProxyVars: EnvVarHealth[];
  apps: ManagedAppRuntimeStatus[];
  pollutedCount: number;
  scannedAt: string;
}

export type AccountStatus = "active" | "standby" | "restricted" | "banned";

export type AccountEnvType = "fingerprint" | "local" | "custom";

export type AccountNodeSource = "none" | "netguard" | "clash_verge" | "custom";

export type AccountBrowserKind = "netguard" | "adspower";

export interface AdsPowerConfigStatus {
  baseUrl: string;
  hasApiKey: boolean;
  apiKeyMasked?: string | null;
}

export interface AdsPowerProfileItem {
  userId: string;
  serialNumber: string;
  name: string;
  groupName: string;
  remark: string;
}

export interface AdsPowerProfilesSnapshot {
  connected: boolean;
  baseUrl: string;
  profiles: AdsPowerProfileItem[];
  error?: string | null;
}

export interface AccountEnvPreset {
  id: string;
  name: string;
  envType: AccountEnvType;
}

export interface ClashVergeNodeItem {
  name: string;
  nodeType: string;
  isGroup: boolean;
}

export interface ClashVergeListenerItem {
  name: string;
  listenerType: string;
  port: number;
  proxy: string;
}

export interface ClashVergeNodesSnapshot {
  detected: boolean;
  sourcePath?: string | null;
  mixedPort?: number | null;
  listeners?: ClashVergeListenerItem[];
  groups: ClashVergeNodeItem[];
  proxies: ClashVergeNodeItem[];
}

export interface AccountRecord {
  id: string;
  label: string;
  provider: string;
  email: string;
  password: string;
  totpSecret?: string | null;
  recoveryCodes?: string | null;
  recoveryEmail?: string | null;
  envType: AccountEnvType;
  environmentName: string;
  environmentProfile?: string | null;
  browserKind?: AccountBrowserKind;
  adspowerUserId?: string | null;
  adspowerSerialNumber?: string | null;
  adspowerProfileName?: string | null;
  linkedNodeSource?: AccountNodeSource;
  linkedNodeId?: string | null;
  linkedNodeName?: string | null;
  linkedBrowserProfileId?: string | null;
  linkedProxyPort?: number | null;
  purpose: string;
  tags: string[];
  status: AccountStatus;
  notes?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ActiveAccountSession {
  accountId: string;
  accountLabel: string;
  email: string;
  nodeSource: AccountNodeSource | string;
  nodeName: string;
  proxyUrl: string;
  localPort: number;
  verifiedExitIp?: ExitIpInfo | null;
  antigravityLaunched: boolean;
  browserKind?: AccountBrowserKind | string;
  browserProfileId?: string | null;
  adspowerUserId?: string | null;
  adspowerProfileLabel?: string | null;
  activatedAt: string;
}

export interface AccountLaunchOutcome {
  message: string;
  config: AppConfig;
  accounts: AccountRecord[];
  status: GatewayStatus;
  session: ActiveAccountSession;
}
