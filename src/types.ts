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
