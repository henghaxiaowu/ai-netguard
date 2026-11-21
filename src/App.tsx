import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { flushSync } from "react-dom";
import {
  AppWindow,
  LayoutGrid,
  Monitor,
  Fingerprint,
  GitFork,
  Shield,
  FileText,
  ShieldCheck,
  ShieldAlert,
  Activity,
  Clock,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Globe,
  Terminal,
  Folder,
  ExternalLink,
  RefreshCw,
  Square,
  Play,
  Download,
  Lock,
  Unlock,
  Wrench,
  Search,
  Copy,
  Trash2,
  ChevronDown,
  ClipboardPaste,
  KeyRound,
  X,
} from "lucide-react";
import { api } from "./api";
import { AccountsView } from "./components/AccountsView";
import { AppsEnvView } from "./components/AppsEnvView";
import { BrowserProfilesView } from "./components/BrowserProfilesView";
import { NodeEditor } from "./components/NodeEditor";
import { ClaudeStarburst } from "./components/ClaudeMotifs";
import { ExitIpMap } from "./components/ExitIpMap";
import { LatencySparkline, SegmentedMeter } from "./components/TelemetryWidgets";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import type {
  AccountEnvPreset,
  AccountRecord,
  AppConfig,
  AppEnvSnapshot,
  BrowserProfile,
  ClashVergeNodesSnapshot,
  DiagnosticCheck,
  DownloadProgress,
  GatewayStatus,
  NodeProfile,
} from "./types";

type TabKey =
  | "dashboard"
  | "browsers"
  | "apps"
  | "accounts"
  | "verify"
  | "nodes"
  | "hardening"
  | "logs";
type CheckFilter = "all" | "core" | "security" | "coexistence" | "cli";

const NAV_GROUPS: {
  group: string;
  items: { key: TabKey; label: string; crumb: string; icon: typeof Monitor }[];
}[] = [
  {
    group: "网关",
    items: [
      { key: "dashboard", label: "总览与安全启动", crumb: "总览", icon: Monitor },
      { key: "browsers", label: "指纹浏览器", crumb: "指纹浏览器", icon: Globe },
      { key: "apps", label: "AI 应用与环境", crumb: "AI 应用与环境", icon: AppWindow },
      { key: "accounts", label: "账号与环境库", crumb: "账号与环境库", icon: KeyRound },
      { key: "verify", label: "IP 与指纹体检", crumb: "IP 与指纹体检", icon: Fingerprint },
      { key: "nodes", label: "出口与共存路由", crumb: "出口与共存路由", icon: GitFork },
    ],
  },
  {
    group: "系统",
    items: [
      { key: "hardening", label: "隔离与规则加固", crumb: "隔离与规则加固", icon: Shield },
      { key: "logs", label: "内核运行日志", crumb: "内核运行日志", icon: FileText },
    ],
  },
];

const DEFAULT_CHECK_LABELS: { id: string; title: string; category: CheckFilter }[] = [
  { id: "exit_ip", title: "出口 IP", category: "core" },
  { id: "coexist", title: "VPN 共存", category: "coexistence" },
  { id: "dns", title: "DNS 防泄漏", category: "security" },
  { id: "ipv6", title: "IPv6 阻断", category: "security" },
  { id: "webrtc", title: "WebRTC / QUIC", category: "security" },
  { id: "wfp", title: "WFP 内核锁", category: "security" },
  { id: "killswitch", title: "熔断策略", category: "core" },
  { id: "cli", title: "CLI 链路", category: "cli" },
];

const SHORT_CHECK_TITLE: Record<string, string> = {
  exit_ip: "出口 IP",
  coexist: "VPN 共存",
  dns: "DNS 防泄漏",
  ipv6: "IPv6 阻断",
  webrtc: "WebRTC / QUIC",
  wfp: "WFP 内核锁",
  killswitch: "熔断策略",
  cli: "CLI 链路",
};

interface ParsedLog {
  index: string;
  time: string;
  source: string;
  variant: "neutral" | "iris" | "danger" | "success" | "warning";
  message: string;
}

function parseLogEntry(rawLine: string, idx: number): ParsedLog {
  const index = String(idx + 1).padStart(3, "0");
  const timeMatch = rawLine.match(/^\[(\d{2}:\d{2}:\d{2})]\s*(.*)$/);
  const time = timeMatch ? timeMatch[1] : "--:--:--";
  let body = timeMatch ? timeMatch[2] : rawLine;

  let source = "系统";
  let variant: ParsedLog["variant"] = "neutral";

  if (body.includes("[实时熔断]") || body.includes("[安全告警]") || body.includes("熔断")) {
    source = "熔断";
    variant = "danger";
  } else if (body.includes("[恢复]") || body.includes("恢复")) {
    source = "恢复";
    variant = "success";
  } else if (body.includes("[sing-box]") || body.includes("sing-box")) {
    source = "sing-box";
    variant = "iris";
  } else if (body.includes("WFP")) {
    source = "WFP";
    variant = "iris";
  } else if (body.includes("Guard")) {
    source = "Guard";
    variant = "neutral";
  } else if (body.includes("体检") || body.includes("检查")) {
    source = "体检";
    variant = "neutral";
  } else if (body.includes("出口") || body.includes("旁路")) {
    source = "出口";
    variant = "neutral";
  } else if (body.includes("警告") || body.includes("失败")) {
    source = "告警";
    variant = "warning";
  }

  body = body
    .replace(/^\[(sing-box|实时熔断|安全告警|恢复|自适应)\]\s*/i, "")
    .trim();

  return { index, time, source, variant, message: body };
}

function PathEndVisible({ path, fallback }: { path?: string; fallback: string }) {
  if (!path) {
    return <span className="truncate text-[0.7rem] text-[#7c8495]">{fallback}</span>;
  }
  const sepIdx = Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/"));
  const dir = sepIdx >= 0 ? path.slice(0, sepIdx) : "";
  const tail = sepIdx >= 0 ? path.slice(sepIdx) : path;
  return (
    <span className="path-split mono-num text-[0.7rem] text-[#7c8495]" title={path}>
      {dir && <span>{dir}</span>}
      <span>{tail}</span>
    </span>
  );
}

export default function App() {
  const uid = useId();
  const [tab, setTab] = useState<TabKey>("dashboard");
  const [config, setConfig] = useState<AppConfig | null>(null);
  const [dirty, setDirty] = useState(false);
  const [status, setStatus] = useState<GatewayStatus | null>(null);
  const [checks, setChecks] = useState<DiagnosticCheck[]>([]);
  const [checkFilter, setCheckFilter] = useState<CheckFilter>("all");
  const [busy, setBusy] = useState(false);
  const [checking, setChecking] = useState(false);
  const [toast, setToast] = useState<string>("");
  const [toastPaused, setToastPaused] = useState(false);
  const [workDir, setWorkDir] = useState("C:\\Projects");
  const [strictCliWfp, setStrictCliWfp] = useState(false);
  const [dlProgress, setDlProgress] = useState<DownloadProgress | null>(null);
  const [logFilter, setLogFilter] = useState("");
  const [domainsOpen, setDomainsOpen] = useState(false);
  const [latencyHistory, setLatencyHistory] = useState<number[]>([]);
  const [appEnv, setAppEnv] = useState<AppEnvSnapshot | null>(null);
  const [scanningApps, setScanningApps] = useState(false);
  const [accounts, setAccounts] = useState<AccountRecord[]>([]);
  const [loadingAccounts, setLoadingAccounts] = useState(true);
  const [envPresets, setEnvPresets] = useState<AccountEnvPreset[]>([
    { id: "env-adspower", name: "AdsPower", envType: "fingerprint" },
    { id: "env-local-browser", name: "本地浏览器", envType: "local" },
  ]);
  const [clashNodes, setClashNodes] = useState<ClashVergeNodesSnapshot | null>(null);
  const [loadingClashNodes, setLoadingClashNodes] = useState(false);
  const [quickProfileId, setQuickProfileId] = useState("default");
  const [preselectedBrowserNode, setPreselectedBrowserNode] = useState<{
    nodeId: string;
    nonce: number;
  } | null>(null);

  const didAutoStartRef = useRef(false);
  const toastRef = useRef<HTMLDivElement>(null);
  const toastTimerRef = useRef<number | null>(null);

  const toastId = `${uid}-toast`;
  const fid = (name: string) => `${uid}-${name}`;

  const supportsPopover = Object.prototype.hasOwnProperty.call(
    HTMLElement.prototype,
    "popover",
  );

  const dismissToast = useCallback(() => {
    if (toastTimerRef.current !== null) {
      window.clearTimeout(toastTimerRef.current);
      toastTimerRef.current = null;
    }
    setToast("");
    const el = toastRef.current;
    if (el && supportsPopover) {
      try {
        el.hidePopover();
      } catch {
        // Ignore if already closed
      }
    }
  }, [supportsPopover]);

  const notify = useCallback(
    (msg: string) => {
      setToast(msg);
      setToastPaused(false);
      const nav = navigator as { ariaNotify?: (text: string) => void };
      if (typeof nav.ariaNotify === "function") {
        nav.ariaNotify(msg);
      }
      const el = toastRef.current;
      if (el && supportsPopover) {
        try {
          if (!el.matches(":popover-open")) {
            el.showPopover();
          }
        } catch {
          // CSS class handles fallback
        }
      }
    },
    [supportsPopover],
  );

  useEffect(() => {
    if (!toast || toastPaused) return;
    toastTimerRef.current = window.setTimeout(() => {
      dismissToast();
    }, 4400);
    return () => {
      if (toastTimerRef.current !== null) {
        window.clearTimeout(toastTimerRef.current);
        toastTimerRef.current = null;
      }
    };
  }, [toast, toastPaused, dismissToast]);

  // Track real observed RTT latency samples cleanly without fake synthetic data
  useEffect(() => {
    const ms = status?.exitIp?.latencyMs;
    if (typeof ms === "number" && Number.isFinite(ms) && ms > 0) {
      setLatencyHistory((prev) => {
        if (prev.length > 0 && prev[prev.length - 1] === ms && prev.length >= 2) {
          return prev;
        }
        return [...prev.slice(-13), ms];
      });
    }
  }, [status?.exitIp?.latencyMs, status?.exitIp?.verifiedAt]);

  const switchTab = useCallback(
    (nextTab: TabKey) => {
      if (nextTab === tab) return;
      const doc = document as Document & {
        startViewTransition?: (cb: () => void) => { finished: Promise<void> };
      };
      const focusHeading = () => {
        document.getElementById("main-heading")?.focus({ preventScroll: true });
      };
      if (!doc.startViewTransition) {
        setTab(nextTab);
        requestAnimationFrame(focusHeading);
        return;
      }
      const transition = doc.startViewTransition(() => {
        flushSync(() => setTab(nextTab));
      });
      transition.finished.finally(focusHeading);
    },
    [tab],
  );

  useEffect(() => {
    const item = NAV_GROUPS.flatMap((g) => g.items).find((i) => i.key === tab);
    document.title = `${item?.label || "总览与安全启动"} | AI NetGuard`;
  }, [tab]);

  const refreshAppEnv = useCallback(async () => {
    setScanningApps(true);
    try {
      const snap = await api.inspectAppsEnv();
      setAppEnv(snap);
    } catch {
      // Ignore if running outside Tauri runtime during preview
    } finally {
      setScanningApps(false);
    }
  }, []);

  const refreshClashNodes = useCallback(async () => {
    setLoadingClashNodes(true);
    try {
      const snap = await api.listClashVergeNodes();
      setClashNodes(snap);
    } catch {
      // Ignore if running outside Tauri runtime during Vite preview
    } finally {
      setLoadingClashNodes(false);
    }
  }, []);

  const refreshAccounts = useCallback(async () => {
    setLoadingAccounts(true);
    try {
      const [list, presets] = await Promise.all([
        api.listAccounts(),
        api.listAccountEnvironments(),
      ]);
      setAccounts(list);
      setEnvPresets(presets);
    } catch {
      // Ignore if running outside Tauri runtime during Vite preview
    } finally {
      setLoadingAccounts(false);
    }
  }, []);

  const refreshAll = async () => {
    void refreshAppEnv();
    void refreshAccounts();
    void refreshClashNodes();
    const [cfg, st] = await Promise.all([api.getConfig(), api.getStatus()]);
    setConfig(cfg);
    setStatus(st);
    return { cfg, st };
  };

  useEffect(() => {
    refreshAll()
      .then(async ({ cfg, st }) => {
        if (didAutoStartRef.current) return;
        didAutoStartRef.current = true;
        const node = cfg.nodes.find((n) => n.id === cfg.activeNodeId);
        if (cfg.autoStartGateway && node?.server.trim() && !st.running) {
          setBusy(true);
          try {
            const started = await api.startGateway();
            setStatus(started);
            setChecks(await api.runDiagnostics());
            notify("安全网关已自动启动" + (cfg.autoLaunchBrowser ? "，已弹出防泄漏浏览器" : ""));
          } catch (err) {
            notify(`自动启动网关失败: ${String(err)}`);
          } finally {
            setBusy(false);
          }
        }
      })
      .catch((e) => notify(`初始化失败: ${String(e)}`));

    const unsubs: Array<() => void> = [];

    api
      .onBrowserDownloadProgress((p) => {
        setDlProgress(p);
        if (p.stage === "done") {
          api.getStatus().then(setStatus).catch(() => {});
          notify("专属防泄漏浏览器下载并配置完成");
        }
      })
      .then((fn) => unsubs.push(fn));

    api
      .onStatusUpdate((st) => {
        setStatus(st);
      })
      .then((fn) => unsubs.push(fn));

    const timer = setInterval(() => {
      api.getStatus().then(setStatus).catch(() => {});
    }, 3500);

    const envTimer = setInterval(() => {
      api.inspectAppsEnv().then(setAppEnv).catch(() => {});
    }, 8000);

    return () => {
      clearInterval(timer);
      clearInterval(envTimer);
      unsubs.forEach((fn) => fn());
    };
  }, [notify]);

  const handleSaveConfig = async (nextConfig?: AppConfig) => {
    const target = nextConfig || config;
    if (!target) return;
    const saved = await api.saveConfig(target);
    setConfig(saved);
    setDirty(false);
    notify("配置已保存");
  };

  const handleToggleGateway = async () => {
    if (!config || !status) return;
    setBusy(true);
    try {
      if (dirty) {
        await handleSaveConfig(config);
      }
      const nextStatus = status.running
        ? await api.stopGateway()
        : await api.startGateway();
      setStatus(nextStatus);
      const result = await api.runDiagnostics();
      setChecks(result);
    } catch (err) {
      notify(`操作失败: ${String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const handleToggleKillSwitch = async () => {
    if (!status?.running) return;
    try {
      const next = await api.toggleKillSwitch(!status.blockedByKillSwitch);
      setStatus(next);
      notify(
        next.blockedByKillSwitch
          ? "已开启紧急熔断：全部 AI 出站已阻断"
          : "已解除熔断，AI 通道恢复",
      );
    } catch (err) {
      notify(`熔断切换失败: ${String(err)}`);
    }
  };

  const handleRunDiagnostics = async () => {
    setChecking(true);
    try {
      const result = await api.runDiagnostics();
      setChecks(result);
      const st = await api.getStatus();
      setStatus(st);
    } catch (err) {
      notify(`体检失败: ${String(err)}`);
    } finally {
      setChecking(false);
    }
  };

  const handleFix = async (action: string) => {
    try {
      const msg = await api.fixDiagnostic(action);
      notify(msg);
      await handleRunDiagnostics();
    } catch (err) {
      notify(`修复失败: ${String(err)}`);
    }
  };

  const handleInstallBrowser = async () => {
    try {
      setDlProgress({
        stage: "downloading",
        downloadedBytes: 0,
        totalBytes: 0,
        message: "正在连接 GitHub 获取便携版 Ungoogled-Chromium...",
      });
      const msg = await api.installBrowser();
      notify(msg);
      setStatus(await api.getStatus());
    } catch (err) {
      setDlProgress(null);
      notify(`下载失败: ${String(err)}`);
    }
  };

  const handleOpenInSafeBrowser = async (url: string) => {
    try {
      const msg = await api.launchBrowserUrl(url);
      notify(msg);
      setStatus(await api.getStatus());
    } catch (err) {
      notify(`打开失败: ${String(err)}`);
    }
  };

  const handleLaunchBrowserProfile = async (profileId: string, url?: string) => {
    try {
      const msg = await api.launchBrowserProfile(profileId, url);
      notify(msg);
      setStatus(await api.getStatus());
    } catch (err) {
      notify(`启动浏览器环境失败: ${String(err)}`);
    }
  };

  const handleCloseBrowserProfile = async (profileId: string) => {
    try {
      const st = await api.closeBrowserProfile(profileId);
      setStatus(st);
      notify("已关闭该浏览器窗口");
    } catch (err) {
      notify(`关闭失败: ${String(err)}`);
    }
  };

  const handleSaveBrowserProfiles = async (profiles: BrowserProfile[]) => {
    if (!config) return;
    const nextConfig: AppConfig = { ...config, browserProfiles: profiles };
    try {
      const saved = await api.saveConfig(nextConfig);
      setConfig(saved);
      setDirty(false);
    } catch (err) {
      if (!isTauriEnv()) {
        setConfig(nextConfig);
        setDirty(false);
        return;
      }
      throw err;
    }
  };

  const handleRestartGateway = async () => {
    setBusy(true);
    try {
      if (dirty && config) {
        await handleSaveConfig(config);
      }
      await api.stopGateway();
      const started = await api.startGateway();
      setStatus(started);
      setChecks(await api.runDiagnostics());
      notify("网关已重启并刷新多出口监听端口");
    } catch (err) {
      notify(`重启网关失败: ${String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const handleQuickLaunchNodeBrowser = async (node: NodeProfile) => {
    if (!config) return;
    if (dirty) {
      await handleSaveConfig(config);
    }
    const isPrimary = node.id === config.activeNodeId;
    const matching = (config.browserProfiles ?? []).find((p) =>
      isPrimary ? p.id === "default" || p.nodeId === node.id : p.nodeId === node.id,
    );
    const portReady = isPrimary
      ? gatewayReady
      : !!status?.running && status?.secondaryNodePorts?.[node.id] !== undefined;

    if (matching && portReady && status?.browserInstalled) {
      await handleLaunchBrowserProfile(matching.id);
      return;
    }
    if (!matching) {
      setPreselectedBrowserNode({ nodeId: node.id, nonce: Date.now() });
    } else if (!status?.running) {
      notify("请先点击右上角或总览中的「启动网关」，即可用该环境启动浏览器");
    } else if (!portReady) {
      notify("该节点本地端口尚未激活，请在「指纹浏览器」点击重启激活后启动");
    }
    switchTab("browsers");
  };

  const handleOpenAllAudits = async () => {
    try {
      await api.launchBrowserUrl("https://ip.net.coffee/");
      await api.launchBrowserUrl("https://fuck-claude.vercel.app/");
      await api.launchBrowserUrl("https://claude.ai/");
      notify("已在安全浏览器打开 IP 信誉 + 指纹信号 + Claude 全部检测页");
      setStatus(await api.getStatus());
    } catch (err) {
      notify(`打开失败: ${String(err)}`);
    }
  };

  const handleLaunchDesktop = async () => {
    try {
      const msg = await api.launchClaudeDesktop();
      notify(msg);
    } catch (err) {
      notify(`启动 Claude Desktop 失败: ${String(err)}`);
    }
  };

  const handleLaunchTerminal = async () => {
    try {
      const msg = await api.launchClaudeTerminal(workDir, strictCliWfp);
      notify(msg);
    } catch (err) {
      notify(`启动终端失败: ${String(err)}`);
    }
  };

  const handleLaunchManagedApp = async (appId: string, relaunch: boolean) => {
    try {
      const msg = await api.launchManagedApp(appId, relaunch);
      notify(msg);
      setStatus(await api.getStatus());
      setTimeout(() => {
        void refreshAppEnv();
      }, 900);
    } catch (err) {
      notify(`操作失败: ${String(err)}`);
    }
  };

  const handleCleanRegistryEnv = async () => {
    try {
      const msg = await api.cleanRegistryProxyEnv();
      notify(msg);
      await refreshAppEnv();
    } catch (err) {
      notify(`清理失败: ${String(err)}`);
    }
  };

  const handleCreateAppShortcut = async (appId: string) => {
    try {
      const msg = await api.createManagedAppShortcut(appId);
      notify(msg);
    } catch (err) {
      notify(`创建快捷方式失败: ${String(err)}`);
    }
  };

  const isTauriEnv = () =>
    typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

  const formatPreviewNow = () => {
    const d = new Date();
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  };

  const handleUpsertAccount = async (record: AccountRecord) => {
    try {
      const next = await api.upsertAccount(record);
      setAccounts(next);
      notify(`已加密保存账号: ${record.email}`);
    } catch (err) {
      if (!isTauriEnv()) {
        const now = formatPreviewNow();
        const id = record.id.trim() || `acc-${Date.now()}`;
        const normalized: AccountRecord = {
          ...record,
          id,
          provider: record.provider.trim() || "Google",
          environmentName: record.environmentName.trim(),
          createdAt: record.createdAt || now,
          updatedAt: now,
        };
        setAccounts((prev) => {
          const idx = prev.findIndex((a) => a.id === id);
          if (idx >= 0) {
            const copy = [...prev];
            copy[idx] = normalized;
            return copy;
          }
          return [normalized, ...prev];
        });
        notify(`已保存账号 (预览模式): ${record.email}`);
        return;
      }
      notify(`保存账号失败: ${String(err)}`);
      throw err;
    }
  };

  const handleDeleteAccount = async (id: string) => {
    try {
      const next = await api.deleteAccount(id);
      setAccounts(next);
      notify("已删除账号记录");
    } catch (err) {
      if (!isTauriEnv()) {
        setAccounts((prev) => prev.filter((a) => a.id !== id));
        notify("已删除账号记录 (预览模式)");
        return;
      }
      notify(`删除账号失败: ${String(err)}`);
    }
  };

  const handleBulkDeleteAccounts = async (ids: string[]) => {
    try {
      const next = await api.deleteAccounts(ids);
      setAccounts(next);
      notify(`已清理 ${ids.length} 条账号记录`);
    } catch (err) {
      if (!isTauriEnv()) {
        const set = new Set(ids);
        setAccounts((prev) => prev.filter((a) => !set.has(a.id)));
        notify(`已清理 ${ids.length} 条账号记录 (预览模式)`);
        return;
      }
      notify(`批量删除失败: ${String(err)}`);
    }
  };

  const handleImportAccounts = async (records: AccountRecord[], replace: boolean) => {
    try {
      const next = await api.importAccounts(records, replace);
      setAccounts(next);
      notify(`已导入 ${records.length} 条账号记录`);
    } catch (err) {
      if (!isTauriEnv()) {
        const now = formatPreviewNow();
        setAccounts((prev) => {
          const base = replace ? [] : [...prev];
          for (const rec of records) {
            const id = rec.id.trim() || `acc-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
            const normalized: AccountRecord = {
              ...rec,
              id,
              provider: rec.provider.trim() || "Google",
              environmentName: rec.environmentName.trim(),
              createdAt: rec.createdAt || now,
              updatedAt: now,
            };
            const idx = base.findIndex(
              (x) =>
                x.id === id ||
                (x.email.toLowerCase() === normalized.email.toLowerCase() &&
                  x.provider.toLowerCase() === normalized.provider.toLowerCase()),
            );
            if (idx >= 0) base[idx] = normalized;
            else base.push(normalized);
          }
          return base;
        });
        notify(`已导入 ${records.length} 条账号记录 (预览模式)`);
        return;
      }
      notify(`导入账号失败: ${String(err)}`);
    }
  };

  const handleSaveEnvPresets = async (presets: AccountEnvPreset[]) => {
    try {
      const next = await api.saveAccountEnvironments(presets);
      setEnvPresets(next);
    } catch (err) {
      if (!isTauriEnv()) {
        setEnvPresets(presets);
        return;
      }
      notify(`保存启动环境预设失败: ${String(err)}`);
      throw err;
    }
  };

  const handleReorderAccounts = async (orderedIds: string[]) => {
    const prevSnapshot = accounts;
    const byId = new Map(accounts.map((a) => [a.id, a]));
    const nextLocal: AccountRecord[] = [];
    const seen = new Set<string>();
    for (const id of orderedIds) {
      const rec = byId.get(id);
      if (rec && !seen.has(id)) {
        seen.add(id);
        nextLocal.push(rec);
      }
    }
    for (const rec of accounts) {
      if (!seen.has(rec.id)) {
        nextLocal.push(rec);
      }
    }
    setAccounts(nextLocal);

    try {
      const persisted = await api.reorderAccounts(orderedIds);
      setAccounts(persisted);
    } catch (err) {
      if (!isTauriEnv()) {
        return;
      }
      setAccounts(prevSnapshot);
      notify(`调整账号顺序失败: ${String(err)}`);
    }
  };

  const handlePasteOAuth = async () => {
    try {
      const clip = (await navigator.clipboard.readText()).trim();
      if (clip.startsWith("https://")) {
        await handleOpenInSafeBrowser(clip);
      } else {
        notify("剪贴板里没有 https:// 链接；若登录弹出默认浏览器，请复制地址再点击此按钮");
      }
    } catch {
      notify("读取剪贴板失败，请直接把登录网址粘贴到防泄漏浏览器地址栏");
    }
  };

  const activeNode = config?.nodes.find((n) => n.id === config.activeNodeId);
  const gatewayReady = !!status?.running && !status?.blockedByKillSwitch && !busy;
  const browserProfiles = config?.browserProfiles ?? [];
  const selectedQuickProfileId = browserProfiles.some((p) => p.id === quickProfileId)
    ? quickProfileId
    : browserProfiles[0]?.id || "default";
  const dirtyInheritedEnvApps = (appEnv?.apps ?? []).filter(
    (a) =>
      a.health === "dead_proxy" ||
      (a.health === "mismatch" &&
        a.envVars.some((v) => !v.key.toUpperCase().includes("NO_PROXY"))),
  );

  const diagnosticItems: DiagnosticCheck[] = useMemo(() => {
    if (checks.length > 0) return checks;
    return DEFAULT_CHECK_LABELS.map((d) => ({
      id: d.id,
      title: d.title,
      category: d.category === "all" ? "core" : d.category,
      status: "pending",
      summary: "点击「运行体检」执行实时校验",
      detail: "待检测",
      fixable: false,
    }));
  }, [checks]);

  const filteredChecks =
    checkFilter === "all"
      ? diagnosticItems
      : diagnosticItems.filter((c) => c.category === checkFilter);

  const passCount = checks.filter((c) => c.status === "pass").length;
  const totalRulesCount =
    (status?.wfpFilterCount || 0) + (status?.persistentClaudeFilterCount || 0);

  const filteredLogs = useMemo(() => {
    const logs = status?.logs ?? [];
    const filter = logFilter.trim().toLowerCase();
    return filter ? logs.filter((line) => line.toLowerCase().includes(filter)) : logs;
  }, [status?.logs, logFilter]);
  const parsedLogs = useMemo(
    () => filteredLogs.map(parseLogEntry),
    [filteredLogs],
  );

  const activeNavItem = NAV_GROUPS.flatMap((g) => g.items).find((i) => i.key === tab)!;

  const countryLabel = useMemo(() => {
    const cc = status?.exitIp?.countryCode || activeNode?.expectedCountry || "KR";
    const cName =
      cc === "KR" ? "韩国" : status?.exitIp?.country || cc;
    const cityName =
      status?.exitIp?.city === "Seoul"
        ? "首尔"
        : status?.exitIp?.city || (cc === "KR" ? "首尔" : "--");
    return `${cName} · ${cityName}`;
  }, [status?.exitIp, activeNode]);

  return (
    <TooltipProvider delayDuration={180}>
      <div className="flex h-dvh w-full overflow-hidden bg-[#f5f6f8] text-[#111827]">
        <a
          href="#main-heading"
          className="visually-hidden focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded-lg focus:bg-[#111827] focus:px-3 focus:py-1.5 focus:text-white focus:font-medium"
        >
          跳转到主内容
        </a>

        {/* Left Apple / MailPulse / ui-guide Rail */}
        <aside
          aria-label="导航与状态栏"
          className="app-scroll flex w-[13.75rem] shrink-0 flex-col justify-between overflow-y-auto bg-[#f8f9fb] px-3 py-4"
        >
          <div className="flex flex-col gap-5">
            {/* Brand Header */}
            <div className="flex items-center gap-2.5 px-2 pt-0.5">
              <div className="grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-[#111827] text-white shadow-[0_1px_2px_rgba(17,24,39,0.22)]">
                <Shield className="h-4 w-4" aria-hidden="true" />
              </div>
              <span className="text-[0.94rem] font-semibold tracking-[-0.02em] text-[#111827]">
                AI NetGuard
              </span>
            </div>

            {/* Grouped Navigation */}
            <nav aria-label="主界面" className="flex flex-col gap-4">
              {NAV_GROUPS.map((grp) => (
                <div key={grp.group} className="flex flex-col gap-1">
                  <div className="px-2.5 pb-0.5 text-[0.69rem] font-medium text-[#8a919f]">
                    {grp.group}
                  </div>
                  {grp.items.map((item) => {
                    const Icon = item.icon;
                    const active = tab === item.key;
                    return (
                      <button
                        key={item.key}
                        type="button"
                        aria-current={active ? "page" : undefined}
                        onClick={() => switchTab(item.key)}
                        className={cn(
                          "flex min-h-8 w-full items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-left text-[0.79rem] transition-all cursor-pointer",
                          active
                            ? "bg-white font-semibold text-[#111827] border border-[#eaecef] shadow-[0_1px_2px_rgba(15,23,42,0.04)]"
                            : "border border-transparent font-medium text-[#525866] hover:bg-white/60 hover:text-[#111827]",
                        )}
                      >
                        <Icon
                          className={cn(
                            "h-4 w-4 shrink-0",
                            active ? "text-[#111827]" : "text-[#7c8495]",
                          )}
                          aria-hidden="true"
                        />
                        <span className="truncate">{item.label}</span>
                        {item.key === "browsers" && (status?.runningBrowserProfiles?.length ?? 0) > 0 && (
                          <span className="mono-num ml-auto inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-[#16a34a] px-1 text-[0.65rem] font-semibold text-white">
                            {status?.runningBrowserProfiles?.length}
                          </span>
                        )}
                        {item.key === "apps" && (appEnv?.pollutedCount ?? 0) > 0 && (
                          <span className="mono-num ml-auto inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-[#dc2626] px-1 text-[0.65rem] font-semibold text-white">
                            {appEnv?.pollutedCount}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              ))}
            </nav>
          </div>

          {/* Minimal Bottom Live Dot + Vitaly Hover Telemetry Tooltip */}
          <Tooltip>
            <TooltipTrigger asChild>
              <div
                tabIndex={0}
                className="mx-1 mt-4 flex items-center gap-2 rounded-lg px-2 py-1.5 text-[0.75rem] font-medium text-[#525866] hover:bg-white/80 transition-colors cursor-default"
              >
                <span
                  className={cn(
                    "h-2 w-2 shrink-0 rounded-full",
                    status?.blockedByKillSwitch
                      ? "bg-[#dc2626] text-[#dc2626] live-pulse"
                      : status?.running
                        ? "bg-[#16a34a] text-[#16a34a] live-pulse"
                        : "bg-[#9ca3af]",
                  )}
                  aria-hidden="true"
                />
                <span className="truncate">
                  {status?.blockedByKillSwitch
                    ? "熔断阻断中"
                    : status?.running
                      ? "网关运行中"
                      : "网关待机"}
                </span>
              </div>
            </TooltipTrigger>
            <TooltipContent side="right" align="end">
              <div className="flex flex-col gap-1 text-[0.7rem]">
                <div className="font-semibold text-white">
                  {activeNode?.name || "未配置节点"}
                </div>
                <div className="text-[#d1d5db] mono-num">
                  出口: {status?.exitIp?.ip || "--"} · {status?.detectedPhysicalNic || "探测中"}
                </div>
                <div className="text-[#9ca3af] mono-num">
                  WFP 规则: {status?.wfpActive ? `${totalRulesCount} 条` : "未激活"}
                </div>
                {status?.detectedConflicts.length ? (
                  <div className="text-[#fcd34d]">
                    共存隔离: {status.detectedConflicts.join(" / ")}
                  </div>
                ) : null}
              </div>
            </TooltipContent>
          </Tooltip>
        </aside>

        {/* Right Workspace Pane */}
        <main className="app-scroll flex min-w-0 flex-1 flex-col overflow-y-auto px-4 pb-4 pt-2.5 lg:px-5">
          {/* Top Breadcrumb Bar (ui-guide + Vitaly + MailPulse) */}
          <div className="mb-2.5 flex min-h-7 shrink-0 items-center justify-between gap-3 px-1">
            <div className="flex items-center gap-2 text-[0.75rem]">
              <LayoutGrid className="h-3.5 w-3.5 text-[#9ca3af]" aria-hidden="true" />
              <span className="text-[#7c8495]">AI NetGuard</span>
              <span className="text-[#c5cad3]" aria-hidden="true">/</span>
              <span className="font-medium text-[#111827]">{activeNavItem.crumb}</span>
            </div>

            <div className="flex items-center gap-2">
              {status?.detectedConflicts.length ? (
                <Badge
                  variant="neutral"
                  className="hidden sm:inline-flex bg-white border-[#eaecef] text-[#525866] font-normal"
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-[#d97706]" aria-hidden="true" />
                  共存旁路: {status.detectedConflicts.join(" / ")}
                </Badge>
              ) : null}
              {dirty &&
                tab !== "nodes" &&
                tab !== "hardening" &&
                tab !== "apps" &&
                tab !== "accounts" && (
                <Button variant="solid" size="xs" onClick={() => handleSaveConfig()}>
                  保存未提交更改
                </Button>
              )}
            </div>
          </div>

          <div className="vt-page-content flex flex-col">
            {/* Live Polluted Process Alert Banner on Overview */}
            {tab === "dashboard" && (appEnv?.pollutedCount ?? 0) > 0 && (
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2.5 rounded-xl border border-[#fecaca] bg-[#fef2f2] px-4 py-2.5 text-[0.77rem] text-[#991b1b]">
                <div className="flex min-w-0 items-center gap-2">
                  <AlertTriangle className="h-4 w-4 shrink-0 text-[#dc2626]" aria-hidden="true" />
                  <span className="font-medium">
                    检测到 {appEnv?.pollutedCount} 个运行中的 AI 进程存在失效或冲突代理环境
                    {dirtyInheritedEnvApps.length > 0 &&
                    appEnv?.systemProxy.enabled &&
                    appEnv.systemProxy.alive
                      ? `（系统代理 ${appEnv.systemProxy.hostPort || ""} 实际正常，属于继承脏环境变量）`
                      : "（运行环境与所选代理策略不一致）"}
                  </span>
                </div>
                <Button
                  variant="destructive"
                  size="xs"
                  onClick={() => {
                    switchTab("apps");
                    void refreshAppEnv();
                  }}
                >
                  前往一键干净重启
                </Button>
              </div>
            )}

            {/* ======================= VIEW 01: OVERVIEW ======================= */}
            {tab === "dashboard" && (
              <div className="bento-sheet flex flex-col divide-y divide-[#eaecef] rounded-2xl border border-[#eaecef] bg-white shadow-[0_1px_3px_rgba(15,23,42,0.03)]">
                {/* Sheet Header */}
                <header className="flex flex-wrap items-center justify-between gap-3 px-6 py-4">
                  <div>
                    <h1
                      id="main-heading"
                      tabIndex={-1}
                      className="vt-page-title text-[1.2rem] font-semibold tracking-[-0.02em] text-[#111827] outline-none"
                    >
                      总览与安全启动
                    </h1>
                    <p className="mt-0.5 text-[0.76rem] text-[#7c8495]">
                      查看出口、隔离状态和应用启动入口
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    {status?.running && (
                      <Button
                        variant={status.blockedByKillSwitch ? "emerald" : "destructive-outline"}
                        size="sm"
                        onClick={handleToggleKillSwitch}
                      >
                        {status.blockedByKillSwitch ? (
                          <Unlock className="h-3.5 w-3.5" aria-hidden="true" />
                        ) : (
                          <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
                        )}
                        {status.blockedByKillSwitch ? "解除熔断" : "紧急熔断"}
                      </Button>
                    )}

                    <Button
                      variant={status?.running ? "outline" : "solid"}
                      size="sm"
                      disabled={busy}
                      onClick={handleToggleGateway}
                    >
                      {status?.running ? (
                        <Square className="h-3 w-3" aria-hidden="true" />
                      ) : (
                        <Play className="h-3 w-3" aria-hidden="true" />
                      )}
                      {busy ? "处理中..." : status?.running ? "停止网关" : "启动网关"}
                    </Button>

                    <Button
                      variant="soft"
                      size="sm"
                      disabled={checking}
                      onClick={handleRunDiagnostics}
                    >
                      <Activity className="h-3.5 w-3.5" aria-hidden="true" />
                      {checking ? "体检中..." : "运行体检"}
                    </Button>
                  </div>
                </header>

                {/* 4-Column Hairline KPI Row */}
                <section
                  aria-label="核心状态指标"
                  className="grid grid-cols-2 lg:grid-cols-4"
                >
                  {/* KPI 1: Gateway State */}
                  <div className="flex flex-col justify-between gap-2 border-b border-r border-[#eaecef] p-4 px-5 lg:border-b-0">
                    <div className="flex items-center gap-2 text-[0.76rem] font-medium text-[#525866]">
                      <span className="inline-grid h-5 w-5 place-items-center rounded-md bg-[#fff7ed] text-[#ea580c]">
                        <Activity className="h-3.5 w-3.5" aria-hidden="true" />
                      </span>
                      网关状态
                    </div>
                    <div className="flex items-baseline justify-between gap-2">
                      <span
                        className={cn(
                          "text-[1.45rem] font-semibold tracking-tight leading-none",
                          status?.blockedByKillSwitch
                            ? "text-[#dc2626]"
                            : status?.running
                              ? "text-[#16a34a]"
                              : "text-[#525866]",
                        )}
                      >
                        {status?.blockedByKillSwitch
                          ? "已熔断"
                          : status?.running
                            ? "运行中"
                            : "待机"}
                      </span>
                      {status?.blockedByKillSwitch ? (
                        <Badge variant="danger">阻断</Badge>
                      ) : status?.running ? (
                        <Badge variant="success">✓ 正常</Badge>
                      ) : (
                        <Badge variant="neutral">待启动</Badge>
                      )}
                    </div>
                    <div className="text-[0.71rem] text-[#7c8495]">
                      {status?.exitIp ? "出口已核验" : "等待出口探针"}
                    </div>
                  </div>

                  {/* KPI 2: Latency + Vitaly Live Sparkline */}
                  <div className="flex flex-col justify-between gap-2 border-b border-[#eaecef] p-4 px-5 lg:border-b-0 lg:border-r">
                    <div className="flex items-center gap-2 text-[0.76rem] font-medium text-[#525866]">
                      <span className="inline-grid h-5 w-5 place-items-center rounded-md bg-[#eff6ff] text-[#2563eb]">
                        <Clock className="h-3.5 w-3.5" aria-hidden="true" />
                      </span>
                      出口延迟
                    </div>
                    <div className="flex items-end justify-between gap-2">
                      <span className="mono-num text-[1.45rem] font-semibold tracking-tight leading-none text-[#111827]">
                        {status?.exitIp?.latencyMs ? `${status.exitIp.latencyMs} ms` : "--"}
                      </span>
                      <LatencySparkline
                        samples={latencyHistory}
                        tone={
                          !status?.running
                            ? "idle"
                            : status.blockedByKillSwitch
                              ? "danger"
                              : (status.exitIp?.latencyMs || 0) > 280
                                ? "warn"
                                : "ok"
                        }
                      />
                    </div>
                    <div className="text-[0.71rem] text-[#7c8495]">{countryLabel}</div>
                  </div>

                  {/* KPI 3: WFP Kernel Lock + MailPulse Rule Density Meter */}
                  <div className="flex flex-col justify-between gap-2 border-r border-[#eaecef] p-4 px-5">
                    <div className="flex items-center gap-2 text-[0.76rem] font-medium text-[#525866]">
                      <span className="inline-grid h-5 w-5 place-items-center rounded-md bg-[#f0edfc] text-[#6d5bd0]">
                        <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                      </span>
                      WFP 内核锁
                    </div>
                    <div className="flex items-baseline justify-between gap-2">
                      <span className="mono-num text-[1.45rem] font-semibold tracking-tight leading-none text-[#111827]">
                        {totalRulesCount} 条
                      </span>
                      {status?.wfpActive ? (
                        <Badge variant="success">✓ 生效</Badge>
                      ) : (
                        <Badge variant="neutral">待激活</Badge>
                      )}
                    </div>
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[0.71rem] text-[#7c8495]">
                        {status?.wfpActive ? "规则生效中" : "未下发动态锁"}
                      </span>
                      <SegmentedMeter
                        total={6}
                        states={Array.from({ length: 6 }, (_, idx) =>
                          status?.wfpActive && idx < Math.min(6, Math.max(2, Math.ceil(totalRulesCount / 5)))
                            ? "active"
                            : "idle",
                        )}
                      />
                    </div>
                  </div>

                  {/* KPI 4: Diagnostics Score + Segmented Health Strip */}
                  <div className="flex flex-col justify-between gap-2 p-4 px-5">
                    <div className="flex items-center gap-2 text-[0.76rem] font-medium text-[#525866]">
                      <span className="inline-grid h-5 w-5 place-items-center rounded-md bg-[#ecfdf3] text-[#16a34a]">
                        <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                      </span>
                      体检结果
                    </div>
                    <div className="flex items-baseline justify-between gap-2">
                      <span className="mono-num text-[1.45rem] font-semibold tracking-tight leading-none text-[#111827]">
                        {checks.length > 0 ? `${passCount} / ${checks.length}` : "-- / 8"}
                      </span>
                      {checks.length === 0 ? (
                        <Badge variant="neutral">待检</Badge>
                      ) : passCount === checks.length ? (
                        <Badge variant="success">✓ 通过</Badge>
                      ) : (
                        <Badge variant="warning">注意</Badge>
                      )}
                    </div>
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[0.71rem] text-[#7c8495]">
                        {checks.length === 0
                          ? "点击体检验证"
                          : passCount === checks.length
                            ? "全部通过"
                            : `${checks.length - passCount} 项待处理`}
                      </span>
                      <SegmentedMeter
                        total={8}
                        states={diagnosticItems.map((c) => c.status)}
                      />
                    </div>
                  </div>
                </section>

                {/* Middle Split: Map (Left) & Quick Launch (Right) */}
                <section className="grid grid-cols-1 divide-y divide-[#eaecef] lg:grid-cols-[minmax(0,1.42fr)_minmax(0,1fr)] lg:divide-x lg:divide-y-0">
                  <div className="p-5 px-6">
                    <ExitIpMap
                      exitIp={status?.exitIp}
                      activeNode={activeNode}
                      running={!!status?.running}
                      blockedByKillSwitch={!!status?.blockedByKillSwitch}
                      compact
                    />
                  </div>

                  <div className="flex flex-col gap-2.5 p-5 px-6">
                    <div className="flex items-center justify-between">
                      <h2 className="text-[0.84rem] font-semibold text-[#111827]">安全启动</h2>
                      {!status?.guardConnected && (
                        <Button
                          variant="ghost"
                          size="xs"
                          onClick={() => api.connectGuard().then(setStatus)}
                        >
                          <Lock className="h-3 w-3" aria-hidden="true" />
                          连接 Guard
                        </Button>
                      )}
                    </div>

                    <div className="flex flex-1 flex-col divide-y divide-[#eaecef]">
                      {/* Row 1: Portable Safe Browser */}
                      <div className="flex flex-col gap-1.5 py-2.5 first:pt-1">
                        <div className="flex items-center justify-between gap-3">
                          <div className="flex min-w-0 items-center gap-2.5">
                            <span className="inline-grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-[#f0edfc] text-[#6d5bd0]">
                              <Globe className="h-4 w-4" aria-hidden="true" />
                            </span>
                            <div className="min-w-0">
                              <div className="text-[0.8rem] font-medium text-[#111827]">
                                防泄漏浏览器
                              </div>
                              <div className="mono-num text-[0.67rem] text-[#7c8495]">
                                {config?.alignFingerprint
                                  ? `${activeNode?.timezone || "Asia/Seoul"} · ${activeNode?.locale || "ko-KR"}`
                                  : "指纹同步已关闭"}
                              </div>
                            </div>
                          </div>
                          {!status?.browserInstalled ? (
                            <Button
                              variant="soft"
                              size="sm"
                              onClick={handleInstallBrowser}
                            >
                              <Download className="h-3.5 w-3.5" aria-hidden="true" />
                              安装 (~200MB)
                            </Button>
                          ) : (
                            <div className="flex shrink-0 items-center gap-1.5">
                              <Button
                                variant="ghost"
                                size="xs"
                                onClick={() => switchTab("browsers")}
                              >
                                多环境
                              </Button>
                              <Button
                                variant="outline"
                                size="sm"
                                disabled={!gatewayReady}
                                onClick={() => handleOpenInSafeBrowser("https://claude.ai")}
                              >
                                <ExternalLink className="h-3.5 w-3.5 text-[#7c8495]" aria-hidden="true" />
                                打开
                              </Button>
                            </div>
                          )}
                        </div>
                        {status?.browserInstalled && browserProfiles.length > 1 && (
                          <div className="flex items-center gap-1.5 pl-9">
                            <label htmlFor={fid("dashQuickBp")} className="visually-hidden">
                              快速启动独立指纹浏览器环境
                            </label>
                            <select
                              id={fid("dashQuickBp")}
                              value={selectedQuickProfileId}
                              onChange={(e) => setQuickProfileId(e.target.value)}
                              className="h-7 min-w-0 flex-1 rounded-md border border-[#dce0e6] bg-[#f8f9fb] px-2 text-[0.7rem] text-[#111827] cursor-pointer"
                            >
                              {browserProfiles.map((bp) => {
                                const nid = bp.nodeId || config?.activeNodeId;
                                const nodeName =
                                  config?.nodes.find((n) => n.id === nid)?.name || "主出口";
                                return (
                                  <option key={bp.id} value={bp.id}>
                                    {bp.name} ({nodeName})
                                  </option>
                                );
                              })}
                            </select>
                            <Button
                              variant="soft"
                              size="xs"
                              disabled={!status?.running || busy}
                              onClick={() => void handleLaunchBrowserProfile(selectedQuickProfileId)}
                            >
                              启动
                            </Button>
                          </div>
                        )}
                        {dlProgress && dlProgress.stage !== "done" && (
                          <div className="flex flex-col gap-1 pl-9">
                            <progress
                              className="h-1.5 w-full accent-[#6d5bd0]"
                              max={100}
                              value={
                                dlProgress.totalBytes
                                  ? Math.min(
                                      100,
                                      Math.round((dlProgress.downloadedBytes / dlProgress.totalBytes) * 100),
                                    )
                                  : undefined
                              }
                            />
                            <span className="text-[0.68rem] text-[#7c8495]">
                              {dlProgress.message}
                            </span>
                          </div>
                        )}
                      </div>

                      {/* Row 2: Claude Desktop */}
                      <div className="flex items-center justify-between gap-2 py-2.5">
                        <div className="flex min-w-0 items-center gap-2.5">
                          <span className="inline-grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-[#fff1ec] text-[#d97757]">
                            <ClaudeStarburst size={16} />
                          </span>
                          <div className="min-w-0">
                            <div className="flex items-center gap-1.5 text-[0.8rem] font-medium text-[#111827]">
                              Claude Desktop
                              {status?.persistentClaudeLockActive && (
                                <Badge variant="success" className="px-1.5 py-0 text-[0.62rem]">
                                  离线锁
                                </Badge>
                              )}
                            </div>
                            <PathEndVisible
                              path={status?.claudeDesktopPath}
                              fallback="未检测到 Claude.exe"
                            />
                          </div>
                        </div>

                        <div className="flex shrink-0 items-center gap-1.5">
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                variant="ghost"
                                size="icon"
                                aria-label="粘贴剪贴板 OAuth 登录链接到安全浏览器"
                                disabled={!gatewayReady || !status?.browserInstalled}
                                onClick={handlePasteOAuth}
                              >
                                <ClipboardPaste className="h-3.5 w-3.5 text-[#525866]" aria-hidden="true" />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>粘贴剪贴板 OAuth 链接到防泄漏浏览器</TooltipContent>
                          </Tooltip>
                          <Button
                            variant="outline"
                            size="sm"
                            disabled={!gatewayReady || !status?.claudeDesktopFound}
                            onClick={handleLaunchDesktop}
                          >
                            <ExternalLink className="h-3.5 w-3.5 text-[#7c8495]" aria-hidden="true" />
                            打开
                          </Button>
                        </div>
                      </div>

                      {/* Row 3: Claude Code CLI */}
                      <div className="flex items-center justify-between gap-2 py-2.5">
                        <div className="flex min-w-0 items-center gap-2.5">
                          <span className="inline-grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-[#eff6ff] text-[#2563eb]">
                            <Terminal className="h-4 w-4" aria-hidden="true" />
                          </span>
                          <div className="min-w-0">
                            <div className="text-[0.8rem] font-medium text-[#111827]">
                              Claude Code 终端
                            </div>
                            <div className="flex items-center gap-1.5 text-[0.68rem] text-[#7c8495]">
                              <label htmlFor={fid("strictCliWfp")} className="cursor-pointer">
                                严格 WFP 锁
                              </label>
                              <Switch
                                id={fid("strictCliWfp")}
                                size="sm"
                                checked={strictCliWfp}
                                onCheckedChange={setStrictCliWfp}
                              />
                            </div>
                          </div>
                        </div>

                        <Button
                          variant="outline"
                          size="sm"
                          disabled={!gatewayReady}
                          onClick={handleLaunchTerminal}
                        >
                          <ExternalLink className="h-3.5 w-3.5 text-[#7c8495]" aria-hidden="true" />
                          打开
                        </Button>
                      </div>
                    </div>

                    {/* Working Directory Input */}
                    <div className="flex items-center gap-2.5 pt-1">
                      <label
                        htmlFor={fid("workDir")}
                        className="shrink-0 text-[0.74rem] text-[#7c8495]"
                      >
                        工作目录
                      </label>
                      <div className="relative flex-1">
                        <Folder
                          className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[#9ca3af]"
                          aria-hidden="true"
                        />
                        <Input
                          id={fid("workDir")}
                          className="mono-num pl-8"
                          value={workDir}
                          onChange={(e) => setWorkDir(e.target.value)}
                        />
                      </div>
                    </div>
                  </div>
                </section>

                {/* Bottom Split: Pipeline Links (Left) & 8-Check Matrix (Right) */}
                <section className="grid grid-cols-1 divide-y divide-[#eaecef] lg:grid-cols-[minmax(0,1fr)_minmax(0,1.42fr)] lg:divide-x lg:divide-y-0">
                  {/* Left: Traffic Pipeline */}
                  <div className="flex flex-col gap-3 p-5 px-6">
                    <h2 className="text-[0.84rem] font-semibold text-[#111827]">
                      流量隔离链路
                    </h2>
                    <dl className="flex flex-col divide-y divide-[#f1f3f5] text-[0.78rem]">
                      <div className="flex items-center justify-between py-2.5">
                        <dt className="text-[#525866]">WFP 内核锁</dt>
                        <dd>
                          {status?.wfpActive ? (
                            <span className="inline-flex items-center gap-1 font-medium text-[#15803d]">
                              <CheckCircle2 className="h-3.5 w-3.5 text-[#16a34a]" aria-hidden="true" />
                              已生效
                            </span>
                          ) : (
                            <span className="text-[#7c8495]">待机</span>
                          )}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between py-2.5">
                        <dt className="text-[#525866]">回环核心</dt>
                        <dd className="mono-num font-medium text-[#111827]">
                          {status?.blockedByKillSwitch
                            ? "ai_block (熔断)"
                            : `127.0.0.1:${config?.browserPort || 17891}`}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between py-2.5">
                        <dt className="text-[#525866]">物理旁路</dt>
                        <dd className="font-medium text-[#111827]">
                          {status?.detectedPhysicalNic || "以太网"}
                          {status?.bypassRouteActive ? " · /32" : ""}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between py-2.5">
                        <dt className="text-[#525866]">远端出口</dt>
                        <dd className="mono-num font-medium text-[#111827]">
                          {status?.exitIp?.ip || activeNode?.server || "--"}
                        </dd>
                      </div>
                    </dl>
                  </div>

                  {/* Right: 8-Check Security Matrix */}
                  <div className="flex flex-col gap-3 p-5 px-6">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h2 className="text-[0.84rem] font-semibold text-[#111827]">
                        八项安全体检
                      </h2>
                      <Tabs
                        value={checkFilter}
                        onValueChange={(v) => setCheckFilter(v as CheckFilter)}
                      >
                        <TabsList aria-label="体检项分类">
                          <TabsTrigger value="all">全部</TabsTrigger>
                          <TabsTrigger value="core">核心</TabsTrigger>
                          <TabsTrigger value="security">防泄漏</TabsTrigger>
                          <TabsTrigger value="coexistence">共存</TabsTrigger>
                          <TabsTrigger value="cli">CLI</TabsTrigger>
                        </TabsList>
                      </Tabs>
                    </div>

                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                      {filteredChecks.map((chk) => {
                        const label = SHORT_CHECK_TITLE[chk.id] || chk.title;
                        return (
                          <Tooltip key={chk.id}>
                            <TooltipTrigger asChild>
                              <div
                                tabIndex={0}
                                className={cn(
                                  "flex min-h-9 items-center justify-between gap-2 rounded-lg border px-3 py-1.5 text-[0.77rem] transition-colors cursor-default",
                                  chk.status === "pass" &&
                                    "border-[#ede9fe] bg-[#f7f6fc] text-[#111827]",
                                  chk.status === "warn" &&
                                    "border-[#fde68a] bg-[#fffbeb] text-[#92400e]",
                                  chk.status === "fail" &&
                                    "border-[#fecaca] bg-[#fef2f2] text-[#991b1b]",
                                  chk.status === "pending" &&
                                    "border-[#eaecef] bg-[#f8f9fb] text-[#525866]",
                                )}
                              >
                                <span className="truncate font-medium">{label}</span>
                                <div className="flex shrink-0 items-center gap-1.5">
                                  {chk.fixable && chk.fixAction && chk.status !== "pass" && (
                                    <Button
                                      variant="outline"
                                      size="xs"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        handleFix(chk.fixAction!);
                                      }}
                                    >
                                      <Wrench className="h-3 w-3" aria-hidden="true" />
                                      修复
                                    </Button>
                                  )}
                                  {chk.status === "pass" ? (
                                    <CheckCircle2
                                      className="h-4 w-4 text-[#16a34a]"
                                      aria-label="通过"
                                    />
                                  ) : chk.status === "warn" ? (
                                    <AlertTriangle
                                      className="h-4 w-4 text-[#d97706]"
                                      aria-label="注意"
                                    />
                                  ) : chk.status === "fail" ? (
                                    <XCircle
                                      className="h-4 w-4 text-[#dc2626]"
                                      aria-label="风险"
                                    />
                                  ) : (
                                    <span
                                      className="h-2.5 w-2.5 rounded-full bg-[#d1d5db]"
                                      aria-label="待检"
                                    />
                                  )}
                                </div>
                              </div>
                            </TooltipTrigger>
                            <TooltipContent side="top">
                              <div className="flex flex-col gap-0.5">
                                <div className="font-semibold text-white">{chk.title}</div>
                                <div className="text-[#e5e7eb]">{chk.summary}</div>
                                <div className="mono-num text-[0.67rem] text-[#a5b4fc]">
                                  {chk.detail}
                                </div>
                              </div>
                            </TooltipContent>
                          </Tooltip>
                        );
                      })}
                    </div>
                  </div>
                </section>
              </div>
            )}

            {/* ======================= VIEW 02: IP & FINGERPRINT ======================= */}
            {tab === "verify" && (
              <div className="bento-sheet flex flex-col divide-y divide-[#eaecef] rounded-2xl border border-[#eaecef] bg-white shadow-[0_1px_3px_rgba(15,23,42,0.03)]">
                <header className="flex flex-wrap items-center justify-between gap-3 px-6 py-4">
                  <div>
                    <h1
                      id="main-heading"
                      tabIndex={-1}
                      className="vt-page-title text-[1.2rem] font-semibold tracking-[-0.02em] text-[#111827] outline-none"
                    >
                      IP 与指纹体检
                    </h1>
                    <p className="mt-0.5 text-[0.76rem] text-[#7c8495]">
                      查看出口归属和浏览器信号
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={checking}
                      onClick={handleRunDiagnostics}
                    >
                      <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                      刷新
                    </Button>
                    <Button
                      variant="soft"
                      size="sm"
                      disabled={!gatewayReady || !status?.browserInstalled}
                      onClick={handleOpenAllAudits}
                    >
                      <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
                      打开全部检测页
                    </Button>
                  </div>
                </header>

                {/* 4-Column IP Telemetry Strip */}
                <section className="grid grid-cols-2 lg:grid-cols-4">
                  <div className="flex flex-col gap-1.5 border-b border-r border-[#eaecef] p-4 px-5 lg:border-b-0">
                    <div className="flex items-center gap-2 text-[0.76rem] font-medium text-[#525866]">
                      <span className="inline-grid h-5 w-5 place-items-center rounded-md bg-[#f0edfc] text-[#6d5bd0]">
                        <Globe className="h-3.5 w-3.5" aria-hidden="true" />
                      </span>
                      出口 IPv4
                    </div>
                    <div className="mono-num text-[1.15rem] font-semibold text-[#111827]">
                      {status?.exitIp?.ip || "--"}
                    </div>
                  </div>

                  <div className="flex flex-col gap-1.5 border-b border-[#eaecef] p-4 px-5 lg:border-b-0 lg:border-r">
                    <div className="flex items-center gap-2 text-[0.76rem] font-medium text-[#525866]">
                      <span className="inline-grid h-5 w-5 place-items-center rounded-md bg-[#eff6ff] text-[#2563eb]">
                        <Globe className="h-3.5 w-3.5" aria-hidden="true" />
                      </span>
                      出口属地
                    </div>
                    <div className="text-[1.1rem] font-semibold text-[#111827]">
                      {status?.exitIp ? countryLabel : "--"}
                    </div>
                  </div>

                  <div className="flex flex-col gap-1.5 border-r border-[#eaecef] p-4 px-5">
                    <div className="flex items-center gap-2 text-[0.76rem] font-medium text-[#525866]">
                      <span className="inline-grid h-5 w-5 place-items-center rounded-md bg-[#f0edfc] text-[#6d5bd0]">
                        <Activity className="h-3.5 w-3.5" aria-hidden="true" />
                      </span>
                      隧道延迟
                    </div>
                    <div className="flex items-center justify-between gap-2">
                      <span className="mono-num text-[1.15rem] font-semibold text-[#111827]">
                        {status?.exitIp?.latencyMs ? `${status.exitIp.latencyMs} ms` : "--"}
                      </span>
                      <LatencySparkline
                        samples={latencyHistory}
                        tone={status?.running ? "ok" : "idle"}
                      />
                    </div>
                  </div>

                  <div className="flex flex-col gap-1.5 p-4 px-5">
                    <div className="flex items-center gap-2 text-[0.76rem] font-medium text-[#525866]">
                      <span className="inline-grid h-5 w-5 place-items-center rounded-md bg-[#ecfdf3] text-[#16a34a]">
                        <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                      </span>
                      核验状态
                    </div>
                    <div>
                      {status?.blockedByKillSwitch ? (
                        <Badge variant="danger" className="text-[0.82rem] px-3 py-1">
                          已阻断
                        </Badge>
                      ) : status?.exitIp ? (
                        <Badge variant="success" className="text-[0.82rem] px-3 py-1">
                          已通过
                        </Badge>
                      ) : (
                        <Badge variant="neutral" className="text-[0.82rem] px-3 py-1">
                          待探测
                        </Badge>
                      )}
                    </div>
                  </div>
                </section>

                {/* Middle Split: Map & IP Spec Table */}
                <section className="grid grid-cols-1 divide-y divide-[#eaecef] lg:grid-cols-[minmax(0,1.42fr)_minmax(0,1fr)] lg:divide-x lg:divide-y-0">
                  <div className="p-5 px-6">
                    <ExitIpMap
                      exitIp={status?.exitIp}
                      activeNode={activeNode}
                      running={!!status?.running}
                      blockedByKillSwitch={!!status?.blockedByKillSwitch}
                    />
                  </div>

                  <div className="flex flex-col gap-3 p-5 px-6">
                    <h2 className="text-[0.84rem] font-semibold text-[#111827]">出口 IP 档案</h2>
                    <dl className="flex flex-col divide-y divide-[#f1f3f5] text-[0.78rem]">
                      <div className="flex items-center justify-between py-3">
                        <dt className="text-[#525866]">ASN</dt>
                        <dd className="mono-num font-medium text-[#111827]">
                          {status?.exitIp?.asn || "--"}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between py-3">
                        <dt className="text-[#525866]">运营商</dt>
                        <dd className="font-medium text-[#111827]">
                          {status?.exitIp?.isp || status?.exitIp?.org || "--"}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between py-3">
                        <dt className="text-[#525866]">IP 时区</dt>
                        <dd className="mono-num font-medium text-[#111827]">
                          {status?.exitIp?.timezone || "--"}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between py-3">
                        <dt className="text-[#525866]">出口核验</dt>
                        <dd>
                          {status?.exitIp ? (
                            <Badge variant="success">通过</Badge>
                          ) : (
                            <Badge variant="neutral">待核验</Badge>
                          )}
                        </dd>
                      </div>
                    </dl>
                  </div>
                </section>

                {/* Bottom Split: ip.net.coffee & fuck-claude */}
                <section className="grid grid-cols-1 divide-y divide-[#eaecef] lg:grid-cols-2 lg:divide-x lg:divide-y-0">
                  {/* Left: ip.net.coffee */}
                  <div className="flex flex-col gap-3.5 p-5 px-6">
                    <div className="flex items-center justify-between gap-2">
                      <h2 className="text-[0.84rem] font-semibold text-[#111827]">
                        IP 信誉检测
                      </h2>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={!gatewayReady || !status?.browserInstalled}
                        onClick={() => handleOpenInSafeBrowser("https://ip.net.coffee/")}
                      >
                        <ExternalLink className="h-3.5 w-3.5 text-[#7c8495]" aria-hidden="true" />
                        在安全浏览器中打开
                      </Button>
                    </div>

                    <div className="flex items-center gap-2 rounded-lg border border-[#ebe7fc] bg-[#f7f5fe] px-3 py-2 text-[0.78rem] font-medium text-[#111827] mono-num">
                      <Globe className="h-4 w-4 text-[#6d5bd0]" aria-hidden="true" />
                      ip.net.coffee
                    </div>

                    <dl className="flex flex-col divide-y divide-[#f1f3f5] text-[0.78rem]">
                      <div className="flex items-center justify-between py-2.5">
                        <dt className="text-[#525866]">属地 / ASN</dt>
                        <dd className="mono-num font-medium text-[#111827]">
                          {status?.exitIp
                            ? `${countryLabel} / ${status.exitIp.asn || "--"}`
                            : "--"}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between py-2.5">
                        <dt className="text-[#525866]">运营商 / 组织</dt>
                        <dd className="font-medium text-[#111827]">
                          {status?.exitIp?.isp || status?.exitIp?.org || "--"}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between py-2.5">
                        <dt className="text-[#525866]">WebRTC / DNS</dt>
                        <dd className="font-medium text-[#15803d]">
                          {status?.running ? "回环隔离 · 无直连泄漏" : "待机"}
                        </dd>
                      </div>
                    </dl>
                  </div>

                  {/* Right: fuck-claude */}
                  <div className="flex flex-col gap-3.5 p-5 px-6">
                    <div className="flex items-center justify-between gap-2">
                      <h2 className="text-[0.84rem] font-semibold text-[#111827]">
                        浏览器指纹检测
                      </h2>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={!gatewayReady || !status?.browserInstalled}
                        onClick={() => handleOpenInSafeBrowser("https://fuck-claude.vercel.app/")}
                      >
                        <ExternalLink className="h-3.5 w-3.5 text-[#7c8495]" aria-hidden="true" />
                        在安全浏览器中打开
                      </Button>
                    </div>

                    <div className="flex items-center gap-2 rounded-lg border border-[#eaecef] bg-[#f8f9fb] px-3 py-2 text-[0.78rem] font-medium text-[#111827] mono-num">
                      <Fingerprint className="h-4 w-4 text-[#6d5bd0]" aria-hidden="true" />
                      fuck-claude.vercel.app
                    </div>

                    <dl className="flex flex-col divide-y divide-[#f1f3f5] text-[0.78rem]">
                      <div className="flex items-center justify-between py-2.5">
                        <dt className="text-[#525866]">JS 时区</dt>
                        <dd className="mono-num font-medium text-[#111827]">
                          {config?.alignFingerprint ? activeNode?.timezone || "Asia/Seoul" : "未对齐"}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between py-2.5">
                        <dt className="text-[#525866]">浏览器语言</dt>
                        <dd className="mono-num font-medium text-[#111827]">
                          {config?.alignFingerprint ? activeNode?.locale || "ko-KR" : "未对齐"}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between py-2.5">
                        <dt className="text-[#525866]">WebRTC / QUIC</dt>
                        <dd className="font-medium text-[#111827]">
                          限制直连 · QUIC Off
                        </dd>
                      </div>
                    </dl>
                  </div>
                </section>
              </div>
            )}

            {/* ======================= VIEW 01A: FINGERPRINT BROWSERS ======================= */}
            {tab === "browsers" && config && (
              <BrowserProfilesView
                config={config}
                status={status}
                gatewayReady={gatewayReady}
                preselectedNodeRequest={preselectedBrowserNode}
                onSaveProfiles={handleSaveBrowserProfiles}
                onLaunchProfile={handleLaunchBrowserProfile}
                onCloseProfile={handleCloseBrowserProfile}
                onProbeNodeExit={(nodeId) => api.probeNodeExit(nodeId)}
                onInstallBrowser={handleInstallBrowser}
                onRestartGateway={handleRestartGateway}
                onNotify={notify}
              />
            )}

            {/* ======================= VIEW 01B: AI APPS & LAUNCH ENV ======================= */}
            {tab === "apps" && config && (
              <AppsEnvView
                config={config}
                snapshot={appEnv}
                scanning={scanningApps}
                gatewayRunning={Boolean(status?.running && !status?.blockedByKillSwitch)}
                dirty={dirty}
                onConfigChange={(next) => {
                  setConfig(next);
                  setDirty(true);
                }}
                onSave={async () => {
                  await handleSaveConfig();
                  await refreshAppEnv();
                }}
                onRescan={refreshAppEnv}
                onLaunchApp={handleLaunchManagedApp}
                onCleanRegistryEnv={handleCleanRegistryEnv}
                onCreateShortcut={handleCreateAppShortcut}
              />
            )}

            {/* ======================= VIEW 01C: ACCOUNTS & ENVIRONMENTS ======================= */}
            {tab === "accounts" && (
              <AccountsView
                accounts={accounts}
                nodes={config?.nodes ?? []}
                envPresets={envPresets}
                clashNodes={clashNodes}
                loading={loadingAccounts}
                loadingClashNodes={loadingClashNodes}
                onUpsert={handleUpsertAccount}
                onDelete={handleDeleteAccount}
                onBulkDelete={handleBulkDeleteAccounts}
                onImport={handleImportAccounts}
                onSaveEnvPresets={handleSaveEnvPresets}
                onRefreshClashNodes={refreshClashNodes}
                onReorder={handleReorderAccounts}
                onNotify={notify}
              />
            )}

            {/* ======================= VIEW 03: EGRESS & ROUTING ======================= */}
            {tab === "nodes" && config && (
              <NodeEditor
                config={config}
                dirty={dirty}
                secondaryNodePorts={status?.secondaryNodePorts}
                onUpdateConfig={(next) => {
                  setConfig(next);
                  setDirty(true);
                }}
                onSave={() => handleSaveConfig()}
                onNotify={notify}
                onQuickLaunchNodeBrowser={handleQuickLaunchNodeBrowser}
              />
            )}

            {/* ======================= VIEW 04: ISOLATION & HARDENING ======================= */}
            {tab === "hardening" && config && (
              <div className="bento-sheet flex flex-col divide-y divide-[#eaecef] rounded-2xl border border-[#eaecef] bg-white shadow-[0_1px_3px_rgba(15,23,42,0.03)]">
                <header className="flex flex-wrap items-center justify-between gap-3 px-6 py-4">
                  <div>
                    <h1
                      id="main-heading"
                      tabIndex={-1}
                      className="vt-page-title text-[1.2rem] font-semibold tracking-[-0.02em] text-[#111827] outline-none"
                    >
                      隔离与规则加固
                    </h1>
                    <p className="mt-0.5 text-[0.76rem] text-[#7c8495]">
                      配置本地防火墙、启动行为和分流规则
                    </p>
                  </div>
                  <Button
                    variant={dirty ? "solid" : "soft"}
                    size="sm"
                    disabled={!dirty}
                    onClick={() => handleSaveConfig()}
                  >
                    保存配置
                  </Button>
                </header>

                {/* Firewall & Isolation */}
                <section className="flex flex-col gap-3 p-5 px-6">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <h2 className="text-[0.84rem] font-semibold text-[#111827]">
                      防火墙与隔离
                    </h2>
                    {status?.wfpActive && (
                      <Badge variant="success">
                        ✓ {totalRulesCount} 条规则生效中
                      </Badge>
                    )}
                  </div>

                  <div className="flex flex-col divide-y divide-[#f1f3f5]">
                    <div className="grid grid-cols-1 items-center gap-2 py-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
                      <div className="flex items-center gap-2.5">
                        <span className="inline-grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-[#f0edfc] text-[#6d5bd0]">
                          <Shield className="h-4 w-4" aria-hidden="true" />
                        </span>
                        <label
                          htmlFor={fid("wfpLockEnabled")}
                          className="font-medium text-[#111827] cursor-pointer"
                        >
                          Windows WFP 内核锁
                        </label>
                      </div>
                      <span className="text-[0.74rem] text-[#7c8495]">
                        限制应用旁路直连（IPv6 / WebRTC / DNS）
                      </span>
                      <div className="justify-self-end">
                        <Switch
                          id={fid("wfpLockEnabled")}
                          checked={config.wfpLockEnabled}
                          onCheckedChange={(checked) => {
                            setConfig({ ...config, wfpLockEnabled: checked });
                            setDirty(true);
                          }}
                        />
                      </div>
                    </div>

                    <div className="grid grid-cols-1 items-center gap-2 py-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
                      <div className="flex items-center gap-2.5">
                        <span className="inline-grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-[#fff1ec] text-[#d97757]">
                          <ClaudeStarburst size={16} />
                        </span>
                        <span className="font-medium text-[#111827]">
                          Claude Desktop 离线锁
                        </span>
                      </div>
                      <span className="text-[0.74rem] text-[#7c8495]">
                        网关关闭时限制联网（防后台自动更新裸奔）
                      </span>
                      <div className="flex items-center gap-2 justify-self-end">
                        {status?.persistentClaudeLockActive && (
                          <Badge variant="success">✓ 已启用</Badge>
                        )}
                        <Button
                          variant={status?.persistentClaudeLockActive ? "outline" : "soft"}
                          size="xs"
                          onClick={async () => {
                            try {
                              const nextEnable = !config.requireNetguardForClaude;
                              const st = await api.togglePersistentClaudeLock(nextEnable);
                              setStatus(st);
                              setConfig({ ...config, requireNetguardForClaude: nextEnable });
                              notify(
                                nextEnable
                                  ? "已写入持久化硬锁：未开 NetGuard 时禁止 Claude Desktop 联网"
                                  : "已移除持久化硬锁",
                              );
                            } catch (err) {
                              notify(`切换离线硬锁失败: ${String(err)}`);
                            }
                          }}
                        >
                          {config.requireNetguardForClaude ? "移除" : "开启"}
                        </Button>
                      </div>
                    </div>
                  </div>
                </section>

                {/* Launch Behavior + Ports & Client Paths */}
                <section className="grid grid-cols-1 divide-y divide-[#eaecef] lg:grid-cols-2 lg:divide-x lg:divide-y-0">
                  <div className="flex flex-col gap-3 p-5 px-6">
                    <h2 className="text-[0.84rem] font-semibold text-[#111827]">
                      启动与浏览器
                    </h2>
                    <div className="flex flex-col divide-y divide-[#f1f3f5]">
                      <div className="flex items-center justify-between gap-4 py-2.5">
                        <div>
                          <label
                            htmlFor={fid("autoStartGateway")}
                            className="text-[0.79rem] font-medium text-[#111827] cursor-pointer"
                          >
                            自动启动安全网关
                          </label>
                          <div className="text-[0.69rem] text-[#7c8495]">
                            启动软件时拉起隧道与 WFP（需 UAC 提权）
                          </div>
                        </div>
                        <Switch
                          id={fid("autoStartGateway")}
                          checked={config.autoStartGateway}
                          onCheckedChange={(checked) => {
                            setConfig({ ...config, autoStartGateway: checked });
                            setDirty(true);
                          }}
                        />
                      </div>

                      <div className="flex items-center justify-between gap-4 py-2.5">
                        <label
                          htmlFor={fid("autoLaunchBrowser")}
                          className="text-[0.79rem] font-medium text-[#111827] cursor-pointer"
                        >
                          网关就绪后打开浏览器
                        </label>
                        <Switch
                          id={fid("autoLaunchBrowser")}
                          checked={config.autoLaunchBrowser}
                          onCheckedChange={(checked) => {
                            setConfig({ ...config, autoLaunchBrowser: checked });
                            setDirty(true);
                          }}
                        />
                      </div>

                      <div className="flex items-center justify-between gap-4 py-2.5">
                        <label
                          htmlFor={fid("autoLaunchDesktop")}
                          className="text-[0.79rem] font-medium text-[#111827] cursor-pointer"
                        >
                          网关就绪后启动 Claude Desktop
                        </label>
                        <Switch
                          id={fid("autoLaunchDesktop")}
                          checked={config.autoLaunchClaudeDesktop}
                          onCheckedChange={(checked) => {
                            setConfig({ ...config, autoLaunchClaudeDesktop: checked });
                            setDirty(true);
                          }}
                        />
                      </div>

                      <div className="flex items-center justify-between gap-4 py-2.5">
                        <div>
                          <label
                            htmlFor={fid("alignFingerprint")}
                            className="text-[0.79rem] font-medium text-[#111827] cursor-pointer"
                          >
                            浏览器时区与语言对齐
                          </label>
                          <div className="mono-num text-[0.69rem] text-[#7c8495]">
                            {activeNode?.timezone || "Asia/Seoul"} · {activeNode?.locale || "ko-KR"}
                          </div>
                        </div>
                        <Switch
                          id={fid("alignFingerprint")}
                          checked={config.alignFingerprint}
                          onCheckedChange={(checked) => {
                            setConfig({ ...config, alignFingerprint: checked });
                            setDirty(true);
                          }}
                        />
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-col gap-3 p-5 px-6">
                    <h2 className="text-[0.84rem] font-semibold text-[#111827]">
                      端口与客户端路径
                    </h2>
                    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                      <div className="flex flex-col gap-1">
                        <label htmlFor={fid("cliPort")} className="text-[0.71rem] text-[#7c8495]">
                          CLI 代理端口
                        </label>
                        <Input
                          id={fid("cliPort")}
                          type="number"
                          className="mono-num"
                          value={config.cliPort}
                          onChange={(e) => {
                            setConfig({ ...config, cliPort: Number(e.target.value) || 17890 });
                            setDirty(true);
                          }}
                        />
                      </div>
                      <div className="flex flex-col gap-1">
                        <label htmlFor={fid("browserPort")} className="text-[0.71rem] text-[#7c8495]">
                          浏览器代理端口
                        </label>
                        <Input
                          id={fid("browserPort")}
                          type="number"
                          className="mono-num"
                          value={config.browserPort}
                          onChange={(e) => {
                            setConfig({
                              ...config,
                              browserPort: Number(e.target.value) || 17891,
                            });
                            setDirty(true);
                          }}
                        />
                      </div>
                      <div className="flex flex-col gap-1 sm:col-span-2">
                        <label htmlFor={fid("customBrowserPath")} className="text-[0.71rem] text-[#7c8495]">
                          便携浏览器路径
                        </label>
                        <Input
                          id={fid("customBrowserPath")}
                          className="mono-num"
                          placeholder="使用内置浏览器"
                          value={config.customBrowserPath || ""}
                          onChange={(e) => {
                            setConfig({ ...config, customBrowserPath: e.target.value });
                            setDirty(true);
                          }}
                        />
                      </div>
                      <div className="flex flex-col gap-1 sm:col-span-2">
                        <label htmlFor={fid("claudeDesktopPath")} className="text-[0.71rem] text-[#7c8495]">
                          Claude Desktop 路径
                        </label>
                        <Input
                          id={fid("claudeDesktopPath")}
                          className="mono-num"
                          placeholder="自动探测"
                          value={config.claudeDesktopPath || ""}
                          onChange={(e) => {
                            setConfig({ ...config, claudeDesktopPath: e.target.value });
                            setDirty(true);
                          }}
                        />
                      </div>
                    </div>
                  </div>
                </section>

                {/* Routing Domains & NO_PROXY */}
                <section className="flex flex-col gap-3 p-5 px-6">
                  <h2 className="text-[0.84rem] font-semibold text-[#111827]">分流规则</h2>
                  <div className="flex flex-wrap items-center gap-4">
                    <label
                      htmlFor={fid("extraNoProxy")}
                      className="w-28 shrink-0 text-[0.76rem] text-[#525866]"
                    >
                      额外 NO_PROXY
                    </label>
                    <Input
                      id={fid("extraNoProxy")}
                      className="mono-num flex-1 min-w-[14rem]"
                      value={config.extraNoProxy}
                      onChange={(e) => {
                        setConfig({ ...config, extraNoProxy: e.target.value });
                        setDirty(true);
                      }}
                    />
                  </div>

                  <Collapsible open={domainsOpen} onOpenChange={setDomainsOpen}>
                    <CollapsibleTrigger asChild>
                      <button
                        type="button"
                        className="flex w-full items-center justify-between rounded-xl border border-[#eaecef] bg-[#f8f9fb] px-4 py-2.5 text-left text-[0.79rem] font-medium text-[#111827] hover:bg-[#f3f4f6] transition-colors cursor-pointer"
                      >
                        <span className="flex items-center gap-2">
                          受保护 AI 域名
                          <Badge variant="neutral" className="mono-num">
                            {config.aiDomains.length} 项
                          </Badge>
                        </span>
                        <ChevronDown
                          className={cn(
                            "h-4 w-4 text-[#7c8495] transition-transform duration-150",
                            domainsOpen && "rotate-180",
                          )}
                          aria-hidden="true"
                        />
                      </button>
                    </CollapsibleTrigger>
                    <CollapsibleContent className="pt-2.5">
                      <label htmlFor={fid("aiDomains")} className="visually-hidden">
                        受保护 AI 域名后缀（每行一个）
                      </label>
                      <textarea
                        id={fid("aiDomains")}
                        rows={7}
                        className="mono-num w-full rounded-xl border border-[#dce0e6] bg-white p-3 text-[0.75rem] text-[#111827] focus-visible:outline-2 focus-visible:outline-[#5b48c4]"
                        value={config.aiDomains.join("\n")}
                        onChange={(e) => {
                          setConfig({
                            ...config,
                            aiDomains: e.target.value
                              .split(/\r?\n/)
                              .map((s) => s.trim())
                              .filter(Boolean),
                          });
                          setDirty(true);
                        }}
                      />
                    </CollapsibleContent>
                  </Collapsible>
                </section>
              </div>
            )}

            {/* ======================= VIEW 05: RUNTIME LOGS ======================= */}
            {tab === "logs" && (
              <div className="bento-sheet flex flex-col gap-4 rounded-2xl border border-[#eaecef] bg-white p-6 shadow-[0_1px_3px_rgba(15,23,42,0.03)]">
                <header className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h1
                      id="main-heading"
                      tabIndex={-1}
                      className="vt-page-title text-[1.2rem] font-semibold tracking-[-0.02em] text-[#111827] outline-none"
                    >
                      内核运行日志
                    </h1>
                    <p className="mt-0.5 text-[0.76rem] text-[#7c8495]">
                      查看网关、出口核验和防护事件
                    </p>
                  </div>
                  <Badge variant={status?.running ? "success" : "neutral"} className="px-2.5 py-1">
                    <span
                      className={cn(
                        "h-1.5 w-1.5 rounded-full",
                        status?.running ? "bg-[#16a34a]" : "bg-[#9ca3af]",
                      )}
                      aria-hidden="true"
                    />
                    {status?.running ? "实时接收" : "待机"}
                  </Badge>
                </header>

                {/* Structured Log Table Shell (ui-guide/05 + Vitaly table) */}
                <div className="flex flex-col overflow-hidden rounded-xl border border-[#eaecef]">
                  {/* Table Toolbar */}
                  <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#eaecef] bg-white px-4 py-3">
                    <div className="flex items-center gap-2 text-[0.8rem] font-medium text-[#111827] mono-num">
                      <span className="inline-grid h-6 w-6 place-items-center rounded-md bg-[#f0edfc] text-[#6d5bd0]">
                        <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                      </span>
                      sing-box · netguard-guard
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <div className="relative">
                        <Search
                          className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[#9ca3af]"
                          aria-hidden="true"
                        />
                        <label htmlFor={fid("logFilter")} className="visually-hidden">
                          过滤日志
                        </label>
                        <Input
                          id={fid("logFilter")}
                          className="w-52 pl-8"
                          placeholder="过滤日志"
                          value={logFilter}
                          onChange={(e) => setLogFilter(e.target.value)}
                        />
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={filteredLogs.length === 0}
                        onClick={async () => {
                          try {
                            await navigator.clipboard.writeText(filteredLogs.join("\n"));
                            notify("日志已复制");
                          } catch (err) {
                            notify(`复制日志失败: ${String(err)}`);
                          }
                        }}
                      >
                        <Copy className="h-3.5 w-3.5 text-[#7c8495]" aria-hidden="true" />
                        复制
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => api.clearLogs().then(() => api.getStatus().then(setStatus))}
                      >
                        <Trash2 className="h-3.5 w-3.5 text-[#7c8495]" aria-hidden="true" />
                        清空日志
                      </Button>
                    </div>
                  </div>

                  {/* Scrollable Log Table */}
                  <div className="app-scroll max-h-[29rem] min-h-[20rem] overflow-y-auto bg-white">
                    <table className="w-full border-collapse text-left text-[0.78rem]">
                      <thead className="sticky top-0 z-10 border-b border-[#eaecef] bg-[#f9fafb] text-[0.71rem] font-medium text-[#7c8495]">
                        <tr>
                          <th scope="col" className="w-16 px-4 py-2.5 font-medium">序号</th>
                          <th scope="col" className="w-24 px-4 py-2.5 font-medium">时间</th>
                          <th scope="col" className="w-28 px-4 py-2.5 font-medium">来源</th>
                          <th scope="col" className="px-4 py-2.5 font-medium">日志</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#f1f3f5]">
                        {parsedLogs.length > 0 ? (
                          parsedLogs.map((row) => (
                            <tr key={row.index} className="hover:bg-[#f9fafb] transition-colors">
                              <td className="mono-num px-4 py-2.5 text-[#7c8495]">{row.index}</td>
                              <td className="mono-num px-4 py-2.5 text-[#525866]">{row.time}</td>
                              <td className="px-4 py-2.5">
                                <Badge variant={row.variant} className="mono-num">
                                  {row.source}
                                </Badge>
                              </td>
                              <td className="px-4 py-2.5 text-[#111827] break-words">
                                {row.message}
                              </td>
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td colSpan={4} className="px-4 py-12 text-center text-[#7c8495]">
                              暂无匹配日志输出
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>

                  {/* Table Footer */}
                  <div className="border-t border-[#eaecef] bg-[#fafbfc] px-4 py-2.5 text-[0.72rem] text-[#7c8495] tabular">
                    共 {parsedLogs.length} 条日志
                  </div>
                </div>
              </div>
            )}
          </div>
        </main>

        {/* Top-Layer Manual Popover Toast Notification */}
        <div role="region" aria-label="系统通知" className="pointer-events-none">
          <div
            id={toastId}
            ref={toastRef}
            {...({ popover: "manual" } as Record<string, string>)}
            role="status"
            className={cn(
              "toast-popover items-center gap-2.5 rounded-xl border border-[#27272a] bg-[#111827] py-2 pl-3.5 pr-2 text-[0.76rem] font-medium text-[#f9fafb] shadow-[0_12px_28px_-6px_rgba(0,0,0,0.4)] max-w-[min(26rem,calc(100vi-2.5rem))]",
              toast ? "is-open" : "",
            )}
            onMouseEnter={() => setToastPaused(true)}
            onMouseLeave={() => setToastPaused(false)}
            onFocus={() => setToastPaused(true)}
            onBlur={() => setToastPaused(false)}
          >
            <span>{toast}</span>
            {toast && (
              <button
                type="button"
                className="inline-grid h-6 w-6 shrink-0 place-items-center rounded-md bg-white/10 text-white hover:bg-white/20 cursor-pointer"
                aria-label="关闭通知"
                {...({ popovertarget: toastId, popovertargetaction: "hide" } as Record<string, string>)}
                onClick={dismissToast}
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            )}
          </div>
        </div>
      </div>
    </TooltipProvider>
  );
}
