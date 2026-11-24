import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronUp,
  Copy,
  Download,
  Eye,
  EyeOff,
  FileUp,
  Globe,
  GripVertical,
  KeyRound,
  Layers,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Sparkles,
  Square,
  Trash2,
  X,
} from "lucide-react";
import type {
  AccountBrowserKind,
  AccountEnvPreset,
  AccountEnvType,
  AccountNodeSource,
  AccountQuotaConfig,
  AccountQuotaPool,
  AccountRecord,
  AccountStatus,
  ActiveAccountSession,
  AdsPowerConfigStatus,
  AdsPowerProfilesSnapshot,
  BrowserProfile,
  ClashVergeListenerItem,
  ClashVergeNodesSnapshot,
  NodeProfile,
} from "../types";
import { generateStrongPassword, generateTotp } from "../lib/totp";
import {
  createAntigravityQuotaPreset,
  createClaudeQuotaPreset,
  createSingleQuotaPreset,
  evaluateAccountQuota,
  isoToLocalDatetimeInput,
  localDatetimeInputToIso,
  type EvaluatedAccountQuota,
} from "../lib/quota";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./ui/select";

interface AccountsViewProps {
  accounts: AccountRecord[];
  nodes: NodeProfile[];
  envPresets: AccountEnvPreset[];
  clashNodes: ClashVergeNodesSnapshot | null;
  browserProfiles: BrowserProfile[];
  activeSession: ActiveAccountSession | null;
  runningBrowserProfiles: string[];
  runningAdspowerProfiles: string[];
  secondaryNodePorts: Record<string, number>;
  gatewayRunning: boolean;
  gatewayBrowserPort: number;
  gatewayActiveNodeId: string;
  adspowerConfig: AdsPowerConfigStatus | null;
  adspowerProfiles: AdsPowerProfilesSnapshot | null;
  loading: boolean;
  loadingClashNodes: boolean;
  loadingAdsPower: boolean;
  onUpsert: (account: AccountRecord) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
  onBulkDelete: (ids: string[]) => Promise<void>;
  onImport: (records: AccountRecord[], replace: boolean) => Promise<void>;
  onSaveEnvPresets: (presets: AccountEnvPreset[]) => Promise<void>;
  onRefreshClashNodes: () => Promise<void>;
  onReorder: (orderedIds: string[]) => Promise<void>;
  onLaunchBrowser: (accountId: string) => Promise<void>;
  onCloseBrowserProfile: (profileId: string) => Promise<void>;
  onCloseAdsPowerProfile: (
    userId?: string | null,
    serialNumber?: string | null,
  ) => Promise<void>;
  onClearActiveSession: (closeBrowser?: boolean) => Promise<void>;
  onSaveAdsPowerConfig: (
    baseUrl: string,
    apiKey: string | null,
    clearApiKey?: boolean,
  ) => Promise<AdsPowerConfigStatus>;
  onTestAdsPowerConnection: () => Promise<string>;
  onRefreshAdsPowerProfiles: () => Promise<AdsPowerProfilesSnapshot | null>;
  onNotify: (msg: string) => void;
}

type StatusFilter = "all" | AccountStatus;

interface AccountFormState {
  id: string;
  label: string;
  provider: string;
  email: string;
  password: string;
  totpSecret: string;
  recoveryCodes: string;
  recoveryEmail: string;
  envType: AccountEnvType;
  environmentName: string;
  environmentProfile: string;
  browserKind: AccountBrowserKind;
  adspowerUserId: string;
  adspowerSerialNumber: string;
  adspowerProfileName: string;
  quotaEnabled: boolean;
  quotaPlanTier: string;
  quotaExpiresAt: string;
  quotaPools: AccountQuotaPool[];
  linkedNodeSource: AccountNodeSource;
  linkedNodeId: string;
  linkedNodeName: string;
  linkedBrowserProfileId: string;
  linkedProxyPort: string;
  purpose: string;
  tagsText: string;
  status: AccountStatus;
  notes: string;
  createdAt: string;
}

type ConfirmTarget =
  | { kind: "single"; account: AccountRecord }
  | { kind: "banned"; ids: string[] };

const STATUS_META: Record<
  AccountStatus,
  { label: string; variant: "success" | "neutral" | "warning" | "danger" }
> = {
  active: { label: "正常", variant: "success" },
  standby: { label: "备用", variant: "neutral" },
  restricted: { label: "受限", variant: "warning" },
  banned: { label: "已封禁", variant: "danger" },
};

const ENV_TYPE_META: Record<
  AccountEnvType,
  { label: string; short: string; badgeVariant: "iris" | "neutral" | "obsidian" }
> = {
  fingerprint: { label: "指纹浏览器", short: "指纹", badgeVariant: "iris" },
  local: { label: "本地", short: "本地", badgeVariant: "neutral" },
  custom: { label: "自定义", short: "自定义", badgeVariant: "obsidian" },
};

const NODE_SOURCE_OPTIONS: { value: AccountNodeSource; label: string }[] = [
  { value: "none", label: "不绑定" },
  { value: "netguard", label: "AI NetGuard" },
  { value: "clash_verge", label: "Clash Verge" },
  { value: "custom", label: "自定义 / 直连" },
];

const PROVIDER_PRESETS = ["Google", "Claude", "OpenAI", "GitHub"];

const NATIVE_SELECT_CLASS =
  "flex min-h-8 w-full rounded-lg border border-[#dce0e6] bg-white px-2.5 py-1.5 text-[0.765rem] text-[#111827] shadow-[0_1px_1px_rgba(15,23,42,0.02)] transition-colors hover:border-[#c3cad6] focus-visible:outline-2 focus-visible:outline-[#5b48c4] focus-visible:outline-offset-1 cursor-pointer";

const TEXTAREA_CLASS =
  "flex w-full rounded-lg border border-[#dce0e6] bg-white px-2.5 py-1.5 text-[0.765rem] text-[#111827] shadow-[0_1px_1px_rgba(15,23,42,0.02)] placeholder:text-[#9ca3af] transition-colors hover:border-[#c3cad6] focus-visible:outline-2 focus-visible:outline-[#5b48c4] focus-visible:outline-offset-1";

export function normalizeEnvType(raw?: string | null): AccountEnvType {
  switch (raw) {
    case "fingerprint":
    case "adspower":
    case "fingerprint_other":
      return "fingerprint";
    case "local":
    case "claude_code":
    case "netguard_browser":
      return "local";
    default:
      return "custom";
  }
}

export function normalizeNodeSource(
  raw?: string | null,
  linkedNodeId?: string | null,
): AccountNodeSource {
  if (
    raw === "none" ||
    raw === "netguard" ||
    raw === "clash_verge" ||
    raw === "custom"
  ) {
    return raw;
  }
  if (linkedNodeId && linkedNodeId.trim()) {
    return "netguard";
  }
  return "none";
}

function emptyFormState(): AccountFormState {
  return {
    id: "",
    label: "",
    provider: "Google",
    email: "",
    password: "",
    totpSecret: "",
    recoveryCodes: "",
    recoveryEmail: "",
    envType: "fingerprint",
    environmentName: "",
    environmentProfile: "",
    browserKind: "netguard",
    adspowerUserId: "",
    adspowerSerialNumber: "",
    adspowerProfileName: "",
    quotaEnabled: false,
    quotaPlanTier: "PRO",
    quotaExpiresAt: "",
    quotaPools: createAntigravityQuotaPreset().pools,
    linkedNodeSource: "none",
    linkedNodeId: "",
    linkedNodeName: "",
    linkedBrowserProfileId: "",
    linkedProxyPort: "",
    purpose: "",
    tagsText: "",
    status: "active",
    notes: "",
    createdAt: "",
  };
}

function recordToFormState(acc: AccountRecord): AccountFormState {
  const source = normalizeNodeSource(acc.linkedNodeSource, acc.linkedNodeId);
  const browserKind: AccountBrowserKind =
    acc.browserKind === "none"
      ? "none"
      : acc.browserKind === "adspower"
        ? "adspower"
        : "netguard";
  const quotaPools =
    acc.quota?.pools && acc.quota.pools.length > 0
      ? acc.quota.pools.map((p) => ({ ...p }))
      : createAntigravityQuotaPreset().pools;
  return {
    id: acc.id,
    label: acc.label || "",
    provider: acc.provider || "Google",
    email: acc.email || "",
    password: acc.password || "",
    totpSecret: acc.totpSecret || "",
    recoveryCodes: acc.recoveryCodes || "",
    recoveryEmail: acc.recoveryEmail || "",
    envType: normalizeEnvType(acc.envType),
    environmentName: acc.environmentName || "",
    environmentProfile: acc.environmentProfile || "",
    browserKind,
    adspowerUserId: acc.adspowerUserId || "",
    adspowerSerialNumber: acc.adspowerSerialNumber || "",
    adspowerProfileName: acc.adspowerProfileName || "",
    quotaEnabled: Boolean(acc.quota?.enabled),
    quotaPlanTier: acc.quota?.planTier || "PRO",
    quotaExpiresAt: acc.quota?.expiresAt || "",
    quotaPools,
    linkedNodeSource: source,
    linkedNodeId: acc.linkedNodeId || "",
    linkedNodeName: acc.linkedNodeName || "",
    linkedBrowserProfileId: acc.linkedBrowserProfileId || "",
    linkedProxyPort: acc.linkedProxyPort ? String(acc.linkedProxyPort) : "",
    purpose: acc.purpose || "",
    tagsText: (acc.tags || []).join(", "),
    status: acc.status || "active",
    notes: acc.notes || "",
    createdAt: acc.createdAt || "",
  };
}

function providerAvatar(provider: string): { code: string; classes: string } {
  const norm = provider.trim().toLowerCase();
  if (norm.includes("google") || norm.includes("gmail")) {
    return { code: "G", classes: "bg-[#eff6ff] text-[#2563eb] border-[#dbeafe]" };
  }
  if (norm.includes("claude") || norm.includes("anthropic")) {
    return { code: "C", classes: "bg-[#fef2ed] text-[#d97757] border-[#fed7aa]" };
  }
  if (norm.includes("openai") || norm.includes("chatgpt")) {
    return { code: "O", classes: "bg-[#ecfdf5] text-[#059669] border-[#a7f3d0]" };
  }
  if (norm.includes("github")) {
    return { code: "GH", classes: "bg-[#f3f4f6] text-[#111827] border-[#d1d5db]" };
  }
  const letters = provider.trim().slice(0, 2).toUpperCase() || "AC";
  return { code: letters, classes: "bg-[#f0edfc] text-[#5b48c4] border-[#dcd4fb]" };
}

function resolveAccountNodeDisplay(
  acc: AccountRecord,
  nodeById: Map<string, NodeProfile>,
  browserProfileById?: Map<string, BrowserProfile>,
): {
  source: AccountNodeSource;
  sourceLabel: string;
  name: string;
  badgeText: string;
  variant: "iris" | "warning" | "neutral";
} | null {
  const source = normalizeNodeSource(acc.linkedNodeSource, acc.linkedNodeId);
  if (source === "none") {
    const pid = acc.linkedBrowserProfileId?.trim();
    const bp =
      acc.browserKind !== "adspower" && pid && browserProfileById
        ? browserProfileById.get(pid)
        : undefined;
    if (!bp) return null;
    if (bp.customProxyUrl?.trim()) {
      const hostPort = bp.customProxyUrl.trim().replace(/^[a-zA-Z0-9+.-]+:\/\//, "");
      return {
        source: "netguard",
        sourceLabel: "指纹环境",
        name: bp.name,
        badgeText: `继承环境 · ${hostPort}`,
        variant: "iris",
      };
    }
    const targetNode = bp.nodeId ? nodeById.get(bp.nodeId) : undefined;
    const nodeName = targetNode?.name || (bp.nodeId ? bp.nodeId : "主安全出口");
    return {
      source: "netguard",
      sourceLabel: "指纹环境",
      name: bp.name,
      badgeText: `继承环境 · ${nodeName}`,
      variant: "iris",
    };
  }

  if (source === "netguard") {
    const node = acc.linkedNodeId ? nodeById.get(acc.linkedNodeId) : undefined;
    const rawName = node
      ? `${node.name}${node.expectedCountry ? ` (${node.expectedCountry})` : ""}`
      : acc.linkedNodeName?.trim() || acc.linkedNodeId?.trim() || "";
    if (!rawName) return null;
    const missingSuffix = !node && acc.linkedNodeId ? " (未在列表)" : "";
    return {
      source,
      sourceLabel: "AI NetGuard",
      name: rawName,
      badgeText: `NetGuard · ${rawName}${missingSuffix}`,
      variant: "iris",
    };
  }

  const name = acc.linkedNodeName?.trim() || "";
  if (!name) return null;

  if (source === "clash_verge") {
    return {
      source,
      sourceLabel: "Clash Verge",
      name,
      badgeText: `Clash · ${name}`,
      variant: "warning",
    };
  }

  return {
    source,
    sourceLabel: "自定义 / 直连",
    name,
    badgeText: `节点 · ${name}`,
    variant: "neutral",
  };
}

function findMatchingClashListener(
  nodeName: string,
  listeners?: ClashVergeListenerItem[],
): ClashVergeListenerItem | undefined {
  const trimmed = nodeName.trim();
  if (!trimmed || !listeners || listeners.length === 0) return undefined;
  const exact = listeners.find(
    (l) => l.proxy.trim() === trimmed || l.name.trim() === trimmed,
  );
  if (exact) return exact;
  const norm = (s: string) => s.toLowerCase().replace(/\s+/g, " ").trim();
  const target = norm(trimmed);
  if (!target) return undefined;
  return listeners.find((l) => {
    const p = norm(l.proxy);
    return p === target || (p.length >= 2 && (target.includes(p) || p.includes(target)));
  });
}

function resolveAccountPreviewPort(
  acc: AccountRecord,
  nodeById: Map<string, NodeProfile>,
  clashNodes: ClashVergeNodesSnapshot | null,
  gatewayRunning: boolean,
  gatewayActiveNodeId: string,
  gatewayBrowserPort: number,
  secondaryNodePorts: Record<string, number>,
  browserProfileById?: Map<string, BrowserProfile>,
): { port: number | null; reason?: string } {
  const source = normalizeNodeSource(acc.linkedNodeSource, acc.linkedNodeId);
  if (source === "none") {
    const pid = acc.linkedBrowserProfileId?.trim();
    const bp =
      acc.browserKind !== "adspower" && pid && browserProfileById
        ? browserProfileById.get(pid)
        : undefined;
    if (bp) {
      if (bp.customProxyUrl?.trim()) {
        const m = bp.customProxyUrl.trim().match(/:(\d{2,5})(?:$|[/?#])/);
        if (m) return { port: Number(m[1]) };
        return { port: null, reason: "指纹环境独立代理格式异常" };
      }
      const id = bp.nodeId?.trim() || gatewayActiveNodeId;
      if (!gatewayRunning) {
        return { port: null, reason: "NetGuard 安全网关未运行" };
      }
      if (id === gatewayActiveNodeId) return { port: gatewayBrowserPort };
      const sec = secondaryNodePorts[id];
      if (sec) return { port: sec };
      return { port: null, reason: "指纹环境绑定多出口副端口未激活" };
    }
    return { port: null, reason: "未绑定节点（禁止裸连），请先在「编辑」中绑定节点或指纹环境" };
  }
  if (source === "netguard") {
    const id = acc.linkedNodeId?.trim();
    if (!id || !nodeById.has(id)) {
      return { port: null, reason: "绑定的 NetGuard 节点不存在，请重新选择" };
    }
    if (!gatewayRunning) {
      return { port: null, reason: "NetGuard 安全网关未运行" };
    }
    if (id === gatewayActiveNodeId) {
      return { port: gatewayBrowserPort };
    }
    const sec = secondaryNodePorts[id];
    if (sec) return { port: sec };
    return { port: null, reason: "多出口副端口未激活（点击可触发校验并提示）" };
  }
  if (source === "clash_verge") {
    if (acc.linkedProxyPort) return { port: acc.linkedProxyPort };
    const matched = findMatchingClashListener(
      acc.linkedNodeName || "",
      clashNodes?.listeners,
    );
    if (matched) return { port: matched.port };
    if (clashNodes?.mixedPort) return { port: clashNodes.mixedPort };
    return { port: 7897 };
  }
  if (acc.linkedProxyPort) return { port: acc.linkedProxyPort };
  const text = acc.linkedNodeName || "";
  const m =
    text.match(/(?:127\.0\.0\.1|localhost):(\d{2,5})/i) || text.match(/\b(\d{4,5})\b/);
  if (m) {
    const p = Number(m[1]);
    if (p >= 1024 && p <= 65535) return { port: p };
  }
  return { port: null, reason: "自定义节点需设置本地代理端口（如 7897）" };
}

function attachLightDismissFallback(dialog: HTMLDialogElement | null) {
  if (!dialog || "closedBy" in HTMLDialogElement.prototype) {
    return () => {};
  }
  let pressedOutside = false;
  const isOutside = (e: PointerEvent) => {
    const r = dialog.getBoundingClientRect();
    return (
      e.clientX < r.left ||
      e.clientX > r.right ||
      e.clientY < r.top ||
      e.clientY > r.bottom
    );
  };
  const onPointerDown = (e: PointerEvent) => {
    pressedOutside = isOutside(e);
  };
  const onPointerUp = (e: PointerEvent) => {
    if (pressedOutside && isOutside(e)) {
      dialog.close();
    }
    pressedOutside = false;
  };
  dialog.addEventListener("pointerdown", onPointerDown);
  dialog.addEventListener("pointerup", onPointerUp);
  return () => {
    dialog.removeEventListener("pointerdown", onPointerDown);
    dialog.removeEventListener("pointerup", onPointerUp);
  };
}

export function AccountsView({
  accounts,
  nodes,
  envPresets,
  clashNodes,
  browserProfiles,
  activeSession,
  runningBrowserProfiles,
  runningAdspowerProfiles,
  secondaryNodePorts,
  gatewayRunning,
  gatewayBrowserPort,
  gatewayActiveNodeId,
  adspowerConfig,
  adspowerProfiles,
  loading,
  loadingClashNodes,
  loadingAdsPower,
  onUpsert,
  onDelete,
  onBulkDelete,
  onImport,
  onSaveEnvPresets,
  onRefreshClashNodes,
  onReorder,
  onLaunchBrowser,
  onCloseBrowserProfile,
  onCloseAdsPowerProfile,
  onClearActiveSession,
  onSaveAdsPowerConfig,
  onTestAdsPowerConnection,
  onRefreshAdsPowerProfiles,
  onNotify,
}: AccountsViewProps) {
  const uid = useId();
  const fid = (name: string) => `${uid}-${name}`;
  const editorTitleId = fid("editor-title");
  const adsTitleId = fid("ads-title");
  const confirmTitleId = fid("confirm-title");

  const [search, setSearch] = useState("");
  const [envFilter, setEnvFilter] = useState<string>("__all__");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [quotaReadyOnly, setQuotaReadyOnly] = useState(false);
  const [expandedIds, setExpandedIds] = useState<Record<string, boolean>>({});
  const [revealedPasswords, setRevealedPasswords] = useState<Record<string, boolean>>({});
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, boolean>>({});
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [saving, setSaving] = useState(false);
  const [launchingBrowserId, setLaunchingBrowserId] = useState<string | null>(null);
  const [clearingSession, setClearingSession] = useState(false);

  const [editorOpen, setEditorOpen] = useState(false);
  const [form, setForm] = useState<AccountFormState>(emptyFormState);
  const [formError, setFormError] = useState("");
  const [showFormPassword, setShowFormPassword] = useState(false);
  const [overrideProfileExit, setOverrideProfileExit] = useState(false);

  const [adsBaseUrl, setAdsBaseUrl] = useState("http://127.0.0.1:50325");
  const [adsApiKeyInput, setAdsApiKeyInput] = useState("");
  const [adsShowKey, setAdsShowKey] = useState(false);
  const [adsSaving, setAdsSaving] = useState(false);
  const [adsTestMessage, setAdsTestMessage] = useState("");
  const [adsTestIsError, setAdsTestIsError] = useState(false);

  const [addingPreset, setAddingPreset] = useState(false);
  const [newPresetName, setNewPresetName] = useState("");
  const [newPresetType, setNewPresetType] = useState<AccountEnvType>("custom");
  const [clashSearch, setClashSearch] = useState("");

  const [confirmTarget, setConfirmTarget] = useState<ConfirmTarget | null>(null);
  const [reorderAnnouncement, setReorderAnnouncement] = useState("");

  const editorDialogRef = useRef<HTMLDialogElement>(null);
  const adsDialogRef = useRef<HTMLDialogElement>(null);
  const confirmDialogRef = useRef<HTMLDialogElement>(null);
  const emailInputRef = useRef<HTMLInputElement>(null);
  const adsUrlInputRef = useRef<HTMLInputElement>(null);
  const confirmCancelRef = useRef<HTMLButtonElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const activeCleanupRef = useRef<(() => void) | null>(null);
  const pendingFlipRef = useRef<{
    rects: Map<string, DOMRect>;
    scrollItemId?: string;
    focusTarget?: {
      id: string;
      dir: "up" | "down";
      nextIndex: number;
      total: number;
    };
  } | null>(null);

  const hasLiveTicker = useMemo(
    () =>
      editorOpen ||
      accounts.some(
        (a) =>
          Boolean(a.totpSecret?.trim()) ||
          Boolean(
            a.quota?.enabled &&
              a.quota.pools.some((p) => Boolean(p.resetAt?.trim())),
          ),
      ),
    [accounts, editorOpen],
  );

  useEffect(() => {
    if (!hasLiveTicker) return;
    setNowMs(Date.now());
    const timer = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [hasLiveTicker]);

  useEffect(() => {
    const cleanEditor = attachLightDismissFallback(editorDialogRef.current);
    const cleanAds = attachLightDismissFallback(adsDialogRef.current);
    const cleanConfirm = attachLightDismissFallback(confirmDialogRef.current);
    return () => {
      cleanEditor();
      cleanAds();
      cleanConfirm();
      activeCleanupRef.current?.();
    };
  }, []);

  const isFiltered = Boolean(
    search.trim() ||
      envFilter !== "__all__" ||
      statusFilter !== "all" ||
      quotaReadyOnly,
  );
  const reorderDisabled = isFiltered || accounts.length < 2;

  const captureRowRects = (overrideDrag?: { id: string; rect: DOMRect }) => {
    const map = new Map<string, DOMRect>();
    const listEl = listRef.current;
    if (!listEl) return map;
    for (const row of listEl.querySelectorAll<HTMLElement>("[data-account-id]")) {
      const id = row.dataset.accountId;
      if (!id) continue;
      if (overrideDrag && overrideDrag.id === id) {
        map.set(id, overrideDrag.rect);
        continue;
      }
      for (const anim of row.getAnimations()) {
        anim.finish();
      }
      map.set(id, row.getBoundingClientRect());
    }
    return map;
  };

  useLayoutEffect(() => {
    const pending = pendingFlipRef.current;
    if (!pending) return;
    pendingFlipRef.current = null;
    const listEl = listRef.current;
    if (!listEl) return;

    if (pending.scrollItemId) {
      const targetRow = Array.from(
        listEl.querySelectorAll<HTMLElement>("[data-account-id]"),
      ).find((el) => el.dataset.accountId === pending.scrollItemId);
      targetRow?.scrollIntoView({ block: "nearest", inline: "nearest" });

      if (pending.focusTarget && targetRow) {
        const { dir, nextIndex, total } = pending.focusTarget;
        const nextBtnDir =
          dir === "up" && nextIndex === 0
            ? "down"
            : dir === "down" && nextIndex === total - 1
              ? "up"
              : dir;
        const btn = targetRow.querySelector<HTMLButtonElement>(
          `button[data-move="${nextBtnDir}"]`,
        );
        btn?.focus({ preventScroll: true });
      }
    }

    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return;
    }

    for (const row of listEl.querySelectorAll<HTMLElement>("[data-account-id]")) {
      const id = row.dataset.accountId;
      if (!id) continue;
      const oldRect = pending.rects.get(id);
      if (!oldRect) continue;
      const newRect = row.getBoundingClientRect();
      const dx = oldRect.left - newRect.left;
      const dy = oldRect.top - newRect.top;
      if (Math.abs(dx) > 0.5 || Math.abs(dy) > 0.5) {
        row.animate(
          [{ translate: `${dx}px ${dy}px` }, { translate: "0px 0px" }],
          { duration: 190, easing: "cubic-bezier(0.22, 1, 0.36, 1)" },
        );
      }
    }
  }, [accounts]);

  const nodeById = useMemo(() => {
    const map = new Map<string, NodeProfile>();
    for (const node of nodes) {
      map.set(node.id, node);
    }
    return map;
  }, [nodes]);

  const browserProfileById = useMemo(() => {
    const map = new Map<string, BrowserProfile>();
    for (const bp of browserProfiles) {
      map.set(bp.id, bp);
    }
    return map;
  }, [browserProfiles]);

  const runningBrowserSet = useMemo(
    () => new Set(runningBrowserProfiles),
    [runningBrowserProfiles],
  );

  const runningAdspowerSet = useMemo(
    () => new Set(runningAdspowerProfiles),
    [runningAdspowerProfiles],
  );

  const matchedFormListener = useMemo(() => {
    if (form.linkedNodeSource !== "clash_verge") return undefined;
    return findMatchingClashListener(form.linkedNodeName, clashNodes?.listeners);
  }, [form.linkedNodeSource, form.linkedNodeName, clashNodes?.listeners]);

  const quotaByAccountId = useMemo(() => {
    const map = new Map<string, EvaluatedAccountQuota>();
    for (const acc of accounts) {
      map.set(acc.id, evaluateAccountQuota(acc, nowMs));
    }
    return map;
  }, [accounts, nowMs]);

  const handleUpdateQuotaPools = async (
    acc: AccountRecord,
    nextPools: AccountQuotaPool[],
    note: string,
  ) => {
    setSaving(true);
    try {
      await onUpsert({
        ...acc,
        quota: {
          enabled: acc.quota?.enabled ?? true,
          planTier: acc.quota?.planTier || "PRO",
          expiresAt: acc.quota?.expiresAt || null,
          pools: nextPools,
        },
      });
      onNotify(note);
    } finally {
      setSaving(false);
    }
  };

  const handleRowLaunchBrowser = async (acc: AccountRecord) => {
    setLaunchingBrowserId(acc.id);
    try {
      await onLaunchBrowser(acc.id);
    } finally {
      setLaunchingBrowserId(null);
    }
  };

  const handleClearSessionClick = async (closeBrowser: boolean) => {
    setClearingSession(true);
    try {
      await onClearActiveSession(closeBrowser);
    } finally {
      setClearingSession(false);
    }
  };

  const distinctEnvironments = useMemo(() => {
    const set = new Set<string>();
    for (const acc of accounts) {
      const name = acc.environmentName.trim();
      if (name) set.add(name);
    }
    return Array.from(set).sort((a, b) => a.localeCompare(b, "zh-CN"));
  }, [accounts]);

  const hasEmptyEnvAccount = useMemo(
    () => accounts.some((acc) => !acc.environmentName.trim()),
    [accounts],
  );

  const stats = useMemo(() => {
    let active = 0;
    let standby = 0;
    let restricted = 0;
    let banned = 0;
    let quotaTracked = 0;
    let quotaReady = 0;
    let quotaExhausted = 0;
    let quotaExpiring = 0;
    for (const acc of accounts) {
      if (acc.status === "active") active += 1;
      else if (acc.status === "standby") standby += 1;
      else if (acc.status === "restricted") restricted += 1;
      else if (acc.status === "banned") banned += 1;
      const q = quotaByAccountId.get(acc.id);
      if (q?.enabled) {
        quotaTracked += 1;
        if (q.isExpiringSoonOrExpired) quotaExpiring += 1;
        if (q.allExhausted) quotaExhausted += 1;
        if (q.hasAvailablePool && q.expiry?.state !== "expired") quotaReady += 1;
      }
    }
    return {
      total: accounts.length,
      active,
      standby,
      restricted,
      banned,
      envCount: distinctEnvironments.length,
      quotaTracked,
      quotaReady,
      quotaExhausted,
      quotaExpiring,
    };
  }, [accounts, distinctEnvironments, quotaByAccountId]);

  const bannedIds = useMemo(
    () => accounts.filter((a) => a.status === "banned").map((a) => a.id),
    [accounts],
  );

  const filteredAccounts = useMemo(() => {
    const query = search.trim().toLowerCase();
    return accounts.filter((acc) => {
      if (statusFilter !== "all" && acc.status !== statusFilter) {
        return false;
      }
      if (quotaReadyOnly) {
        const q = quotaByAccountId.get(acc.id);
        if (!q?.enabled || !q.hasAvailablePool || q.expiry?.state === "expired") {
          return false;
        }
      }
      if (envFilter === "__empty__" && acc.environmentName.trim() !== "") {
        return false;
      }
      if (
        envFilter !== "__all__" &&
        envFilter !== "__empty__" &&
        acc.environmentName.trim() !== envFilter
      ) {
        return false;
      }
      if (!query) return true;
      const nodeDisplay = resolveAccountNodeDisplay(acc, nodeById, browserProfileById);
      const envMeta = ENV_TYPE_META[normalizeEnvType(acc.envType)];
      const haystack = [
        acc.label,
        acc.provider,
        acc.email,
        acc.environmentName,
        acc.environmentProfile || "",
        acc.quota?.planTier || "",
        envMeta.label,
        nodeDisplay?.sourceLabel || "",
        nodeDisplay?.name || "",
        acc.purpose,
        acc.recoveryEmail || "",
        acc.notes || "",
        ...acc.tags,
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [
    accounts,
    statusFilter,
    quotaReadyOnly,
    quotaByAccountId,
    envFilter,
    search,
    nodeById,
    browserProfileById,
  ]);

  const filteredClashGroups = useMemo(() => {
    const list = clashNodes?.groups ?? [];
    const q = clashSearch.trim().toLowerCase();
    return q
      ? list.filter(
          (item) =>
            item.name.toLowerCase().includes(q) ||
            item.nodeType.toLowerCase().includes(q),
        )
      : list;
  }, [clashNodes?.groups, clashSearch]);

  const filteredClashProxies = useMemo(() => {
    const list = clashNodes?.proxies ?? [];
    const q = clashSearch.trim().toLowerCase();
    return q
      ? list.filter(
          (item) =>
            item.name.toLowerCase().includes(q) ||
            item.nodeType.toLowerCase().includes(q),
        )
      : list;
  }, [clashNodes?.proxies, clashSearch]);

  const formTotpPreview = useMemo(() => {
    const trimmed = form.totpSecret.trim();
    if (!trimmed) return { present: false, result: null };
    return { present: true, result: generateTotp(trimmed, nowMs) };
  }, [form.totpSecret, nowMs]);

  const selectedLinkedProfile =
    form.browserKind === "netguard" && form.linkedBrowserProfileId.trim()
      ? browserProfileById.get(form.linkedBrowserProfileId.trim())
      : undefined;

  const selectedLinkedProfileExitSummary = useMemo(() => {
    if (!selectedLinkedProfile) return "";
    if (selectedLinkedProfile.customProxyUrl?.trim()) {
      return `自定义代理 ${selectedLinkedProfile.customProxyUrl.trim()}`;
    }
    if (selectedLinkedProfile.nodeId) {
      const n = nodeById.get(selectedLinkedProfile.nodeId);
      return n ? `NetGuard 节点「${n.name}」` : `NetGuard 节点 ${selectedLinkedProfile.nodeId}`;
    }
    const active = nodeById.get(gatewayActiveNodeId);
    return active
      ? `NetGuard 当前活动节点「${active.name}」`
      : "NetGuard 当前活动节点";
  }, [selectedLinkedProfile, nodeById, gatewayActiveNodeId]);

  const openEditor = (existing?: AccountRecord) => {
    const nextForm = existing ? recordToFormState(existing) : emptyFormState();
    setForm(nextForm);
    setFormError("");
    setShowFormPassword(false);
    setAddingPreset(false);
    setNewPresetName("");
    setNewPresetType("custom");
    setClashSearch("");
    setOverrideProfileExit(
      Boolean(
        nextForm.browserKind === "netguard" &&
          nextForm.linkedBrowserProfileId.trim() &&
          nextForm.linkedNodeSource !== "none",
      ),
    );
    setEditorOpen(true);
    if (!clashNodes?.detected) {
      void onRefreshClashNodes();
    }
    if (
      (existing?.browserKind === "adspower" ||
        adspowerConfig?.hasApiKey) &&
      !adspowerProfiles?.connected
    ) {
      void onRefreshAdsPowerProfiles();
    }
    const dlg = editorDialogRef.current;
    if (dlg && !dlg.open) {
      dlg.showModal();
      requestAnimationFrame(() => emailInputRef.current?.focus());
    }
  };

  const closeEditor = () => {
    const dlg = editorDialogRef.current;
    if (dlg?.open) {
      dlg.close();
    }
    setEditorOpen(false);
  };

  const openAdsDialog = () => {
    setAdsBaseUrl(adspowerConfig?.baseUrl || "http://127.0.0.1:50325");
    setAdsApiKeyInput("");
    setAdsShowKey(false);
    setAdsTestMessage("");
    setAdsTestIsError(false);
    const dlg = adsDialogRef.current;
    if (dlg && !dlg.open) {
      dlg.showModal();
      requestAnimationFrame(() => adsUrlInputRef.current?.focus());
    }
  };

  const closeAdsDialog = () => {
    const dlg = adsDialogRef.current;
    if (dlg?.open) {
      dlg.close();
    }
  };

  const handleSaveAdsPower = async (andTest: boolean) => {
    setAdsSaving(true);
    setAdsTestMessage("");
    setAdsTestIsError(false);
    try {
      const nextKey = adsApiKeyInput.trim() ? adsApiKeyInput.trim() : null;
      await onSaveAdsPowerConfig(adsBaseUrl, nextKey, false);
      setAdsApiKeyInput("");
      if (andTest) {
        const msg = await onTestAdsPowerConnection();
        const snap = await onRefreshAdsPowerProfiles();
        const count = snap?.profiles.length ?? 0;
        setAdsTestMessage(
          snap?.connected
            ? `${msg} · 已读取 ${count} 个 AdsPower 环境`
            : msg,
        );
        setAdsTestIsError(false);
      } else {
        setAdsTestMessage("AdsPower Local API 设置已加密保存");
        setAdsTestIsError(false);
      }
    } catch (err) {
      setAdsTestMessage(String(err));
      setAdsTestIsError(true);
    } finally {
      setAdsSaving(false);
    }
  };

  const handleClearAdsPowerKey = async () => {
    setAdsSaving(true);
    setAdsTestMessage("");
    setAdsTestIsError(false);
    try {
      await onSaveAdsPowerConfig(adsBaseUrl, null, true);
      setAdsApiKeyInput("");
      setAdsTestMessage("已清除保存的 API Key");
    } catch (err) {
      setAdsTestMessage(String(err));
      setAdsTestIsError(true);
    } finally {
      setAdsSaving(false);
    }
  };

  const openConfirmDelete = (target: ConfirmTarget) => {
    setConfirmTarget(target);
    const dlg = confirmDialogRef.current;
    if (dlg && !dlg.open) {
      dlg.returnValue = "";
      dlg.showModal();
      requestAnimationFrame(() => confirmCancelRef.current?.focus());
    }
  };

  const handleConfirmDialogClose = async () => {
    const dlg = confirmDialogRef.current;
    const rv = dlg?.returnValue || "";
    if (dlg) {
      dlg.returnValue = "";
    }
    const target = confirmTarget;
    setConfirmTarget(null);
    if (rv !== "confirm" || !target) return;

    setSaving(true);
    try {
      if (target.kind === "single") {
        await onDelete(target.account.id);
      } else if (target.ids.length > 0) {
        await onBulkDelete(target.ids);
      }
    } finally {
      setSaving(false);
    }
  };

  const handleCopy = async (text: string, label: string) => {
    if (!text) {
      onNotify(`${label}为空`);
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      onNotify(`已复制${label}`);
    } catch (err) {
      onNotify(`复制失败: ${String(err)}`);
    }
  };

  const handleAddEnvPreset = async () => {
    const name = newPresetName.trim();
    if (!name) return;
    const existing = envPresets.find(
      (p) => p.name.trim().toLowerCase() === name.toLowerCase(),
    );
    if (existing) {
      setForm((prev) => ({
        ...prev,
        envType: existing.envType,
        environmentName: existing.name,
      }));
      setAddingPreset(false);
      setNewPresetName("");
      onNotify(`已选中现有环境「${existing.name}」`);
      return;
    }
    const created: AccountEnvPreset = {
      id: `env-${Date.now().toString(36)}`,
      name,
      envType: newPresetType,
    };
    await onSaveEnvPresets([...envPresets, created]);
    setForm((prev) => ({
      ...prev,
      envType: created.envType,
      environmentName: created.name,
    }));
    setAddingPreset(false);
    setNewPresetName("");
    onNotify(`已新增启动环境「${created.name}」`);
  };

  const handleRemoveEnvPreset = async (preset: AccountEnvPreset) => {
    const next = envPresets.filter((p) => p.id !== preset.id);
    await onSaveEnvPresets(next);
    onNotify(`已从环境预设移除「${preset.name}」（已有账号记录保留不变）`);
  };

  const handleSelectNodeSource = (nextSource: AccountNodeSource) => {
    if (nextSource === "clash_verge" && !clashNodes?.detected) {
      void onRefreshClashNodes();
    }
    setForm((prev) => {
      if (nextSource === "none") {
        return {
          ...prev,
          linkedNodeSource: "none",
          linkedNodeId: "",
          linkedNodeName: "",
          linkedProxyPort: "",
        };
      }
      if (nextSource === "netguard") {
        const currentNode = prev.linkedNodeId ? nodeById.get(prev.linkedNodeId) : undefined;
        return {
          ...prev,
          linkedNodeSource: "netguard",
          linkedNodeName: currentNode?.name || "",
          linkedProxyPort: "",
        };
      }
      return {
        ...prev,
        linkedNodeSource: nextSource,
        linkedNodeId: "",
        linkedNodeName: prev.linkedNodeSource === nextSource ? prev.linkedNodeName : "",
        linkedProxyPort: prev.linkedNodeSource === nextSource ? prev.linkedProxyPort : "",
      };
    });
  };

  const handleSubmitForm = async (e: React.FormEvent) => {
    e.preventDefault();
    const email = form.email.trim();
    if (!email) {
      setFormError("请输入账号或邮箱地址");
      emailInputRef.current?.focus();
      return;
    }

    const tags = form.tagsText
      .split(/[,，]/)
      .map((t) => t.trim())
      .filter(Boolean);

    let effectiveSource = form.linkedNodeSource;
    let effectiveNodeId: string | null = null;
    let effectiveNodeName: string | null = null;

    if (effectiveSource === "netguard") {
      const id = form.linkedNodeId.trim();
      const matched = id ? nodeById.get(id) : undefined;
      if (id) {
        effectiveNodeId = id;
        effectiveNodeName = matched?.name || form.linkedNodeName.trim() || null;
      } else {
        effectiveSource = "none";
      }
    } else if (effectiveSource === "clash_verge" || effectiveSource === "custom") {
      const name = form.linkedNodeName.trim();
      if (name) {
        effectiveNodeName = name;
      } else {
        effectiveSource = "none";
      }
    }

    let parsedProxyPort: number | null = null;
    if (
      (effectiveSource === "clash_verge" || effectiveSource === "custom") &&
      form.linkedProxyPort.trim()
    ) {
      const n = Number(form.linkedProxyPort.trim());
      if (!Number.isInteger(n) || n < 1 || n > 65535) {
        setFormError("独立监听端口必须是 1 到 65535 之间的整数");
        return;
      }
      parsedProxyPort = n;
    }

    const sanitizedQuota: AccountQuotaConfig | null = form.quotaEnabled
      ? {
          enabled: true,
          planTier: form.quotaPlanTier.trim() || "PRO",
          expiresAt: form.quotaExpiresAt.trim() || null,
          pools: form.quotaPools
            .map((p, idx) => ({
              id: p.id.trim() || `pool-${idx + 1}`,
              label: p.label.trim(),
              remainingPct: Math.max(
                0,
                Math.min(100, Math.round(Number(p.remainingPct) || 0)),
              ),
              resetHours: Math.max(0, Math.round(Number(p.resetHours) || 0)),
              resetAt: p.resetAt?.trim() || null,
            }))
            .filter((p) => p.label.length > 0),
        }
      : form.quotaExpiresAt.trim() ||
          (form.quotaPools && form.quotaPools.length > 0 && form.id)
        ? {
            enabled: false,
            planTier: form.quotaPlanTier.trim(),
            expiresAt: form.quotaExpiresAt.trim() || null,
            pools: form.quotaPools.filter((p) => p.label.trim().length > 0),
          }
        : null;

    if (form.quotaEnabled && (!sanitizedQuota || sanitizedQuota.pools.length === 0)) {
      setFormError("已开启额度管理时，请至少保留一个有效的模型分组名称");
      return;
    }

    const record: AccountRecord = {
      id: form.id,
      label: form.label.trim(),
      provider: form.provider.trim() || "Google",
      email,
      password: form.password,
      totpSecret: form.totpSecret.trim() || null,
      recoveryCodes: form.recoveryCodes.trim() || null,
      recoveryEmail: form.recoveryEmail.trim() || null,
      envType: form.envType,
      environmentName: form.environmentName.trim(),
      environmentProfile: form.environmentProfile.trim() || null,
      browserKind: form.browserKind,
      adspowerUserId: form.adspowerUserId.trim() || null,
      adspowerSerialNumber:
        form.adspowerSerialNumber.trim().replace(/^#/, "").trim() || null,
      adspowerProfileName: form.adspowerProfileName.trim() || null,
      quota: sanitizedQuota,
      linkedNodeSource: effectiveSource,
      linkedNodeId: effectiveNodeId,
      linkedNodeName: effectiveNodeName,
      linkedBrowserProfileId: form.linkedBrowserProfileId.trim() || null,
      linkedProxyPort: parsedProxyPort,
      purpose: form.purpose.trim(),
      tags,
      status: form.status,
      notes: form.notes.trim() || null,
      createdAt: form.createdAt,
      updatedAt: "",
    };

    setSaving(true);
    setFormError("");
    try {
      await onUpsert(record);
      closeEditor();
    } catch (err) {
      setFormError(String(err));
    } finally {
      setSaving(false);
    }
  };

  const handleQuickStatus = async (acc: AccountRecord, nextStatus: AccountStatus) => {
    if (acc.status === nextStatus) return;
    setSaving(true);
    try {
      await onUpsert({ ...acc, status: nextStatus });
    } finally {
      setSaving(false);
    }
  };

  const handleExportJson = () => {
    if (accounts.length === 0) {
      onNotify("暂无可导出的账号记录");
      return;
    }
    const payload = {
      version: 1,
      exportedAt: new Date().toISOString(),
      accounts,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const day = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    link.href = url;
    link.download = `ai-netguard-accounts-${day}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    onNotify(`已导出 ${accounts.length} 条账号备份（明文 JSON，请妥善保管）`);
  };

  const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as unknown;
      const listRaw = Array.isArray(parsed)
        ? parsed
        : parsed &&
            typeof parsed === "object" &&
            Array.isArray((parsed as { accounts?: unknown }).accounts)
          ? (parsed as { accounts: unknown[] }).accounts
          : null;
      if (!listRaw) {
        onNotify("导入失败：JSON 格式必须是账号数组或包含 accounts 字段");
        return;
      }
      const validRecords: AccountRecord[] = listRaw
        .filter(
          (item): item is Record<string, unknown> =>
            Boolean(
              item &&
                typeof item === "object" &&
                typeof (item as { email?: unknown }).email === "string" &&
                (item as { email: string }).email.trim(),
            ),
        )
        .map((item) => {
          const linkedNodeId =
            typeof item.linkedNodeId === "string" ? item.linkedNodeId : null;
          const linkedNodeSource = normalizeNodeSource(
            typeof item.linkedNodeSource === "string" ? item.linkedNodeSource : null,
            linkedNodeId,
          );
          return {
            id: typeof item.id === "string" ? item.id : "",
            label: typeof item.label === "string" ? item.label : "",
            provider: typeof item.provider === "string" ? item.provider : "Google",
            email: String(item.email).trim(),
            password: typeof item.password === "string" ? item.password : "",
            totpSecret: typeof item.totpSecret === "string" ? item.totpSecret : null,
            recoveryCodes:
              typeof item.recoveryCodes === "string" ? item.recoveryCodes : null,
            recoveryEmail:
              typeof item.recoveryEmail === "string" ? item.recoveryEmail : null,
            envType: normalizeEnvType(
              typeof item.envType === "string" ? item.envType : null,
            ),
            environmentName:
              typeof item.environmentName === "string" ? item.environmentName : "",
            environmentProfile:
              typeof item.environmentProfile === "string"
                ? item.environmentProfile
                : null,
            browserKind:
              item.browserKind === "none"
                ? "none"
                : item.browserKind === "adspower"
                  ? "adspower"
                  : "netguard",
            adspowerUserId:
              typeof item.adspowerUserId === "string"
                ? item.adspowerUserId
                : null,
            adspowerSerialNumber:
              typeof item.adspowerSerialNumber === "string"
                ? item.adspowerSerialNumber
                : null,
            adspowerProfileName:
              typeof item.adspowerProfileName === "string"
                ? item.adspowerProfileName
                : null,
            quota:
              item.quota && typeof item.quota === "object"
                ? (item.quota as AccountQuotaConfig)
                : null,
            linkedNodeSource,
            linkedNodeId,
            linkedNodeName:
              typeof item.linkedNodeName === "string" ? item.linkedNodeName : null,
            linkedBrowserProfileId:
              typeof item.linkedBrowserProfileId === "string"
                ? item.linkedBrowserProfileId
                : null,
            linkedProxyPort:
              typeof item.linkedProxyPort === "number" ? item.linkedProxyPort : null,
            purpose: typeof item.purpose === "string" ? item.purpose : "",
            tags: Array.isArray(item.tags)
              ? item.tags.filter((t): t is string => typeof t === "string")
              : [],
            status:
              typeof item.status === "string"
                ? (item.status as AccountStatus)
                : "active",
            notes: typeof item.notes === "string" ? item.notes : null,
            createdAt: typeof item.createdAt === "string" ? item.createdAt : "",
            updatedAt: typeof item.updatedAt === "string" ? item.updatedAt : "",
          };
        });

      if (validRecords.length === 0) {
        onNotify("未找到包含有效 email 的账号记录");
        return;
      }
      await onImport(validRecords, false);
    } catch (err) {
      onNotify(`导入 JSON 失败: ${String(err)}`);
    }
  };

  const toggleRevealPassword = (id: string) => {
    setRevealedPasswords((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const toggleRevealSecret = (id: string) => {
    setRevealedSecrets((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const toggleExpanded = (id: string) => {
    setExpandedIds((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleMoveAccount = (index: number, delta: -1 | 1) => {
    if (reorderDisabled) return;
    const targetIndex = index + delta;
    if (targetIndex < 0 || targetIndex >= accounts.length) return;
    const moved = accounts[index];
    const rects = captureRowRects();
    const nextIds = accounts.map((a) => a.id);
    const [removed] = nextIds.splice(index, 1);
    nextIds.splice(targetIndex, 0, removed);

    const dir = delta < 0 ? "up" : "down";
    pendingFlipRef.current = {
      rects,
      scrollItemId: moved.id,
      focusTarget: {
        id: moved.id,
        dir,
        nextIndex: targetIndex,
        total: nextIds.length,
      },
    };
    void onReorder(nextIds);
    setReorderAnnouncement(
      `已将「${moved.label || moved.email}」${dir === "up" ? "上移" : "下移"}至第 ${targetIndex + 1} 位，共 ${nextIds.length} 项`,
    );
  };

  const handleDragPointerDown = (
    e: React.PointerEvent<HTMLButtonElement>,
    accountId: string,
    sourceIndex: number,
  ) => {
    if (e.button !== 0 || reorderDisabled) return;
    if (activeCleanupRef.current) return;

    const handleEl = e.currentTarget;
    const itemEl = handleEl.closest<HTMLElement>("[data-account-id]");
    const listEl = listRef.current;
    if (!itemEl || !listEl) return;

    e.preventDefault();
    const pointerId = e.pointerId;
    const scrollEl = listEl.closest("main") as HTMLElement | null;
    const startY = e.clientY;
    const startScrollTop = scrollEl?.scrollTop ?? 0;
    const itemHeight = itemEl.offsetHeight;
    let lastY = e.clientY;
    let currentDropIndex = sourceIndex;
    let rafId = 0;
    let lastFrameTime = performance.now();
    let ended = false;

    const getRows = () =>
      Array.from(listEl.children).filter(
        (el): el is HTMLElement =>
          el instanceof HTMLElement && Boolean(el.dataset.accountId),
      );

    const clearDropMarker = () => {
      listEl.removeAttribute("data-drop");
      listEl.style.removeProperty("--drop-x");
      listEl.style.removeProperty("--drop-y");
      listEl.style.removeProperty("--drop-w");
    };

    const updateDragAndDropSpot = (clientY: number) => {
      lastY = clientY;
      const scrollDelta = (scrollEl?.scrollTop ?? 0) - startScrollTop;
      const dy = clientY - startY + scrollDelta;
      itemEl.style.translate = `0px ${dy}px`;

      const rows = getRows();
      if (rows.length === 0) return;

      const listRect = listEl.getBoundingClientRect();
      const scrollRect = scrollEl ? scrollEl.getBoundingClientRect() : null;
      const clampedClientY = scrollRect
        ? Math.max(scrollRect.top, Math.min(scrollRect.bottom, clientY))
        : clientY;
      const pointerInList = clampedClientY - listRect.top - listEl.clientTop;

      let dropIdx = rows.length;
      for (let i = 0; i < rows.length; i += 1) {
        const mid = rows[i].offsetTop + rows[i].offsetHeight / 2;
        if (pointerInList < mid) {
          dropIdx = i;
          break;
        }
      }
      currentDropIndex = dropIdx;

      if (dropIdx === sourceIndex || dropIdx === sourceIndex + 1) {
        clearDropMarker();
        return;
      }

      let dropY: number;
      if (dropIdx <= 0) {
        dropY = rows[0].getBoundingClientRect().top;
      } else if (dropIdx >= rows.length) {
        dropY = rows[rows.length - 1].getBoundingClientRect().bottom;
      } else {
        const prevR = rows[dropIdx - 1].getBoundingClientRect();
        const nextR = rows[dropIdx].getBoundingClientRect();
        dropY = (prevR.bottom + nextR.top) / 2;
      }
      const refRect = rows[0].getBoundingClientRect();
      listEl.style.setProperty("--drop-x", `${refRect.left + 12}px`);
      listEl.style.setProperty("--drop-y", `${dropY}px`);
      listEl.style.setProperty("--drop-w", `${Math.max(0, refRect.width - 24)}px`);
      listEl.setAttribute("data-drop", "true");
    };

    const cleanup = () => {
      if (ended) return;
      ended = true;
      if (rafId) {
        window.cancelAnimationFrame(rafId);
        rafId = 0;
      }
      window.removeEventListener("keydown", onKeyDown, true);
      handleEl.removeEventListener("pointermove", onPointerMove);
      handleEl.removeEventListener("pointerup", onPointerUp);
      handleEl.removeEventListener("pointercancel", onPointerCancel);
      handleEl.removeEventListener("lostpointercapture", onLostCapture);
      document.documentElement.classList.remove("ng-dragging-reorder");
      itemEl.removeAttribute("data-dragging");
      clearDropMarker();
      if (handleEl.hasPointerCapture(pointerId)) {
        try {
          handleEl.releasePointerCapture(pointerId);
        } catch {
          // Ignore if capture already released
        }
      }
      activeCleanupRef.current = null;
    };

    const cancelDrag = (animateBack: boolean, announceCancel: boolean) => {
      const releasedRect = itemEl.getBoundingClientRect();
      cleanup();
      itemEl.style.translate = "";
      if (announceCancel) {
        itemEl.scrollIntoView({ block: "nearest", inline: "nearest" });
        setReorderAnnouncement("已取消调整账号顺序");
      }
      if (
        animateBack &&
        !window.matchMedia("(prefers-reduced-motion: reduce)").matches
      ) {
        const finalRect = itemEl.getBoundingClientRect();
        const dx = releasedRect.left - finalRect.left;
        const dy = releasedRect.top - finalRect.top;
        if (Math.abs(dx) > 0.5 || Math.abs(dy) > 0.5) {
          itemEl.animate(
            [{ translate: `${dx}px ${dy}px` }, { translate: "0px 0px" }],
            { duration: 180, easing: "cubic-bezier(0.22, 1, 0.36, 1)" },
          );
        }
      }
    };

    const onPointerMove = (ev: PointerEvent) => {
      if (ev.pointerId !== pointerId || ended) return;
      updateDragAndDropSpot(ev.clientY);
    };

    const onPointerUp = (ev: PointerEvent) => {
      if (ev.pointerId !== pointerId || ended) return;
      const isNoOp =
        currentDropIndex === sourceIndex || currentDropIndex === sourceIndex + 1;
      if (isNoOp) {
        cancelDrag(true, false);
        return;
      }
      for (const anim of itemEl.getAnimations()) {
        anim.finish();
      }
      const releasedRect = itemEl.getBoundingClientRect();
      cleanup();
      itemEl.style.translate = "";

      const rects = captureRowRects({ id: accountId, rect: releasedRect });
      const nextIds = accounts.map((a) => a.id);
      const targetIndex =
        currentDropIndex > sourceIndex ? currentDropIndex - 1 : currentDropIndex;
      const [removed] = nextIds.splice(sourceIndex, 1);
      nextIds.splice(targetIndex, 0, removed);

      const movedAcc = accounts[sourceIndex];
      pendingFlipRef.current = { rects, scrollItemId: accountId };
      void onReorder(nextIds);
      if (movedAcc) {
        setReorderAnnouncement(
          `已将「${movedAcc.label || movedAcc.email}」移至第 ${targetIndex + 1} 位，共 ${nextIds.length} 项`,
        );
      }
    };

    const onPointerCancel = (ev: PointerEvent) => {
      if (ev.pointerId !== pointerId || ended) return;
      cancelDrag(true, false);
    };

    const onLostCapture = (ev: PointerEvent) => {
      if (ev.pointerId !== pointerId || ended) return;
      cancelDrag(true, false);
    };

    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !ended) {
        ev.preventDefault();
        ev.stopPropagation();
        cancelDrag(true, true);
      }
    };

    const tickAutoScroll = (now: number) => {
      if (ended) return;
      const dt = Math.max(8, Math.min(50, now - lastFrameTime));
      lastFrameTime = now;

      if (scrollEl && scrollEl.scrollHeight > scrollEl.clientHeight) {
        const sr = scrollEl.getBoundingClientRect();
        const zone = Math.min(itemHeight, scrollEl.clientHeight / 3);
        let velocity = 0;
        if (lastY < sr.top + zone) {
          const ratio = Math.min(1.5, (sr.top + zone - lastY) / Math.max(1, zone));
          velocity = -720 * ratio;
        } else if (lastY > sr.bottom - zone) {
          const ratio = Math.min(1.5, (lastY - (sr.bottom - zone)) / Math.max(1, zone));
          velocity = 720 * ratio;
        }
        if (velocity !== 0) {
          const prevScroll = scrollEl.scrollTop;
          scrollEl.scrollTop += (velocity * dt) / 1000;
          if (scrollEl.scrollTop !== prevScroll) {
            updateDragAndDropSpot(lastY);
          }
        }
      }
      rafId = window.requestAnimationFrame(tickAutoScroll);
    };

    document.documentElement.classList.add("ng-dragging-reorder");
    itemEl.setAttribute("data-dragging", "true");
    try {
      handleEl.setPointerCapture(pointerId);
    } catch {
      // Ignore if synthetic event lacks active pointer
    }

    activeCleanupRef.current = cleanup;
    window.addEventListener("keydown", onKeyDown, true);
    handleEl.addEventListener("pointermove", onPointerMove);
    handleEl.addEventListener("pointerup", onPointerUp);
    handleEl.addEventListener("pointercancel", onPointerCancel);
    handleEl.addEventListener("lostpointercapture", onLostCapture);
    updateDragAndDropSpot(e.clientY);
    rafId = window.requestAnimationFrame(tickAutoScroll);
  };

  return (
    <div className="bento-sheet flex flex-col divide-y divide-[#eaecef] rounded-2xl border border-[#eaecef] bg-white shadow-[0_1px_3px_rgba(15,23,42,0.03)]">
      {/* Header */}
      <header className="flex flex-wrap items-center justify-between gap-3 px-6 py-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1
              id="main-heading"
              tabIndex={-1}
              className="vt-page-title text-[1.2rem] font-semibold tracking-[-0.02em] text-[#111827] outline-none"
            >
              账号与环境库
            </h1>
            <Badge variant="iris">
              <ShieldCheck className="h-3 w-3" aria-hidden="true" />
              DPAPI 本地加密
            </Badge>
          </div>
          <p className="mt-0.5 text-[0.76rem] text-[#7c8495]">
            统一记录 Google 等账号凭据、离线 2FA 动态码、自定义启动环境与 NetGuard / Clash Verge 绑定节点
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            ref={fileInputRef}
            type="file"
            accept=".json,application/json"
            className="hidden"
            onChange={handleImportFile}
          />
          <Button
            variant="outline"
            size="sm"
            onClick={openAdsDialog}
            title={
              adspowerConfig?.hasApiKey
                ? `AdsPower Local API 已配置密钥 (${adspowerConfig.apiKeyMasked || "DPAPI"})`
                : "配置 AdsPower Local API 地址与 API Key 鉴权"
            }
          >
            <span
              className={`h-2 w-2 rounded-full ${
                adspowerConfig?.hasApiKey ? "bg-[#16a34a]" : "bg-[#9ca3af]"
              }`}
              aria-hidden="true"
            />
            AdsPower API
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => fileInputRef.current?.click()}
            disabled={saving}
          >
            <FileUp className="h-3.5 w-3.5 text-[#7c8495]" aria-hidden="true" />
            导入 JSON
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleExportJson}
            disabled={accounts.length === 0}
          >
            <Download className="h-3.5 w-3.5 text-[#7c8495]" aria-hidden="true" />
            导出备份
          </Button>
          <Button variant="solid" size="sm" onClick={() => openEditor()}>
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            新增账号
          </Button>
        </div>
      </header>

      {/* Top 4-Column Telemetry Strip */}
      <section className="grid grid-cols-2 lg:grid-cols-4">
        <div className="flex flex-col gap-1 border-b border-r border-[#eaecef] p-4 px-5 lg:border-b-0">
          <div className="flex items-center justify-between gap-2 text-[0.74rem] font-medium text-[#7c8495]">
            <span>账号总数</span>
            <KeyRound className="h-3.5 w-3.5 text-[#6d5bd0]" aria-hidden="true" />
          </div>
          <div className="mono-num text-[1.2rem] font-semibold text-[#111827]">
            {stats.total}
          </div>
          <div className="text-[0.7rem] text-[#7c8495]">
            {loading ? "正在解密库..." : "仅本机当前 Windows 用户可解"}
          </div>
        </div>

        <div className="flex flex-col gap-1 border-b border-[#eaecef] p-4 px-5 lg:border-b-0 lg:border-r">
          <div className="flex items-center justify-between gap-2 text-[0.74rem] font-medium text-[#7c8495]">
            <span>正常使用</span>
            <Badge variant="success">可用</Badge>
          </div>
          <div className="mono-num text-[1.2rem] font-semibold text-[#15803d]">
            {stats.active}
          </div>
          <div className="mono-num text-[0.7rem] text-[#7c8495]">
            备用闲置 {stats.standby} 个
            {stats.quotaTracked > 0
              ? ` · 可用额度 ${stats.quotaReady}/${stats.quotaTracked}`
              : ""}
          </div>
        </div>

        <div className="flex flex-col gap-1 border-r border-[#eaecef] p-4 px-5">
          <div className="flex items-center justify-between gap-2 text-[0.74rem] font-medium text-[#7c8495]">
            <span>启动环境数</span>
            <Layers className="h-3.5 w-3.5 text-[#7c8495]" aria-hidden="true" />
          </div>
          <div className="mono-num text-[1.2rem] font-semibold text-[#111827]">
            {stats.envCount}
          </div>
          <div className="truncate text-[0.7rem] text-[#7c8495]">
            {distinctEnvironments.length > 0
              ? distinctEnvironments.slice(0, 3).join(" · ")
              : "暂未绑定环境"}
          </div>
        </div>

        <div className="flex flex-col gap-1 p-4 px-5">
          <div className="flex items-center justify-between gap-2 text-[0.74rem] font-medium text-[#7c8495]">
            <span>受限 / 已封禁</span>
            {stats.banned > 0 ? (
              <Badge variant="danger">{stats.banned} 封禁</Badge>
            ) : stats.quotaExpiring > 0 || stats.quotaExhausted > 0 ? (
              <Badge variant="warning">
                冷却 {stats.quotaExhausted} · 临期 {stats.quotaExpiring}
              </Badge>
            ) : (
              <Badge variant="neutral">状态良好</Badge>
            )}
          </div>
          <div className="mono-num text-[1.2rem] font-semibold text-[#111827]">
            {stats.restricted + stats.banned}
          </div>
          <div className="mono-num text-[0.7rem] text-[#7c8495]">
            受限 {stats.restricted} · 封禁 {stats.banned}
            {stats.quotaTracked > 0
              ? ` · 冷却 ${stats.quotaExhausted} / 临期 ${stats.quotaExpiring}`
              : ""}
          </div>
        </div>
      </section>

      {/* Active Account Environment Banner */}
      <section
        aria-label="当前激活的账号环境"
        className={`flex flex-wrap items-center justify-between gap-3 px-6 py-3 ${
          activeSession ? "bg-[#f8f7fe]" : "bg-[#fafbfc]"
        }`}
      >
        {activeSession ? (
          <>
            <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2 text-[0.75rem]">
              <span className="inline-flex items-center gap-1.5 font-semibold text-[#111827]">
                <span
                  className="h-2 w-2 shrink-0 rounded-full bg-[#16a34a]"
                  aria-hidden="true"
                />
                当前激活环境：
                <span className="truncate text-[#5b48c4]">
                  {activeSession.accountLabel || activeSession.email}
                </span>
              </span>
              {activeSession.accountLabel &&
                activeSession.accountLabel !== activeSession.email && (
                  <span className="mono-num truncate text-[0.71rem] text-[#525866]">
                    ({activeSession.email})
                  </span>
                )}
              <Badge variant="iris" className="mono-num">
                {activeSession.localPort > 0
                  ? `${activeSession.nodeName} · 127.0.0.1:${activeSession.localPort}`
                  : activeSession.nodeName}
              </Badge>
              {activeSession.verifiedExitIp && (
                <Badge variant="success" className="mono-num">
                  ✓ 出口核验 {activeSession.verifiedExitIp.ip} (
                  {activeSession.verifiedExitIp.countryCode || "--"})
                  {activeSession.verifiedExitIp.latencyMs
                    ? ` · ${activeSession.verifiedExitIp.latencyMs}ms`
                    : ""}
                </Badge>
              )}
              {activeSession.browserKind === "adspower" ? (
                <Badge
                  variant={
                    activeSession.adspowerUserId &&
                    runningAdspowerSet.has(activeSession.adspowerUserId)
                      ? "success"
                      : "neutral"
                  }
                >
                  AdsPower{" "}
                  {activeSession.adspowerProfileLabel
                    ? `(${activeSession.adspowerProfileLabel}) `
                    : ""}
                  {activeSession.adspowerUserId &&
                  runningAdspowerSet.has(activeSession.adspowerUserId)
                    ? "运行中"
                    : "已绑定"}
                </Badge>
              ) : activeSession.browserKind === "none" ? null : (
                activeSession.browserProfileId && (
                  <Badge
                    variant={
                      runningBrowserSet.has(activeSession.browserProfileId)
                        ? "success"
                        : "neutral"
                    }
                  >
                    专属浏览器{" "}
                    {runningBrowserSet.has(activeSession.browserProfileId)
                      ? "运行中"
                      : "已绑定"}
                  </Badge>
                )
              )}
            </div>

            <div className="flex shrink-0 flex-wrap items-center gap-1.5">
              {activeSession.browserKind !== "none" && (
                <Button
                  variant="outline"
                  size="xs"
                  disabled={launchingBrowserId === activeSession.accountId}
                  onClick={() => {
                    const acc = accounts.find((a) => a.id === activeSession.accountId);
                    if (acc) void handleRowLaunchBrowser(acc);
                    else void onLaunchBrowser(activeSession.accountId);
                  }}
                >
                  {launchingBrowserId === activeSession.accountId ? (
                    <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
                  ) : (
                    <Globe className="h-3 w-3 text-[#6d5bd0]" aria-hidden="true" />
                  )}
                  {activeSession.browserKind === "adspower"
                    ? "再开 AdsPower"
                    : "再开浏览器"}
                </Button>
              )}
              {activeSession.browserKind === "adspower" ? (
                activeSession.adspowerUserId &&
                runningAdspowerSet.has(activeSession.adspowerUserId) && (
                  <Button
                    variant="destructive-outline"
                    size="xs"
                    onClick={() => {
                      const target = activeSession.adspowerUserId!;
                      const isDigits = /^\d+$/.test(target);
                      void onCloseAdsPowerProfile(
                        isDigits ? null : target,
                        isDigits ? target : null,
                      );
                    }}
                  >
                    <Square className="h-3 w-3" aria-hidden="true" />
                    关闭 AdsPower
                  </Button>
                )
              ) : (
                activeSession.browserProfileId &&
                runningBrowserSet.has(activeSession.browserProfileId) && (
                  <Button
                    variant="destructive-outline"
                    size="xs"
                    onClick={() =>
                      void onCloseBrowserProfile(activeSession.browserProfileId!)
                    }
                  >
                    <Square className="h-3 w-3" aria-hidden="true" />
                    关闭浏览器
                  </Button>
                )
              )}
              <Button
                variant="ghost"
                size="xs"
                disabled={clearingSession}
                onClick={() => void handleClearSessionClick(false)}
              >
                清除状态
              </Button>
            </div>
          </>
        ) : (
          <div className="flex flex-wrap items-center gap-2 text-[0.73rem] text-[#7c8495]">
            <span
              className="h-2 w-2 shrink-0 rounded-full bg-[#9ca3af]"
              aria-hidden="true"
            />
            <span className="font-medium text-[#525866]">当前激活环境：待机</span>
            <span>
              点击下方任意已绑定节点的账号「🌐 浏览器」或「AdsPower」，将先完成外部真实出口 IP 强校验再纯净拉起（Antigravity 账号与代理启动已统一交由 Cockpit Tools 管理）
            </span>
          </div>
        )}
      </section>

      {/* Search & Filter Toolbar */}
      <section className="flex flex-col gap-3 bg-[#fafbfc] px-6 py-3.5">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative min-w-[14rem] flex-1">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[#9ca3af]"
              aria-hidden="true"
            />
            <label htmlFor={fid("search")} className="visually-hidden">
              搜索账号、环境或节点
            </label>
            <Input
              id={fid("search")}
              className="pl-8"
              placeholder="搜索邮箱、别名、用途、环境名、Clash/NetGuard 节点、标签..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <div className="w-48 shrink-0">
            <Select value={envFilter} onValueChange={setEnvFilter}>
              <SelectTrigger aria-label="按启动环境筛选">
                <SelectValue placeholder="全部环境" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__all__">全部环境 ({accounts.length})</SelectItem>
                {hasEmptyEnvAccount && (
                  <SelectItem value="__empty__">未设置环境</SelectItem>
                )}
                {distinctEnvironments.map((env) => (
                  <SelectItem key={env} value={env}>
                    {env}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {bannedIds.length > 0 && (
            <Button
              variant="destructive-outline"
              size="sm"
              disabled={saving}
              onClick={() => openConfirmDelete({ kind: "banned", ids: bannedIds })}
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
              清理已封禁 ({bannedIds.length})
            </Button>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="状态筛选">
            {(
              [
                { key: "all", label: "全部", count: stats.total },
                { key: "active", label: "正常", count: stats.active },
                { key: "standby", label: "备用", count: stats.standby },
                { key: "restricted", label: "受限", count: stats.restricted },
                { key: "banned", label: "已封禁", count: stats.banned },
              ] as { key: StatusFilter; label: string; count: number }[]
            ).map((pill) => {
              const selected = statusFilter === pill.key;
              return (
                <button
                  key={pill.key}
                  type="button"
                  onClick={() => setStatusFilter(pill.key)}
                  aria-pressed={selected}
                  className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[0.72rem] font-medium transition-colors cursor-pointer ${
                    selected
                      ? "border-[#dcd4fb] bg-[#f0edfc] text-[#5b48c4]"
                      : "border-[#eaecef] bg-white text-[#525866] hover:bg-[#f3f4f6] hover:text-[#111827]"
                  }`}
                >
                  <span>{pill.label}</span>
                  <span className="mono-num text-[0.68rem] opacity-80">{pill.count}</span>
                </button>
              );
            })}
            <button
              type="button"
              onClick={() => setQuotaReadyOnly((v) => !v)}
              aria-pressed={quotaReadyOnly}
              className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[0.72rem] font-medium transition-colors cursor-pointer ${
                quotaReadyOnly
                  ? "border-[#bbf7d0] bg-[#ecfdf5] text-[#15803d]"
                  : "border-[#eaecef] bg-white text-[#525866] hover:bg-[#f3f4f6] hover:text-[#111827]"
              }`}
              title="筛选开启了额度管理且至少有一个模型分组未耗尽、订阅未过期的账号"
            >
              <span>仅看有可用额度</span>
              <span className="mono-num text-[0.68rem] opacity-80">
                {stats.quotaReady}
              </span>
            </button>
          </div>

          <div className="flex items-center gap-2">
            {isFiltered && accounts.length > 1 && (
              <span className="rounded-md border border-[#eaecef] bg-white px-2 py-0.5 text-[0.68rem] text-[#7c8495]">
                筛选中已暂停拖拽调序
              </span>
            )}
            <span className="mono-num text-[0.71rem] text-[#7c8495]">
              显示 {filteredAccounts.length} / {accounts.length} 条
            </span>
          </div>
        </div>
      </section>

      <p role="status" className="visually-hidden">
        {reorderAnnouncement}
      </p>

      {/* Fixed Column Header Strip */}
      {filteredAccounts.length > 0 && (
        <div
          aria-hidden="true"
          className="grid grid-cols-[2rem_minmax(0,1.25fr)_minmax(0,1fr)_12.5rem] items-center gap-3 border-b border-[#eaecef] bg-[#f9fafb] px-5 py-2 text-[0.7rem] font-medium text-[#7c8495]"
        >
          <span className="text-center">排序</span>
          <span>账号与用途</span>
          <span>启动环境与节点</span>
          <span>密码与 2FA</span>
        </div>
      )}

      {/* Accounts List */}
      <section className="flex flex-col">
        {accounts.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-3 px-6 py-12 text-center">
            <span className="inline-grid h-11 w-11 place-items-center rounded-2xl bg-[#f0edfc] text-[#6d5bd0]">
              <KeyRound className="h-5 w-5" aria-hidden="true" />
            </span>
            <div className="max-w-md space-y-1">
              <div className="text-[0.9rem] font-semibold text-[#111827]">
                还没有录入任何账号与启动环境
              </div>
              <p className="text-[0.76rem] text-[#7c8495]">
                统一记录 Google / AI 等账号、密码与离线 2FA 动态码，并可自由配置指纹浏览器、本地或自定义环境与 NetGuard / Clash Verge 节点。
              </p>
            </div>
            <div className="flex flex-wrap items-center justify-center gap-2 pt-1">
              <Button variant="solid" size="sm" onClick={() => openEditor()}>
                <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                添加第一个账号
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => fileInputRef.current?.click()}
              >
                <FileUp className="h-3.5 w-3.5 text-[#7c8495]" aria-hidden="true" />
                从 JSON 导入
              </Button>
            </div>
          </div>
        ) : filteredAccounts.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2.5 px-6 py-10 text-center">
            <div className="text-[0.85rem] font-medium text-[#525866]">
              当前筛选条件下没有匹配的账号记录
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setSearch("");
                setEnvFilter("__all__");
                setStatusFilter("all");
                setQuotaReadyOnly(false);
              }}
            >
              重置筛选条件
            </Button>
          </div>
        ) : (
          <div ref={listRef} className="ng-account-list flex flex-col divide-y divide-[#eaecef]">
            {filteredAccounts.map((acc, rowIndex) => {
              const avatar = providerAvatar(acc.provider);
              const statusMeta = STATUS_META[acc.status] || STATUS_META.active;
              const envType = normalizeEnvType(acc.envType);
              const envMeta = ENV_TYPE_META[envType];
              const envNameTrimmed = acc.environmentName.trim();
              const envProfileTrimmed = acc.environmentProfile?.trim() || "";
              const nodeDisplay = resolveAccountNodeDisplay(
                acc,
                nodeById,
                browserProfileById,
              );
              const previewPort = resolveAccountPreviewPort(
                acc,
                nodeById,
                clashNodes,
                gatewayRunning,
                gatewayActiveNodeId,
                gatewayBrowserPort,
                secondaryNodePorts,
                browserProfileById,
              );
              const isUnbound = !nodeDisplay;
              const showBrowserBtn = acc.browserKind !== "none";
              const rowQuota = quotaByAccountId.get(acc.id);
              const isAdspower = acc.browserKind === "adspower";
              const adsUidTrimmed = acc.adspowerUserId?.trim() || "";
              const adsSnTrimmed =
                acc.adspowerSerialNumber?.trim().replace(/^#/, "") ||
                acc.environmentProfile?.trim().replace(/^#/, "") ||
                "";
              const hasAdspowerTarget = Boolean(adsUidTrimmed || adsSnTrimmed);
              const canLaunchBrowser = isAdspower ? hasAdspowerTarget : !isUnbound;
              const isBusyRow = launchingBrowserId === acc.id;
              const isAccBrowserRunning = isAdspower
                ? Boolean(
                    (adsUidTrimmed && runningAdspowerSet.has(adsUidTrimmed)) ||
                      (adsSnTrimmed && runningAdspowerSet.has(adsSnTrimmed)),
                  )
                : Boolean(
                    acc.linkedBrowserProfileId &&
                      runningBrowserSet.has(acc.linkedBrowserProfileId),
                  );
              const isActiveSessionAccount = activeSession?.accountId === acc.id;
              const isExpanded = Boolean(expandedIds[acc.id]);
              const isPassShown = Boolean(revealedPasswords[acc.id]);
              const isSecretShown = Boolean(revealedSecrets[acc.id]);
              const rawSecret = acc.totpSecret?.trim() || "";
              const totp = rawSecret ? generateTotp(rawSecret, nowMs) : null;
              const isBanned = acc.status === "banned";
              const isRestricted = acc.status === "restricted";
              const titleText = acc.label.trim() || acc.email;
              const visibleTags = acc.tags.slice(0, 2);
              const extraTagCount = acc.tags.length - visibleTags.length;

              return (
                <article
                  key={acc.id}
                  data-account-id={acc.id}
                  className={`ng-account-row grid grid-cols-[2rem_minmax(0,1fr)] items-start gap-3 px-5 py-3.5 transition-colors ${
                    isBanned
                      ? "bg-[#fef2f2]/35"
                      : isRestricted
                        ? "bg-[#fffbeb]/35"
                        : isActiveSessionAccount
                          ? "bg-[#f8f7fe]/70"
                          : "hover:bg-[#fafbfc]/70"
                  }`}
                >
                  {/* Left Sort Rail */}
                  <div className="flex w-8 shrink-0 flex-col items-center gap-0.5 pt-0.5">
                    <button
                      type="button"
                      className="ng-drag-handle inline-grid h-6 w-7 place-items-center rounded-md text-[#7c8495] transition-colors disabled:opacity-35"
                      disabled={reorderDisabled}
                      aria-label={`拖动调整 ${titleText} 的顺序`}
                      title={
                        isFiltered
                          ? "清空搜索和筛选条件后即可拖拽排序"
                          : "按住上下拖动调整顺序（Esc 取消）"
                      }
                      onPointerDown={(e) =>
                        handleDragPointerDown(e, acc.id, rowIndex)
                      }
                    >
                      <GripVertical className="h-3.5 w-3.5" aria-hidden="true" />
                    </button>
                    <button
                      type="button"
                      data-move="up"
                      disabled={reorderDisabled || rowIndex === 0}
                      onClick={() => handleMoveAccount(rowIndex, -1)}
                      aria-label={`上移 ${titleText}`}
                      title="上移一位"
                      className="inline-grid h-5 w-7 place-items-center rounded text-[#7c8495] transition-colors hover:bg-[#f3f4f6] hover:text-[#111827] disabled:pointer-events-none disabled:opacity-30 cursor-pointer"
                    >
                      <ChevronUp className="h-3 w-3" aria-hidden="true" />
                    </button>
                    <button
                      type="button"
                      data-move="down"
                      disabled={
                        reorderDisabled || rowIndex === filteredAccounts.length - 1
                      }
                      onClick={() => handleMoveAccount(rowIndex, 1)}
                      aria-label={`下移 ${titleText}`}
                      title="下移一位"
                      className="inline-grid h-5 w-7 place-items-center rounded text-[#7c8495] transition-colors hover:bg-[#f3f4f6] hover:text-[#111827] disabled:pointer-events-none disabled:opacity-30 cursor-pointer"
                    >
                      <ChevronDown className="h-3 w-3" aria-hidden="true" />
                    </button>
                  </div>

                  {/* Right Fixed Content */}
                  <div className="flex min-w-0 flex-col gap-2">
                    {/* Band 1: Fixed 1-Line Identity + Row Actions */}
                    <div className="flex h-7 items-center justify-between gap-2">
                      <div className="flex min-w-0 flex-1 items-center gap-2">
                        <span
                          className={`inline-grid h-6 w-6 shrink-0 place-items-center rounded-lg border text-[0.69rem] font-bold ${avatar.classes}`}
                          aria-hidden="true"
                        >
                          {avatar.code}
                        </span>
                        <span
                          title={titleText}
                          className={`min-w-0 truncate text-[0.86rem] font-semibold ${
                            isBanned
                              ? "text-[#7c8495] line-through"
                              : "text-[#111827]"
                          }`}
                        >
                          {titleText}
                        </span>
                        <Badge variant={statusMeta.variant} className="shrink-0">
                          {statusMeta.label}
                        </Badge>
                        <Badge
                          variant="neutral"
                          className="max-w-[6.5rem] shrink-0 overflow-hidden"
                          title={acc.provider}
                        >
                          <span className="truncate">{acc.provider}</span>
                        </Badge>
                      </div>

                      <div className="flex shrink-0 items-center gap-1">
                        {showBrowserBtn && (
                          <Button
                            variant={isAccBrowserRunning ? "solid" : "outline"}
                            size="xs"
                            disabled={isBusyRow || !canLaunchBrowser}
                            title={
                              isAdspower
                                ? !hasAdspowerTarget
                                  ? "已设为 AdsPower 模式，请先在「编辑」中选择或填写 AdsPower 环境 ID / 序号"
                                  : `通过 Local API 拉起 AdsPower 环境「${acc.adspowerProfileName || (adsSnTrimmed ? `#${adsSnTrimmed}` : adsUidTrimmed)}」${!isUnbound && previewPort.port ? `（启动前先核验 :${previewPort.port} 出口 IP，保持 AdsPower 原代理不变）` : "（使用 AdsPower 原代理设置）"}`
                                : isUnbound
                                  ? "未绑定节点（禁止裸连），请先在「编辑」中绑定节点"
                                  : isAccBrowserRunning
                                    ? `专属浏览器运行中${previewPort.port ? ` (:${previewPort.port})` : ""}，点击再开新标签页`
                                    : `打开此账号专属隔离指纹浏览器${previewPort.port ? ` (:${previewPort.port})` : ""}`
                            }
                            onClick={() => void handleRowLaunchBrowser(acc)}
                          >
                            {launchingBrowserId === acc.id ? (
                              <Loader2
                                className="h-3 w-3 animate-spin"
                                aria-hidden="true"
                              />
                            ) : isAccBrowserRunning ? (
                              <span
                                className="h-2 w-2 rounded-full bg-[#4ade80]"
                                aria-hidden="true"
                              />
                            ) : (
                              <Globe
                                className="h-3 w-3 text-[#6d5bd0]"
                                aria-hidden="true"
                              />
                            )}
                            {isAdspower ? "AdsPower" : "浏览器"}
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="xs"
                          onClick={() => toggleExpanded(acc.id)}
                          aria-expanded={isExpanded}
                        >
                          详情
                          {isExpanded ? (
                            <ChevronUp className="h-3.5 w-3.5" aria-hidden="true" />
                          ) : (
                            <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
                          )}
                        </Button>
                        <Button
                          variant="outline"
                          size="xs"
                          onClick={() => openEditor(acc)}
                        >
                          <Pencil className="h-3 w-3 text-[#525866]" aria-hidden="true" />
                          编辑
                        </Button>
                        <Button
                          variant="destructive-outline"
                          size="xs"
                          onClick={() => openConfirmDelete({ kind: "single", account: acc })}
                          aria-label={`删除 ${acc.email}`}
                        >
                          <Trash2 className="h-3 w-3" aria-hidden="true" />
                        </Button>
                      </div>
                    </div>

                    {/* Band 2: Fixed 3-Column Alignment Grid */}
                    <div className="grid grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)_12.5rem] items-center gap-3">
                      {/* Col 1: Account Email + Purpose/Tags */}
                      <div className="flex min-w-0 flex-col gap-1.5">
                        <div className="flex h-5 min-w-0 items-center gap-1.5">
                          <span className="w-7 shrink-0 text-[0.68rem] text-[#9ca3af]">
                            账号
                          </span>
                          <span
                            title={acc.email}
                            className="mono-num min-w-0 truncate text-[0.75rem] font-medium text-[#374151]"
                          >
                            {acc.email}
                          </span>
                          <button
                            type="button"
                            onClick={() => handleCopy(acc.email, "账号邮箱")}
                            className="inline-grid h-5 w-5 shrink-0 place-items-center rounded text-[#5b48c4] hover:bg-[#f0edfc] cursor-pointer"
                            aria-label={`复制账号 ${acc.email}`}
                            title="复制账号"
                          >
                            <Copy className="h-3 w-3" aria-hidden="true" />
                          </button>
                        </div>

                        <div className="flex h-5 min-w-0 items-center gap-1.5">
                          <span className="w-7 shrink-0 text-[0.68rem] text-[#9ca3af]">
                            用途
                          </span>
                          {acc.purpose ? (
                            <span
                              title={acc.purpose}
                              className="min-w-0 flex-1 truncate text-[0.72rem] text-[#525866]"
                            >
                              {acc.purpose}
                            </span>
                          ) : (
                            <span className="min-w-0 flex-1 truncate text-[0.72rem] text-[#9ca3af]">
                              未填写
                            </span>
                          )}
                          {visibleTags.length > 0 && (
                            <div
                              className="flex shrink-0 items-center gap-1"
                              title={acc.tags.map((t) => `#${t}`).join(" ")}
                            >
                              {visibleTags.map((tag) => (
                                <span
                                  key={tag}
                                  className="inline-flex max-w-[4.75rem] items-center truncate rounded-md border border-[#eaecef] bg-[#f8f9fb] px-1.5 py-0.5 text-[0.64rem] text-[#525866]"
                                >
                                  #{tag}
                                </span>
                              ))}
                              {extraTagCount > 0 && (
                                <span className="mono-num inline-flex items-center rounded-md border border-[#eaecef] bg-[#f8f9fb] px-1 py-0.5 text-[0.64rem] text-[#7c8495]">
                                  +{extraTagCount}
                                </span>
                              )}
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Col 2: Fixed Environment Slot + Fixed Node Slot */}
                      <div className="flex min-w-0 flex-col gap-1.5">
                        <div className="flex h-5 min-w-0 items-center gap-1.5">
                          <span className="w-7 shrink-0 text-[0.68rem] text-[#9ca3af]">
                            环境
                          </span>
                          <div className="flex min-w-0 flex-1 items-center">
                            {envNameTrimmed ? (
                              <Badge
                                variant={envMeta.badgeVariant}
                                className="max-w-full overflow-hidden"
                                title={`[${envMeta.short}] ${envNameTrimmed}${envProfileTrimmed ? ` · ${envProfileTrimmed}` : ""}`}
                              >
                                <span className="truncate">
                                  [{envMeta.short}] {envNameTrimmed}
                                  {envProfileTrimmed ? ` · ${envProfileTrimmed}` : ""}
                                </span>
                              </Badge>
                            ) : envProfileTrimmed ? (
                              <Badge
                                variant="neutral"
                                className="max-w-full overflow-hidden"
                                title={`标识 · ${envProfileTrimmed}`}
                              >
                                <span className="truncate">标识 · {envProfileTrimmed}</span>
                              </Badge>
                            ) : (
                              <span className="truncate text-[0.72rem] text-[#9ca3af]">
                                未设置
                              </span>
                            )}
                          </div>
                        </div>

                        <div className="flex h-5 min-w-0 items-center gap-1.5">
                          <span className="w-7 shrink-0 text-[0.68rem] text-[#9ca3af]">
                            节点
                          </span>
                          <div className="flex min-w-0 flex-1 items-center gap-1">
                            {nodeDisplay ? (
                              <>
                                <Badge
                                  variant={nodeDisplay.variant}
                                  className="min-w-0 max-w-full overflow-hidden"
                                  title={nodeDisplay.badgeText}
                                >
                                  <span className="truncate">{nodeDisplay.badgeText}</span>
                                </Badge>
                                {previewPort.port && (
                                  <span
                                    className="mono-num shrink-0 rounded border border-[#eaecef] bg-[#f8f9fb] px-1 py-0.5 text-[0.63rem] font-medium text-[#374151]"
                                    title={`独立本地监听端口 127.0.0.1:${previewPort.port}`}
                                  >
                                    :{previewPort.port}
                                  </span>
                                )}
                              </>
                            ) : (
                              <span className="truncate text-[0.72rem] text-[#9ca3af]">
                                未绑定
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Col 3: Fixed-Width Password + 2FA Column */}
                      <div className="flex w-[12.5rem] flex-col gap-1.5">
                        <div className="flex h-6 w-full items-center gap-1.5 rounded-md border border-[#eaecef] bg-[#f8f9fb] px-2">
                          <span className="shrink-0 text-[0.66rem] text-[#7c8495]">
                            密码
                          </span>
                          <span className="mono-num min-w-0 flex-1 truncate text-[0.73rem] font-medium text-[#111827]">
                            {acc.password
                              ? isPassShown
                                ? acc.password
                                : "••••••••••"
                              : "未设置"}
                          </span>
                          {acc.password && (
                            <>
                              <button
                                type="button"
                                onClick={() => toggleRevealPassword(acc.id)}
                                className="inline-grid h-4 w-4 shrink-0 place-items-center rounded text-[#7c8495] hover:bg-white hover:text-[#111827] cursor-pointer"
                                aria-label={isPassShown ? "隐藏密码" : "显示密码"}
                              >
                                {isPassShown ? (
                                  <EyeOff className="h-3 w-3" aria-hidden="true" />
                                ) : (
                                  <Eye className="h-3 w-3" aria-hidden="true" />
                                )}
                              </button>
                              <button
                                type="button"
                                onClick={() => handleCopy(acc.password, "登录密码")}
                                className="inline-grid h-4 w-4 shrink-0 place-items-center rounded text-[#5b48c4] hover:bg-white cursor-pointer"
                                aria-label="复制登录密码"
                              >
                                <Copy className="h-3 w-3" aria-hidden="true" />
                              </button>
                            </>
                          )}
                        </div>

                        {rawSecret ? (
                          totp ? (
                            <div className="flex h-6 w-full items-center justify-between gap-1 rounded-md border border-[#dcd4fb] bg-[#f0edfc]/65 px-2">
                              <span className="shrink-0 text-[0.66rem] font-medium text-[#5b48c4]">
                                2FA
                              </span>
                              <span className="mono-num text-[0.78rem] font-semibold tracking-wider text-[#111827]">
                                {totp.formatted}
                              </span>
                              <span
                                className={`mono-num shrink-0 rounded px-1 py-0.5 text-[0.64rem] font-semibold leading-none ${
                                  totp.remaining <= 5
                                    ? "bg-[#fffbeb] text-[#d97706]"
                                    : "bg-white text-[#5b48c4]"
                                }`}
                              >
                                {totp.remaining}s
                              </span>
                              <button
                                type="button"
                                onClick={() => handleCopy(totp.code, "2FA 验证码")}
                                className="inline-grid h-4 w-4 shrink-0 place-items-center rounded text-[#5b48c4] hover:bg-white cursor-pointer"
                                aria-label="复制当前 2FA 动态码"
                              >
                                <Copy className="h-3 w-3" aria-hidden="true" />
                              </button>
                            </div>
                          ) : (
                            <div className="flex h-6 w-full items-center rounded-md border border-[#fde68a] bg-[#fffbeb] px-2 text-[0.69rem] font-medium text-[#92400e]">
                              2FA 密钥格式无效
                            </div>
                          )
                        ) : acc.recoveryCodes ? (
                          <div className="flex h-6 w-full items-center rounded-md border border-[#e5e7eb] bg-[#f3f4f6] px-2 text-[0.69rem] font-medium text-[#4b5563]">
                            含备用恢复码
                          </div>
                        ) : (
                          <div className="flex h-6 w-full items-center rounded-md border border-dashed border-[#dce0e6] px-2 text-[0.69rem] text-[#9ca3af]">
                            未配置 2FA
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Band 3: Compact Cockpit Quota Bar (only when enabled) */}
                    {rowQuota?.enabled && rowQuota.pools.length > 0 && (
                      <div
                        data-quota-bar={acc.id}
                        className="space-y-1.5 rounded-lg border border-[#eaecef] bg-[#fafbfc] px-3 py-2"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2 text-[0.7rem]">
                          <div className="flex flex-wrap items-center gap-1.5">
                            {rowQuota.planTier && (
                              <Badge variant="iris" className="mono-num">
                                {rowQuota.planTier}
                              </Badge>
                            )}
                            {rowQuota.expiry && (
                              <Badge
                                variant={
                                  rowQuota.expiry.state === "expired"
                                    ? "danger"
                                    : rowQuota.expiry.state === "soon"
                                      ? "warning"
                                      : "neutral"
                                }
                                className="mono-num"
                                title={`订阅到期日: ${acc.quota?.expiresAt || ""}`}
                              >
                                {rowQuota.expiry.label}
                              </Badge>
                            )}
                            {rowQuota.allExhausted ? (
                              <Badge variant="danger">全池冷却中</Badge>
                            ) : (
                              <Badge variant="success">额度可用</Badge>
                            )}
                          </div>

                          {rowQuota.pools.some((item) => item.effectivePct < 100) && (
                            <button
                              type="button"
                              disabled={saving}
                              onClick={() => {
                                const refilled = (acc.quota?.pools ?? []).map((p) => ({
                                  ...p,
                                  remainingPct: 100,
                                  resetAt: null,
                                }));
                                void handleUpdateQuotaPools(
                                  acc,
                                  refilled,
                                  `已将「${titleText}」全部模型额度重置为 100%`,
                                );
                              }}
                              className="rounded border border-[#dcd4fb] bg-white px-2 py-0.5 text-[0.67rem] font-medium text-[#5b48c4] hover:bg-[#f0edfc] cursor-pointer disabled:opacity-45"
                            >
                              全部回满
                            </button>
                          )}
                        </div>

                        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 md:grid-cols-3">
                          {rowQuota.pools.map((item, idx) => {
                            const barColor =
                              item.effectivePct <= 0
                                ? "bg-[#ef4444]"
                                : item.effectivePct <= 25
                                  ? "bg-[#f59e0b]"
                                  : "bg-[#16a34a]";
                            const textColor =
                              item.effectivePct <= 0
                                ? "text-[#dc2626]"
                                : item.effectivePct <= 25
                                  ? "text-[#d97706]"
                                  : "text-[#15803d]";
                            return (
                              <div
                                key={`${item.pool.id}-${idx}`}
                                className="space-y-1 rounded-md border border-[#eaecef] bg-white px-2.5 py-1.5"
                              >
                                <div className="flex items-center justify-between gap-2 text-[0.7rem]">
                                  <span
                                    title={item.pool.label}
                                    className="min-w-0 truncate font-medium text-[#111827]"
                                  >
                                    {item.pool.label}
                                  </span>
                                  <span className={`mono-num shrink-0 font-semibold ${textColor}`}>
                                    {item.effectivePct}%
                                  </span>
                                </div>
                                <div className="h-1.5 w-full overflow-hidden rounded-full bg-[#e5e7eb]">
                                  <div
                                    className={`h-full rounded-full transition-all ${barColor}`}
                                    style={{ width: `${item.effectivePct}%` }}
                                  />
                                </div>
                                <div className="flex items-center justify-between gap-1 text-[0.65rem]">
                                  <span className="mono-num truncate text-[#7c8495]">
                                    {item.countdownText
                                      ? `恢复 ${item.countdownText}`
                                      : item.effectivePct >= 100
                                        ? "满血就绪"
                                        : item.pool.resetHours > 0
                                          ? `周期 ${item.pool.resetHours}h`
                                          : "手动控制"}
                                  </span>
                                  <div className="flex shrink-0 items-center gap-1">
                                    {item.effectivePct > 0 && (
                                      <>
                                        <button
                                          type="button"
                                          disabled={saving}
                                          onClick={() => {
                                            const nextPct = Math.max(
                                              0,
                                              item.effectivePct - 20,
                                            );
                                            const nextResetAt =
                                              nextPct === 0 && item.pool.resetHours > 0
                                                ? new Date(
                                                    Date.now() +
                                                      item.pool.resetHours * 3_600_000,
                                                  ).toISOString()
                                                : item.isRefilled
                                                  ? null
                                                  : item.pool.resetAt || null;
                                            const updated = (acc.quota?.pools ?? []).map(
                                              (p, i) =>
                                                i === idx
                                                  ? {
                                                      ...p,
                                                      remainingPct: nextPct,
                                                      resetAt: nextResetAt,
                                                    }
                                                  : p,
                                            );
                                            void handleUpdateQuotaPools(
                                              acc,
                                              updated,
                                              `「${item.pool.label}」剩余额度已调整为 ${nextPct}%`,
                                            );
                                          }}
                                          className="mono-num rounded border border-[#eaecef] bg-[#f8f9fb] px-1.5 py-0.5 text-[0.63rem] text-[#525866] hover:bg-[#f3f4f6] cursor-pointer disabled:opacity-45"
                                        >
                                          -20%
                                        </button>
                                        <button
                                          type="button"
                                          disabled={saving}
                                          onClick={() => {
                                            const nextResetAt =
                                              item.pool.resetHours > 0
                                                ? new Date(
                                                    Date.now() +
                                                      item.pool.resetHours * 3_600_000,
                                                  ).toISOString()
                                                : null;
                                            const updated = (acc.quota?.pools ?? []).map(
                                              (p, i) =>
                                                i === idx
                                                  ? {
                                                      ...p,
                                                      remainingPct: 0,
                                                      resetAt: nextResetAt,
                                                    }
                                                  : p,
                                            );
                                            void handleUpdateQuotaPools(
                                              acc,
                                              updated,
                                              item.pool.resetHours > 0
                                                ? `已标记「${item.pool.label}」耗尽，开始 ${item.pool.resetHours}h 恢复倒计时`
                                                : `已标记「${item.pool.label}」额度耗尽`,
                                            );
                                          }}
                                          className="rounded border border-[#fecaca] bg-[#fef2f2] px-1.5 py-0.5 text-[0.63rem] font-medium text-[#dc2626] hover:bg-[#fee2e2] cursor-pointer disabled:opacity-45"
                                        >
                                          耗尽
                                        </button>
                                      </>
                                    )}
                                    {item.effectivePct < 100 && (
                                      <button
                                        type="button"
                                        disabled={saving}
                                        onClick={() => {
                                          const updated = (acc.quota?.pools ?? []).map(
                                            (p, i) =>
                                              i === idx
                                                ? {
                                                    ...p,
                                                    remainingPct: 100,
                                                    resetAt: null,
                                                  }
                                                : p,
                                          );
                                          void handleUpdateQuotaPools(
                                            acc,
                                            updated,
                                            `已恢复「${item.pool.label}」为 100%`,
                                          );
                                        }}
                                        className="rounded border border-[#bbf7d0] bg-[#ecfdf5] px-1.5 py-0.5 text-[0.63rem] font-medium text-[#15803d] hover:bg-[#dcfce7] cursor-pointer disabled:opacity-45"
                                      >
                                        回满
                                      </button>
                                    )}
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* Inline Expanded Details */}
                    {isExpanded && (
                      <div className="space-y-3 rounded-xl border border-[#eaecef] bg-[#fafbfc] p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#eaecef] pb-2.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="text-[0.72rem] font-medium text-[#525866]">
                          快捷切换状态:
                        </span>
                        {(["active", "standby", "restricted", "banned"] as AccountStatus[]).map(
                          (st) => {
                            const active = acc.status === st;
                            return (
                              <button
                                key={st}
                                type="button"
                                disabled={saving}
                                onClick={() => handleQuickStatus(acc, st)}
                                className={`rounded-md border px-2 py-0.5 text-[0.7rem] font-medium transition-colors cursor-pointer ${
                                  active
                                    ? "border-[#5b48c4] bg-[#6d5bd0] text-white"
                                    : "border-[#dce0e6] bg-white text-[#525866] hover:bg-[#f3f4f6]"
                                }`}
                              >
                                {STATUS_META[st].label}
                              </button>
                            );
                          },
                        )}
                      </div>

                      <div className="mono-num flex flex-wrap items-center gap-3 text-[0.69rem] text-[#7c8495]">
                        <span>
                          启动环境: {envNameTrimmed ? `${envMeta.label} · ${envNameTrimmed}` : "未绑定"}
                        </span>
                        {acc.createdAt && <span>创建: {acc.createdAt}</span>}
                        {acc.updatedAt && <span>更新: {acc.updatedAt}</span>}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                      {/* Bound Node Info */}
                      <div className="space-y-1 rounded-lg border border-[#eaecef] bg-white p-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[0.71rem] font-medium text-[#7c8495]">
                            绑定节点 ({nodeDisplay ? nodeDisplay.sourceLabel : "未绑定"})
                          </span>
                          {nodeDisplay && (
                            <button
                              type="button"
                              onClick={() => handleCopy(nodeDisplay.name, "节点名称")}
                              className="inline-flex items-center gap-1 text-[0.69rem] text-[#5b48c4] hover:underline cursor-pointer"
                            >
                              <Copy className="h-3 w-3" aria-hidden="true" />
                              复制节点名
                            </button>
                          )}
                        </div>
                        <div className="mono-num break-all text-[0.76rem] text-[#111827]">
                          {nodeDisplay ? nodeDisplay.name : "未绑定固定出口节点"}
                        </div>
                      </div>

                      {/* Recovery Email */}
                      <div className="space-y-1 rounded-lg border border-[#eaecef] bg-white p-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[0.71rem] font-medium text-[#7c8495]">
                            辅助邮箱 / 恢复手机
                          </span>
                          {acc.recoveryEmail && (
                            <button
                              type="button"
                              onClick={() =>
                                handleCopy(acc.recoveryEmail || "", "辅助邮箱/手机")
                              }
                              className="inline-flex items-center gap-1 text-[0.69rem] text-[#5b48c4] hover:underline cursor-pointer"
                            >
                              <Copy className="h-3 w-3" aria-hidden="true" />
                              复制
                            </button>
                          )}
                        </div>
                        <div className="mono-num break-all text-[0.76rem] text-[#111827]">
                          {acc.recoveryEmail || "未填写"}
                        </div>
                      </div>

                      {/* Raw 2FA Secret */}
                      <div className="space-y-1 rounded-lg border border-[#eaecef] bg-white p-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[0.71rem] font-medium text-[#7c8495]">
                            2FA 原始密钥 / URI
                          </span>
                          {rawSecret && (
                            <div className="flex items-center gap-2">
                              <button
                                type="button"
                                onClick={() => toggleRevealSecret(acc.id)}
                                className="inline-flex items-center gap-1 text-[0.69rem] text-[#525866] hover:text-[#111827] cursor-pointer"
                              >
                                {isSecretShown ? "隐藏" : "显示"}
                              </button>
                              <button
                                type="button"
                                onClick={() => handleCopy(rawSecret, "2FA 密钥")}
                                className="inline-flex items-center gap-1 text-[0.69rem] text-[#5b48c4] hover:underline cursor-pointer"
                              >
                                <Copy className="h-3 w-3" aria-hidden="true" />
                                复制
                              </button>
                            </div>
                          )}
                        </div>
                        <div className="mono-num break-all text-[0.74rem] text-[#111827]">
                          {rawSecret
                            ? isSecretShown
                              ? rawSecret
                              : "••••••••••••••••••••••••"
                            : "未配置"}
                        </div>
                      </div>

                      {/* Recovery Codes */}
                      <div className="space-y-1 rounded-lg border border-[#eaecef] bg-white p-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[0.71rem] font-medium text-[#7c8495]">
                            2FA 备用恢复码
                          </span>
                          {acc.recoveryCodes && (
                            <div className="flex items-center gap-2">
                              <button
                                type="button"
                                onClick={() => toggleRevealSecret(acc.id)}
                                className="inline-flex items-center gap-1 text-[0.69rem] text-[#525866] hover:text-[#111827] cursor-pointer"
                              >
                                {isSecretShown ? "隐藏" : "显示"}
                              </button>
                              <button
                                type="button"
                                onClick={() =>
                                  handleCopy(acc.recoveryCodes || "", "备用恢复码")
                                }
                                className="inline-flex items-center gap-1 text-[0.69rem] text-[#5b48c4] hover:underline cursor-pointer"
                              >
                                <Copy className="h-3 w-3" aria-hidden="true" />
                                复制
                              </button>
                            </div>
                          )}
                        </div>
                        <div className="mono-num whitespace-pre-wrap break-all text-[0.74rem] text-[#111827]">
                          {acc.recoveryCodes
                            ? isSecretShown
                              ? acc.recoveryCodes
                              : "••••-•••• (点击显示查看备用恢复码)"
                            : "未记录"}
                        </div>
                      </div>

                      {/* Notes */}
                      <div className="space-y-1 rounded-lg border border-[#eaecef] bg-white p-3 md:col-span-2">
                        <span className="block text-[0.71rem] font-medium text-[#7c8495]">
                          环境与账号备注
                        </span>
                        <div className="whitespace-pre-wrap break-words text-[0.75rem] text-[#374151]">
                          {acc.notes || "暂无备注"}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>

      {/* Modal 1: Add / Edit Account Native <dialog> */}
      <dialog
        ref={editorDialogRef}
        aria-labelledby={editorTitleId}
        {...({ closedby: "any" } as Record<string, string>)}
        onClose={() => {
          if (editorDialogRef.current) {
            editorDialogRef.current.returnValue = "";
          }
          setEditorOpen(false);
        }}
        className="ng-dialog m-auto w-[min(46rem,calc(100vi-2rem))] max-w-none overflow-hidden rounded-2xl border border-[#dce0e6] bg-white p-0 text-[#111827] shadow-[0_24px_56px_-12px_rgba(15,23,42,0.28)]"
      >
        <form onSubmit={handleSubmitForm} className="flex max-h-[88dvh] flex-col overflow-hidden">
          {/* Modal Header */}
          <div className="flex shrink-0 items-center justify-between gap-3 border-b border-[#eaecef] px-6 py-3.5">
            <div className="min-w-0">
              <h2
                id={editorTitleId}
                className="text-[1rem] font-semibold tracking-tight text-[#111827]"
              >
                {form.id ? "编辑账号与环境" : "新增账号与启动环境"}
              </h2>
              <p className="mt-0.5 text-[0.72rem] text-[#7c8495]">
                凭据将通过 Windows DPAPI 加密保存于本地 accounts.vault，绝不联网上传
              </p>
            </div>
            <button
              type="button"
              onClick={closeEditor}
              aria-label="关闭窗口"
              className="inline-grid h-7 w-7 shrink-0 place-items-center rounded-lg text-[#7c8495] hover:bg-[#f3f4f6] hover:text-[#111827] cursor-pointer"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>

          {/* Modal Scrollable Body */}
          <div className="app-scroll min-h-0 flex-1 space-y-4 overflow-y-auto px-6 py-4">
            {formError && (
              <div
                role="alert"
                className="flex items-center gap-2 rounded-xl border border-[#fecaca] bg-[#fef2f2] px-3.5 py-2 text-[0.76rem] font-medium text-[#dc2626]"
              >
                <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />
                <span>{formError}</span>
              </div>
            )}

            {/* Section 1: Account Identity */}
            <fieldset className="space-y-3">
              <legend className="text-[0.76rem] font-semibold text-[#111827]">
                1. 账号基本信息
              </legend>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <label
                      htmlFor={fid("provider")}
                      className="text-[0.73rem] font-medium text-[#525866]"
                    >
                      所属平台
                    </label>
                    <div className="flex flex-wrap gap-1">
                      {PROVIDER_PRESETS.map((p) => (
                        <button
                          key={p}
                          type="button"
                          onClick={() => setForm((prev) => ({ ...prev, provider: p }))}
                          className={`rounded border px-1.5 py-0.5 text-[0.66rem] cursor-pointer ${
                            form.provider === p
                              ? "border-[#dcd4fb] bg-[#f0edfc] font-semibold text-[#5b48c4]"
                              : "border-[#eaecef] bg-[#f8f9fb] text-[#525866] hover:bg-[#f3f4f6]"
                          }`}
                        >
                          {p}
                        </button>
                      ))}
                    </div>
                  </div>
                  <Input
                    id={fid("provider")}
                    placeholder="Google / Claude / CloudCart..."
                    value={form.provider}
                    onChange={(e) =>
                      setForm((prev) => ({ ...prev, provider: e.target.value }))
                    }
                  />
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor={fid("status")}
                    className="block text-[0.73rem] font-medium text-[#525866]"
                  >
                    账号状态
                  </label>
                  <select
                    id={fid("status")}
                    className={NATIVE_SELECT_CLASS}
                    value={form.status}
                    onChange={(e) =>
                      setForm((prev) => ({
                        ...prev,
                        status: e.target.value as AccountStatus,
                      }))
                    }
                  >
                    <option value="active">正常使用 (Active)</option>
                    <option value="standby">备用闲置 (Standby)</option>
                    <option value="restricted">风控受限 (Restricted)</option>
                    <option value="banned">已封禁 (Banned)</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor={fid("email")}
                    className="block text-[0.73rem] font-medium text-[#525866]"
                  >
                    账号 / 邮箱 <span className="text-[#dc2626]">*</span>
                  </label>
                  <Input
                    ref={emailInputRef}
                    id={fid("email")}
                    autoFocus
                    className="mono-num"
                    placeholder="name@gmail.com"
                    value={form.email}
                    onChange={(e) =>
                      setForm((prev) => ({ ...prev, email: e.target.value }))
                    }
                  />
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor={fid("label")}
                    className="block text-[0.73rem] font-medium text-[#525866]"
                  >
                    别名 / 识别名称
                  </label>
                  <Input
                    id={fid("label")}
                    placeholder="例如：Google 主号 #1 / 美区店铺号"
                    value={form.label}
                    onChange={(e) =>
                      setForm((prev) => ({ ...prev, label: e.target.value }))
                    }
                  />
                </div>
              </div>
            </fieldset>

            {/* Section 2: Credentials & 2FA */}
            <fieldset className="space-y-3 border-t border-[#eaecef] pt-4">
              <legend className="text-[0.76rem] font-semibold text-[#111827]">
                2. 登录凭据与二步验证 (2FA)
              </legend>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <label
                      htmlFor={fid("password")}
                      className="text-[0.73rem] font-medium text-[#525866]"
                    >
                      登录密码
                    </label>
                    <button
                      type="button"
                      onClick={() => {
                        const pwd = generateStrongPassword(18);
                        setForm((prev) => ({ ...prev, password: pwd }));
                        setShowFormPassword(true);
                      }}
                      className="inline-flex items-center gap-1 text-[0.68rem] font-medium text-[#5b48c4] hover:underline cursor-pointer"
                    >
                      <Sparkles className="h-3 w-3" aria-hidden="true" />
                      生成强密码
                    </button>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Input
                      id={fid("password")}
                      type={showFormPassword ? "text" : "password"}
                      className="mono-num flex-1"
                      placeholder="输入或生成登录密码"
                      value={form.password}
                      onChange={(e) =>
                        setForm((prev) => ({ ...prev, password: e.target.value }))
                      }
                    />
                    <Button
                      type="button"
                      variant="outline"
                      size="icon"
                      onClick={() => setShowFormPassword((v) => !v)}
                      aria-label={showFormPassword ? "隐藏密码" : "显示密码"}
                      className="h-8 w-8 shrink-0 text-[#7c8495] hover:text-[#111827]"
                    >
                      {showFormPassword ? (
                        <EyeOff className="h-3.5 w-3.5" aria-hidden="true" />
                      ) : (
                        <Eye className="h-3.5 w-3.5" aria-hidden="true" />
                      )}
                    </Button>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor={fid("recoveryEmail")}
                    className="block text-[0.73rem] font-medium text-[#525866]"
                  >
                    辅助邮箱 / 接码手机
                  </label>
                  <Input
                    id={fid("recoveryEmail")}
                    className="mono-num"
                    placeholder="recovery@outlook.com / +1 ..."
                    value={form.recoveryEmail}
                    onChange={(e) =>
                      setForm((prev) => ({ ...prev, recoveryEmail: e.target.value }))
                    }
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label
                  htmlFor={fid("totpSecret")}
                  className="block text-[0.73rem] font-medium text-[#525866]"
                >
                  2FA TOTP 密钥或 otpauth:// 链接
                </label>
                <Input
                  id={fid("totpSecret")}
                  className="mono-num"
                  placeholder="例如：JBSWY3DPEHPK3PXP 或 otpauth://totp/..."
                  value={form.totpSecret}
                  onChange={(e) =>
                    setForm((prev) => ({ ...prev, totpSecret: e.target.value }))
                  }
                />
                {formTotpPreview.present && (
                  <div className="flex items-center gap-2 text-[0.72rem]">
                    {formTotpPreview.result ? (
                      <span className="inline-flex items-center gap-1.5 rounded-md border border-[#dcd4fb] bg-[#f0edfc] px-2 py-0.5 text-[#5b48c4]">
                        <RefreshCw className="h-3 w-3" aria-hidden="true" />
                        实时验证码预览:{" "}
                        <strong className="mono-num text-[#111827]">
                          {formTotpPreview.result.formatted}
                        </strong>
                        <span className="mono-num">
                          ({formTotpPreview.result.remaining}s)
                        </span>
                      </span>
                    ) : (
                      <span className="text-[#d97706]">
                        密钥格式暂无法解析（请填写 Base32 密钥或标准 otpauth://totp/... URI）
                      </span>
                    )}
                  </div>
                )}
              </div>

              <div className="space-y-1.5">
                <label
                  htmlFor={fid("recoveryCodes")}
                  className="block text-[0.73rem] font-medium text-[#525866]"
                >
                  2FA 备用恢复码（每行或空格分隔）
                </label>
                <textarea
                  id={fid("recoveryCodes")}
                  rows={2}
                  className={`${TEXTAREA_CLASS} mono-num`}
                  placeholder="粘贴 Google 8 位一次性备用恢复码..."
                  value={form.recoveryCodes}
                  onChange={(e) =>
                    setForm((prev) => ({ ...prev, recoveryCodes: e.target.value }))
                  }
                />
              </div>
            </fieldset>

            {/* Section 3: Customizable Optional Launch Environment + Multi-Source Node Binding */}
            <fieldset className="space-y-3 border-t border-[#eaecef] pt-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <legend className="text-[0.76rem] font-semibold text-[#111827]">
                  3. 启动环境与绑定节点（均为可选项，可留空）
                </legend>
                <button
                  type="button"
                  onClick={() => setAddingPreset((v) => !v)}
                  className="inline-flex items-center gap-1 rounded-md border border-[#dce0e6] bg-white px-2 py-0.5 text-[0.68rem] font-medium text-[#5b48c4] hover:bg-[#f0edfc] cursor-pointer"
                >
                  <Plus className="h-3 w-3" aria-hidden="true" />
                  新增环境预设
                </button>
              </div>

              {/* Customizable Environment Chips */}
              <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-1.5">
                  {envPresets.length > 0 ? (
                    envPresets.map((preset) => {
                      const active =
                        form.environmentName.trim() === preset.name &&
                        form.envType === preset.envType;
                      const meta = ENV_TYPE_META[normalizeEnvType(preset.envType)];
                      return (
                        <div
                          key={preset.id}
                          className={`inline-flex items-center overflow-hidden rounded-md border text-[0.69rem] ${
                            active
                              ? "border-[#c4b5fd] bg-[#f0edfc] text-[#5b48c4] font-semibold"
                              : "border-[#eaecef] bg-[#f8f9fb] text-[#525866]"
                          }`}
                        >
                          <button
                            type="button"
                            onClick={() =>
                              setForm((prev) =>
                                active
                                  ? { ...prev, environmentName: "" }
                                  : {
                                      ...prev,
                                      envType: normalizeEnvType(preset.envType),
                                      environmentName: preset.name,
                                    },
                              )
                            }
                            className="inline-flex items-center gap-1 px-2 py-0.5 hover:bg-black/5 cursor-pointer"
                          >
                            <span className="opacity-70">[{meta.short}]</span>
                            <span>{preset.name}</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => handleRemoveEnvPreset(preset)}
                            aria-label={`删除环境预设 ${preset.name}`}
                            className="inline-grid h-5 w-5 place-items-center border-l border-black/10 text-[#7c8495] hover:bg-[#fee2e2] hover:text-[#dc2626] cursor-pointer"
                          >
                            <X className="h-2.5 w-2.5" aria-hidden="true" />
                          </button>
                        </div>
                      );
                    })
                  ) : (
                    <span className="text-[0.71rem] text-[#9ca3af]">
                      预设环境列表已清空，可点击右上角「新增环境预设」或直接在下方输入/留空
                    </span>
                  )}
                </div>

                {addingPreset && (
                  <div className="flex flex-wrap items-center gap-2 rounded-xl border border-[#dcd4fb] bg-[#f8f7fe] p-2.5">
                    <Input
                      className="min-w-[9rem] flex-1"
                      placeholder="输入常用环境名，例如 CloudCart / 比特浏览器"
                      value={newPresetName}
                      onChange={(e) => setNewPresetName(e.target.value)}
                    />
                    <div className="w-32 shrink-0">
                      <select
                        aria-label="新环境分类"
                        className={NATIVE_SELECT_CLASS}
                        value={newPresetType}
                        onChange={(e) =>
                          setNewPresetType(e.target.value as AccountEnvType)
                        }
                      >
                        <option value="fingerprint">指纹浏览器</option>
                        <option value="local">本地</option>
                        <option value="custom">自定义</option>
                      </select>
                    </div>
                    <Button
                      type="button"
                      variant="solid"
                      size="xs"
                      onClick={handleAddEnvPreset}
                      disabled={!newPresetName.trim()}
                    >
                      添加
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      size="xs"
                      onClick={() => {
                        setAddingPreset(false);
                        setNewPresetName("");
                      }}
                    >
                      取消
                    </Button>
                  </div>
                )}
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div className="space-y-1.5">
                  <label
                    htmlFor={fid("envType")}
                    className="block text-[0.73rem] font-medium text-[#525866]"
                  >
                    环境大类
                  </label>
                  <select
                    id={fid("envType")}
                    className={NATIVE_SELECT_CLASS}
                    value={form.envType}
                    onChange={(e) =>
                      setForm((prev) => ({
                        ...prev,
                        envType: e.target.value as AccountEnvType,
                      }))
                    }
                  >
                    <option value="fingerprint">指纹浏览器</option>
                    <option value="local">本地</option>
                    <option value="custom">自定义</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor={fid("environmentName")}
                    className="block text-[0.73rem] font-medium text-[#525866]"
                  >
                    环境名称（可留空）
                  </label>
                  <div className="flex items-center gap-1">
                    <Input
                      id={fid("environmentName")}
                      className="flex-1"
                      placeholder="留空或手填，如 CloudCart"
                      value={form.environmentName}
                      onChange={(e) =>
                        setForm((prev) => ({
                          ...prev,
                          environmentName: e.target.value,
                        }))
                      }
                    />
                    {form.environmentName && (
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        aria-label="清空环境名称"
                        onClick={() =>
                          setForm((prev) => ({ ...prev, environmentName: "" }))
                        }
                        className="h-8 w-8 shrink-0 text-[#7c8495]"
                      >
                        <X className="h-3.5 w-3.5" aria-hidden="true" />
                      </Button>
                    )}
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor={fid("environmentProfile")}
                    className="block text-[0.73rem] font-medium text-[#525866]"
                  >
                    窗口编号 / 标识（可选）
                  </label>
                  <Input
                    id={fid("environmentProfile")}
                    className="mono-num"
                    placeholder="例如：#042 / Profile-US"
                    value={form.environmentProfile}
                    onChange={(e) =>
                      setForm((prev) => ({
                        ...prev,
                        environmentProfile: e.target.value,
                      }))
                    }
                  />
                </div>
              </div>

              {/* Browser Engine */}
              <div className="space-y-3 rounded-xl border border-[#eaecef] bg-[#fafbfc] p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[0.73rem] font-medium text-[#525866]">
                    浏览器启动引擎（不需要专用浏览器时选「不启用」）
                  </span>
                  <div className="flex flex-wrap gap-1" role="group" aria-label="浏览器引擎">
                    {(
                      [
                        { value: "none", label: "不启用" },
                        { value: "netguard", label: "NetGuard 内置浏览器" },
                        { value: "adspower", label: "AdsPower 专属窗口" },
                      ] as const
                    ).map((opt) => {
                      const active = form.browserKind === opt.value;
                      return (
                        <button
                          key={opt.value}
                          type="button"
                          aria-pressed={active}
                          onClick={() => {
                            setForm((prev) => ({ ...prev, browserKind: opt.value }));
                            if (
                              opt.value === "adspower" &&
                              !adspowerProfiles?.connected
                            ) {
                              void onRefreshAdsPowerProfiles();
                            }
                          }}
                          className={`rounded-md border px-2 py-0.5 text-[0.69rem] font-medium transition-colors cursor-pointer ${
                            active
                              ? "border-[#dcd4fb] bg-[#6d5bd0] text-white"
                              : "border-[#dce0e6] bg-white text-[#525866] hover:bg-[#f3f4f6]"
                          }`}
                        >
                          {opt.label}
                        </button>
                      );
                    })}
                  </div>
                </div>

                {form.browserKind === "none" ? (
                  <p className="rounded-lg border border-dashed border-[#dce0e6] bg-white px-3 py-2 text-[0.7rem] text-[#7c8495]">
                    已关闭此账号的浏览器启动功能，列表中将不再显示「🌐 浏览器 / AdsPower」按钮。
                  </p>
                ) : form.browserKind === "netguard" ? (
                  <div className="space-y-1.5">
                    <label
                      htmlFor={fid("linkedBrowserProfileId")}
                      className="block text-[0.71rem] font-medium text-[#7c8495]"
                    >
                      关联「指纹浏览器」独立档案
                    </label>
                    <select
                      id={fid("linkedBrowserProfileId")}
                      className={NATIVE_SELECT_CLASS}
                      value={form.linkedBrowserProfileId}
                      onChange={(e) => {
                        const nextPid = e.target.value;
                        const hasSelectedProfile = Boolean(nextPid.trim());
                        setForm((prev) => ({
                          ...prev,
                          linkedBrowserProfileId: nextPid,
                          ...(hasSelectedProfile
                            ? {
                                linkedNodeSource: "none" as AccountNodeSource,
                                linkedNodeId: "",
                                linkedNodeName: "",
                                linkedProxyPort: "",
                              }
                            : {}),
                        }));
                        setOverrideProfileExit(!hasSelectedProfile);
                      }}
                    >
                      <option value="">
                        自动为本账号创建并记住独立环境（推荐，独立缓存目录 + 指纹）
                      </option>
                      {browserProfiles.map((bp) => (
                        <option key={bp.id} value={bp.id}>
                          {bp.name}
                          {bp.customProxyUrl
                            ? ` · ${bp.customProxyUrl}`
                            : bp.nodeId
                              ? ` · ${nodeById.get(bp.nodeId)?.name || bp.nodeId}`
                              : ""}
                        </option>
                      ))}
                    </select>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-[0.7rem] text-[#7c8495]">
                      <span>
                        {adspowerProfiles?.connected
                          ? `已连接 AdsPower：读取到 ${adspowerProfiles.profiles.length} 个环境`
                          : adspowerProfiles?.error
                            ? adspowerProfiles.error
                            : "点击右侧拉取本机 AdsPower 环境，或在下方直接填写 ID / 序号"}
                      </span>
                      <div className="flex items-center gap-1.5">
                        <Button
                          type="button"
                          variant="outline"
                          size="xs"
                          onClick={openAdsDialog}
                        >
                          配置 API Key
                        </Button>
                        <Button
                          type="button"
                          variant="outline"
                          size="xs"
                          disabled={loadingAdsPower}
                          onClick={() => void onRefreshAdsPowerProfiles()}
                        >
                          <RefreshCw
                            className={`h-3 w-3 ${loadingAdsPower ? "animate-spin" : ""}`}
                            aria-hidden="true"
                          />
                          拉取环境
                        </Button>
                      </div>
                    </div>

                    <div className="space-y-1">
                      <label
                        htmlFor={fid("adspowerUserIdSelect")}
                        className="block text-[0.71rem] font-medium text-[#525866]"
                      >
                        选择 AdsPower 环境
                      </label>
                      <select
                        id={fid("adspowerUserIdSelect")}
                        className={NATIVE_SELECT_CLASS}
                        value={form.adspowerUserId}
                        onChange={(e) => {
                          const uidVal = e.target.value;
                          const matched = adspowerProfiles?.profiles.find(
                            (p) => p.userId === uidVal,
                          );
                          if (!matched) {
                            setForm((prev) => ({
                              ...prev,
                              adspowerUserId: "",
                              adspowerProfileName: "",
                            }));
                            return;
                          }
                          setForm((prev) => ({
                            ...prev,
                            adspowerUserId: matched.userId,
                            adspowerSerialNumber: matched.serialNumber,
                            adspowerProfileName: matched.name,
                            environmentName: prev.environmentName.trim()
                              ? prev.environmentName
                              : "AdsPower",
                            environmentProfile:
                              prev.environmentProfile.trim() || !matched.serialNumber
                                ? prev.environmentProfile
                                : `#${matched.serialNumber}`,
                          }));
                        }}
                      >
                        <option value="">
                          -- 请选择 AdsPower 环境（或下方手动填写 user_id / 序号）--
                        </option>
                        {(adspowerProfiles?.profiles ?? []).map((p) => (
                          <option key={p.userId} value={p.userId}>
                            {p.serialNumber ? `#${p.serialNumber} · ` : ""}
                            {p.name || p.userId}
                            {p.groupName ? ` [${p.groupName}]` : ""} ({p.userId})
                          </option>
                        ))}
                        {form.adspowerUserId &&
                          !(adspowerProfiles?.profiles ?? []).some(
                            (p) => p.userId === form.adspowerUserId,
                          ) && (
                            <option value={form.adspowerUserId}>
                              已绑定：{form.adspowerProfileName || form.adspowerUserId} (
                              {form.adspowerUserId})
                            </option>
                          )}
                      </select>
                    </div>

                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                      <div className="space-y-1">
                        <label
                          htmlFor={fid("adspowerUserId")}
                          className="block text-[0.69rem] text-[#7c8495]"
                        >
                          AdsPower user_id
                        </label>
                        <Input
                          id={fid("adspowerUserId")}
                          className="mono-num h-7 text-[0.72rem]"
                          placeholder="例如：j82xkp41"
                          value={form.adspowerUserId}
                          onChange={(e) =>
                            setForm((prev) => ({
                              ...prev,
                              adspowerUserId: e.target.value,
                            }))
                          }
                        />
                      </div>
                      <div className="space-y-1">
                        <label
                          htmlFor={fid("adspowerSerialNumber")}
                          className="block text-[0.69rem] text-[#7c8495]"
                        >
                          窗口序号 serial_number（可选）
                        </label>
                        <Input
                          id={fid("adspowerSerialNumber")}
                          className="mono-num h-7 text-[0.72rem]"
                          placeholder="例如：42（留空将尝试读取上方窗口编号）"
                          value={form.adspowerSerialNumber}
                          onChange={(e) =>
                            setForm((prev) => ({
                              ...prev,
                              adspowerSerialNumber: e.target.value,
                            }))
                          }
                        />
                      </div>
                    </div>

                    <p className="rounded-lg border border-[#eaecef] bg-white px-2.5 py-1.5 text-[0.69rem] text-[#525866]">
                      拉起时会<strong className="text-[#111827]">完全保留 AdsPower 里已配好的代理与指纹</strong>；若下方同时绑定了 Clash / NetGuard 节点，启动前会自动先核验该端口的真实出口 IP。
                    </p>
                  </div>
                )}
              </div>

              {/* Multi-Source Node Binding */}
              {selectedLinkedProfile && !overrideProfileExit ? (
                <div className="flex flex-wrap items-center justify-between gap-2.5 rounded-xl border border-[#dcd4fb] bg-[#f7f5fe] p-3">
                  <div className="min-w-0 space-y-0.5">
                    <div className="flex flex-wrap items-center gap-1.5 text-[0.74rem] font-medium text-[#111827]">
                      <ShieldCheck
                        className="h-3.5 w-3.5 shrink-0 text-[#6d5bd0]"
                        aria-hidden="true"
                      />
                      <span>
                        已直接继承指纹环境网络：{selectedLinkedProfile.name}
                      </span>
                    </div>
                    <p className="text-[0.69rem] text-[#525866]">
                      当前出口：{" "}
                      <span className="font-medium text-[#111827]">
                        {selectedLinkedProfileExitSummary}
                      </span>
                      {" · "}
                      时区 / 语言：{" "}
                      <span className="mono-num">
                        {selectedLinkedProfile.fingerprint.timezone || "跟随节点"} /{" "}
                        {selectedLinkedProfile.fingerprint.locale || "en-US"}
                      </span>
                      （启动前仍强制 Fail-Closed 校验真实出口 IP）
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    size="xs"
                    onClick={() => {
                      setOverrideProfileExit(true);
                      if (form.linkedNodeSource === "none") {
                        handleSelectNodeSource("netguard");
                      }
                    }}
                  >
                    单独覆盖出口
                  </Button>
                </div>
              ) : (
              <div className="space-y-2.5 rounded-xl border border-[#eaecef] bg-[#fafbfc] p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[0.73rem] font-medium text-[#525866]">
                    {selectedLinkedProfile
                      ? `单独覆盖「${selectedLinkedProfile.name}」的出口节点（保存后优先使用此节点）`
                      : "绑定出口节点（支持 NetGuard / Clash Verge / 自定义）"}
                  </span>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {selectedLinkedProfile && (
                      <Button
                        type="button"
                        variant="soft"
                        size="xs"
                        onClick={() => {
                          setOverrideProfileExit(false);
                          setForm((prev) => ({
                            ...prev,
                            linkedNodeSource: "none",
                            linkedNodeId: "",
                            linkedNodeName: "",
                            linkedProxyPort: "",
                          }));
                        }}
                      >
                        恢复继承环境网络
                      </Button>
                    )}
                    <div className="flex flex-wrap gap-1" role="group" aria-label="节点来源">
                    {NODE_SOURCE_OPTIONS.map((opt) => {
                      const active = form.linkedNodeSource === opt.value;
                      return (
                        <button
                          key={opt.value}
                          type="button"
                          aria-pressed={active}
                          onClick={() => handleSelectNodeSource(opt.value)}
                          className={`rounded-md border px-2 py-0.5 text-[0.69rem] font-medium transition-colors cursor-pointer ${
                            active
                              ? "border-[#dcd4fb] bg-[#6d5bd0] text-white"
                              : "border-[#dce0e6] bg-white text-[#525866] hover:bg-[#f3f4f6]"
                          }`}
                        >
                          {opt.label}
                        </button>
                      );
                    })}
                    </div>
                  </div>
                </div>

                {form.linkedNodeSource === "netguard" && (
                  <div className="space-y-1.5">
                    <label
                      htmlFor={fid("linkedNodeId")}
                      className="visually-hidden"
                    >
                      选择 AI NetGuard 节点
                    </label>
                    <select
                      id={fid("linkedNodeId")}
                      className={NATIVE_SELECT_CLASS}
                      value={form.linkedNodeId}
                      onChange={(e) => {
                        const id = e.target.value;
                        const matched = id ? nodeById.get(id) : undefined;
                        setForm((prev) => ({
                          ...prev,
                          linkedNodeId: id,
                          linkedNodeName: matched?.name || "",
                        }));
                      }}
                    >
                      <option value="">-- 请选择 AI NetGuard 节点（可留空）--</option>
                      {nodes.map((node) => (
                        <option key={node.id} value={node.id}>
                          {node.name}
                          {node.expectedCountry ? ` (${node.expectedCountry})` : ""}
                        </option>
                      ))}
                    </select>
                    {nodes.length === 0 && (
                      <p className="text-[0.7rem] text-[#9ca3af]">
                        当前未检测到 NetGuard 节点，可切换到「Clash Verge」或「自定义 / 直连」。
                      </p>
                    )}
                  </div>
                )}

                {form.linkedNodeSource === "clash_verge" && (
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-[0.7rem] text-[#7c8495]">
                      <span>
                        {clashNodes?.detected
                          ? `已自动读取本地 Clash Verge：${clashNodes.groups.length} 个策略组 · ${clashNodes.proxies.length} 个节点`
                          : "未检测到本地 Clash Verge 配置文件，可直接手动输入节点名"}
                      </span>
                      <Button
                        type="button"
                        variant="outline"
                        size="xs"
                        onClick={() => void onRefreshClashNodes()}
                        disabled={loadingClashNodes}
                      >
                        <RefreshCw
                          className={`h-3 w-3 ${loadingClashNodes ? "animate-spin" : ""}`}
                          aria-hidden="true"
                        />
                        刷新 Clash 节点
                      </Button>
                    </div>

                    <div className="flex items-center gap-1.5">
                      <Input
                        className="flex-1"
                        placeholder="点击下方列表选择，或直接输入 Clash 节点 / 策略组名称"
                        value={form.linkedNodeName}
                        onChange={(e) =>
                          setForm((prev) => ({
                            ...prev,
                            linkedNodeName: e.target.value,
                          }))
                        }
                      />
                      {form.linkedNodeName && (
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          aria-label="清空绑定节点"
                          onClick={() =>
                            setForm((prev) => ({ ...prev, linkedNodeName: "" }))
                          }
                          className="h-8 w-8 shrink-0 text-[#7c8495]"
                        >
                          <X className="h-3.5 w-3.5" aria-hidden="true" />
                        </Button>
                      )}
                    </div>

                    {((clashNodes?.groups.length ?? 0) > 0 ||
                      (clashNodes?.proxies.length ?? 0) > 0) && (
                      <div className="space-y-1.5">
                        <div className="relative">
                          <Search
                            className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[#9ca3af]"
                            aria-hidden="true"
                          />
                          <Input
                            className="pl-8"
                            placeholder="搜索策略组或节点名（如 香港、美国、自动选择）..."
                            value={clashSearch}
                            onChange={(e) => setClashSearch(e.target.value)}
                          />
                        </div>

                        <div className="app-scroll max-h-36 space-y-2 overflow-y-auto rounded-lg border border-[#eaecef] bg-white p-1.5">
                          {filteredClashGroups.length > 0 && (
                            <div className="space-y-1">
                              <div className="px-2 pt-0.5 text-[0.67rem] font-semibold text-[#7c8495]">
                                策略组 ({filteredClashGroups.length})
                              </div>
                              {filteredClashGroups.map((item) => {
                                const selected = form.linkedNodeName === item.name;
                                return (
                                  <button
                                    key={`grp-${item.name}`}
                                    type="button"
                                    onClick={() =>
                                      setForm((prev) => ({
                                        ...prev,
                                        linkedNodeName: item.name,
                                      }))
                                    }
                                    className={`flex w-full items-center justify-between gap-2 rounded-md px-2 py-1 text-left text-[0.74rem] transition-colors cursor-pointer ${
                                      selected
                                        ? "bg-[#f0edfc] font-semibold text-[#5b48c4]"
                                        : "text-[#111827] hover:bg-[#f3f4f6]"
                                    }`}
                                  >
                                    <span className="flex min-w-0 items-center gap-1.5 truncate">
                                      {selected && (
                                        <Check className="h-3 w-3 shrink-0" aria-hidden="true" />
                                      )}
                                      <span className="truncate">{item.name}</span>
                                    </span>
                                    <span className="mono-num shrink-0 rounded bg-[#f3f4f6] px-1.5 py-0.5 text-[0.65rem] text-[#525866]">
                                      {item.nodeType}
                                    </span>
                                  </button>
                                );
                              })}
                            </div>
                          )}

                          {filteredClashProxies.length > 0 && (
                            <div className="space-y-1">
                              <div className="px-2 pt-0.5 text-[0.67rem] font-semibold text-[#7c8495]">
                                代理节点 ({filteredClashProxies.length})
                              </div>
                              {filteredClashProxies.map((item) => {
                                const selected = form.linkedNodeName === item.name;
                                return (
                                  <button
                                    key={`px-${item.name}`}
                                    type="button"
                                    onClick={() =>
                                      setForm((prev) => ({
                                        ...prev,
                                        linkedNodeName: item.name,
                                      }))
                                    }
                                    className={`flex w-full items-center justify-between gap-2 rounded-md px-2 py-1 text-left text-[0.74rem] transition-colors cursor-pointer ${
                                      selected
                                        ? "bg-[#f0edfc] font-semibold text-[#5b48c4]"
                                        : "text-[#111827] hover:bg-[#f3f4f6]"
                                    }`}
                                  >
                                    <span className="flex min-w-0 items-center gap-1.5 truncate">
                                      {selected && (
                                        <Check className="h-3 w-3 shrink-0" aria-hidden="true" />
                                      )}
                                      <span className="truncate">{item.name}</span>
                                    </span>
                                    <span className="mono-num shrink-0 rounded bg-[#f3f4f6] px-1.5 py-0.5 text-[0.65rem] text-[#525866]">
                                      {item.nodeType}
                                    </span>
                                  </button>
                                );
                              })}
                            </div>
                          )}

                          {filteredClashGroups.length === 0 &&
                            filteredClashProxies.length === 0 && (
                              <div className="px-2 py-3 text-center text-[0.72rem] text-[#9ca3af]">
                                没有匹配的 Clash 策略组或节点
                              </div>
                            )}
                        </div>
                      </div>
                    )}

                    <div className="grid grid-cols-1 gap-2 rounded-lg border border-[#eaecef] bg-white px-3 py-2 sm:grid-cols-[minmax(0,1fr)_10.5rem] sm:items-center">
                      <div className="text-[0.7rem] text-[#525866]">
                        {form.linkedProxyPort.trim() ? (
                          <span>
                            使用手动覆盖端口：{" "}
                            <span className="mono-num font-semibold text-[#5b48c4]">
                              127.0.0.1:{form.linkedProxyPort.trim()}
                            </span>
                          </span>
                        ) : matchedFormListener ? (
                          <span className="text-[#15803d]">
                            ✓ 自动匹配 Listener「{matchedFormListener.name}」→{" "}
                            <span className="mono-num font-semibold">
                              127.0.0.1:{matchedFormListener.port}
                            </span>
                          </span>
                        ) : (
                          <span>
                            未命中专用 Listener，默认走 Clash mixed-port：{" "}
                            <span className="mono-num font-semibold text-[#111827]">
                              127.0.0.1:{clashNodes?.mixedPort || 7897}
                            </span>
                          </span>
                        )}
                      </div>
                      <Input
                        aria-label="独立监听端口覆盖"
                        type="number"
                        min={1}
                        max={65535}
                        className="mono-num h-7 text-[0.72rem]"
                        placeholder="覆盖端口 (可选)"
                        value={form.linkedProxyPort}
                        onChange={(e) =>
                          setForm((prev) => ({
                            ...prev,
                            linkedProxyPort: e.target.value,
                          }))
                        }
                      />
                    </div>
                  </div>
                )}

                {form.linkedNodeSource === "custom" && (
                  <div className="space-y-2">
                    <Input
                      placeholder="输入自定义代理节点或直连描述，如：静态住宅 1.2.3.4 / socks5://127.0.0.1:10808"
                      value={form.linkedNodeName}
                      onChange={(e) =>
                        setForm((prev) => ({
                          ...prev,
                          linkedNodeName: e.target.value,
                        }))
                      }
                    />
                    <div className="grid grid-cols-1 gap-2 rounded-lg border border-[#eaecef] bg-white px-3 py-2 sm:grid-cols-[minmax(0,1fr)_10.5rem] sm:items-center">
                      <span className="text-[0.7rem] text-[#525866]">
                        一键拉起所需的本地 SOCKS5 / HTTP 代理端口（禁止无代理裸连防 IP 污染）
                      </span>
                      <Input
                        aria-label="自定义本地代理端口"
                        type="number"
                        min={1}
                        max={65535}
                        className="mono-num h-7 text-[0.72rem]"
                        placeholder="本地端口 如 7897"
                        value={form.linkedProxyPort}
                        onChange={(e) =>
                          setForm((prev) => ({
                            ...prev,
                            linkedProxyPort: e.target.value,
                          }))
                        }
                      />
                    </div>
                  </div>
                )}
              </div>
              )}
            </fieldset>

            {/* Section 4: Cockpit-Style Quota & Cooldown */}
            <fieldset className="space-y-3 border-t border-[#eaecef] pt-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <legend className="text-[0.76rem] font-semibold text-[#111827]">
                  4. 额度与订阅周期管理（Cockpit 风格）
                </legend>
                <div className="flex gap-1" role="group" aria-label="启用额度管理">
                  {(
                    [
                      { value: true, label: "开启" },
                      { value: false, label: "关闭" },
                    ] as const
                  ).map((opt) => {
                    const active = form.quotaEnabled === opt.value;
                    return (
                      <button
                        key={String(opt.value)}
                        type="button"
                        aria-pressed={active}
                        onClick={() =>
                          setForm((prev) => ({
                            ...prev,
                            quotaEnabled: opt.value,
                            quotaPools:
                              opt.value && prev.quotaPools.length === 0
                                ? createAntigravityQuotaPreset().pools
                                : prev.quotaPools,
                          }))
                        }
                        className={`rounded-md border px-2.5 py-0.5 text-[0.69rem] font-medium transition-colors cursor-pointer ${
                          active
                            ? "border-[#dcd4fb] bg-[#6d5bd0] text-white"
                            : "border-[#dce0e6] bg-white text-[#525866] hover:bg-[#f3f4f6]"
                        }`}
                      >
                        {opt.label}
                      </button>
                    );
                  })}
                </div>
              </div>

              {form.quotaEnabled ? (
                <div className="space-y-3 rounded-xl border border-[#eaecef] bg-[#fafbfc] p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-[0.71rem] text-[#7c8495]">
                      快捷套用模板：
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      <button
                        type="button"
                        onClick={() => {
                          const p = createAntigravityQuotaPreset();
                          setForm((prev) => ({
                            ...prev,
                            quotaPlanTier: prev.quotaPlanTier || p.planTier,
                            quotaPools: p.pools,
                          }));
                        }}
                        className="rounded border border-[#dcd4fb] bg-[#f0edfc] px-2 py-0.5 text-[0.68rem] font-medium text-[#5b48c4] hover:bg-[#e7e1fa] cursor-pointer"
                      >
                        Antigravity 三分组 (Cockpit)
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          const p = createClaudeQuotaPreset();
                          setForm((prev) => ({
                            ...prev,
                            quotaPlanTier: prev.quotaPlanTier || p.planTier,
                            quotaPools: p.pools,
                          }));
                        }}
                        className="rounded border border-[#dce0e6] bg-white px-2 py-0.5 text-[0.68rem] font-medium text-[#525866] hover:bg-[#f3f4f6] cursor-pointer"
                      >
                        Claude 双窗口
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          const p = createSingleQuotaPreset();
                          setForm((prev) => ({
                            ...prev,
                            quotaPlanTier: prev.quotaPlanTier || p.planTier,
                            quotaPools: p.pools,
                          }));
                        }}
                        className="rounded border border-[#dce0e6] bg-white px-2 py-0.5 text-[0.68rem] font-medium text-[#525866] hover:bg-[#f3f4f6] cursor-pointer"
                      >
                        单主额度
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <div className="space-y-1">
                      <div className="flex items-center justify-between gap-1">
                        <label
                          htmlFor={fid("quotaPlanTier")}
                          className="text-[0.71rem] font-medium text-[#525866]"
                        >
                          套餐等级
                        </label>
                        <div className="flex gap-1">
                          {["FREE", "PRO", "ULTRA", "MAX"].map((tier) => (
                            <button
                              key={tier}
                              type="button"
                              onClick={() =>
                                setForm((prev) => ({ ...prev, quotaPlanTier: tier }))
                              }
                              className={`rounded border px-1.5 py-0.5 text-[0.63rem] cursor-pointer ${
                                form.quotaPlanTier === tier
                                  ? "border-[#dcd4fb] bg-[#f0edfc] font-semibold text-[#5b48c4]"
                                  : "border-[#eaecef] bg-white text-[#525866] hover:bg-[#f3f4f6]"
                              }`}
                            >
                              {tier}
                            </button>
                          ))}
                        </div>
                      </div>
                      <Input
                        id={fid("quotaPlanTier")}
                        className="mono-num h-8"
                        placeholder="PRO / ULTRA / FREE"
                        value={form.quotaPlanTier}
                        onChange={(e) =>
                          setForm((prev) => ({
                            ...prev,
                            quotaPlanTier: e.target.value,
                          }))
                        }
                      />
                    </div>

                    <div className="space-y-1">
                      <label
                        htmlFor={fid("quotaExpiresAt")}
                        className="block text-[0.71rem] font-medium text-[#525866]"
                      >
                        订阅到期日（可选）
                      </label>
                      <Input
                        id={fid("quotaExpiresAt")}
                        type="date"
                        className="mono-num h-8"
                        value={form.quotaExpiresAt}
                        onChange={(e) =>
                          setForm((prev) => ({
                            ...prev,
                            quotaExpiresAt: e.target.value,
                          }))
                        }
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[0.71rem] font-medium text-[#525866]">
                        模型分组额度池（最多 4 组，到点自动回满 100%）
                      </span>
                      {form.quotaPools.length < 4 && (
                        <Button
                          type="button"
                          variant="outline"
                          size="xs"
                          onClick={() =>
                            setForm((prev) => ({
                              ...prev,
                              quotaPools: [
                                ...prev.quotaPools,
                                {
                                  id: `pool-${prev.quotaPools.length + 1}`,
                                  label: `分组 ${prev.quotaPools.length + 1}`,
                                  remainingPct: 100,
                                  resetHours: 5,
                                  resetAt: null,
                                },
                              ],
                            }))
                          }
                        >
                          <Plus className="h-3 w-3" aria-hidden="true" />
                          添加模型分组
                        </Button>
                      )}
                    </div>

                    <div className="space-y-2">
                      {form.quotaPools.map((pool, idx) => (
                        <div
                          key={`${pool.id}-${idx}`}
                          className="grid grid-cols-1 gap-2 rounded-lg border border-[#eaecef] bg-white p-2 sm:grid-cols-[minmax(0,1fr)_5rem_7.5rem_11.5rem_auto] sm:items-end"
                        >
                          <div className="space-y-1">
                            <span className="block text-[0.65rem] text-[#7c8495]">
                              分组名称
                            </span>
                            <Input
                              aria-label={`分组名称 ${idx + 1}`}
                              className="h-7 text-[0.72rem]"
                              value={pool.label}
                              onChange={(e) => {
                                const v = e.target.value;
                                setForm((prev) => ({
                                  ...prev,
                                  quotaPools: prev.quotaPools.map((item, i) =>
                                    i === idx ? { ...item, label: v } : item,
                                  ),
                                }));
                              }}
                            />
                          </div>
                          <div className="space-y-1">
                            <span className="block text-[0.65rem] text-[#7c8495]">
                              剩余 %
                            </span>
                            <Input
                              aria-label={`剩余百分比 ${idx + 1}`}
                              type="number"
                              min={0}
                              max={100}
                              className="mono-num h-7 text-[0.72rem]"
                              value={pool.remainingPct}
                              onChange={(e) => {
                                const n = Math.max(
                                  0,
                                  Math.min(100, Number(e.target.value) || 0),
                                );
                                setForm((prev) => ({
                                  ...prev,
                                  quotaPools: prev.quotaPools.map((item, i) =>
                                    i === idx ? { ...item, remainingPct: n } : item,
                                  ),
                                }));
                              }}
                            />
                          </div>
                          <div className="space-y-1">
                            <span className="block text-[0.65rem] text-[#7c8495]">
                              刷新周期
                            </span>
                            <select
                              aria-label={`刷新周期 ${idx + 1}`}
                              className={`${NATIVE_SELECT_CLASS} min-h-7 py-0.5 text-[0.71rem]`}
                              value={String(pool.resetHours)}
                              onChange={(e) => {
                                const h = Number(e.target.value) || 0;
                                setForm((prev) => ({
                                  ...prev,
                                  quotaPools: prev.quotaPools.map((item, i) =>
                                    i === idx ? { ...item, resetHours: h } : item,
                                  ),
                                }));
                              }}
                            >
                              <option value="5">5 小时</option>
                              <option value="24">24 小时</option>
                              <option value="168">7 天 (168h)</option>
                              <option value="720">30 天 (720h)</option>
                              <option value="0">手动 (不倒计时)</option>
                            </select>
                          </div>
                          <div className="space-y-1">
                            <span className="block text-[0.65rem] text-[#7c8495]">
                              恢复时间 (可选)
                            </span>
                            <Input
                              aria-label={`恢复时间 ${idx + 1}`}
                              type="datetime-local"
                              className="mono-num h-7 text-[0.69rem]"
                              value={isoToLocalDatetimeInput(pool.resetAt)}
                              onChange={(e) => {
                                const iso = localDatetimeInputToIso(e.target.value);
                                setForm((prev) => ({
                                  ...prev,
                                  quotaPools: prev.quotaPools.map((item, i) =>
                                    i === idx ? { ...item, resetAt: iso } : item,
                                  ),
                                }));
                              }}
                            />
                          </div>
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            disabled={form.quotaPools.length <= 1}
                            aria-label={`删除模型分组 ${idx + 1}`}
                            onClick={() =>
                              setForm((prev) => ({
                                ...prev,
                                quotaPools: prev.quotaPools.filter((_, i) => i !== idx),
                              }))
                            }
                            className="h-7 w-7 text-[#7c8495] hover:text-[#dc2626]"
                          >
                            <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                          </Button>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <p className="text-[0.71rem] text-[#7c8495]">
                  未启用额度跟踪的账号保持简洁展示，不占用额外行高；需要统计余量与冷却时可随时打开。
                </p>
              )}
            </fieldset>

            {/* Section 5: Purpose, Tags, Notes */}
            <fieldset className="space-y-3 border-t border-[#eaecef] pt-4">
              <legend className="text-[0.76rem] font-semibold text-[#111827]">
                5. 用途与备注
              </legend>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <label
                    htmlFor={fid("purpose")}
                    className="block text-[0.73rem] font-medium text-[#525866]"
                  >
                    账号用途
                  </label>
                  <Input
                    id={fid("purpose")}
                    placeholder="例如：CloudCart 店铺管理 / Google Ads / Claude 登录"
                    value={form.purpose}
                    onChange={(e) =>
                      setForm((prev) => ({ ...prev, purpose: e.target.value }))
                    }
                  />
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor={fid("tagsText")}
                    className="block text-[0.73rem] font-medium text-[#525866]"
                  >
                    标签（逗号分隔）
                  </label>
                  <Input
                    id={fid("tagsText")}
                    placeholder="主力, CloudCart, 美区"
                    value={form.tagsText}
                    onChange={(e) =>
                      setForm((prev) => ({ ...prev, tagsText: e.target.value }))
                    }
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label
                  htmlFor={fid("notes")}
                  className="block text-[0.73rem] font-medium text-[#525866]"
                >
                  详细备注
                </label>
                <textarea
                  id={fid("notes")}
                  rows={2}
                  className={TEXTAREA_CLASS}
                  placeholder="记录代理 IP 段要求、注册日期、绑定卡号尾号或风控注意事项..."
                  value={form.notes}
                  onChange={(e) =>
                    setForm((prev) => ({ ...prev, notes: e.target.value }))
                  }
                />
              </div>
            </fieldset>
          </div>

          {/* Modal Footer */}
          <div className="flex shrink-0 items-center justify-end gap-2 border-t border-[#eaecef] bg-[#fafbfc] px-6 py-3.5">
            <Button type="button" variant="outline" size="sm" onClick={closeEditor}>
              取消
            </Button>
            <Button type="submit" variant="solid" size="sm" disabled={saving}>
              {saving ? "保存中..." : form.id ? "保存修改" : "加密保存到本地"}
            </Button>
          </div>
        </form>
      </dialog>

      {/* Modal 2: Delete Confirmation Native <dialog> */}
      <dialog
        ref={confirmDialogRef}
        aria-labelledby={confirmTitleId}
        {...({ closedby: "any" } as Record<string, string>)}
        onClose={handleConfirmDialogClose}
        className="ng-dialog m-auto w-[min(27rem,calc(100vi-2rem))] max-w-none rounded-2xl border border-[#dce0e6] bg-white p-0 text-[#111827] shadow-[0_24px_56px_-12px_rgba(15,23,42,0.28)]"
      >
        <form method="dialog" className="flex flex-col">
          <div className="flex items-start justify-between gap-3 px-6 pt-5 pb-3">
            <div className="flex items-start gap-3">
              <span className="mt-0.5 inline-grid h-8 w-8 shrink-0 place-items-center rounded-xl bg-[#fef2f2] text-[#dc2626]">
                <AlertTriangle className="h-4 w-4" aria-hidden="true" />
              </span>
              <div>
                <h2
                  id={confirmTitleId}
                  className="text-[0.95rem] font-semibold text-[#111827]"
                >
                  {confirmTarget?.kind === "banned"
                    ? `确认清理 ${confirmTarget.ids.length} 个已封禁账号？`
                    : "确认删除该账号记录？"}
                </h2>
                <p className="mt-1 text-[0.76rem] text-[#525866]">
                  {confirmTarget?.kind === "banned"
                    ? "所有状态标记为「已封禁」的账号、密码及 2FA 密钥都将从本地加密库中永久移除。"
                    : confirmTarget?.kind === "single"
                      ? `即将永久移除「${confirmTarget.account.label || confirmTarget.account.email}」(${confirmTarget.account.email})，此操作不可撤销。`
                      : "此操作将从本地加密库中永久移除该账号记录。"}
                </p>
              </div>
            </div>
            <button
              type="submit"
              value="cancel"
              aria-label="关闭确认框"
              className="inline-grid h-7 w-7 shrink-0 place-items-center rounded-lg text-[#7c8495] hover:bg-[#f3f4f6] hover:text-[#111827] cursor-pointer"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>

          <div className="flex items-center justify-end gap-2 border-t border-[#eaecef] bg-[#fafbfc] px-6 py-3.5">
            <Button
              ref={confirmCancelRef}
              type="submit"
              value="cancel"
              variant="outline"
              size="sm"
              autoFocus
            >
              取消
            </Button>
            <Button type="submit" value="confirm" variant="destructive" size="sm">
              <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
              确认删除
            </Button>
          </div>
        </form>
      </dialog>

      {/* Modal 3: AdsPower Local API Configuration Native <dialog> */}
      <dialog
        ref={adsDialogRef}
        aria-labelledby={adsTitleId}
        {...({ closedby: "any" } as Record<string, string>)}
        className="ng-dialog m-auto w-[min(32rem,calc(100vi-2rem))] max-w-none overflow-hidden rounded-2xl border border-[#dce0e6] bg-white p-0 text-[#111827] shadow-[0_24px_56px_-12px_rgba(15,23,42,0.28)]"
      >
        <div className="flex flex-col">
          <div className="flex items-center justify-between gap-3 border-b border-[#eaecef] px-6 py-3.5">
            <div className="min-w-0">
              <h2
                id={adsTitleId}
                className="text-[0.98rem] font-semibold tracking-tight text-[#111827]"
              >
                AdsPower Local API 连接设置
              </h2>
              <p className="mt-0.5 text-[0.72rem] text-[#7c8495]">
                API Key 使用 Windows DPAPI 本地加密保存，仅直连本机 AdsPower 环回接口
              </p>
            </div>
            <button
              type="button"
              onClick={closeAdsDialog}
              aria-label="关闭 AdsPower 设置"
              className="inline-grid h-7 w-7 shrink-0 place-items-center rounded-lg text-[#7c8495] hover:bg-[#f3f4f6] hover:text-[#111827] cursor-pointer"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>

          <div className="space-y-3.5 px-6 py-4">
            <div className="space-y-1.5">
              <label
                htmlFor={fid("adsBaseUrl")}
                className="block text-[0.73rem] font-medium text-[#525866]"
              >
                Local API 接口地址
              </label>
              <Input
                ref={adsUrlInputRef}
                id={fid("adsBaseUrl")}
                className="mono-num"
                placeholder="http://127.0.0.1:50325"
                value={adsBaseUrl}
                onChange={(e) => setAdsBaseUrl(e.target.value)}
              />
              <p className="text-[0.68rem] text-[#7c8495]">
                仅允许本机地址（`http://127.0.0.1:50325` / `localhost` / `local.adspower.net`），可在 AdsPower 客户端「自动化 / Local API」查看
              </p>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <label
                  htmlFor={fid("adsApiKey")}
                  className="block text-[0.73rem] font-medium text-[#525866]"
                >
                  API Key（已在 AdsPower 开启鉴权时必填）
                </label>
                {adspowerConfig?.hasApiKey && (
                  <button
                    type="button"
                    disabled={adsSaving}
                    onClick={() => void handleClearAdsPowerKey()}
                    className="text-[0.69rem] font-medium text-[#dc2626] hover:underline cursor-pointer"
                  >
                    清除已存密钥
                  </button>
                )}
              </div>
              <div className="flex items-center gap-1.5">
                <Input
                  id={fid("adsApiKey")}
                  type={adsShowKey ? "text" : "password"}
                  className="mono-num flex-1"
                  placeholder={
                    adspowerConfig?.hasApiKey
                      ? `已加密保存 (${adspowerConfig.apiKeyMasked || "DPAPI"})，留空保持不变`
                      : "粘贴 AdsPower Local API Key（Authorization Bearer）"
                  }
                  value={adsApiKeyInput}
                  onChange={(e) => setAdsApiKeyInput(e.target.value)}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  aria-label={adsShowKey ? "隐藏 API Key" : "显示 API Key"}
                  onClick={() => setAdsShowKey((v) => !v)}
                  className="h-8 w-8 shrink-0 text-[#525866]"
                >
                  {adsShowKey ? (
                    <EyeOff className="h-3.5 w-3.5" aria-hidden="true" />
                  ) : (
                    <Eye className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                </Button>
              </div>
            </div>

            {adsTestMessage && (
              <div
                role="status"
                className={`rounded-lg border px-3 py-2 text-[0.73rem] ${
                  adsTestIsError
                    ? "border-[#fecaca] bg-[#fef2f2] text-[#b91c1c]"
                    : "border-[#bbf7d0] bg-[#f0fdf4] text-[#15803d]"
                }`}
              >
                {adsTestMessage}
              </div>
            )}
          </div>

          <div className="flex items-center justify-end gap-2 border-t border-[#eaecef] bg-[#fafbfc] px-6 py-3.5">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={closeAdsDialog}
            >
              关闭
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={adsSaving}
              onClick={() => void handleSaveAdsPower(false)}
            >
              仅保存
            </Button>
            <Button
              type="button"
              variant="solid"
              size="sm"
              disabled={adsSaving}
              onClick={() => void handleSaveAdsPower(true)}
            >
              {adsSaving ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
              ) : (
                <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
              )}
              保存并测试连接
            </Button>
          </div>
        </div>
      </dialog>
    </div>
  );
}
