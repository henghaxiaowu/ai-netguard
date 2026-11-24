import { useEffect, useId, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Check,
  ClipboardPaste,
  Copy,
  Cpu,
  Download,
  ExternalLink,
  Fingerprint,
  Globe,
  KeyRound,
  Monitor,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Sparkles,
  Square,
  Trash2,
  X,
} from "lucide-react";
import { api } from "../api";
import type {
  AppConfig,
  BrowserCookieRecord,
  BrowserFingerprintConfig,
  BrowserFingerprintMode,
  BrowserProfile,
  ClashVergeNodesSnapshot,
  DownloadProgress,
  ExitIpInfo,
  GatewayStatus,
  NodeProfile,
  ProfileCookiesSnapshot,
} from "../types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Input } from "./ui/input";

interface Props {
  config: AppConfig;
  status: GatewayStatus | null;
  gatewayReady: boolean;
  dlProgress?: DownloadProgress | null;
  clashNodes?: ClashVergeNodesSnapshot | null;
  preselectedNodeRequest?: { nodeId: string; nonce: number } | null;
  onSaveProfiles: (profiles: BrowserProfile[]) => Promise<void>;
  onLaunchProfile: (profileId: string, url?: string) => Promise<void>;
  onCloseProfile: (profileId: string) => Promise<void>;
  onProbeNodeExit: (nodeId: string) => Promise<ExitIpInfo>;
  onProbeProxyExit?: (proxyUrl: string) => Promise<ExitIpInfo>;
  onRefreshClashNodes?: () => Promise<void>;
  onInstallBrowser: () => Promise<void>;
  onRestartGateway?: () => Promise<void>;
  onNotify: (msg: string) => void;
}

const NATIVE_SELECT_CLASS =
  "flex min-h-8 w-full rounded-lg border border-[#dce0e6] bg-white px-2.5 py-1.5 text-[0.765rem] text-[#111827] shadow-[0_1px_1px_rgba(15,23,42,0.02)] transition-colors hover:border-[#c3cad6] focus-visible:outline-2 focus-visible:outline-[#5b48c4] focus-visible:outline-offset-1 cursor-pointer";

const LOCALE_PRESETS: { value: string; label: string }[] = [
  { value: "en-US", label: "en-US · 英文 (United States · 默认)" },
  { value: "en-GB", label: "en-GB · 英文 (United Kingdom)" },
  { value: "en-SG", label: "en-SG · 英文 (Singapore)" },
  { value: "ja-JP", label: "ja-JP · 日语 (Japan)" },
  { value: "ko-KR", label: "ko-KR · 韩语 (Korea)" },
  { value: "zh-TW", label: "zh-TW · 繁体中文 (台湾)" },
  { value: "zh-HK", label: "zh-HK · 繁体中文 (香港)" },
  { value: "zh-CN", label: "zh-CN · 简体中文 (中国)" },
  { value: "de-DE", label: "de-DE · 德语 (Germany)" },
  { value: "fr-FR", label: "fr-FR · 法语 (France)" },
  { value: "", label: "跟随出口节点默认语言" },
];

const GPU_PRESETS: { vendor: string; renderer: string }[] = [
  {
    vendor: "Google Inc. (NVIDIA)",
    renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
  },
  {
    vendor: "Google Inc. (NVIDIA)",
    renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
  },
  {
    vendor: "Google Inc. (NVIDIA)",
    renderer: "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11)",
  },
  {
    vendor: "Google Inc. (AMD)",
    renderer: "ANGLE (AMD, AMD Radeon RX 6700 XT Direct3D11 vs_5_0 ps_5_0, D3D11)",
  },
  {
    vendor: "Google Inc. (Intel)",
    renderer: "ANGLE (Intel, Intel(R) UHD Graphics 770 Direct3D11 vs_5_0 ps_5_0, D3D11)",
  },
];

const SCREEN_PRESETS: { width: number; height: number; dpr: number }[] = [
  { width: 1920, height: 1080, dpr: 1.0 },
  { width: 1920, height: 1080, dpr: 1.25 },
  { width: 2560, height: 1440, dpr: 1.0 },
  { width: 1680, height: 1050, dpr: 1.0 },
  { width: 1536, height: 864, dpr: 1.25 },
];

const HW_CONCURRENCY_OPTIONS = [4, 8, 12, 16];
const DEVICE_MEMORY_OPTIONS = [8, 16, 32];

const HOMEPAGE_SHORTCUTS = [
  { label: "Claude", url: "https://claude.ai" },
  { label: "Chrome 商店", url: "https://chromewebstore.google.com/" },
  { label: "IP 信誉检测", url: "https://ip.net.coffee/" },
  { label: "指纹检测", url: "https://fuck-claude.vercel.app/" },
  { label: "Google", url: "https://www.google.com/" },
];

const COUNTRY_LOCALE_DEFAULTS: Record<string, { timezone: string; locale: string }> = {
  JP: { timezone: "Asia/Tokyo", locale: "ja-JP" },
  KR: { timezone: "Asia/Seoul", locale: "ko-KR" },
  US: { timezone: "America/Los_Angeles", locale: "en-US" },
  GB: { timezone: "Europe/London", locale: "en-GB" },
  UK: { timezone: "Europe/London", locale: "en-GB" },
  DE: { timezone: "Europe/Berlin", locale: "de-DE" },
  SG: { timezone: "Asia/Singapore", locale: "en-SG" },
  HK: { timezone: "Asia/Hong_Kong", locale: "zh-HK" },
  TW: { timezone: "Asia/Taipei", locale: "zh-TW" },
  FR: { timezone: "Europe/Paris", locale: "fr-FR" },
  NL: { timezone: "Europe/Amsterdam", locale: "nl-NL" },
  CA: { timezone: "America/Toronto", locale: "en-CA" },
  AU: { timezone: "Australia/Sydney", locale: "en-AU" },
};

function inferTimezoneLocaleFromExit(info: ExitIpInfo): {
  timezone: string;
  locale: string;
} {
  const cc = (info.countryCode || "").trim().toUpperCase();
  const mapped = COUNTRY_LOCALE_DEFAULTS[cc];
  const tz = (info.timezone || "").trim() || mapped?.timezone || "America/New_York";
  const locale = mapped?.locale || "en-US";
  return { timezone: tz, locale };
}

function normalizeLoopbackProxyKey(raw?: string | null): string {
  const trimmed = (raw ?? "").trim().toLowerCase();
  if (!trimmed) return "";
  return trimmed.includes("://") ? trimmed : `http://${trimmed}`;
}

function parseLoopbackProxyInput(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed || /\s/.test(trimmed)) return null;
  const withScheme = trimmed.includes("://") ? trimmed : `socks5://${trimmed}`;
  try {
    const parsed = new URL(withScheme);
    const scheme = parsed.protocol.replace(/:$/, "").toLowerCase();
    if (!["http", "https", "socks5", "socks5h"].includes(scheme)) return null;
    const host = parsed.hostname.toLowerCase();
    if (host !== "127.0.0.1" && host !== "localhost") return null;
    const port = Number(parsed.port);
    if (!Number.isInteger(port) || port <= 1024 || port > 65535) return null;
    return `${scheme}://${host}:${port}`;
  } catch {
    return null;
  }
}

function randomHexSeed(bytesLen = 8): string {
  const bytes = new Uint8Array(bytesLen);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function generateConsistentFingerprint(
  tz?: string | null,
  locale?: string | null,
): BrowserFingerprintConfig {
  const gpu = GPU_PRESETS[Math.floor(Math.random() * GPU_PRESETS.length)];
  const scr = SCREEN_PRESETS[Math.floor(Math.random() * SCREEN_PRESETS.length)];
  const hw =
    HW_CONCURRENCY_OPTIONS[
      Math.floor(Math.random() * HW_CONCURRENCY_OPTIONS.length)
    ];
  const mem =
    DEVICE_MEMORY_OPTIONS[
      Math.floor(Math.random() * DEVICE_MEMORY_OPTIONS.length)
    ];
  return {
    timezone: tz || undefined,
    locale: locale || undefined,
    screenWidth: scr.width,
    screenHeight: scr.height,
    devicePixelRatio: scr.dpr,
    hardwareConcurrency: hw,
    deviceMemory: mem,
    webglVendor: gpu.vendor,
    webglRenderer: gpu.renderer,
    userAgent: undefined,
    noiseSeed: `ng-${randomHexSeed(6)}`,
  };
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

function extractProxyHostPort(url: string): string {
  return url.replace(/^[a-zA-Z0-9+.-]+:\/\//, "").split("/")[0] || url;
}

function createFormForNode(
  node: NodeProfile | undefined,
  mode: BrowserFingerprintMode = "isolated_fingerprint",
): BrowserProfile {
  return {
    id: "",
    name: node ? `环境 · ${node.name}` : "新独立指纹浏览器",
    builtin: false,
    nodeId: node?.id ?? null,
    customProxyUrl: null,
    homepage: "https://claude.ai",
    fingerprintMode: mode,
    fingerprint: generateConsistentFingerprint(
      node?.timezone || null,
      "en-US",
    ),
    notes: "",
  };
}

export function BrowserProfilesView({
  config,
  status,
  dlProgress,
  clashNodes,
  preselectedNodeRequest,
  onSaveProfiles,
  onLaunchProfile,
  onCloseProfile,
  onProbeNodeExit,
  onProbeProxyExit,
  onRefreshClashNodes,
  onInstallBrowser,
  onRestartGateway,
  onNotify,
}: Props) {
  const uid = useId();
  const fid = (name: string) => `${uid}-${name}`;
  const editorTitleId = fid("bp-editor-title");
  const confirmTitleId = fid("bp-confirm-title");
  const cookieTitleId = fid("bp-cookie-title");

  const profiles = useMemo<BrowserProfile[]>(() => {
    if (config.browserProfiles && config.browserProfiles.length > 0) {
      return config.browserProfiles;
    }
    return [
      {
        id: "default",
        name: "默认安全浏览器 (主出口)",
        builtin: true,
        nodeId: null,
        homepage: "https://claude.ai",
        fingerprintMode: "clean_align",
        fingerprint: {
          screenWidth: 1920,
          screenHeight: 1080,
          devicePixelRatio: 1,
          hardwareConcurrency: 8,
          deviceMemory: 8,
          webglVendor: "Google Inc. (NVIDIA)",
          webglRenderer:
            "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
          noiseSeed: "ng-default-seed",
        },
        notes: "默认跟随活跃主出口节点，使用纯净时区与语言对齐",
      },
    ];
  }, [config.browserProfiles]);

  const nodeById = useMemo(
    () => new Map(config.nodes.map((n) => [n.id, n])),
    [config.nodes],
  );

  const runningSet = useMemo(
    () => new Set(status?.runningBrowserProfiles ?? []),
    [status?.runningBrowserProfiles],
  );

  const clashPortPresets = useMemo(() => {
    const out: { url: string; label: string; nodeHint: string }[] = [];
    const seen = new Set<number>();
    for (const l of clashNodes?.listeners ?? []) {
      if (!l.port || l.port <= 1024 || seen.has(l.port)) continue;
      seen.add(l.port);
      const scheme = l.listenerType.toLowerCase() === "http" ? "http" : "socks5";
      out.push({
        url: `${scheme}://127.0.0.1:${l.port}`,
        label: `:${l.port}`,
        nodeHint: l.proxy || l.name || "",
      });
    }
    if (
      clashNodes?.mixedPort &&
      clashNodes.mixedPort > 1024 &&
      !seen.has(clashNodes.mixedPort)
    ) {
      out.push({
        url: `socks5://127.0.0.1:${clashNodes.mixedPort}`,
        label: `:${clashNodes.mixedPort}`,
        nodeHint: "Clash 混合端口",
      });
    }
    return out;
  }, [clashNodes]);

  const [editorOpen, setEditorOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<BrowserProfile>(() =>
    createFormForNode(config.nodes[0]),
  );
  const [exitSource, setExitSource] = useState<"node" | "custom_proxy">("node");
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);
  const [autoMatchingTz, setAutoMatchingTz] = useState(false);
  const [refreshingClash, setRefreshingClash] = useState(false);
  const [customLocaleMode, setCustomLocaleMode] = useState(false);
  const [initialCookiesText, setInitialCookiesText] = useState("");

  const [cookieDialogProfile, setCookieDialogProfile] =
    useState<BrowserProfile | null>(null);
  const [cookieSnapshot, setCookieSnapshot] =
    useState<ProfileCookiesSnapshot | null>(null);
  const [cookieLoading, setCookieLoading] = useState(false);
  const [cookieBusy, setCookieBusy] = useState(false);
  const [cookieTab, setCookieTab] = useState<"list" | "import">("list");
  const [cookieSearch, setCookieSearch] = useState("");
  const [importText, setImportText] = useState("");
  const [importReplace, setImportReplace] = useState(false);
  const [confirmClearCookies, setConfirmClearCookies] = useState(false);
  const [cookieError, setCookieError] = useState("");
  const [copiedCookieKey, setCopiedCookieKey] = useState<string | null>(null);

  const [confirmDelete, setConfirmDelete] = useState<BrowserProfile | null>(
    null,
  );
  const [probingNodeId, setProbingNodeId] = useState<string | null>(null);
  const [nodeProbeResults, setNodeProbeResults] = useState<
    Record<string, ExitIpInfo>
  >({});
  const [probingProfileId, setProbingProfileId] = useState<string | null>(null);
  const [proxyProbeResults, setProxyProbeResults] = useState<
    Record<string, ExitIpInfo>
  >({});

  const editorDialogRef = useRef<HTMLDialogElement>(null);
  const confirmDialogRef = useRef<HTMLDialogElement>(null);
  const cookieDialogRef = useRef<HTMLDialogElement>(null);
  const nameInputRef = useRef<HTMLInputElement>(null);
  const confirmCancelRef = useRef<HTMLButtonElement>(null);
  const cookieCloseRef = useRef<HTMLButtonElement>(null);
  const handledPreselectNonce = useRef<number>(0);

  // Sync native <dialog> showModal() lifecycle
  useEffect(() => {
    const dialog = editorDialogRef.current;
    if (!dialog) return;
    if (editorOpen && !dialog.open) {
      dialog.returnValue = "";
      dialog.showModal();
      requestAnimationFrame(() => nameInputRef.current?.focus());
    } else if (!editorOpen && dialog.open) {
      dialog.close();
    }
    return attachLightDismissFallback(dialog);
  }, [editorOpen]);

  useEffect(() => {
    const dialog = confirmDialogRef.current;
    if (!dialog) return;
    if (confirmDelete && !dialog.open) {
      dialog.returnValue = "";
      dialog.showModal();
      requestAnimationFrame(() => confirmCancelRef.current?.focus());
    } else if (!confirmDelete && dialog.open) {
      dialog.close();
    }
    return attachLightDismissFallback(dialog);
  }, [confirmDelete]);

  useEffect(() => {
    const dialog = cookieDialogRef.current;
    if (!dialog) return;
    if (cookieDialogProfile && !dialog.open) {
      dialog.returnValue = "";
      dialog.showModal();
      requestAnimationFrame(() => cookieCloseRef.current?.focus());
    } else if (!cookieDialogProfile && dialog.open) {
      dialog.close();
    }
    return attachLightDismissFallback(dialog);
  }, [cookieDialogProfile]);

  // Open preselected node creation modal when triggered from NodeEditor
  useEffect(() => {
    if (!preselectedNodeRequest) return;
    if (preselectedNodeRequest.nonce === handledPreselectNonce.current) return;
    handledPreselectNonce.current = preselectedNodeRequest.nonce;
    const node = nodeById.get(preselectedNodeRequest.nodeId);
    setEditingId(null);
    setForm(createFormForNode(node, "isolated_fingerprint"));
    setExitSource("node");
    setCustomLocaleMode(false);
    setInitialCookiesText("");
    setFormError("");
    setEditorOpen(true);
  }, [preselectedNodeRequest, nodeById]);

  const openCreateModal = (presetNodeId?: string) => {
    const fallbackNode =
      (presetNodeId ? nodeById.get(presetNodeId) : undefined) ||
      config.nodes.find((n) => n.id !== config.activeNodeId) ||
      nodeById.get(config.activeNodeId);
    setEditingId(null);
    setForm(
      createFormForNode(
        fallbackNode,
        fallbackNode?.id === config.activeNodeId
          ? "clean_align"
          : "isolated_fingerprint",
      ),
    );
    setExitSource("node");
    setCustomLocaleMode(false);
    setInitialCookiesText("");
    setFormError("");
    setEditorOpen(true);
  };

  const openEditModal = (profile: BrowserProfile) => {
    const curLoc = profile.fingerprint.locale ?? "";
    setEditingId(profile.id);
    setForm({
      ...profile,
      fingerprint: { ...profile.fingerprint },
    });
    setExitSource(profile.customProxyUrl?.trim() ? "custom_proxy" : "node");
    setCustomLocaleMode(!LOCALE_PRESETS.some((p) => p.value === curLoc));
    setInitialCookiesText("");
    setFormError("");
    setEditorOpen(true);
  };

  const handleDuplicateProfile = async (profile: BrowserProfile) => {
    const node = profile.nodeId
      ? nodeById.get(profile.nodeId)
      : nodeById.get(config.activeNodeId);
    const cloned: BrowserProfile = {
      ...profile,
      id: `bp-${Date.now()}`,
      name: `${profile.name} (副本)`,
      builtin: false,
      fingerprint: {
        ...profile.fingerprint,
        timezone: profile.fingerprint.timezone || node?.timezone || undefined,
        locale: profile.fingerprint.locale || node?.locale || "en-US",
        noiseSeed: `ng-${randomHexSeed(6)}`,
      },
    };
    await onSaveProfiles([...profiles, cloned]);
    onNotify(`已复制独立浏览器环境: ${cloned.name}（已分配新指纹种子与独立数据目录）`);
  };

  const handleConfirmDelete = async () => {
    if (!confirmDelete || confirmDelete.builtin) {
      setConfirmDelete(null);
      return;
    }
    const targetName = confirmDelete.name;
    const next = profiles.filter((p) => p.id !== confirmDelete.id);
    await onSaveProfiles(next);
    setConfirmDelete(null);
    onNotify(`已删除浏览器环境: ${targetName}`);
  };

  const handleSaveForm = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanName = form.name.trim();
    if (!cleanName) {
      setFormError("请输入浏览器环境名称");
      return;
    }
    const cleanHomepage = form.homepage.trim() || "https://claude.ai";
    if (!cleanHomepage.startsWith("https://")) {
      setFormError("启动首页必须以 https:// 开头");
      return;
    }

    let finalNodeId: string | null = form.nodeId?.trim() || null;
    let finalCustomProxy: string | null = null;
    if (exitSource === "custom_proxy") {
      const parsedProxy = parseLoopbackProxyInput(form.customProxyUrl || "");
      if (!parsedProxy) {
        setFormError(
          "请填写或点选有效的本机回环代理地址（如 socks5://127.0.0.1:10808 或 http://127.0.0.1:7897）",
        );
        return;
      }
      finalNodeId = null;
      finalCustomProxy = parsedProxy;
    }

    const nextRecord: BrowserProfile = {
      ...form,
      id: editingId || `bp-${Date.now()}`,
      name: cleanName,
      homepage: cleanHomepage,
      nodeId: finalNodeId,
      customProxyUrl: finalCustomProxy,
      notes: form.notes?.trim() || undefined,
      fingerprint: {
        ...form.fingerprint,
        timezone: form.fingerprint.timezone?.trim() || undefined,
        locale: form.fingerprint.locale?.trim() || undefined,
        userAgent: form.fingerprint.userAgent?.trim() || undefined,
        webglVendor:
          form.fingerprint.webglVendor.trim() || "Google Inc. (NVIDIA)",
        webglRenderer:
          form.fingerprint.webglRenderer.trim() ||
          "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        noiseSeed: form.fingerprint.noiseSeed.trim() || `ng-${randomHexSeed(6)}`,
      },
    };

    setSaving(true);
    try {
      const nextList = editingId
        ? profiles.map((p) => (p.id === editingId ? nextRecord : p))
        : [...profiles, nextRecord];
      await onSaveProfiles(nextList);

      const pendingInitCookies = !editingId ? initialCookiesText.trim() : "";
      if (pendingInitCookies) {
        try {
          const outcome = await api.importProfileCookies(
            nextRecord.id,
            pendingInitCookies,
            true,
          );
          setInitialCookiesText("");
          setEditorOpen(false);
          onNotify(
            `已保存浏览器环境 ${nextRecord.name}，并写入 ${outcome.importedCount} 条初始 Cookie` +
              (outcome.warning ? `（${outcome.warning}）` : ""),
          );
        } catch (cookieErr) {
          setEditorOpen(false);
          onNotify(
            `环境「${nextRecord.name}」已保存，但初始 Cookie 写入失败：${String(cookieErr)}（可点击卡片「Cookie」重试）`,
          );
        }
      } else {
        setEditorOpen(false);
        onNotify(`已保存浏览器环境: ${nextRecord.name}`);
      }
    } catch (err) {
      setFormError(`保存失败: ${String(err)}`);
    } finally {
      setSaving(false);
    }
  };

  const loadProfileCookies = async (profileId: string) => {
    setCookieLoading(true);
    setCookieError("");
    try {
      const snap = await api.getProfileCookies(profileId);
      setCookieSnapshot(snap);
    } catch (err) {
      setCookieError(`读取 Cookie 失败：${String(err)}`);
    } finally {
      setCookieLoading(false);
    }
  };

  const openCookieDialog = (
    profile: BrowserProfile,
    tab: "list" | "import" = "list",
  ) => {
    setCookieDialogProfile(profile);
    setCookieSnapshot(null);
    setCookieTab(tab);
    setCookieSearch("");
    setImportText("");
    setImportReplace(false);
    setConfirmClearCookies(false);
    setCookieError("");
    setCopiedCookieKey(null);
    void loadProfileCookies(profile.id);
  };

  const handleImportCookies = async () => {
    if (!cookieDialogProfile) return;
    if (!importText.trim()) {
      setCookieError(
        "请先粘贴 AdsPower / EditThisCookie JSON 或 Netscape cookies.txt 内容",
      );
      return;
    }
    setCookieBusy(true);
    setCookieError("");
    setConfirmClearCookies(false);
    try {
      const outcome = await api.importProfileCookies(
        cookieDialogProfile.id,
        importText,
        importReplace,
      );
      setCookieSnapshot({
        profileId: cookieDialogProfile.id,
        liveMode: outcome.liveMode,
        cookies: outcome.cookies,
        exportJson: outcome.exportJson,
      });
      setImportText("");
      setCookieTab("list");
      onNotify(
        `已导入 ${outcome.importedCount} 条 Cookie（当前共 ${outcome.totalCount} 条` +
          (outcome.liveMode ? " · 已实时同步" : " · 离线写入完成") +
          (outcome.warning ? ` · ${outcome.warning}` : "") +
          "）",
      );
    } catch (err) {
      setCookieError(String(err));
    } finally {
      setCookieBusy(false);
    }
  };

  const handleDeleteSingleCookie = async (c: BrowserCookieRecord) => {
    if (!cookieDialogProfile) return;
    setCookieBusy(true);
    setCookieError("");
    setConfirmClearCookies(false);
    try {
      const snap = await api.deleteProfileCookies(cookieDialogProfile.id, [
        { name: c.name, domain: c.domain, path: c.path, secure: c.secure },
      ]);
      setCookieSnapshot(snap);
      onNotify(`已删除 Cookie: ${c.name} (${c.domain})`);
    } catch (err) {
      setCookieError(`删除 Cookie 失败：${String(err)}`);
    } finally {
      setCookieBusy(false);
    }
  };

  const handleDeleteDomainCookies = async (domain: string) => {
    if (!cookieDialogProfile || !cookieSnapshot) return;
    const targets = cookieSnapshot.cookies
      .filter((c) => c.domain === domain)
      .map((c) => ({
        name: c.name,
        domain: c.domain,
        path: c.path,
        secure: c.secure,
      }));
    if (targets.length === 0) return;
    setCookieBusy(true);
    setCookieError("");
    setConfirmClearCookies(false);
    try {
      const snap = await api.deleteProfileCookies(
        cookieDialogProfile.id,
        targets,
      );
      setCookieSnapshot(snap);
      onNotify(`已删除域名 ${domain} 下的 ${targets.length} 条 Cookie`);
    } catch (err) {
      setCookieError(`删除域名 Cookie 失败：${String(err)}`);
    } finally {
      setCookieBusy(false);
    }
  };

  const handleClearAllCookies = async () => {
    if (!cookieDialogProfile) return;
    if (!confirmClearCookies) {
      setConfirmClearCookies(true);
      return;
    }
    setCookieBusy(true);
    setCookieError("");
    try {
      const snap = await api.clearProfileCookies(cookieDialogProfile.id);
      setCookieSnapshot(snap);
      setConfirmClearCookies(false);
      onNotify(`已清空环境「${cookieDialogProfile.name}」的所有 Cookie`);
    } catch (err) {
      setCookieError(`清空 Cookie 失败：${String(err)}`);
    } finally {
      setCookieBusy(false);
    }
  };

  const formatSubsetExportJson = (list: BrowserCookieRecord[]) =>
    JSON.stringify(
      list.map((c) => {
        const sameSite =
          c.sameSite === "None"
            ? "no_restriction"
            : c.sameSite === "Lax"
              ? "lax"
              : c.sameSite === "Strict"
                ? "strict"
                : "unspecified";
        const obj: Record<string, unknown> = { domain: c.domain };
        if (typeof c.expires === "number" && c.expires > 0) {
          obj.expirationDate = c.expires;
        }
        obj.hostOnly = c.hostOnly;
        obj.httpOnly = c.httpOnly;
        obj.name = c.name;
        obj.path = c.path;
        obj.sameSite = sameSite;
        obj.secure = c.secure;
        obj.session = c.session;
        obj.value = c.value;
        return obj;
      }),
      null,
      2,
    );

  const handleCopyTextFeedback = async (
    key: string,
    text: string,
    notifyMsg: string,
  ) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedCookieKey(key);
      setTimeout(() => {
        setCopiedCookieKey((cur) => (cur === key ? null : cur));
      }, 2000);
      onNotify(notifyMsg);
    } catch (err) {
      setCookieError(`复制失败：${String(err)}`);
    }
  };

  const handleDownloadExportJson = (jsonStr: string) => {
    if (!cookieDialogProfile) return;
    const blob = new Blob([jsonStr], {
      type: "application/json;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cookies-${cookieDialogProfile.id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    onNotify(`已导出 cookies-${cookieDialogProfile.id}.json`);
  };

  const filteredCookies = useMemo(() => {
    const all = cookieSnapshot?.cookies ?? [];
    const q = cookieSearch.trim().toLowerCase();
    if (!q) return all;
    return all.filter(
      (c) =>
        c.domain.toLowerCase().includes(q) ||
        c.name.toLowerCase().includes(q) ||
        c.value.toLowerCase().includes(q),
    );
  }, [cookieSnapshot?.cookies, cookieSearch]);

  const groupedCookies = useMemo(() => {
    const groups = new Map<string, BrowserCookieRecord[]>();
    for (const c of filteredCookies) {
      const list = groups.get(c.domain) ?? [];
      list.push(c);
      groups.set(c.domain, list);
    }
    return Array.from(groups.entries());
  }, [filteredCookies]);

  const handleNodeChangeInForm = (selectedVal: string) => {
    const nextNodeId = selectedVal === "__active__" ? null : selectedVal;
    const targetNode = nextNodeId
      ? nodeById.get(nextNodeId)
      : nodeById.get(config.activeNodeId);
    setForm((prev) => ({
      ...prev,
      nodeId: nextNodeId,
      customProxyUrl: null,
      fingerprint: {
        ...prev.fingerprint,
        timezone: targetNode?.timezone || prev.fingerprint.timezone,
      },
    }));
  };

  const handleProbeNode = async (nodeId: string) => {
    setProbingNodeId(nodeId);
    try {
      const info = await onProbeNodeExit(nodeId);
      setNodeProbeResults((prev) => ({ ...prev, [nodeId]: info }));
      onNotify(
        `节点探测通过: ${info.ip} (${info.countryCode || "--"}) · ${info.latencyMs || "--"}ms`,
      );
    } catch (err) {
      onNotify(`探测失败: ${String(err)}`);
    } finally {
      setProbingNodeId(null);
    }
  };

  const handleProbeCustomProxy = async (profileId: string, proxyUrl: string) => {
    if (!onProbeProxyExit) return;
    setProbingProfileId(profileId);
    try {
      const info = await onProbeProxyExit(proxyUrl);
      setProxyProbeResults((prev) => ({ ...prev, [profileId]: info }));
      onNotify(
        `独立代理探测通过: ${info.ip} (${info.countryCode || "--"}) · ${info.latencyMs || "--"}ms`,
      );
    } catch (err) {
      onNotify(`独立代理探测失败: ${String(err)}`);
    } finally {
      setProbingProfileId(null);
    }
  };

  const handleRefreshClashPorts = async () => {
    if (!onRefreshClashNodes) return;
    setRefreshingClash(true);
    try {
      await onRefreshClashNodes();
      onNotify("已刷新本地 Clash Verge 监听端口");
    } catch (err) {
      onNotify(`刷新 Clash 端口失败: ${String(err)}`);
    } finally {
      setRefreshingClash(false);
    }
  };

  const handleAutoMatchTzLocale = async () => {
    setFormError("");
    setAutoMatchingTz(true);
    try {
      let info: ExitIpInfo;
      if (exitSource === "custom_proxy") {
        if (!onProbeProxyExit) {
          throw new Error("当前运行环境不支持本地代理探测");
        }
        const parsed = parseLoopbackProxyInput(form.customProxyUrl || "");
        if (!parsed) {
          throw new Error("请先填写或点选有效的本地代理端口");
        }
        info = await onProbeProxyExit(parsed);
      } else {
        const targetNodeId = form.nodeId?.trim() || config.activeNodeId;
        info = await onProbeNodeExit(targetNodeId);
        setNodeProbeResults((prev) => ({ ...prev, [targetNodeId]: info }));
      }
      const matched = inferTimezoneLocaleFromExit(info);
      setForm((prev) => ({
        ...prev,
        fingerprint: {
          ...prev.fingerprint,
          timezone: matched.timezone,
        },
      }));
      onNotify(
        `已按出口 IP ${info.ip} (${info.countryCode || "--"}) 自动匹配时区: ${matched.timezone}（语言保持 ${form.fingerprint.locale || "跟随节点"}）`,
      );
    } catch (err) {
      setFormError(`自动匹配时区失败: ${String(err)}`);
    } finally {
      setAutoMatchingTz(false);
    }
  };

  const downloading = Boolean(dlProgress && dlProgress.stage !== "done");
  const activePrimaryNode = nodeById.get(config.activeNodeId);
  const secondaryPortEntries = Object.entries(status?.secondaryNodePorts ?? {});

  return (
    <div className="bento-sheet flex flex-col divide-y divide-[#eaecef] rounded-2xl border border-[#eaecef] bg-white shadow-[0_1px_3px_rgba(15,23,42,0.03)]">
      {/* Page Header */}
      <header className="flex flex-wrap items-center justify-between gap-3 px-6 py-4">
        <div>
          <h1
            id="main-heading"
            tabIndex={-1}
            className="vt-page-title text-[1.2rem] font-semibold tracking-[-0.02em] text-[#111827] outline-none"
          >
            指纹浏览器
          </h1>
          <p className="mt-0.5 text-[0.76rem] text-[#7c8495]">
            多出口并发多开 · 每套环境拥有独立数据目录、本地 SOCKS5 端口与持久化一致性指纹
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {status?.fpBrowserInstalled ? (
            <>
              <Badge variant="success">Fingerprint-Chromium 150</Badge>
              {status?.webStoreExtInstalled ? (
                <Badge variant="neutral" className="text-[0.68rem]">
                  Chrome 商店插件就绪
                </Badge>
              ) : (
                <Button
                  variant="soft"
                  size="sm"
                  disabled={downloading}
                  onClick={() => void onInstallBrowser()}
                >
                  <Download className="h-3.5 w-3.5" aria-hidden="true" />
                  补装商店插件
                </Button>
              )}
            </>
          ) : (
            <Button
              variant="soft"
              size="sm"
              disabled={downloading}
              onClick={() => void onInstallBrowser()}
            >
              <Download className="h-3.5 w-3.5" aria-hidden="true" />
              {status?.browserInstalled
                ? "升级到 Fingerprint-Chromium 150 (~185MB)"
                : "安装 Fingerprint-Chromium 150 (~185MB)"}
            </Button>
          )}
          <Button variant="solid" size="sm" onClick={() => openCreateModal()}>
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            新建浏览器环境
          </Button>
        </div>
      </header>

      {/* Live Engine Download / Extraction Progress */}
      {downloading && dlProgress && (
        <section className="flex flex-col gap-1.5 bg-[#f8f9ff] px-6 py-3">
          <div className="flex items-center justify-between gap-2 text-[0.74rem]">
            <span className="font-medium text-[#111827]">
              {dlProgress.message}
            </span>
            {dlProgress.totalBytes > 0 && (
              <span className="mono-num text-[0.7rem] text-[#6d5bd0]">
                {Math.min(
                  100,
                  Math.round(
                    (dlProgress.downloadedBytes / dlProgress.totalBytes) * 100,
                  ),
                )}
                %
              </span>
            )}
          </div>
          <progress
            className="h-1.5 w-full accent-[#6d5bd0]"
            max={100}
            value={
              dlProgress.totalBytes > 0
                ? Math.min(
                    100,
                    Math.round(
                      (dlProgress.downloadedBytes / dlProgress.totalBytes) * 100,
                    ),
                  )
                : undefined
            }
          />
        </section>
      )}

      {/* Concurrent Multi-Exit Routing Overview Strip */}
      <section className="flex flex-wrap items-center justify-between gap-3 bg-[#f9fafb] px-6 py-3 text-[0.74rem]">
        <div className="flex flex-wrap items-center gap-2 text-[#525866]">
          <Badge variant={status?.running ? "success" : "neutral"}>
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                status?.running ? "bg-[#16a34a]" : "bg-[#9ca3af]"
              }`}
              aria-hidden="true"
            />
            {status?.running ? "多出口核心在线" : "网关待机"}
          </Badge>
          <span className="text-[#7c8495]">主安全入口 (Claude):</span>
          <Badge variant="iris" className="mono-num">
            {activePrimaryNode?.name || "未选择"} · 127.0.0.1:{config.browserPort}
          </Badge>
          {secondaryPortEntries.map(([nid, port]) => {
            const n = nodeById.get(nid);
            return (
              <Badge key={nid} variant="neutral" className="mono-num bg-white">
                {n?.name || nid} · 127.0.0.1:{port}
              </Badge>
            );
          })}
        </div>

        <div className="text-[0.71rem] text-[#7c8495]">
          运行中窗口：<span className="mono-num font-semibold text-[#111827]">{runningSet.size}</span> 个
        </div>
      </section>

      {/* Profile Cards Grid */}
      <section className="p-5 px-6">
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {profiles.map((profile) => {
            const customProxyUrl = profile.customProxyUrl?.trim() || "";
            const hasCustomProxy = Boolean(customProxyUrl);
            const customProxyHostPort = hasCustomProxy
              ? extractProxyHostPort(customProxyUrl)
              : "";
            const boundNodeId = profile.nodeId || config.activeNodeId;
            const boundNode = nodeById.get(boundNodeId);
            const isPrimary =
              !hasCustomProxy && boundNodeId === config.activeNodeId;
            const isRunning = runningSet.has(profile.id);
            const secPort =
              !hasCustomProxy && !isPrimary
                ? status?.secondaryNodePorts?.[boundNodeId]
                : undefined;
            const activePort = isPrimary ? config.browserPort : secPort;
            const needsGatewayRestart =
              !hasCustomProxy &&
              !!status?.running &&
              !isPrimary &&
              secPort === undefined;
            const effectiveTz =
              profile.fingerprint.timezone || boundNode?.timezone || "Asia/Seoul";
            const effectiveLocale =
              profile.fingerprint.locale || boundNode?.locale || "en-US";
            const canLaunch =
              !!status?.browserInstalled &&
              (hasCustomProxy ||
                (!!status?.running &&
                  !(isPrimary && status?.blockedByKillSwitch) &&
                  !needsGatewayRestart));
            const probeInfo = hasCustomProxy
              ? proxyProbeResults[profile.id]
              : isPrimary && status?.exitIp
                ? status.exitIp
                : nodeProbeResults[boundNodeId];

            return (
              <article
                key={profile.id}
                className="flex flex-col justify-between gap-3 rounded-xl border border-[#eaecef] bg-white p-4 shadow-[0_1px_2px_rgba(15,23,42,0.02)] transition-colors hover:border-[#d5dae3]"
              >
                {/* Top Card Header */}
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Globe
                        className="h-4 w-4 shrink-0 text-[#6d5bd0]"
                        aria-hidden="true"
                      />
                      <h2 className="truncate text-[0.88rem] font-semibold text-[#111827]">
                        {profile.name}
                      </h2>
                      {profile.builtin && (
                        <Badge variant="neutral" className="text-[0.63rem]">
                          主默认
                        </Badge>
                      )}
                      {isRunning && (
                        <Badge variant="success" className="text-[0.63rem]">
                          ● 运行中
                        </Badge>
                      )}
                    </div>
                    {profile.notes && (
                      <p className="mt-1 line-clamp-1 text-[0.71rem] text-[#7c8495]">
                        {profile.notes}
                      </p>
                    )}
                  </div>

                  <Badge
                    variant={
                      profile.fingerprintMode === "isolated_fingerprint"
                        ? "iris"
                        : "neutral"
                    }
                    className="shrink-0 text-[0.65rem]"
                  >
                    {profile.fingerprintMode === "isolated_fingerprint"
                      ? "完整独立指纹"
                      : "纯净对齐 (Claude 推荐)"}
                  </Badge>
                </div>

                {/* Exit Node & Port Allocation Box */}
                <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[#eaecef] bg-[#f8f9fb] px-3 py-2 text-[0.73rem]">
                  <div className="flex min-w-0 flex-wrap items-center gap-1.5">
                    <span className="font-medium text-[#525866]">绑定出口:</span>
                    {hasCustomProxy ? (
                      <>
                        <span className="truncate font-semibold text-[#111827]">
                          独立代理
                        </span>
                        <Badge
                          variant="warning"
                          className="mono-num uppercase text-[0.62rem]"
                        >
                          PROXY
                        </Badge>
                        <span className="mono-num text-[0.7rem] text-[#15803d]">
                          {customProxyHostPort}
                        </span>
                      </>
                    ) : (
                      <>
                        <span className="truncate font-semibold text-[#111827]">
                          {boundNode?.name || "未找到节点"}
                        </span>
                        {boundNode && (
                          <Badge
                            variant="neutral"
                            className="mono-num uppercase text-[0.62rem]"
                          >
                            {boundNode.protocol}
                          </Badge>
                        )}
                        {activePort ? (
                          <span className="mono-num text-[0.7rem] text-[#15803d]">
                            127.0.0.1:{activePort}
                          </span>
                        ) : needsGatewayRestart ? (
                          <span className="inline-flex items-center gap-1 text-[0.69rem] text-[#b45309]">
                            <AlertTriangle className="h-3 w-3" aria-hidden="true" />
                            需重启网关激活端口
                          </span>
                        ) : (
                          <span className="text-[0.69rem] text-[#9ca3af]">待启动</span>
                        )}
                      </>
                    )}
                  </div>

                  <div className="flex items-center gap-1.5">
                    {probeInfo && (
                      <span className="mono-num text-[0.69rem] text-[#525866]">
                        {probeInfo.ip} ({probeInfo.countryCode || "--"})
                        {probeInfo.latencyMs ? ` · ${probeInfo.latencyMs}ms` : ""}
                      </span>
                    )}
                    {hasCustomProxy ? (
                      onProbeProxyExit ? (
                        <Button
                          variant="ghost"
                          size="xs"
                          disabled={probingProfileId === profile.id}
                          onClick={() =>
                            void handleProbeCustomProxy(profile.id, customProxyUrl)
                          }
                        >
                          <Activity
                            className={`h-3 w-3 ${
                              probingProfileId === profile.id ? "animate-spin" : ""
                            }`}
                            aria-hidden="true"
                          />
                          测速/查 IP
                        </Button>
                      ) : (
                        <span className="text-[0.68rem] text-[#7c8495]">
                          账号独立代理 · 需本地代理在线
                        </span>
                      )
                    ) : needsGatewayRestart && onRestartGateway ? (
                      <Button
                        variant="outline"
                        size="xs"
                        onClick={() => void onRestartGateway()}
                      >
                        <RefreshCw className="h-3 w-3" aria-hidden="true" />
                        重启激活
                      </Button>
                    ) : (
                      <Button
                        variant="ghost"
                        size="xs"
                        disabled={!status?.running || (!isPrimary && !secPort) || probingNodeId === boundNodeId}
                        onClick={() => void handleProbeNode(boundNodeId)}
                      >
                        <Activity
                          className={`h-3 w-3 ${probingNodeId === boundNodeId ? "animate-spin" : ""}`}
                          aria-hidden="true"
                        />
                        测速/查 IP
                      </Button>
                    )}
                  </div>
                </div>

                {/* Deterministic Fingerprint Spec Matrix */}
                <dl className="grid grid-cols-2 gap-x-3 gap-y-1.5 rounded-lg border border-[#f1f3f5] px-3 py-2 text-[0.71rem]">
                  <div className="flex items-center justify-between gap-2">
                    <dt className="text-[#7c8495]">时区 / 语言</dt>
                    <dd className="mono-num truncate font-medium text-[#111827]">
                      {effectiveTz} · {effectiveLocale}
                    </dd>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <dt className="text-[#7c8495]">启动首页</dt>
                    <dd
                      className="mono-num truncate font-medium text-[#111827]"
                      title={profile.homepage}
                    >
                      {profile.homepage.replace(/^https?:\/\//, "")}
                    </dd>
                  </div>

                  {profile.fingerprintMode === "isolated_fingerprint" ? (
                    <>
                      <div className="flex items-center justify-between gap-2">
                        <dt className="text-[#7c8495]">屏幕 / 硬件</dt>
                        <dd className="mono-num truncate font-medium text-[#111827]">
                          {profile.fingerprint.screenWidth}×{profile.fingerprint.screenHeight} ({profile.fingerprint.devicePixelRatio}x) · {profile.fingerprint.hardwareConcurrency}C/{profile.fingerprint.deviceMemory}G
                        </dd>
                      </div>
                      <div className="flex items-center justify-between gap-2">
                        <dt className="text-[#7c8495]">噪声种子</dt>
                        <dd className="mono-num truncate font-medium text-[#6d5bd0]">
                          {profile.fingerprint.noiseSeed}
                        </dd>
                      </div>
                      <div className="col-span-2 flex items-center justify-between gap-2">
                        <dt className="shrink-0 text-[#7c8495]">WebGL GPU</dt>
                        <dd
                          className="mono-num truncate text-[#374151]"
                          title={profile.fingerprint.webglRenderer}
                        >
                          {profile.fingerprint.webglRenderer}
                        </dd>
                      </div>
                    </>
                  ) : (
                    <div className="col-span-2 flex items-center gap-1.5 text-[0.69rem] text-[#525866]">
                      <ShieldCheck className="h-3.5 w-3.5 text-[#16a34a]" aria-hidden="true" />
                      {status?.fpBrowserInstalled
                        ? "中文界面 · C++ 原生时区/语言与 Chrome 品牌对齐（无硬件噪声，Claude / hCaptcha 最稳）"
                        : "中文界面 · 仅对齐时区与语言，保留真实 Chromium 原生硬件信号以防 hCaptcha 拒绝"}
                    </div>
                  )}
                </dl>

                {/* Action Footer */}
                <div className="flex flex-wrap items-center justify-between gap-2 pt-0.5">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Button
                      variant="solid"
                      size="xs"
                      disabled={!canLaunch}
                      onClick={() => void onLaunchProfile(profile.id)}
                    >
                      <Play className="h-3 w-3" aria-hidden="true" />
                      {isRunning ? "再开首页" : "启动独立窗口"}
                    </Button>
                    <Button
                      variant="outline"
                      size="xs"
                      disabled={!canLaunch}
                      onClick={() =>
                        void onLaunchProfile(
                          profile.id,
                          "https://chromewebstore.google.com/",
                        )
                      }
                    >
                      <ExternalLink className="h-3 w-3" aria-hidden="true" />
                      扩展商店
                    </Button>
                    <Button
                      variant="outline"
                      size="xs"
                      disabled={!canLaunch}
                      onClick={() =>
                        void onLaunchProfile(
                          profile.id,
                          "https://fuck-claude.vercel.app/",
                        )
                      }
                    >
                      <ExternalLink className="h-3 w-3" aria-hidden="true" />
                      打开指纹检测
                    </Button>
                    <Button
                      variant="outline"
                      size="xs"
                      disabled={!status?.browserInstalled}
                      onClick={() => openCookieDialog(profile)}
                    >
                      <KeyRound className="h-3 w-3" aria-hidden="true" />
                      Cookie
                    </Button>
                    {isRunning && (
                      <Button
                        variant="destructive-outline"
                        size="xs"
                        onClick={() => void onCloseProfile(profile.id)}
                      >
                        <Square className="h-3 w-3" aria-hidden="true" />
                        关闭窗口
                      </Button>
                    )}
                  </div>

                  <div className="flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="xs"
                      onClick={() => openEditModal(profile)}
                    >
                      <Pencil className="h-3 w-3" aria-hidden="true" />
                      编辑
                    </Button>
                    <Button
                      variant="ghost"
                      size="xs"
                      onClick={() => void handleDuplicateProfile(profile)}
                    >
                      <Copy className="h-3 w-3" aria-hidden="true" />
                      复制
                    </Button>
                    {!profile.builtin && (
                      <Button
                        variant="ghost"
                        size="xs"
                        className="text-[#dc2626] hover:bg-[#fef2f2] hover:text-[#dc2626]"
                        onClick={() => setConfirmDelete(profile)}
                      >
                        <Trash2 className="h-3 w-3" aria-hidden="true" />
                        删除
                      </Button>
                    )}
                  </div>
                </div>
              </article>
            );
          })}
        </div>
      </section>

      {/* Native Top-Layer Modal <dialog>: Create / Edit Browser Profile */}
      <dialog
        ref={editorDialogRef}
        {...({ closedby: "any" } as Record<string, string>)}
        aria-labelledby={editorTitleId}
        onClose={(e) => {
          e.currentTarget.returnValue = "";
          setEditorOpen(false);
        }}
        className="ng-dialog m-auto w-[min(42rem,calc(100vi-2rem))] max-h-[calc(100dvh-2.5rem)] overflow-y-auto rounded-2xl border border-[#eaecef] bg-white p-0 text-[#111827] shadow-[0_24px_48px_-12px_rgba(15,23,42,0.22)]"
      >
        <form onSubmit={handleSaveForm} className="flex flex-col divide-y divide-[#eaecef]">
          <div className="flex items-center justify-between gap-3 px-5 py-4">
            <div className="flex items-center gap-2">
              <span className="inline-grid h-7 w-7 place-items-center rounded-lg bg-[#f0edfc] text-[#6d5bd0]">
                <Fingerprint className="h-4 w-4" aria-hidden="true" />
              </span>
              <h2 id={editorTitleId} className="text-[0.95rem] font-semibold">
                {editingId ? "编辑浏览器指纹环境" : "新建独立浏览器环境"}
              </h2>
            </div>
            <button
              type="button"
              aria-label="关闭弹窗"
              onClick={() => setEditorOpen(false)}
              className="inline-grid h-7 w-7 place-items-center rounded-lg text-[#7c8495] hover:bg-[#f3f4f6] hover:text-[#111827] cursor-pointer"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>

          <div className="space-y-4 px-5 py-4">
            {formError && (
              <div
                role="alert"
                className="flex items-center gap-2 rounded-lg border border-[#fecaca] bg-[#fef2f2] px-3 py-2 text-[0.75rem] text-[#991b1b]"
              >
                <AlertTriangle className="h-4 w-4 shrink-0 text-[#dc2626]" aria-hidden="true" />
                {formError}
              </div>
            )}

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="space-y-1">
                <label
                  htmlFor={fid("bpName")}
                  className="block text-[0.72rem] font-medium text-[#525866]"
                >
                  环境名称
                </label>
                <Input
                  ref={nameInputRef}
                  id={fid("bpName")}
                  placeholder="例如：日本家宽 · 通用工作窗"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                />
              </div>

              <div className="space-y-1">
                <span className="block text-[0.72rem] font-medium text-[#525866]">
                  出口来源
                </span>
                <div className="grid grid-cols-2 gap-1.5 rounded-lg border border-[#dce0e6] bg-[#f8f9fb] p-1">
                  <button
                    type="button"
                    onClick={() => {
                      setExitSource("node");
                      setForm((prev) => ({ ...prev, customProxyUrl: null }));
                    }}
                    className={`rounded-md px-2 py-1 text-[0.73rem] font-medium transition-colors cursor-pointer ${
                      exitSource === "node"
                        ? "bg-white text-[#111827] shadow-[0_1px_2px_rgba(15,23,42,0.08)]"
                        : "text-[#525866] hover:text-[#111827]"
                    }`}
                  >
                    AI NetGuard 节点
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setExitSource("custom_proxy");
                      setForm((prev) => ({
                        ...prev,
                        nodeId: null,
                        customProxyUrl:
                          prev.customProxyUrl?.trim() ||
                          clashPortPresets[0]?.url ||
                          "socks5://127.0.0.1:10808",
                      }));
                    }}
                    className={`rounded-md px-2 py-1 text-[0.73rem] font-medium transition-colors cursor-pointer ${
                      exitSource === "custom_proxy"
                        ? "bg-white text-[#111827] shadow-[0_1px_2px_rgba(15,23,42,0.08)]"
                        : "text-[#525866] hover:text-[#111827]"
                    }`}
                  >
                    Clash / 本地代理
                  </button>
                </div>
              </div>

              {exitSource === "node" ? (
                <div className="space-y-1 sm:col-span-2">
                  <label
                    htmlFor={fid("bpNode")}
                    className="block text-[0.72rem] font-medium text-[#525866]"
                  >
                    绑定 AI NetGuard 出口节点
                  </label>
                  <select
                    id={fid("bpNode")}
                    className={NATIVE_SELECT_CLASS}
                    value={form.nodeId || "__active__"}
                    onChange={(e) => handleNodeChangeInForm(e.target.value)}
                  >
                    <option value="__active__">
                      跟随当前主安全出口 ({activePrimaryNode?.name || config.activeNodeId})
                    </option>
                    {config.nodes.map((node) => (
                      <option key={node.id} value={node.id}>
                        {node.name} ({node.protocol.toUpperCase()}
                        {node.expectedCountry ? ` · ${node.expectedCountry}` : ""})
                      </option>
                    ))}
                  </select>
                </div>
              ) : (
                <div className="space-y-2 rounded-xl border border-[#eaecef] bg-[#f8f9fb] p-3 sm:col-span-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <label
                      htmlFor={fid("bpCustomProxy")}
                      className="text-[0.72rem] font-medium text-[#525866]"
                    >
                      指定本地代理地址（如 Clash Verge 独立 Listener）
                    </label>
                    {onRefreshClashNodes && (
                      <Button
                        type="button"
                        variant="ghost"
                        size="xs"
                        disabled={refreshingClash}
                        onClick={() => void handleRefreshClashPorts()}
                      >
                        <RefreshCw
                          className={`h-3 w-3 ${refreshingClash ? "animate-spin" : ""}`}
                          aria-hidden="true"
                        />
                        刷新 Clash 端口
                      </Button>
                    )}
                  </div>
                  <Input
                    id={fid("bpCustomProxy")}
                    className="mono-num bg-white"
                    placeholder="socks5://127.0.0.1:10808 或 http://127.0.0.1:7897"
                    value={form.customProxyUrl || ""}
                    onChange={(e) =>
                      setForm({ ...form, customProxyUrl: e.target.value })
                    }
                  />
                  {clashPortPresets.length > 0 ? (
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="text-[0.68rem] text-[#7c8495]">
                        本机 Clash 端口一键填入:
                      </span>
                      {clashPortPresets.map((preset) => {
                        const selected =
                          normalizeLoopbackProxyKey(form.customProxyUrl) ===
                          normalizeLoopbackProxyKey(preset.url);
                        return (
                          <button
                            key={preset.url}
                            type="button"
                            title={
                              preset.nodeHint
                                ? `${preset.url}（${preset.nodeHint}）`
                                : preset.url
                            }
                            onClick={() =>
                              setForm((prev) => ({
                                ...prev,
                                customProxyUrl: preset.url,
                              }))
                            }
                            className={`mono-num rounded-md border px-2 py-0.5 text-[0.68rem] transition-colors cursor-pointer ${
                              selected
                                ? "border-[#6d5bd0] bg-[#f0edfc] font-semibold text-[#5b48c4]"
                                : "border-[#dce0e6] bg-white text-[#525866] hover:border-[#c3cad6] hover:text-[#111827]"
                            }`}
                          >
                            {preset.label}
                            {preset.nodeHint ? ` · ${preset.nodeHint}` : ""}
                          </button>
                        );
                      })}
                    </div>
                  ) : (
                    <p className="text-[0.68rem] text-[#7c8495]">
                      未读取到 Clash Verge 多端口 Listener，可手动输入 <code className="mono-num">socks5://127.0.0.1:10808</code> 或 <code className="mono-num">http://127.0.0.1:7897</code>
                    </p>
                  )}
                </div>
              )}

              <div className="space-y-1 sm:col-span-2">
                <div className="flex items-center justify-between gap-2">
                  <label
                    htmlFor={fid("bpHomepage")}
                    className="block text-[0.72rem] font-medium text-[#525866]"
                  >
                    默认启动网址 (HTTPS)
                  </label>
                  <div className="flex flex-wrap gap-1">
                    {HOMEPAGE_SHORTCUTS.map((s) => (
                      <button
                        key={s.url}
                        type="button"
                        onClick={() => setForm({ ...form, homepage: s.url })}
                        className="rounded border border-[#eaecef] bg-[#f8f9fb] px-1.5 py-0.5 text-[0.65rem] text-[#525866] hover:bg-[#f0edfc] hover:text-[#5b48c4] cursor-pointer"
                      >
                        {s.label}
                      </button>
                    ))}
                  </div>
                </div>
                <Input
                  id={fid("bpHomepage")}
                  className="mono-num"
                  placeholder="https://claude.ai"
                  value={form.homepage}
                  onChange={(e) => setForm({ ...form, homepage: e.target.value })}
                />
              </div>
            </div>

            {/* Fingerprint Mode Selection */}
            <fieldset className="space-y-2 rounded-xl border border-[#eaecef] bg-[#f8f9fb] p-3">
              <legend className="px-1 text-[0.72rem] font-semibold text-[#525866]">
                指纹策略模式
              </legend>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <label
                  className={`flex cursor-pointer flex-col gap-1 rounded-lg border p-2.5 transition-colors ${
                    form.fingerprintMode === "clean_align"
                      ? "border-[#6d5bd0] bg-white shadow-[0_1px_2px_rgba(109,91,208,0.12)]"
                      : "border-[#dce0e6] bg-white/70 hover:bg-white"
                  }`}
                >
                  <div className="flex items-center gap-2 text-[0.77rem] font-semibold">
                    <input
                      type="radio"
                      name={fid("fpMode")}
                      checked={form.fingerprintMode === "clean_align"}
                      onChange={() =>
                        setForm({ ...form, fingerprintMode: "clean_align" })
                      }
                    />
                    纯净对齐 (推荐 Claude)
                  </div>
                  <p className="text-[0.68rem] text-[#7c8495]">
                    只做 C++ 原生时区/语言与 Chrome 品牌对齐，关闭硬件随机噪声，hCaptcha 最稳。
                  </p>
                </label>

                <label
                  className={`flex cursor-pointer flex-col gap-1 rounded-lg border p-2.5 transition-colors ${
                    form.fingerprintMode === "isolated_fingerprint"
                      ? "border-[#6d5bd0] bg-white shadow-[0_1px_2px_rgba(109,91,208,0.12)]"
                      : "border-[#dce0e6] bg-white/70 hover:bg-white"
                  }`}
                >
                  <div className="flex items-center gap-2 text-[0.77rem] font-semibold">
                    <input
                      type="radio"
                      name={fid("fpMode")}
                      checked={form.fingerprintMode === "isolated_fingerprint"}
                      onChange={() =>
                        setForm({
                          ...form,
                          fingerprintMode: "isolated_fingerprint",
                        })
                      }
                    />
                    完整独立指纹 (防关联多开)
                  </div>
                  <p className="text-[0.68rem] text-[#7c8495]">
                    启用固定 C++ 底层硬件、Canvas/Audio/字体/GPU 指纹种子，多账号彻底隔离。
                  </p>
                </label>
              </div>
            </fieldset>

            {/* Timezone & Locale with Exit IP Auto-Match */}
            <div className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[0.72rem] font-medium text-[#525866]">
                  时区与语言对齐（界面保持中文，网页头与 JS 与代理出口一致）
                </span>
                <Button
                  type="button"
                  variant="soft"
                  size="xs"
                  disabled={autoMatchingTz}
                  onClick={() => void handleAutoMatchTzLocale()}
                >
                  <Activity
                    className={`h-3 w-3 ${autoMatchingTz ? "animate-spin" : ""}`}
                    aria-hidden="true"
                  />
                  {autoMatchingTz ? "探测出口中..." : "按出口 IP 自动匹配时区"}
                </Button>
              </div>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <label
                    htmlFor={fid("bpTz")}
                    className="block text-[0.72rem] font-medium text-[#525866]"
                  >
                    时区覆盖（留空则跟随节点）
                  </label>
                  <Input
                    id={fid("bpTz")}
                    className="mono-num"
                    placeholder="Asia/Tokyo"
                    value={form.fingerprint.timezone || ""}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        fingerprint: {
                          ...form.fingerprint,
                          timezone: e.target.value,
                        },
                      })
                    }
                  />
                </div>
                <div className="space-y-1">
                  <label
                    htmlFor={fid("bpLocale")}
                    className="block text-[0.72rem] font-medium text-[#525866]"
                  >
                    网页语言 Accept-Language（默认 en-US）
                  </label>
                  <select
                    id={fid("bpLocale")}
                    className={NATIVE_SELECT_CLASS}
                    value={
                      customLocaleMode ||
                      !LOCALE_PRESETS.some(
                        (p) => p.value === (form.fingerprint.locale ?? ""),
                      )
                        ? "__custom__"
                        : (form.fingerprint.locale ?? "")
                    }
                    onChange={(e) => {
                      const v = e.target.value;
                      if (v === "__custom__") {
                        setCustomLocaleMode(true);
                        return;
                      }
                      setCustomLocaleMode(false);
                      setForm({
                        ...form,
                        fingerprint: {
                          ...form.fingerprint,
                          locale: v,
                        },
                      });
                    }}
                  >
                    {LOCALE_PRESETS.map((p) => (
                      <option key={p.value || "__node_default__"} value={p.value}>
                        {p.label}
                      </option>
                    ))}
                    <option value="__custom__">自定义语言代码...</option>
                  </select>
                  {customLocaleMode && (
                    <Input
                      aria-label="自定义 Accept-Language"
                      className="mono-num mt-1.5"
                      placeholder="例如 es-ES 或 en-AU"
                      value={form.fingerprint.locale || ""}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          fingerprint: {
                            ...form.fingerprint,
                            locale: e.target.value,
                          },
                        })
                      }
                    />
                  )}
                </div>
              </div>
            </div>

            {/* Full Isolated Fingerprint Parameters */}
            {form.fingerprintMode === "isolated_fingerprint" && (
              <div className="space-y-3 rounded-xl border border-[#e5defb] bg-[#faf9fe] p-3.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 text-[0.76rem] font-semibold text-[#111827]">
                    <Cpu className="h-3.5 w-3.5 text-[#6d5bd0]" aria-hidden="true" />
                    固定 C++ 底层指纹参数（Fingerprint-Chromium 原生生效）
                  </div>
                  <Button
                    type="button"
                    variant="soft"
                    size="xs"
                    onClick={() =>
                      setForm((prev) => ({
                        ...prev,
                        fingerprint: generateConsistentFingerprint(
                          prev.fingerprint.timezone,
                          prev.fingerprint.locale,
                        ),
                      }))
                    }
                  >
                    <Sparkles className="h-3 w-3" aria-hidden="true" />
                    随机生成新一套指纹
                  </Button>
                </div>

                <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
                  <div className="space-y-1">
                    <label htmlFor={fid("fpW")} className="block text-[0.69rem] text-[#525866]">
                      屏幕宽 (px)
                    </label>
                    <Input
                      id={fid("fpW")}
                      type="number"
                      className="mono-num"
                      value={form.fingerprint.screenWidth}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          fingerprint: {
                            ...form.fingerprint,
                            screenWidth: Number(e.target.value) || 1920,
                          },
                        })
                      }
                    />
                  </div>
                  <div className="space-y-1">
                    <label htmlFor={fid("fpH")} className="block text-[0.69rem] text-[#525866]">
                      屏幕高 (px)
                    </label>
                    <Input
                      id={fid("fpH")}
                      type="number"
                      className="mono-num"
                      value={form.fingerprint.screenHeight}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          fingerprint: {
                            ...form.fingerprint,
                            screenHeight: Number(e.target.value) || 1080,
                          },
                        })
                      }
                    />
                  </div>
                  <div className="space-y-1">
                    <label htmlFor={fid("fpCpu")} className="block text-[0.69rem] text-[#525866]">
                      逻辑核心 (CPU)
                    </label>
                    <select
                      id={fid("fpCpu")}
                      className={NATIVE_SELECT_CLASS}
                      value={form.fingerprint.hardwareConcurrency}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          fingerprint: {
                            ...form.fingerprint,
                            hardwareConcurrency: Number(e.target.value) || 8,
                          },
                        })
                      }
                    >
                      {[2, 4, 6, 8, 12, 16, 24].map((v) => (
                        <option key={v} value={v}>
                          {v} 核
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="space-y-1">
                    <label htmlFor={fid("fpMem")} className="block text-[0.69rem] text-[#525866]">
                      内存 (GB)
                    </label>
                    <select
                      id={fid("fpMem")}
                      className={NATIVE_SELECT_CLASS}
                      value={form.fingerprint.deviceMemory}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          fingerprint: {
                            ...form.fingerprint,
                            deviceMemory: Number(e.target.value) || 8,
                          },
                        })
                      }
                    >
                      {[4, 8, 16, 32].map((v) => (
                        <option key={v} value={v}>
                          {v} GB
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                  <div className="space-y-1">
                    <label htmlFor={fid("fpGpu")} className="block text-[0.69rem] text-[#525866]">
                      WebGL 显卡型号预设
                    </label>
                    <select
                      id={fid("fpGpu")}
                      className={NATIVE_SELECT_CLASS}
                      value={
                        GPU_PRESETS.some(
                          (g) => g.renderer === form.fingerprint.webglRenderer,
                        )
                          ? form.fingerprint.webglRenderer
                          : "__custom__"
                      }
                      onChange={(e) => {
                        const match = GPU_PRESETS.find(
                          (g) => g.renderer === e.target.value,
                        );
                        if (match) {
                          setForm({
                            ...form,
                            fingerprint: {
                              ...form.fingerprint,
                              webglVendor: match.vendor,
                              webglRenderer: match.renderer,
                            },
                          });
                        }
                      }}
                    >
                      {GPU_PRESETS.map((g) => (
                        <option key={g.renderer} value={g.renderer}>
                          {g.renderer}
                        </option>
                      ))}
                      {!GPU_PRESETS.some(
                        (g) => g.renderer === form.fingerprint.webglRenderer,
                      ) && (
                        <option value="__custom__">
                          自定义 ({form.fingerprint.webglRenderer})
                        </option>
                      )}
                    </select>
                  </div>

                  <div className="space-y-1">
                    <label htmlFor={fid("fpSeed")} className="block text-[0.69rem] text-[#525866]">
                      Canvas / Audio 固定种子
                    </label>
                    <Input
                      id={fid("fpSeed")}
                      className="mono-num"
                      value={form.fingerprint.noiseSeed}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          fingerprint: {
                            ...form.fingerprint,
                            noiseSeed: e.target.value,
                          },
                        })
                      }
                    />
                  </div>
                </div>

                <div className="space-y-1">
                  <label htmlFor={fid("fpUa")} className="block text-[0.69rem] text-[#525866]">
                    自定义 User-Agent（推荐留空以保持与当前 Chromium 内核一致）
                  </label>
                  <Input
                    id={fid("fpUa")}
                    className="mono-num"
                    placeholder="留空即使用内置真实 Chromium User-Agent"
                    value={form.fingerprint.userAgent || ""}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        fingerprint: {
                          ...form.fingerprint,
                          userAgent: e.target.value,
                        },
                      })
                    }
                  />
                </div>
              </div>
            )}

            {editingId ? (
              <div className="flex flex-wrap items-center justify-between gap-2.5 rounded-xl border border-[#eaecef] bg-[#f8f9fb] px-3 py-2.5">
                <div className="min-w-0 space-y-0.5">
                  <p className="text-[0.73rem] font-medium text-[#111827]">
                    环境 Cookie 管理（支持 AdsPower / EditThisCookie JSON 与 Netscape）
                  </p>
                  <p className="text-[0.68rem] text-[#7c8495]">
                    支持窗口开启时实时同步，或窗口关闭后离线直接读写该环境独立数据目录。
                  </p>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="xs"
                  disabled={!status?.browserInstalled}
                  onClick={() => {
                    const target =
                      profiles.find((p) => p.id === editingId) || form;
                    setEditorOpen(false);
                    openCookieDialog(target);
                  }}
                >
                  <KeyRound className="h-3.5 w-3.5" aria-hidden="true" />
                  管理 / 编辑此环境 Cookie
                </Button>
              </div>
            ) : (
              <div className="space-y-1">
                <label
                  htmlFor={fid("bpInitCookies")}
                  className="block text-[0.72rem] font-medium text-[#525866]"
                >
                  初始化导入 Cookie（可选 · 支持 AdsPower JSON / EditThisCookie / cookies.txt）
                </label>
                <textarea
                  id={fid("bpInitCookies")}
                  rows={3}
                  className="w-full rounded-lg border border-[#dce0e6] bg-white px-2.5 py-1.5 font-mono text-[0.72rem] text-[#111827] placeholder:text-[#9ca3af] shadow-[0_1px_1px_rgba(15,23,42,0.02)] focus-visible:outline-2 focus-visible:outline-[#5b48c4] focus-visible:outline-offset-1"
                  placeholder={'粘贴 [{"name":"sessionKey","value":"...","domain":".claude.ai",...}] 或 Netscape 文本，保存环境时自动写入'}
                  value={initialCookiesText}
                  onChange={(e) => setInitialCookiesText(e.target.value)}
                />
              </div>
            )}

            <div className="space-y-1">
              <label
                htmlFor={fid("bpNotes")}
                className="block text-[0.72rem] font-medium text-[#525866]"
              >
                用途备注（可选）
              </label>
              <Input
                id={fid("bpNotes")}
                placeholder="例如：专门跑日本节点网页、Google 账号注册 / 养号"
                value={form.notes || ""}
                onChange={(e) => setForm({ ...form, notes: e.target.value })}
              />
            </div>
          </div>

          <div className="flex items-center justify-end gap-2 bg-[#fafbfc] px-5 py-3">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setEditorOpen(false)}
            >
              取消
            </Button>
            <Button type="submit" variant="solid" size="sm" disabled={saving}>
              <Monitor className="h-3.5 w-3.5" aria-hidden="true" />
              {saving ? "保存中..." : "保存浏览器环境"}
            </Button>
          </div>
        </form>
      </dialog>

      {/* Native Top-Layer Modal <dialog>: Confirm Profile Deletion */}
      <dialog
        ref={confirmDialogRef}
        {...({ closedby: "any" } as Record<string, string>)}
        aria-labelledby={confirmTitleId}
        onClose={(e) => {
          e.currentTarget.returnValue = "";
          setConfirmDelete(null);
        }}
        className="ng-dialog m-auto w-[min(26rem,calc(100vi-2rem))] rounded-2xl border border-[#eaecef] bg-white p-5 text-[#111827] shadow-[0_24px_48px_-12px_rgba(15,23,42,0.22)]"
      >
        <div className="space-y-3">
          <div className="flex items-center gap-2.5">
            <span className="inline-grid h-8 w-8 place-items-center rounded-lg bg-[#fef2f2] text-[#dc2626]">
              <AlertTriangle className="h-4 w-4" aria-hidden="true" />
            </span>
            <h2 id={confirmTitleId} className="text-[0.95rem] font-semibold">
              确认删除浏览器环境？
            </h2>
          </div>
          <p className="text-[0.77rem] text-[#525866]">
            将从配置列表移除环境{" "}
            <span className="font-semibold text-[#111827]">
              {confirmDelete?.name}
            </span>{" "}
            （仅移除配置条目，不破坏其他环境窗口与缓存）。
          </p>
          <div className="flex items-center justify-end gap-2 pt-2">
            <Button
              ref={confirmCancelRef}
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setConfirmDelete(null)}
            >
              取消
            </Button>
            <Button
              type="button"
              variant="destructive"
              size="sm"
              onClick={() => void handleConfirmDelete()}
            >
              确认删除
            </Button>
          </div>
        </div>
      </dialog>

      {/* Native Top-Layer Modal <dialog>: AdsPower-Style Cookie Manager */}
      <dialog
        ref={cookieDialogRef}
        {...({ closedby: "any" } as Record<string, string>)}
        aria-labelledby={cookieTitleId}
        onClose={(e) => {
          e.currentTarget.returnValue = "";
          setCookieDialogProfile(null);
          setConfirmClearCookies(false);
        }}
        className="ng-dialog m-auto w-[min(46rem,calc(100vi-2rem))] max-h-[86dvh] overflow-hidden rounded-2xl border border-[#eaecef] bg-white p-0 text-[#111827] shadow-[0_24px_48px_-12px_rgba(15,23,42,0.22)]"
      >
        <div className="flex max-h-[86dvh] flex-col divide-y divide-[#eaecef]">
          {/* Header */}
          <div className="flex items-center justify-between gap-2 px-5 py-3.5">
            <div className="min-w-0 flex-1 space-y-0.5">
              <div className="flex flex-wrap items-center gap-2">
                <h2
                  id={cookieTitleId}
                  className="flex items-center gap-1.5 text-[0.94rem] font-semibold text-[#111827]"
                >
                  <KeyRound className="h-4 w-4 text-[#6d5bd0]" aria-hidden="true" />
                  Cookie 管理器
                </h2>
                {cookieDialogProfile && (
                  <Badge variant="neutral" className="max-w-[14rem] truncate text-[0.67rem]">
                    {cookieDialogProfile.name}
                  </Badge>
                )}
                {cookieSnapshot && (
                  <Badge
                    variant={cookieSnapshot.liveMode ? "success" : "neutral"}
                    className="text-[0.65rem]"
                  >
                    {cookieSnapshot.liveMode ? "窗口运行中 · 实时同步" : "窗口已关闭 · 离线读写"}
                  </Badge>
                )}
                {cookieSnapshot && (
                  <span className="mono-num text-[0.7rem] text-[#7c8495]">
                    共 {cookieSnapshot.cookies.length} 条
                  </span>
                )}
              </div>
              <p className="text-[0.69rem] text-[#7c8495]">
                完全兼容 AdsPower / EditThisCookie JSON 与 Netscape cookies.txt，操作仅在本地回环完成。
              </p>
            </div>

            <div className="flex shrink-0 items-center gap-1.5">
              <Button
                type="button"
                variant="outline"
                size="xs"
                disabled={cookieLoading || cookieBusy || !cookieDialogProfile}
                onClick={() =>
                  cookieDialogProfile && void loadProfileCookies(cookieDialogProfile.id)
                }
              >
                <RefreshCw
                  className={`h-3 w-3 ${cookieLoading ? "animate-spin" : ""}`}
                  aria-hidden="true"
                />
                刷新
              </Button>
              <button
                ref={cookieCloseRef}
                type="button"
                aria-label="关闭"
                onClick={() => setCookieDialogProfile(null)}
                className="rounded-lg p-1 text-[#7c8495] hover:bg-[#f3f4f6] hover:text-[#111827] cursor-pointer"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>
          </div>

          {/* Tabs + Toolbar */}
          <div className="flex flex-wrap items-center justify-between gap-2 bg-[#fafbfc] px-5 py-2.5">
            <div className="flex items-center gap-1" role="group" aria-label="Cookie 面板模式">
              <button
                type="button"
                aria-pressed={cookieTab === "list"}
                onClick={() => {
                  setCookieTab("list");
                  setCookieError("");
                  setConfirmClearCookies(false);
                }}
                className={`rounded-md border px-2.5 py-1 text-[0.72rem] font-medium transition-colors cursor-pointer ${
                  cookieTab === "list"
                    ? "border-[#dcd4fb] bg-[#6d5bd0] text-white"
                    : "border-[#dce0e6] bg-white text-[#525866] hover:bg-[#f3f4f6]"
                }`}
              >
                查看与管理 ({cookieSnapshot?.cookies.length ?? 0})
              </button>
              <button
                type="button"
                aria-pressed={cookieTab === "import"}
                onClick={() => {
                  setCookieTab("import");
                  setCookieError("");
                  setConfirmClearCookies(false);
                }}
                className={`rounded-md border px-2.5 py-1 text-[0.72rem] font-medium transition-colors cursor-pointer ${
                  cookieTab === "import"
                    ? "border-[#dcd4fb] bg-[#6d5bd0] text-white"
                    : "border-[#dce0e6] bg-white text-[#525866] hover:bg-[#f3f4f6]"
                }`}
              >
                导入 / 批量粘贴
              </button>
            </div>

            {cookieTab === "list" && (
              <div className="flex flex-wrap items-center gap-1.5">
                <Button
                  type="button"
                  variant="outline"
                  size="xs"
                  disabled={!cookieSnapshot || filteredCookies.length === 0 || cookieBusy}
                  onClick={() => {
                    if (!cookieSnapshot) return;
                    const text = cookieSearch.trim()
                      ? formatSubsetExportJson(filteredCookies)
                      : cookieSnapshot.exportJson;
                    void handleCopyTextFeedback(
                      "__all__",
                      text,
                      `已复制 ${filteredCookies.length} 条 Cookie JSON（可直接导入 AdsPower）`,
                    );
                  }}
                >
                  {copiedCookieKey === "__all__" ? (
                    <Check className="h-3 w-3 text-[#16a34a]" aria-hidden="true" />
                  ) : (
                    <Copy className="h-3 w-3" aria-hidden="true" />
                  )}
                  {copiedCookieKey === "__all__" ? "已复制 JSON" : "复制 JSON"}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="xs"
                  disabled={!cookieSnapshot || filteredCookies.length === 0 || cookieBusy}
                  onClick={() => {
                    if (!cookieSnapshot) return;
                    const text = cookieSearch.trim()
                      ? formatSubsetExportJson(filteredCookies)
                      : cookieSnapshot.exportJson;
                    handleDownloadExportJson(text);
                  }}
                >
                  <Download className="h-3 w-3" aria-hidden="true" />
                  下载 .json
                </Button>
                <Button
                  type="button"
                  variant={confirmClearCookies ? "destructive" : "destructive-outline"}
                  size="xs"
                  disabled={!cookieSnapshot || cookieSnapshot.cookies.length === 0 || cookieBusy}
                  onClick={() => void handleClearAllCookies()}
                >
                  <Trash2 className="h-3 w-3" aria-hidden="true" />
                  {confirmClearCookies ? "再次点击确认清空" : "清空全部"}
                </Button>
              </div>
            )}
          </div>

          {/* Body */}
          <div className="min-h-[16rem] flex-1 space-y-3 overflow-y-auto px-5 py-4">
            {cookieError && (
              <div className="rounded-lg border border-[#fecaca] bg-[#fef2f2] px-3 py-2 text-[0.74rem] text-[#b91c1c]">
                {cookieError}
              </div>
            )}

            {cookieTab === "list" ? (
              <>
                <div className="relative">
                  <Search
                    className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-[#9ca3af]"
                    aria-hidden="true"
                  />
                  <Input
                    aria-label="按域名、Cookie 名称或值搜索"
                    className="pl-8"
                    placeholder="按域名、Cookie 名称或值过滤，如 .claude.ai / sessionKey / accounts.google.com..."
                    value={cookieSearch}
                    onChange={(e) => setCookieSearch(e.target.value)}
                  />
                </div>

                {cookieLoading && !cookieSnapshot ? (
                  <div className="rounded-xl border border-dashed border-[#dce0e6] bg-[#fafbfc] px-4 py-10 text-center text-[0.76rem] text-[#7c8495]">
                    正在通过本地回环通道读取该环境 Cookie...
                  </div>
                ) : groupedCookies.length === 0 ? (
                  <div className="space-y-2 rounded-xl border border-dashed border-[#dce0e6] bg-[#fafbfc] px-4 py-8 text-center">
                    <p className="text-[0.78rem] font-medium text-[#525866]">
                      {cookieSearch.trim()
                        ? "没有匹配当前搜索关键词的 Cookie"
                        : "该浏览器环境当前暂无 Cookie 记录"}
                    </p>
                    {!cookieSearch.trim() && (
                      <Button
                        type="button"
                        variant="soft"
                        size="xs"
                        onClick={() => setCookieTab("import")}
                      >
                        <ClipboardPaste className="h-3 w-3" aria-hidden="true" />
                        去粘贴导入 Cookie
                      </Button>
                    )}
                  </div>
                ) : (
                  <div className="space-y-2.5">
                    {groupedCookies.map(([domain, items]) => (
                      <section
                        key={domain}
                        className="overflow-hidden rounded-xl border border-[#eaecef] bg-white"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#eaecef] bg-[#f8f9fb] px-3 py-2">
                          <div className="flex min-w-0 items-center gap-2">
                            <span className="mono-num truncate text-[0.76rem] font-semibold text-[#111827]">
                              {domain}
                            </span>
                            <Badge variant="neutral" className="text-[0.64rem]">
                              {items.length} 条
                            </Badge>
                          </div>
                          <Button
                            type="button"
                            variant="destructive-outline"
                            size="xs"
                            disabled={cookieBusy}
                            onClick={() => void handleDeleteDomainCookies(domain)}
                          >
                            <Trash2 className="h-3 w-3" aria-hidden="true" />
                            删此域名
                          </Button>
                        </div>

                        <ul className="divide-y divide-[#f1f3f5]">
                          {items.map((c) => {
                            const key = `${c.domain}|${c.path}|${c.name}`;
                            const expText = c.session
                              ? "会话"
                              : c.expires
                                ? new Date(c.expires * 1000).toLocaleDateString()
                                : "--";
                            return (
                              <li
                                key={key}
                                className="flex items-center justify-between gap-3 px-3 py-2 text-[0.72rem]"
                              >
                                <div className="min-w-0 flex-1 space-y-0.5">
                                  <div className="flex flex-wrap items-center gap-1.5">
                                    <span className="mono-num truncate font-semibold text-[#111827]">
                                      {c.name}
                                    </span>
                                    <span className="mono-num text-[0.65rem] text-[#7c8495]">
                                      {c.path}
                                    </span>
                                    {c.httpOnly && (
                                      <span className="rounded bg-[#eef2ff] px-1 py-0.2 text-[0.62rem] font-medium text-[#4f46e5]">
                                        HttpOnly
                                      </span>
                                    )}
                                    {c.secure && (
                                      <span className="rounded bg-[#ecfdf5] px-1 py-0.2 text-[0.62rem] font-medium text-[#15803d]">
                                        Secure
                                      </span>
                                    )}
                                    {c.sameSite && (
                                      <span className="rounded bg-[#f3f4f6] px-1 py-0.2 text-[0.62rem] text-[#525866]">
                                        {c.sameSite}
                                      </span>
                                    )}
                                    <span className="mono-num text-[0.64rem] text-[#9ca3af]">
                                      到期 {expText}
                                    </span>
                                  </div>
                                  <p className="mono-num truncate text-[0.69rem] text-[#525866]">
                                    {c.value || "(空值)"}
                                  </p>
                                </div>

                                <div className="flex shrink-0 items-center gap-1">
                                  <Button
                                    type="button"
                                    variant="ghost"
                                    size="xs"
                                    disabled={cookieBusy}
                                    onClick={() =>
                                      void handleCopyTextFeedback(
                                        key,
                                        c.value,
                                        `已复制 Cookie 值: ${c.name}`,
                                      )
                                    }
                                  >
                                    {copiedCookieKey === key ? (
                                      <Check className="h-3 w-3 text-[#16a34a]" aria-hidden="true" />
                                    ) : (
                                      <Copy className="h-3 w-3" aria-hidden="true" />
                                    )}
                                    复制值
                                  </Button>
                                  <Button
                                    type="button"
                                    variant="destructive-outline"
                                    size="xs"
                                    disabled={cookieBusy}
                                    onClick={() => void handleDeleteSingleCookie(c)}
                                  >
                                    <Trash2 className="h-3 w-3" aria-hidden="true" />
                                    删除
                                  </Button>
                                </div>
                              </li>
                            );
                          })}
                        </ul>
                      </section>
                    ))}
                  </div>
                )}
              </>
            ) : (
              <div className="space-y-3">
                <div className="space-y-1">
                  <label
                    htmlFor={fid("cookieImportArea")}
                    className="block text-[0.74rem] font-medium text-[#111827]"
                  >
                    粘贴 Cookie 文本（自动识别格式）
                  </label>
                  <p className="text-[0.69rem] text-[#7c8495]">
                    支持 AdsPower 导出 JSON 数组、EditThisCookie / Cookie-Editor JSON、{" "}
                    <span className="mono-num">{"{\"cookies\":[...]}"}</span> 或 Netscape{" "}
                    <span className="mono-num">cookies.txt</span>（Tab 分隔 7 列）。
                  </p>
                  <textarea
                    id={fid("cookieImportArea")}
                    rows={9}
                    className="w-full rounded-xl border border-[#dce0e6] bg-white px-3 py-2 font-mono text-[0.72rem] text-[#111827] placeholder:text-[#9ca3af] shadow-[0_1px_1px_rgba(15,23,42,0.02)] focus-visible:outline-2 focus-visible:outline-[#5b48c4] focus-visible:outline-offset-1"
                    placeholder={'[\n  {\n    "domain": ".claude.ai",\n    "name": "sessionKey",\n    "value": "sk-ant-sid01-...",\n    "path": "/",\n    "secure": true,\n    "httpOnly": true\n  }\n]'}
                    value={importText}
                    onChange={(e) => setImportText(e.target.value)}
                  />
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[#eaecef] bg-[#fafbfc] px-3 py-2.5">
                  <label className="flex cursor-pointer items-center gap-2 text-[0.74rem] text-[#111827]">
                    <input
                      type="checkbox"
                      className="h-3.5 w-3.5 rounded border-[#c3cad6] accent-[#6d5bd0] cursor-pointer"
                      checked={importReplace}
                      onChange={(e) => setImportReplace(e.target.checked)}
                    />
                    <span>清空该环境现有 Cookie 后覆盖导入（默认勾选关闭 = 仅合并更新同名键）</span>
                  </label>

                  <Button
                    type="button"
                    variant="solid"
                    size="sm"
                    disabled={cookieBusy || !importText.trim()}
                    onClick={() => void handleImportCookies()}
                  >
                    <ClipboardPaste className="h-3.5 w-3.5" aria-hidden="true" />
                    {cookieBusy ? "写入中..." : "立即导入 Cookie"}
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>
      </dialog>
    </div>
  );
}
