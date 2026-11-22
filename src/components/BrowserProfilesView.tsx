import { useEffect, useId, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Copy,
  Cpu,
  ExternalLink,
  Fingerprint,
  Globe,
  Monitor,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Square,
  Trash2,
  X,
} from "lucide-react";
import type {
  AppConfig,
  BrowserFingerprintConfig,
  BrowserFingerprintMode,
  BrowserProfile,
  ExitIpInfo,
  GatewayStatus,
  NodeProfile,
} from "../types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Input } from "./ui/input";

interface Props {
  config: AppConfig;
  status: GatewayStatus | null;
  gatewayReady: boolean;
  preselectedNodeRequest?: { nodeId: string; nonce: number } | null;
  onSaveProfiles: (profiles: BrowserProfile[]) => Promise<void>;
  onLaunchProfile: (profileId: string, url?: string) => Promise<void>;
  onCloseProfile: (profileId: string) => Promise<void>;
  onProbeNodeExit: (nodeId: string) => Promise<ExitIpInfo>;
  onInstallBrowser: () => Promise<void>;
  onRestartGateway?: () => Promise<void>;
  onNotify: (msg: string) => void;
}

const NATIVE_SELECT_CLASS =
  "flex min-h-8 w-full rounded-lg border border-[#dce0e6] bg-white px-2.5 py-1.5 text-[0.765rem] text-[#111827] shadow-[0_1px_1px_rgba(15,23,42,0.02)] transition-colors hover:border-[#c3cad6] focus-visible:outline-2 focus-visible:outline-[#5b48c4] focus-visible:outline-offset-1 cursor-pointer";

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
  { label: "IP 信誉检测", url: "https://ip.net.coffee/" },
  { label: "指纹检测", url: "https://fuck-claude.vercel.app/" },
  { label: "Google", url: "https://www.google.com/" },
];

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
      node?.locale || null,
    ),
    notes: "",
  };
}

export function BrowserProfilesView({
  config,
  status,
  preselectedNodeRequest,
  onSaveProfiles,
  onLaunchProfile,
  onCloseProfile,
  onProbeNodeExit,
  onInstallBrowser,
  onRestartGateway,
  onNotify,
}: Props) {
  const uid = useId();
  const fid = (name: string) => `${uid}-${name}`;
  const editorTitleId = fid("bp-editor-title");
  const confirmTitleId = fid("bp-confirm-title");

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

  const [editorOpen, setEditorOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<BrowserProfile>(() =>
    createFormForNode(config.nodes[0]),
  );
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);

  const [confirmDelete, setConfirmDelete] = useState<BrowserProfile | null>(
    null,
  );
  const [probingNodeId, setProbingNodeId] = useState<string | null>(null);
  const [nodeProbeResults, setNodeProbeResults] = useState<
    Record<string, ExitIpInfo>
  >({});

  const editorDialogRef = useRef<HTMLDialogElement>(null);
  const confirmDialogRef = useRef<HTMLDialogElement>(null);
  const nameInputRef = useRef<HTMLInputElement>(null);
  const confirmCancelRef = useRef<HTMLButtonElement>(null);
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

  // Open preselected node creation modal when triggered from NodeEditor
  useEffect(() => {
    if (!preselectedNodeRequest) return;
    if (preselectedNodeRequest.nonce === handledPreselectNonce.current) return;
    handledPreselectNonce.current = preselectedNodeRequest.nonce;
    const node = nodeById.get(preselectedNodeRequest.nodeId);
    setEditingId(null);
    setForm(createFormForNode(node, "isolated_fingerprint"));
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
    setFormError("");
    setEditorOpen(true);
  };

  const openEditModal = (profile: BrowserProfile) => {
    setEditingId(profile.id);
    setForm({
      ...profile,
      fingerprint: { ...profile.fingerprint },
    });
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
        locale: profile.fingerprint.locale || node?.locale || undefined,
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

    const nextRecord: BrowserProfile = {
      ...form,
      id: editingId || `bp-${Date.now()}`,
      name: cleanName,
      homepage: cleanHomepage,
      nodeId: form.nodeId?.trim() || null,
      customProxyUrl: form.customProxyUrl?.trim() || null,
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
      setEditorOpen(false);
      onNotify(`已保存浏览器环境: ${nextRecord.name}`);
    } catch (err) {
      setFormError(`保存失败: ${String(err)}`);
    } finally {
      setSaving(false);
    }
  };

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
        locale: targetNode?.locale || prev.fingerprint.locale,
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
          {!status?.browserInstalled && (
            <Button variant="soft" size="sm" onClick={() => void onInstallBrowser()}>
              安装便携 Chromium (~200MB)
            </Button>
          )}
          <Button variant="solid" size="sm" onClick={() => openCreateModal()}>
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            新建浏览器环境
          </Button>
        </div>
      </header>

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
              profile.fingerprint.locale || boundNode?.locale || "ko-KR";
            const canLaunch =
              !!status?.browserInstalled &&
              (hasCustomProxy ||
                (!!status?.running &&
                  !(isPrimary && status?.blockedByKillSwitch) &&
                  !needsGatewayRestart));
            const probeInfo = hasCustomProxy
              ? undefined
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
                      <span className="text-[0.68rem] text-[#7c8495]">
                        账号独立代理 · 需本地代理在线
                      </span>
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
                      仅对齐时区与语言，保留真实 Chromium 原生硬件信号以防 hCaptcha 拒绝
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
                          "https://fuck-claude.vercel.app/",
                        )
                      }
                    >
                      <ExternalLink className="h-3 w-3" aria-hidden="true" />
                      打开指纹检测
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
                <label
                  htmlFor={fid("bpNode")}
                  className="block text-[0.72rem] font-medium text-[#525866]"
                >
                  绑定出口节点
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
                {form.customProxyUrl?.trim() && (
                  <div className="mt-1 flex items-center justify-between gap-2 rounded-md border border-[#fde68a] bg-[#fffbeb] px-2 py-1 text-[0.68rem] text-[#92400e]">
                    <span className="mono-num truncate">
                      当前使用独立代理: {form.customProxyUrl}
                    </span>
                    <button
                      type="button"
                      onClick={() => setForm({ ...form, customProxyUrl: null })}
                      className="shrink-0 font-medium text-[#b45309] underline hover:text-[#78350f] cursor-pointer"
                    >
                      清除改用节点
                    </button>
                  </div>
                )}
              </div>

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
                    只对齐时区与语言，不做 Canvas/WebGL JS 改写，hCaptcha 与风控最稳。
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
                    记住固定的屏幕、CPU/内存、WebGL GPU 与 Canvas/Audio 种子，多账号彼此隔离。
                  </p>
                </label>
              </div>
            </fieldset>

            {/* Timezone & Locale */}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="space-y-1">
                <label
                  htmlFor={fid("bpTz")}
                  className="block text-[0.72rem] font-medium text-[#525866]"
                >
                  时区覆盖（留空则跟随所选节点）
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
                  语言覆盖（留空则跟随所选节点）
                </label>
                <Input
                  id={fid("bpLocale")}
                  className="mono-num"
                  placeholder="ja-JP"
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
              </div>
            </div>

            {/* Full Isolated Fingerprint Parameters */}
            {form.fingerprintMode === "isolated_fingerprint" && (
              <div className="space-y-3 rounded-xl border border-[#e5defb] bg-[#faf9fe] p-3.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 text-[0.76rem] font-semibold text-[#111827]">
                    <Cpu className="h-3.5 w-3.5 text-[#6d5bd0]" aria-hidden="true" />
                    固定一致性硬件与图像指纹（每次启动完全复现）
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
    </div>
  );
}
