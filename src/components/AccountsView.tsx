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
  GripVertical,
  KeyRound,
  Layers,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Sparkles,
  Trash2,
  X,
} from "lucide-react";
import type {
  AccountEnvPreset,
  AccountEnvType,
  AccountNodeSource,
  AccountRecord,
  AccountStatus,
  ClashVergeNodesSnapshot,
  NodeProfile,
} from "../types";
import { generateStrongPassword, generateTotp } from "../lib/totp";
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
  loading: boolean;
  loadingClashNodes: boolean;
  onUpsert: (account: AccountRecord) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
  onBulkDelete: (ids: string[]) => Promise<void>;
  onImport: (records: AccountRecord[], replace: boolean) => Promise<void>;
  onSaveEnvPresets: (presets: AccountEnvPreset[]) => Promise<void>;
  onRefreshClashNodes: () => Promise<void>;
  onReorder: (orderedIds: string[]) => Promise<void>;
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
  linkedNodeSource: AccountNodeSource;
  linkedNodeId: string;
  linkedNodeName: string;
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
    linkedNodeSource: "none",
    linkedNodeId: "",
    linkedNodeName: "",
    purpose: "",
    tagsText: "",
    status: "active",
    notes: "",
    createdAt: "",
  };
}

function recordToFormState(acc: AccountRecord): AccountFormState {
  const source = normalizeNodeSource(acc.linkedNodeSource, acc.linkedNodeId);
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
    linkedNodeSource: source,
    linkedNodeId: acc.linkedNodeId || "",
    linkedNodeName: acc.linkedNodeName || "",
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
): {
  source: AccountNodeSource;
  sourceLabel: string;
  name: string;
  badgeText: string;
  variant: "iris" | "warning" | "neutral";
} | null {
  const source = normalizeNodeSource(acc.linkedNodeSource, acc.linkedNodeId);
  if (source === "none") return null;

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
  loading,
  loadingClashNodes,
  onUpsert,
  onDelete,
  onBulkDelete,
  onImport,
  onSaveEnvPresets,
  onRefreshClashNodes,
  onReorder,
  onNotify,
}: AccountsViewProps) {
  const uid = useId();
  const fid = (name: string) => `${uid}-${name}`;
  const editorTitleId = fid("editor-title");
  const confirmTitleId = fid("confirm-title");

  const [search, setSearch] = useState("");
  const [envFilter, setEnvFilter] = useState<string>("__all__");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [expandedIds, setExpandedIds] = useState<Record<string, boolean>>({});
  const [revealedPasswords, setRevealedPasswords] = useState<Record<string, boolean>>({});
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, boolean>>({});
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [saving, setSaving] = useState(false);

  const [editorOpen, setEditorOpen] = useState(false);
  const [form, setForm] = useState<AccountFormState>(emptyFormState);
  const [formError, setFormError] = useState("");
  const [showFormPassword, setShowFormPassword] = useState(false);

  const [addingPreset, setAddingPreset] = useState(false);
  const [newPresetName, setNewPresetName] = useState("");
  const [newPresetType, setNewPresetType] = useState<AccountEnvType>("custom");
  const [clashSearch, setClashSearch] = useState("");

  const [confirmTarget, setConfirmTarget] = useState<ConfirmTarget | null>(null);
  const [reorderAnnouncement, setReorderAnnouncement] = useState("");

  const editorDialogRef = useRef<HTMLDialogElement>(null);
  const confirmDialogRef = useRef<HTMLDialogElement>(null);
  const emailInputRef = useRef<HTMLInputElement>(null);
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

  const hasTotpTargets = useMemo(
    () => editorOpen || accounts.some((a) => Boolean(a.totpSecret?.trim())),
    [accounts, editorOpen],
  );

  useEffect(() => {
    if (!hasTotpTargets) return;
    setNowMs(Date.now());
    const timer = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [hasTotpTargets]);

  useEffect(() => {
    const cleanEditor = attachLightDismissFallback(editorDialogRef.current);
    const cleanConfirm = attachLightDismissFallback(confirmDialogRef.current);
    return () => {
      cleanEditor();
      cleanConfirm();
      activeCleanupRef.current?.();
    };
  }, []);

  const isFiltered = Boolean(
    search.trim() || envFilter !== "__all__" || statusFilter !== "all",
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
    for (const acc of accounts) {
      if (acc.status === "active") active += 1;
      else if (acc.status === "standby") standby += 1;
      else if (acc.status === "restricted") restricted += 1;
      else if (acc.status === "banned") banned += 1;
    }
    return {
      total: accounts.length,
      active,
      standby,
      restricted,
      banned,
      envCount: distinctEnvironments.length,
    };
  }, [accounts, distinctEnvironments]);

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
      const nodeDisplay = resolveAccountNodeDisplay(acc, nodeById);
      const envMeta = ENV_TYPE_META[normalizeEnvType(acc.envType)];
      const haystack = [
        acc.label,
        acc.provider,
        acc.email,
        acc.environmentName,
        acc.environmentProfile || "",
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
  }, [accounts, statusFilter, envFilter, search, nodeById]);

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

  const openEditor = (existing?: AccountRecord) => {
    setForm(existing ? recordToFormState(existing) : emptyFormState());
    setFormError("");
    setShowFormPassword(false);
    setAddingPreset(false);
    setNewPresetName("");
    setNewPresetType("custom");
    setClashSearch("");
    setEditorOpen(true);
    if (!clashNodes?.detected) {
      void onRefreshClashNodes();
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
        };
      }
      if (nextSource === "netguard") {
        const currentNode = prev.linkedNodeId ? nodeById.get(prev.linkedNodeId) : undefined;
        return {
          ...prev,
          linkedNodeSource: "netguard",
          linkedNodeName: currentNode?.name || "",
        };
      }
      return {
        ...prev,
        linkedNodeSource: nextSource,
        linkedNodeId: "",
        linkedNodeName: prev.linkedNodeSource === nextSource ? prev.linkedNodeName : "",
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
      linkedNodeSource: effectiveSource,
      linkedNodeId: effectiveNodeId,
      linkedNodeName: effectiveNodeName,
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
            linkedNodeSource,
            linkedNodeId,
            linkedNodeName:
              typeof item.linkedNodeName === "string" ? item.linkedNodeName : null,
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
            ) : (
              <Badge variant="neutral">状态良好</Badge>
            )}
          </div>
          <div className="mono-num text-[1.2rem] font-semibold text-[#111827]">
            {stats.restricted + stats.banned}
          </div>
          <div className="mono-num text-[0.7rem] text-[#7c8495]">
            受限 {stats.restricted} · 已封禁 {stats.banned}
          </div>
        </div>
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
              const nodeDisplay = resolveAccountNodeDisplay(acc, nodeById);
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
                          <div className="flex min-w-0 flex-1 items-center">
                            {nodeDisplay ? (
                              <Badge
                                variant={nodeDisplay.variant}
                                className="max-w-full overflow-hidden"
                                title={nodeDisplay.badgeText}
                              >
                                <span className="truncate">{nodeDisplay.badgeText}</span>
                              </Badge>
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

              {/* Multi-Source Node Binding */}
              <div className="space-y-2.5 rounded-xl border border-[#eaecef] bg-[#fafbfc] p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[0.73rem] font-medium text-[#525866]">
                    绑定出口节点（支持 NetGuard / Clash Verge / 自定义）
                  </span>
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
                  </div>
                )}

                {form.linkedNodeSource === "custom" && (
                  <Input
                    placeholder="输入自定义代理节点或直连描述，如：静态住宅 1.2.3.4 / 本地直连 / 指纹内置 Socks5"
                    value={form.linkedNodeName}
                    onChange={(e) =>
                      setForm((prev) => ({
                        ...prev,
                        linkedNodeName: e.target.value,
                      }))
                    }
                  />
                )}
              </div>
            </fieldset>

            {/* Section 4: Purpose, Tags, Notes */}
            <fieldset className="space-y-3 border-t border-[#eaecef] pt-4">
              <legend className="text-[0.76rem] font-semibold text-[#111827]">
                4. 用途与备注
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
    </div>
  );
}
