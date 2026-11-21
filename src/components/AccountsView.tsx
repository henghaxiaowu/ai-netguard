import { useEffect, useId, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Copy,
  Download,
  Eye,
  EyeOff,
  FileUp,
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
  AccountEnvType,
  AccountRecord,
  AccountStatus,
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
  loading: boolean;
  onUpsert: (account: AccountRecord) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
  onBulkDelete: (ids: string[]) => Promise<void>;
  onImport: (records: AccountRecord[], replace: boolean) => Promise<void>;
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
  linkedNodeId: string;
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
  { label: string; badgeVariant: "iris" | "obsidian" | "success" | "neutral" | "warning" }
> = {
  adspower: { label: "AdsPower 指纹浏览器", badgeVariant: "iris" },
  claude_code: { label: "Claude Code / Desktop", badgeVariant: "warning" },
  netguard_browser: { label: "NetGuard 防泄漏浏览器", badgeVariant: "success" },
  local: { label: "本地环境", badgeVariant: "neutral" },
  fingerprint_other: { label: "其他指纹浏览器", badgeVariant: "iris" },
  custom: { label: "自定义环境", badgeVariant: "obsidian" },
};

const PROVIDER_PRESETS = ["Google", "Claude", "OpenAI", "GitHub"];

const ENV_PRESETS: { label: string; envType: AccountEnvType; envName: string }[] = [
  { label: "AdsPower", envType: "adspower", envName: "AdsPower" },
  { label: "CloudCart", envType: "custom", envName: "CloudCart" },
  { label: "Claude Code", envType: "claude_code", envName: "Claude Code" },
  { label: "NetGuard 浏览器", envType: "netguard_browser", envName: "NetGuard 安全浏览器" },
  { label: "本地 Chrome", envType: "local", envName: "本地 Chrome" },
];

const NATIVE_SELECT_CLASS =
  "flex min-h-8 w-full rounded-lg border border-[#dce0e6] bg-white px-2.5 py-1.5 text-[0.765rem] text-[#111827] shadow-[0_1px_1px_rgba(15,23,42,0.02)] transition-colors hover:border-[#c3cad6] focus-visible:outline-2 focus-visible:outline-[#5b48c4] focus-visible:outline-offset-1 cursor-pointer";

const TEXTAREA_CLASS =
  "flex w-full rounded-lg border border-[#dce0e6] bg-white px-2.5 py-1.5 text-[0.765rem] text-[#111827] shadow-[0_1px_1px_rgba(15,23,42,0.02)] placeholder:text-[#9ca3af] transition-colors hover:border-[#c3cad6] focus-visible:outline-2 focus-visible:outline-[#5b48c4] focus-visible:outline-offset-1";

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
    envType: "adspower",
    environmentName: "AdsPower",
    environmentProfile: "",
    linkedNodeId: "",
    purpose: "",
    tagsText: "",
    status: "active",
    notes: "",
    createdAt: "",
  };
}

function recordToFormState(acc: AccountRecord): AccountFormState {
  return {
    id: acc.id,
    label: acc.label || "",
    provider: acc.provider || "Google",
    email: acc.email || "",
    password: acc.password || "",
    totpSecret: acc.totpSecret || "",
    recoveryCodes: acc.recoveryCodes || "",
    recoveryEmail: acc.recoveryEmail || "",
    envType: acc.envType || "adspower",
    environmentName: acc.environmentName || "",
    environmentProfile: acc.environmentProfile || "",
    linkedNodeId: acc.linkedNodeId || "",
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
  loading,
  onUpsert,
  onDelete,
  onBulkDelete,
  onImport,
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

  const [confirmTarget, setConfirmTarget] = useState<ConfirmTarget | null>(null);

  const editorDialogRef = useRef<HTMLDialogElement>(null);
  const confirmDialogRef = useRef<HTMLDialogElement>(null);
  const emailInputRef = useRef<HTMLInputElement>(null);
  const confirmCancelRef = useRef<HTMLButtonElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

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
    };
  }, []);

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
      if (envFilter !== "__all__" && acc.environmentName.trim() !== envFilter) {
        return false;
      }
      if (!query) return true;
      const node = acc.linkedNodeId ? nodeById.get(acc.linkedNodeId) : undefined;
      const haystack = [
        acc.label,
        acc.provider,
        acc.email,
        acc.environmentName,
        acc.environmentProfile || "",
        acc.purpose,
        acc.recoveryEmail || "",
        acc.notes || "",
        node?.name || "",
        ...acc.tags,
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [accounts, statusFilter, envFilter, search, nodeById]);

  const formTotpPreview = useMemo(() => {
    const trimmed = form.totpSecret.trim();
    if (!trimmed) return { present: false, result: null };
    return { present: true, result: generateTotp(trimmed, nowMs) };
  }, [form.totpSecret, nowMs]);

  const openEditor = (existing?: AccountRecord) => {
    setForm(existing ? recordToFormState(existing) : emptyFormState());
    setFormError("");
    setShowFormPassword(false);
    setEditorOpen(true);
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
      linkedNodeId: form.linkedNodeId.trim() || null,
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
            Boolean(item && typeof item === "object" && typeof (item as { email?: unknown }).email === "string" && (item as { email: string }).email.trim()),
        )
        .map((item) => ({
          id: typeof item.id === "string" ? item.id : "",
          label: typeof item.label === "string" ? item.label : "",
          provider: typeof item.provider === "string" ? item.provider : "Google",
          email: String(item.email).trim(),
          password: typeof item.password === "string" ? item.password : "",
          totpSecret: typeof item.totpSecret === "string" ? item.totpSecret : null,
          recoveryCodes: typeof item.recoveryCodes === "string" ? item.recoveryCodes : null,
          recoveryEmail: typeof item.recoveryEmail === "string" ? item.recoveryEmail : null,
          envType:
            typeof item.envType === "string"
              ? (item.envType as AccountEnvType)
              : "adspower",
          environmentName:
            typeof item.environmentName === "string" ? item.environmentName : "",
          environmentProfile:
            typeof item.environmentProfile === "string" ? item.environmentProfile : null,
          linkedNodeId: typeof item.linkedNodeId === "string" ? item.linkedNodeId : null,
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
        }));

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
            统一记录 Google 等账号凭据、离线 2FA 动态码、AdsPower / CloudCart / 本地启动环境与用途状态
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
              搜索账号或环境
            </label>
            <Input
              id={fid("search")}
              className="pl-8"
              placeholder="搜索邮箱、别名、用途、AdsPower / CloudCart 环境、窗口ID、标签..."
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

          <span className="mono-num text-[0.71rem] text-[#7c8495]">
            显示 {filteredAccounts.length} / {accounts.length} 条
          </span>
        </div>
      </section>

      {/* Accounts List */}
      <section className="flex flex-col divide-y divide-[#eaecef]">
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
                把不同指纹浏览器（如 AdsPower、CloudCart）或本地环境使用的 Google / AI 账号、密码、2FA 密钥和用途统一加密收纳在这里。
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
          filteredAccounts.map((acc) => {
            const avatar = providerAvatar(acc.provider);
            const statusMeta = STATUS_META[acc.status] || STATUS_META.active;
            const envMeta = ENV_TYPE_META[acc.envType] || ENV_TYPE_META.custom;
            const linkedNode = acc.linkedNodeId ? nodeById.get(acc.linkedNodeId) : undefined;
            const isExpanded = Boolean(expandedIds[acc.id]);
            const isPassShown = Boolean(revealedPasswords[acc.id]);
            const isSecretShown = Boolean(revealedSecrets[acc.id]);
            const rawSecret = acc.totpSecret?.trim() || "";
            const totp = rawSecret ? generateTotp(rawSecret, nowMs) : null;
            const isBanned = acc.status === "banned";
            const isRestricted = acc.status === "restricted";

            return (
              <article
                key={acc.id}
                className={`flex flex-col gap-3 px-6 py-4 transition-colors ${
                  isBanned
                    ? "bg-[#fef2f2]/35"
                    : isRestricted
                      ? "bg-[#fffbeb]/35"
                      : "hover:bg-[#fafbfc]/70"
                }`}
              >
                <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                  {/* Left: Identity + Environment + Purpose */}
                  <div className="flex min-w-0 flex-1 items-start gap-3">
                    <span
                      className={`mt-0.5 inline-grid h-8 w-8 shrink-0 place-items-center rounded-xl border text-[0.76rem] font-bold ${avatar.classes}`}
                      aria-hidden="true"
                    >
                      {avatar.code}
                    </span>

                    <div className="min-w-0 flex-1 space-y-1">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span
                          className={`truncate text-[0.88rem] font-semibold ${
                            isBanned
                              ? "text-[#7c8495] line-through"
                              : "text-[#111827]"
                          }`}
                        >
                          {acc.label || acc.email}
                        </span>
                        <Badge variant={statusMeta.variant}>{statusMeta.label}</Badge>
                        <Badge variant="neutral">{acc.provider}</Badge>
                        <Badge variant={envMeta.badgeVariant}>
                          {acc.environmentName}
                          {acc.environmentProfile ? ` · ${acc.environmentProfile}` : ""}
                        </Badge>
                        {acc.linkedNodeId && (
                          <Badge variant="neutral">
                            节点:{" "}
                            {linkedNode
                              ? `${linkedNode.name}${linkedNode.expectedCountry ? ` (${linkedNode.expectedCountry})` : ""}`
                              : `${acc.linkedNodeId} (未在列表)`}
                          </Badge>
                        )}
                      </div>

                      {/* Email row */}
                      <div className="flex flex-wrap items-center gap-2 text-[0.76rem]">
                        <span className="mono-num truncate font-medium text-[#374151]">
                          {acc.email}
                        </span>
                        <button
                          type="button"
                          onClick={() => handleCopy(acc.email, "账号邮箱")}
                          className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[0.68rem] text-[#5b48c4] hover:bg-[#f0edfc] cursor-pointer"
                          aria-label={`复制账号 ${acc.email}`}
                        >
                          <Copy className="h-3 w-3" aria-hidden="true" />
                          复制账号
                        </button>
                      </div>

                      {/* Purpose & Tags */}
                      {(acc.purpose || acc.tags.length > 0) && (
                        <div className="flex flex-wrap items-center gap-1.5 text-[0.72rem] text-[#525866]">
                          {acc.purpose && (
                            <span className="truncate">用途: {acc.purpose}</span>
                          )}
                          {acc.tags.map((tag) => (
                            <span
                              key={tag}
                              className="inline-flex items-center rounded-md border border-[#eaecef] bg-[#f8f9fb] px-1.5 py-0.5 text-[0.66rem] text-[#525866]"
                            >
                              #{tag}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Right: Credentials + Live 2FA + Row Actions */}
                  <div className="flex flex-wrap items-center gap-2 lg:shrink-0">
                    {/* Password Box */}
                    <div className="flex items-center gap-1 rounded-lg border border-[#eaecef] bg-[#f8f9fb] px-2 py-1">
                      <span className="text-[0.67rem] text-[#7c8495]">密码</span>
                      <span className="mono-num max-w-[8.5rem] truncate text-[0.74rem] font-medium text-[#111827]">
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
                            className="inline-grid h-5 w-5 place-items-center rounded text-[#7c8495] hover:bg-white hover:text-[#111827] cursor-pointer"
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
                            className="inline-grid h-5 w-5 place-items-center rounded text-[#5b48c4] hover:bg-white cursor-pointer"
                            aria-label="复制登录密码"
                          >
                            <Copy className="h-3 w-3" aria-hidden="true" />
                          </button>
                        </>
                      )}
                    </div>

                    {/* Live 2FA Box */}
                    {rawSecret ? (
                      totp ? (
                        <div className="flex items-center gap-1.5 rounded-lg border border-[#dcd4fb] bg-[#f0edfc]/65 px-2.5 py-1">
                          <span className="text-[0.67rem] font-medium text-[#5b48c4]">
                            2FA
                          </span>
                          <span className="mono-num text-[0.82rem] font-semibold tracking-wider text-[#111827]">
                            {totp.formatted}
                          </span>
                          <span
                            className={`mono-num rounded px-1 py-0.5 text-[0.66rem] font-semibold ${
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
                            className="inline-grid h-5 w-5 place-items-center rounded text-[#5b48c4] hover:bg-white cursor-pointer"
                            aria-label="复制当前 2FA 动态码"
                          >
                            <Copy className="h-3 w-3" aria-hidden="true" />
                          </button>
                        </div>
                      ) : (
                        <Badge variant="warning">2FA 密钥格式无效</Badge>
                      )
                    ) : acc.recoveryCodes ? (
                      <Badge variant="neutral">含备用恢复码</Badge>
                    ) : (
                      <span className="rounded-lg border border-dashed border-[#dce0e6] px-2 py-1 text-[0.69rem] text-[#9ca3af]">
                        无 2FA
                      </span>
                    )}

                    {/* Action Buttons */}
                    <div className="flex items-center gap-1">
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
                </div>

                {/* Inline Expanded Details */}
                {isExpanded && (
                  <div className="rounded-xl border border-[#eaecef] bg-[#fafbfc] p-4 space-y-3">
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
                        <span>环境分类: {envMeta.label}</span>
                        {acc.createdAt && <span>创建: {acc.createdAt}</span>}
                        {acc.updatedAt && <span>更新: {acc.updatedAt}</span>}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                      {/* Recovery Email */}
                      <div className="rounded-lg border border-[#eaecef] bg-white p-3 space-y-1">
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
                      <div className="rounded-lg border border-[#eaecef] bg-white p-3 space-y-1">
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
                      <div className="rounded-lg border border-[#eaecef] bg-white p-3 space-y-1">
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
                      <div className="rounded-lg border border-[#eaecef] bg-white p-3 space-y-1">
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
              </article>
            );
          })
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
                          className={`rounded px-1.5 py-0.5 text-[0.66rem] border cursor-pointer ${
                            form.provider === p
                              ? "border-[#dcd4fb] bg-[#f0edfc] text-[#5b48c4] font-semibold"
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
                    placeholder="例如：Google 主号 #1 / CloudCart 美区店"
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

            {/* Section 3: Launch Environment */}
            <fieldset className="space-y-3 border-t border-[#eaecef] pt-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <legend className="text-[0.76rem] font-semibold text-[#111827]">
                  3. 启动环境与绑定节点
                </legend>
                <div className="flex flex-wrap gap-1">
                  {ENV_PRESETS.map((preset) => (
                    <button
                      key={preset.label}
                      type="button"
                      onClick={() =>
                        setForm((prev) => ({
                          ...prev,
                          envType: preset.envType,
                          environmentName: preset.envName,
                        }))
                      }
                      className={`rounded-md border px-2 py-0.5 text-[0.68rem] cursor-pointer ${
                        form.environmentName === preset.envName
                          ? "border-[#dcd4fb] bg-[#f0edfc] text-[#5b48c4] font-semibold"
                          : "border-[#eaecef] bg-[#f8f9fb] text-[#525866] hover:bg-[#f3f4f6]"
                      }`}
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <label
                    htmlFor={fid("envType")}
                    className="block text-[0.73rem] font-medium text-[#525866]"
                  >
                    环境分类
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
                    <option value="adspower">AdsPower 指纹浏览器</option>
                    <option value="custom">自定义环境 (CloudCart 等)</option>
                    <option value="fingerprint_other">其他指纹浏览器 (BitBrowser 等)</option>
                    <option value="claude_code">Claude Code / Desktop</option>
                    <option value="netguard_browser">NetGuard 防泄漏浏览器</option>
                    <option value="local">本地浏览器 / 本地环境</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor={fid("environmentName")}
                    className="block text-[0.73rem] font-medium text-[#525866]"
                  >
                    环境名称
                  </label>
                  <Input
                    id={fid("environmentName")}
                    placeholder="AdsPower / CloudCart / 本地 Chrome..."
                    value={form.environmentName}
                    onChange={(e) =>
                      setForm((prev) => ({
                        ...prev,
                        environmentName: e.target.value,
                      }))
                    }
                  />
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor={fid("environmentProfile")}
                    className="block text-[0.73rem] font-medium text-[#525866]"
                  >
                    窗口编号 / Profile ID / 环境标识
                  </label>
                  <Input
                    id={fid("environmentProfile")}
                    className="mono-num"
                    placeholder="例如：#042 / Profile-US-01 / 独立容器"
                    value={form.environmentProfile}
                    onChange={(e) =>
                      setForm((prev) => ({
                        ...prev,
                        environmentProfile: e.target.value,
                      }))
                    }
                  />
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor={fid("linkedNodeId")}
                    className="block text-[0.73rem] font-medium text-[#525866]"
                  >
                    关联 NetGuard 出口节点
                  </label>
                  <select
                    id={fid("linkedNodeId")}
                    className={NATIVE_SELECT_CLASS}
                    value={form.linkedNodeId}
                    onChange={(e) =>
                      setForm((prev) => ({ ...prev, linkedNodeId: e.target.value }))
                    }
                  >
                    <option value="">不关联节点</option>
                    {nodes.map((node) => (
                      <option key={node.id} value={node.id}>
                        {node.name}
                        {node.expectedCountry ? ` (${node.expectedCountry})` : ""}
                      </option>
                    ))}
                  </select>
                </div>
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
                    placeholder="例如：CloudCart 店铺收款 / Google Ads / Claude 登录"
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
          <div className="flex items-center justify-end gap-2 border-t border-[#eaecef] bg-[#fafbfc] px-6 py-3.5">
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
