import { useId, useState } from "react";
import {
  AlertTriangle,
  AppWindow,
  CheckCircle2,
  Cpu,
  Globe,
  Link2,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Settings2,
  Shield,
  Sparkles,
  Trash2,
  Wrench,
} from "lucide-react";
import type {
  AppConfig,
  AppEnvSnapshot,
  AppProxyMode,
  ManagedAppConfig,
  ManagedAppRuntimeStatus,
} from "../types";
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
import { Switch } from "./ui/switch";

interface AppsEnvViewProps {
  config: AppConfig;
  snapshot: AppEnvSnapshot | null;
  scanning: boolean;
  gatewayRunning: boolean;
  dirty: boolean;
  onConfigChange: (next: AppConfig) => void;
  onSave: () => Promise<void>;
  onRescan: () => Promise<void>;
  onLaunchApp: (appId: string, relaunch: boolean) => Promise<void>;
  onCleanRegistryEnv: () => Promise<void>;
  onCreateShortcut: (appId: string) => Promise<void>;
}

const MODE_LABELS: Record<AppProxyMode, string> = {
  netguard: "AI NetGuard 独享出口",
  system_proxy: "干净系统代理 (Clash)",
  direct: "直连无代理",
  custom_proxy: "自定义代理",
};

function appIconMeta(id: string) {
  switch (id) {
    case "claude-desktop":
      return { bg: "bg-[#fef2ed] text-[#d97757]", Icon: Sparkles };
    case "antigravity":
      return { bg: "bg-[#f0edfc] text-[#6d5bd0]", Icon: Cpu };
    case "chatgpt":
      return { bg: "bg-[#ecfdf5] text-[#059669]", Icon: Globe };
    case "cockpit-tools":
      return { bg: "bg-[#eff6ff] text-[#2563eb]", Icon: Wrench };
    default:
      return { bg: "bg-[#f3f4f6] text-[#4b5563]", Icon: AppWindow };
  }
}

function healthBadge(rt?: ManagedAppRuntimeStatus) {
  if (!rt || !rt.running) {
    return <Badge variant="neutral">未运行</Badge>;
  }
  switch (rt.health) {
    case "dead_proxy":
      return <Badge variant="danger">死代理污染</Badge>;
    case "mismatch":
      return <Badge variant="warning">策略不一致</Badge>;
    default:
      return <Badge variant="success">干净运行</Badge>;
  }
}

export function AppsEnvView({
  config,
  snapshot,
  scanning,
  gatewayRunning,
  dirty,
  onConfigChange,
  onSave,
  onRescan,
  onLaunchApp,
  onCleanRegistryEnv,
  onCreateShortcut,
}: AppsEnvViewProps) {
  const uid = useId();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [busyAppId, setBusyAppId] = useState<string | null>(null);
  const [cleaningReg, setCleaningReg] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newName, setNewName] = useState("");
  const [newPath, setNewPath] = useState("");
  const [newMode, setNewMode] = useState<AppProxyMode>("system_proxy");

  const runtimeById = new Map<string, ManagedAppRuntimeStatus>();
  for (const rt of snapshot?.apps ?? []) {
    runtimeById.set(rt.id, rt);
  }

  const updateApp = (id: string, patch: Partial<ManagedAppConfig>) => {
    const nextApps = config.managedApps.map((a) =>
      a.id === id ? { ...a, ...patch } : a,
    );
    onConfigChange({ ...config, managedApps: nextApps });
  };

  const removeCustomApp = (id: string) => {
    const nextApps = config.managedApps.filter((a) => a.id !== id || a.builtin);
    onConfigChange({ ...config, managedApps: nextApps });
    if (expandedId === id) setExpandedId(null);
  };

  const handleAddApp = () => {
    const name = newName.trim();
    const exePath = newPath.trim();
    if (!name || !exePath) return;
    const baseName = exePath.split(/[/\\]/).pop() || "";
    const id = `custom-${Date.now().toString(36)}`;
    const nextApp: ManagedAppConfig = {
      id,
      name,
      builtin: false,
      exePath,
      processNames: baseName ? [baseName] : [],
      proxyMode: newMode,
      customProxyUrl: null,
      wfpLock: newMode === "netguard",
      extraArgs: [],
    };
    onConfigChange({
      ...config,
      managedApps: [...config.managedApps, nextApp],
    });
    setNewName("");
    setNewPath("");
    setNewMode("system_proxy");
    setShowAddForm(false);
  };

  const runLaunch = async (appId: string, relaunch: boolean) => {
    setBusyAppId(appId);
    try {
      if (dirty) {
        await onSave();
      }
      await onLaunchApp(appId, relaunch);
    } finally {
      setBusyAppId(null);
    }
  };

  const runCleanReg = async () => {
    setCleaningReg(true);
    try {
      await onCleanRegistryEnv();
    } finally {
      setCleaningReg(false);
    }
  };

  const sysProxy = snapshot?.systemProxy;
  const regVars = snapshot?.registryProxyVars ?? [];
  const runningCount = (snapshot?.apps ?? []).filter((a) => a.running).length;
  const totalCount = config.managedApps.length;
  const pollutedCount = snapshot?.pollutedCount ?? 0;

  return (
    <div className="bento-sheet flex flex-col divide-y divide-[#eaecef] rounded-2xl border border-[#eaecef] bg-white shadow-[0_1px_3px_rgba(15,23,42,0.03)]">
      {/* Header */}
      <header className="flex flex-wrap items-center justify-between gap-3 px-6 py-4">
        <div className="min-w-0">
          <h1
            id="main-heading"
            tabIndex={-1}
            className="text-[1.15rem] font-semibold tracking-tight text-[#111827] outline-none"
          >
            AI 应用与启动环境
          </h1>
          <p className="mt-0.5 text-[0.76rem] text-[#7c8495]">
            实时扫描进程内存 (PEB) 代理变量与端口活体，隔离脏继承并按应用精准分配通道
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={onRescan}
            disabled={scanning}
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${scanning ? "animate-spin" : ""}`}
              aria-hidden="true"
            />
            {scanning ? "扫描中..." : "刷新 PEB 扫描"}
          </Button>
          {dirty && (
            <Button variant="solid" size="sm" onClick={onSave}>
              保存策略
            </Button>
          )}
        </div>
      </header>

      {/* Top 3-Column Environment Telemetry Strip */}
      <section className="grid grid-cols-1 divide-y divide-[#eaecef] md:grid-cols-3 md:divide-x md:divide-y-0">
        {/* Cell 1: Windows System Proxy */}
        <div className="flex flex-col justify-between gap-2 px-6 py-4">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[0.74rem] font-medium text-[#7c8495]">
              Windows 系统代理
            </span>
            {sysProxy?.enabled ? (
              sysProxy.alive ? (
                <Badge variant="success">在线正常</Badge>
              ) : (
                <Badge variant="danger">端口不可达</Badge>
              )
            ) : (
              <Badge variant="neutral">未启用</Badge>
            )}
          </div>
          <div className="mono-num truncate text-[0.95rem] font-semibold text-[#111827]">
            {sysProxy?.enabled
              ? sysProxy.hostPort || sysProxy.server || "已启用"
              : "系统直连"}
          </div>
          <div className="text-[0.71rem] text-[#7c8495]">
            {sysProxy?.enabled && sysProxy.alive
              ? "Clash 等系统代理工作正常，不会误判"
              : sysProxy?.enabled
                ? "系统代理端口未监听，请检查代理软件"
                : "跟随操作系统默认路由"}
          </div>
        </div>

        {/* Cell 2: Registry Global Proxy Vars */}
        <div className="flex flex-col justify-between gap-2 px-6 py-4">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[0.74rem] font-medium text-[#7c8495]">
              注册表全局代理变量
            </span>
            {regVars.length === 0 ? (
              <Badge variant="success">干净</Badge>
            ) : (
              <Badge variant="warning">{regVars.length} 项残留</Badge>
            )}
          </div>
          <div className="flex items-center justify-between gap-2">
            <span className="mono-num truncate text-[0.95rem] font-semibold text-[#111827]">
              {regVars.length === 0
                ? "0 污染 (HKCU/HKLM)"
                : regVars.map((v) => v.key).join(" · ")}
            </span>
            {regVars.length > 0 && (
              <Button
                variant="outline"
                size="xs"
                onClick={runCleanReg}
                disabled={cleaningReg}
              >
                {cleaningReg ? "清理中..." : "一键清空"}
              </Button>
            )}
          </div>
          <div className="text-[0.71rem] text-[#7c8495]">
            {regVars.length === 0
              ? "新启动的 IDE / 终端不会继承全局死端口"
              : "全局代理会被子进程继承，建议清空改为按应用注入"}
          </div>
        </div>

        {/* Cell 3: Live PEB Health */}
        <div className="flex flex-col justify-between gap-2 px-6 py-4">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[0.74rem] font-medium text-[#7c8495]">
              活跃进程 PEB 巡检
            </span>
            {pollutedCount > 0 ? (
              <Badge variant="danger">{pollutedCount} 项异常</Badge>
            ) : (
              <Badge variant="success">全部健康</Badge>
            )}
          </div>
          <div className="mono-num text-[0.95rem] font-semibold text-[#111827]">
            {runningCount} / {totalCount} 运行中
          </div>
          <div className="mono-num text-[0.71rem] text-[#7c8495]">
            {snapshot?.scannedAt
              ? `上次扫描 ${snapshot.scannedAt}`
              : "等待首次扫描"}
          </div>
        </div>
      </section>

      {/* Managed Apps List */}
      <section className="flex flex-col divide-y divide-[#eaecef]">
        {config.managedApps.map((app) => {
          const rt = runtimeById.get(app.id);
          const { bg, Icon } = appIconMeta(app.id);
          const isExpanded = expandedId === app.id;
          const isBusy = busyAppId === app.id;
          const isNetguard = app.proxyMode === "netguard";
          const isDead = rt?.health === "dead_proxy";
          const isMismatch = rt?.health === "mismatch";

          return (
            <div
              key={app.id}
              className={`flex flex-col gap-3 px-6 py-4 transition-colors ${
                isDead ? "bg-[#fef2f2]/45" : isMismatch ? "bg-[#fffbeb]/45" : ""
              }`}
            >
              <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                {/* Identity + Live Status */}
                <div className="flex min-w-0 flex-1 items-start gap-3">
                  <span
                    className={`mt-0.5 inline-grid h-8 w-8 shrink-0 place-items-center rounded-xl ${bg}`}
                  >
                    <Icon className="h-4 w-4" aria-hidden="true" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[0.88rem] font-semibold text-[#111827]">
                        {app.name}
                      </span>
                      {healthBadge(rt)}
                      {rt?.running && (
                        <span className="mono-num text-[0.7rem] text-[#7c8495]">
                          {rt.pids.length} 进程 (PID {rt.pids[0]})
                        </span>
                      )}
                      {!rt?.installed && !rt?.running && (
                        <span className="text-[0.7rem] text-[#9ca3af]">
                          未自动检测到路径
                        </span>
                      )}
                    </div>

                    {/* Live PEB Diagnosis */}
                    <div
                      className={`mt-1 flex items-start gap-1.5 text-[0.75rem] leading-relaxed ${
                        isDead
                          ? "font-medium text-[#b91c1c]"
                          : isMismatch
                            ? "text-[#b45309]"
                            : "text-[#525866]"
                      }`}
                    >
                      {isDead || isMismatch ? (
                        <AlertTriangle
                          className="mt-0.5 h-3.5 w-3.5 shrink-0"
                          aria-hidden="true"
                        />
                      ) : rt?.running ? (
                        <CheckCircle2
                          className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[#16a34a]"
                          aria-hidden="true"
                        />
                      ) : null}
                      <span className="min-w-0 break-words">
                        {rt?.diagnosis || "等待扫描运行环境"}
                      </span>
                    </div>

                    {/* Detected live PEB proxy pills */}
                    {rt && rt.envVars.length > 0 && (
                      <div className="mt-1.5 flex flex-wrap gap-1.5">
                        {rt.envVars.map((v) => (
                          <span
                            key={`${v.key}-${v.value}`}
                            className={`mono-num inline-flex max-w-full flex-wrap items-center gap-1 break-all rounded-md border px-2 py-0.5 text-[0.69rem] ${
                              v.alive === false
                                ? "border-[#fecaca] bg-[#fef2f2] text-[#b91c1c]"
                                : v.alive === true
                                  ? "border-[#bbf7d0] bg-[#f0fdf4] text-[#15803d]"
                                  : "border-[#eaecef] bg-[#f8f9fb] text-[#525866]"
                            }`}
                          >
                            {v.key}={v.value}
                            {v.alive === false && " · 无人监听"}
                            {v.alive === true && " · 在线"}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Controls */}
                <div className="flex shrink-0 flex-wrap items-center gap-2 pl-11 lg:pl-0">
                  <div className="w-[178px]">
                    <Select
                      value={app.proxyMode}
                      onValueChange={(v) => {
                        const mode = v as AppProxyMode;
                        updateApp(app.id, {
                          proxyMode: mode,
                          wfpLock: mode === "netguard" ? app.wfpLock : false,
                        });
                      }}
                    >
                      <SelectTrigger
                        aria-label={`${app.name} 代理策略`}
                        className="h-8 text-[0.76rem]"
                      >
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {(
                          [
                            "netguard",
                            "system_proxy",
                            "direct",
                            "custom_proxy",
                          ] as AppProxyMode[]
                        ).map((mode) => (
                          <SelectItem
                            key={mode}
                            value={mode}
                            className="text-[0.76rem]"
                          >
                            {MODE_LABELS[mode]}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  {/* Per-app WFP Lock switch (only active when NetGuard mode selected) */}
                  <div
                    className="flex items-center gap-1.5 rounded-lg border border-[#eaecef] bg-[#f8f9fb] px-2.5 py-1.5"
                    title={
                      isNetguard
                        ? "仅允许该应用访问 AI NetGuard 回环端口，阻断直连"
                        : "仅在选择「AI NetGuard 独享出口」模式时可启用 WFP 锁"
                    }
                  >
                    <Shield
                      className={`h-3.5 w-3.5 ${
                        app.wfpLock && isNetguard
                          ? "text-[#6d5bd0]"
                          : "text-[#9ca3af]"
                      }`}
                      aria-hidden="true"
                    />
                    <label
                      htmlFor={`${uid}-wfp-${app.id}`}
                      className="text-[0.72rem] text-[#525866] cursor-pointer select-none"
                    >
                      WFP
                    </label>
                    <Switch
                      id={`${uid}-wfp-${app.id}`}
                      size="sm"
                      disabled={!isNetguard}
                      checked={isNetguard && app.wfpLock}
                      onCheckedChange={(checked) =>
                        updateApp(app.id, { wfpLock: checked })
                      }
                    />
                  </div>

                  {/* Launch / Clean Relaunch Action */}
                  {rt?.running ? (
                    <Button
                      variant={
                        isDead ? "destructive" : isMismatch ? "solid" : "outline"
                      }
                      size="xs"
                      disabled={
                        isBusy || (isNetguard && !gatewayRunning)
                      }
                      onClick={() => runLaunch(app.id, true)}
                    >
                      <RotateCcw className="h-3 w-3" aria-hidden="true" />
                      {isBusy ? "重启中..." : "干净重启"}
                    </Button>
                  ) : (
                    <Button
                      variant="soft"
                      size="xs"
                      disabled={
                        isBusy || (isNetguard && !gatewayRunning)
                      }
                      onClick={() => runLaunch(app.id, false)}
                    >
                      <Play className="h-3 w-3" aria-hidden="true" />
                      {isBusy ? "启动中..." : "干净启动"}
                    </Button>
                  )}

                  <Button
                    variant="ghost"
                    size="xs"
                    title={`在桌面创建 ${app.name} 托管快捷方式（双击直接按当前策略启动，无需打开 AI NetGuard）`}
                    aria-label={`为 ${app.name} 创建桌面快捷方式`}
                    disabled={isBusy}
                    onClick={async () => {
                      setBusyAppId(app.id);
                      try {
                        if (dirty) await onSave();
                        await onCreateShortcut(app.id);
                      } finally {
                        setBusyAppId(null);
                      }
                    }}
                  >
                    <Link2 className="h-3.5 w-3.5" aria-hidden="true" />
                  </Button>

                  <Button
                    variant="ghost"
                    size="xs"
                    aria-label={`配置 ${app.name} 路径与参数`}
                    aria-expanded={isExpanded}
                    onClick={() =>
                      setExpandedId(isExpanded ? null : app.id)
                    }
                  >
                    <Settings2 className="h-3.5 w-3.5" aria-hidden="true" />
                  </Button>
                </div>
              </div>

              {/* Custom proxy inline input when CustomProxy selected */}
              {app.proxyMode === "custom_proxy" && (
                <div className="flex flex-wrap items-center gap-2 pl-11">
                  <label
                    htmlFor={`${uid}-cproxy-${app.id}`}
                    className="text-[0.72rem] font-medium text-[#7c8495]"
                  >
                    自定义代理 URL
                  </label>
                  <Input
                    id={`${uid}-cproxy-${app.id}`}
                    className="mono-num h-7 max-w-[260px] text-[0.75rem]"
                    placeholder="http://127.0.0.1:7897"
                    value={app.customProxyUrl || ""}
                    onChange={(e) =>
                      updateApp(app.id, { customProxyUrl: e.target.value })
                    }
                  />
                </div>
              )}

              {/* Expanded Path & Process Names Drawer */}
              {isExpanded && (
                <div className="mt-1 grid grid-cols-1 gap-3 rounded-xl border border-[#eaecef] bg-[#f8f9fb] p-3.5 sm:grid-cols-2">
                  <div className="flex flex-col gap-1">
                    <label
                      htmlFor={`${uid}-path-${app.id}`}
                      className="text-[0.71rem] font-medium text-[#7c8495]"
                    >
                      可执行文件路径（留空则自动探测）
                    </label>
                    <Input
                      id={`${uid}-path-${app.id}`}
                      className="mono-num h-8 bg-white text-[0.74rem]"
                      placeholder={
                        rt?.resolvedPath || "例如 D:\\Apps\\MyAI\\app.exe"
                      }
                      value={app.exePath || ""}
                      onChange={(e) =>
                        updateApp(app.id, {
                          exePath: e.target.value.trim() || null,
                        })
                      }
                    />
                  </div>
                  <div className="flex flex-col gap-1">
                    <label
                      htmlFor={`${uid}-procs-${app.id}`}
                      className="text-[0.71rem] font-medium text-[#7c8495]"
                    >
                      关联监控进程名（逗号分隔）
                    </label>
                    <div className="flex items-center gap-2">
                      <Input
                        id={`${uid}-procs-${app.id}`}
                        className="mono-num h-8 bg-white text-[0.74rem]"
                        value={app.processNames.join(", ")}
                        onChange={(e) =>
                          updateApp(app.id, {
                            processNames: e.target.value
                              .split(",")
                              .map((s) => s.trim())
                              .filter(Boolean),
                          })
                        }
                      />
                      {!app.builtin && (
                        <Button
                          variant="destructive"
                          size="xs"
                          onClick={() => removeCustomApp(app.id)}
                        >
                          <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                          删除
                        </Button>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </section>

      {/* Footer: Add Custom AI App */}
      <footer className="px-6 py-3.5 bg-[#fafbfc] rounded-b-2xl">
        {!showAddForm ? (
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-[0.73rem] text-[#7c8495]">
              可继续纳入 Cursor、Windsurf、Cherry Studio 等任意桌面 AI 工具
            </span>
            <Button
              variant="outline"
              size="xs"
              onClick={() => setShowAddForm(true)}
            >
              <Plus className="h-3.5 w-3.5" aria-hidden="true" />
              添加自定义 AI 应用
            </Button>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-12 items-end">
            <div className="flex flex-col gap-1 sm:col-span-3">
              <label
                htmlFor={`${uid}-new-name`}
                className="text-[0.71rem] font-medium text-[#7c8495]"
              >
                应用名称
              </label>
              <Input
                id={`${uid}-new-name`}
                className="h-8 bg-white text-[0.76rem]"
                placeholder="例如 Cursor"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1 sm:col-span-5">
              <label
                htmlFor={`${uid}-new-path`}
                className="text-[0.71rem] font-medium text-[#7c8495]"
              >
                .exe 绝对路径
              </label>
              <Input
                id={`${uid}-new-path`}
                className="mono-num h-8 bg-white text-[0.75rem]"
                placeholder="C:\Users\...\Cursor.exe"
                value={newPath}
                onChange={(e) => setNewPath(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1 sm:col-span-2">
              <label className="text-[0.71rem] font-medium text-[#7c8495]">
                默认策略
              </label>
              <Select
                value={newMode}
                onValueChange={(v) => setNewMode(v as AppProxyMode)}
              >
                <SelectTrigger className="h-8 bg-white text-[0.74rem]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="system_proxy">干净系统代理</SelectItem>
                  <SelectItem value="netguard">AI NetGuard</SelectItem>
                  <SelectItem value="direct">直连</SelectItem>
                  <SelectItem value="custom_proxy">自定义代理</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-1.5 sm:col-span-2">
              <Button
                variant="solid"
                size="xs"
                className="flex-1"
                disabled={!newName.trim() || !newPath.trim()}
                onClick={handleAddApp}
              >
                添加
              </Button>
              <Button
                variant="ghost"
                size="xs"
                onClick={() => setShowAddForm(false)}
              >
                取消
              </Button>
            </div>
          </div>
        )}
      </footer>
    </div>
  );
}
