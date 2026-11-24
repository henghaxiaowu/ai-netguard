import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Check,
  Copy,
  ExternalLink,
  Globe,
  RefreshCw,
  Search,
  ShieldAlert,
  Sparkles,
  X,
} from "lucide-react";
import { api } from "../api";
import type {
  AccountRecord,
  AdsPowerProfileItem,
  AdsPowerProfilesSnapshot,
  AppConfig,
  GatewayStatus,
  PendingUrlPickPayload,
} from "../types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Input } from "./ui/input";

function matchLinkedAccount(
  prof: AdsPowerProfileItem,
  accounts: AccountRecord[],
): AccountRecord | undefined {
  return accounts.find((acc) => {
    if (acc.browserKind !== "adspower") return false;
    const uid = acc.adspowerUserId?.trim();
    const sn =
      acc.adspowerSerialNumber?.trim().replace(/^#/, "") ||
      acc.environmentProfile?.trim().replace(/^#/, "");
    return (
      (uid && uid === prof.userId) ||
      (sn && prof.serialNumber && sn === prof.serialNumber)
    );
  });
}

export function UrlPickerWindow() {
  const [payload, setPayload] = useState<PendingUrlPickPayload | null>(null);
  const [config, setConfig] = useState<AppConfig | null>(null);
  const [status, setStatus] = useState<GatewayStatus | null>(null);
  const [accounts, setAccounts] = useState<AccountRecord[]>([]);
  const [adsSnapshot, setAdsSnapshot] = useState<AdsPowerProfilesSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingAds, setLoadingAds] = useState(false);
  const [search, setSearch] = useState("");
  const [showFullUrl, setShowFullUrl] = useState(false);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [copied, setCopied] = useState(false);

  const loadPickAndContext = useCallback(async () => {
    setLoading(true);
    try {
      const [pending, cfg, st, accs] = await Promise.all([
        api.getPendingUrlPick(),
        api.getConfig(),
        api.getStatus(),
        api.listAccounts(),
      ]);
      setPayload(pending);
      setConfig(cfg);
      setStatus(st);
      setAccounts(accs);
    } catch (err) {
      setErrorMsg(`加载上下文失败: ${String(err)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshAdsProfiles = useCallback(async () => {
    setLoadingAds(true);
    try {
      const snap = await api.listAdsPowerProfiles();
      setAdsSnapshot(snap);
    } catch (err) {
      setAdsSnapshot({
        connected: false,
        baseUrl: "http://127.0.0.1:50325",
        profiles: [],
        error: String(err),
      });
    } finally {
      setLoadingAds(false);
    }
  }, []);

  useEffect(() => {
    document.title = "选择打开环境 | AI NetGuard";
    void loadPickAndContext();
    void refreshAdsProfiles();

    let unsub: (() => void) | undefined;
    api
      .onUrlPickerUpdated(() => {
        setErrorMsg("");
        setShowFullUrl(false);
        setCopied(false);
        void loadPickAndContext();
        void refreshAdsProfiles();
      })
      .then((fn) => {
        unsub = fn;
      })
      .catch(() => {});

    return () => {
      if (unsub) unsub();
    };
  }, [loadPickAndContext, refreshAdsProfiles]);

  const handleResolve = useCallback(
    async (
      key: string,
      action: string,
      extra?: {
        adspowerUserId?: string | null;
        adspowerSerialNumber?: string | null;
        adspowerProfileName?: string | null;
        browserProfileId?: string | null;
        addEdgeBypassHost?: boolean;
      },
    ) => {
      if (!payload?.pick) return;
      setBusyKey(key);
      setErrorMsg("");
      try {
        await api.resolveUrlPick({
          pickId: payload.pick.id,
          action,
          ...extra,
        });
      } catch (err) {
        setErrorMsg(String(err));
      } finally {
        setBusyKey(null);
      }
    },
    [payload],
  );

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && payload?.pick && !busyKey) {
        e.preventDefault();
        void handleResolve("cancel", "cancel");
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [payload, busyKey, handleResolve]);

  const filteredProfiles = useMemo(() => {
    const list = adsSnapshot?.profiles ?? [];
    const q = search.trim().toLowerCase();
    if (!q) return list;
    return list.filter((p) => {
      const linked = matchLinkedAccount(p, accounts);
      const hay = `${p.serialNumber} ${p.name} ${p.groupName} ${p.remark} ${linked?.label || ""} ${linked?.email || ""}`.toLowerCase();
      return hay.includes(q);
    });
  }, [adsSnapshot?.profiles, accounts, search]);

  const [browserSearch, setBrowserSearch] = useState("");
  const browserProfiles = useMemo(() => config?.browserProfiles ?? [], [config?.browserProfiles]);
  const nodeById = useMemo(
    () => new Map((config?.nodes ?? []).map((n) => [n.id, n])),
    [config?.nodes],
  );
  const runningBrowserSet = useMemo(
    () => new Set(status?.runningBrowserProfiles ?? []),
    [status?.runningBrowserProfiles],
  );
  const filteredBrowserProfiles = useMemo(() => {
    const q = browserSearch.trim().toLowerCase();
    if (!q) return browserProfiles;
    return browserProfiles.filter((bp) => {
      const linkedAcc = accounts.find((acc) => acc.linkedBrowserProfileId === bp.id);
      const boundNode = nodeById.get(bp.nodeId || config?.activeNodeId || "");
      const hay = `${bp.name} ${bp.customProxyUrl || ""} ${boundNode?.name || ""} ${linkedAcc?.label || ""} ${linkedAcc?.email || ""}`.toLowerCase();
      return hay.includes(q);
    });
  }, [browserProfiles, browserSearch, accounts, nodeById, config?.activeNodeId]);

  const gatewayReady = Boolean(status?.running && !status?.blockedByKillSwitch);
  const pick = payload?.pick;

  const handleCopy = async () => {
    if (!pick) return;
    try {
      await navigator.clipboard.writeText(pick.url);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
      await handleResolve("copied", "copied");
    } catch (err) {
      setErrorMsg(`复制失败: ${String(err)}`);
    }
  };

  return (
    <div className="flex min-h-screen flex-col justify-between bg-[#f6f7f9] p-3 text-[#111827]">
      <div className="flex flex-col gap-2.5">
        {/* Header */}
        <header className="flex items-start justify-between gap-2 rounded-xl border border-[#eaecef] bg-white px-4 py-3 shadow-[0_1px_2px_rgba(15,23,42,0.03)]">
          <div className="flex min-w-0 items-start gap-2.5">
            <span className="mt-0.5 inline-grid h-8 w-8 shrink-0 place-items-center rounded-xl bg-[#fffbeb] text-[#d97706]">
              <ShieldAlert className="h-4 w-4" aria-hidden="true" />
            </span>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-1.5">
                <h1 className="text-[0.94rem] font-semibold tracking-tight text-[#111827]">
                  已拦截敏感链接 · 请选择打开环境
                </h1>
                {(payload?.remainingCount ?? 0) > 0 && (
                  <Badge variant="warning" className="mono-num">
                    队列 +{payload?.remainingCount}
                  </Badge>
                )}
              </div>
              <p className="mt-0.5 text-[0.71rem] text-[#7c8495]">
                防止携带账号或登录凭据的链接直接进入日常 Edge 浏览器
              </p>
            </div>
          </div>
          {pick && (
            <button
              type="button"
              aria-label="取消并关闭"
              disabled={busyKey !== null}
              onClick={() => void handleResolve("cancel", "cancel")}
              className="rounded-lg p-1 text-[#7c8495] hover:bg-[#f3f4f6] hover:text-[#111827] cursor-pointer"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          )}
        </header>

        {/* Intercepted URL Card */}
        {loading && !pick ? (
          <div className="rounded-xl border border-[#eaecef] bg-white px-4 py-6 text-center text-[0.78rem] text-[#7c8495]">
            正在读取待分流链接...
          </div>
        ) : !pick ? (
          <div className="rounded-xl border border-[#eaecef] bg-white px-4 py-6 text-center text-[0.78rem] text-[#7c8495]">
            当前没有待分流的链接
          </div>
        ) : (
          <section className="flex flex-col gap-2 rounded-xl border border-[#eaecef] bg-white px-4 py-3 shadow-[0_1px_2px_rgba(15,23,42,0.03)]">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1.5">
                <span className="mono-num truncate text-[0.88rem] font-semibold text-[#111827]">
                  {pick.host}
                </span>
                <Badge variant="iris" className="max-w-full truncate">
                  {pick.reason}
                </Badge>
              </div>
              <div className="flex shrink-0 items-center gap-1.5">
                <Button
                  variant="ghost"
                  size="xs"
                  onClick={() => setShowFullUrl((v) => !v)}
                >
                  {showFullUrl ? "收起参数" : "查看详情"}
                </Button>
                <Button
                  variant="outline"
                  size="xs"
                  disabled={busyKey !== null}
                  onClick={() => void handleCopy()}
                >
                  {copied ? (
                    <Check className="h-3 w-3 text-[#16a34a]" aria-hidden="true" />
                  ) : (
                    <Copy className="h-3 w-3" aria-hidden="true" />
                  )}
                  {copied ? "已复制" : "复制链接"}
                </Button>
              </div>
            </div>
            <div
              className="mono-num break-all rounded-lg border border-[#f1f3f5] bg-[#fafbfc] px-2.5 py-1.5 text-[0.71rem] text-[#525866]"
              title={pick.displayUrl}
            >
              {showFullUrl ? pick.url : pick.displayUrl}
            </div>
          </section>
        )}

        {errorMsg && (
          <div className="flex items-start gap-2 rounded-xl border border-[#fecaca] bg-[#fef2f2] px-3.5 py-2.5 text-[0.73rem] text-[#b91c1c]">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            <span className="min-w-0 break-words">{errorMsg}</span>
          </div>
        )}

        {/* Section 1: AI NetGuard Built-in Fingerprint Browser Profiles (Promoted Top) */}
        <section className="flex flex-col gap-2 rounded-xl border border-[#eaecef] bg-white px-4 py-3 shadow-[0_1px_2px_rgba(15,23,42,0.03)]">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-1.5">
              <Globe className="h-3.5 w-3.5 text-[#059669]" aria-hidden="true" />
              <h2 className="text-[0.8rem] font-semibold text-[#111827]">
                在 AI NetGuard 指纹浏览器中打开
              </h2>
              {status?.fpBrowserInstalled && (
                <Badge variant="success" className="mono-num">
                  FP-150
                </Badge>
              )}
              <Badge variant="neutral" className="mono-num">
                {browserProfiles.length} 个环境
              </Badge>
            </div>
            {!gatewayReady && (
              <span className="text-[0.68rem] text-[#b45309]">网关待机（独立 Clash 环境可用）</span>
            )}
          </div>

          {browserProfiles.length > 4 && (
            <div className="relative">
              <Search
                className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[#9ca3af]"
                aria-hidden="true"
              />
              <Input
                className="h-7 pl-8 text-[0.74rem]"
                placeholder="搜索内置环境名称、节点、代理端口或关联账号..."
                value={browserSearch}
                onChange={(e) => setBrowserSearch(e.target.value)}
              />
            </div>
          )}

          {filteredBrowserProfiles.length === 0 ? (
            <div className="rounded-lg border border-dashed border-[#eaecef] bg-[#fafbfc] px-3 py-2.5 text-center text-[0.72rem] text-[#9ca3af]">
              未匹配到符合条件的内置浏览器环境
            </div>
          ) : (
            <div className="flex max-h-[196px] flex-col gap-1.5 overflow-y-auto pr-0.5">
              {filteredBrowserProfiles.map((bp) => {
                const key = `ng-${bp.id}`;
                const isBusy = busyKey === key;
                const hasCustomProxy = Boolean(bp.customProxyUrl?.trim());
                const needsGateway = !hasCustomProxy;
                const disabled =
                  !status?.browserInstalled ||
                  !pick ||
                  busyKey !== null ||
                  (needsGateway && !gatewayReady);
                const isRunning = runningBrowserSet.has(bp.id);
                const linkedAcc = accounts.find(
                  (acc) => acc.linkedBrowserProfileId === bp.id,
                );
                const boundNode = nodeById.get(bp.nodeId || config?.activeNodeId || "");
                const effTz = bp.fingerprint.timezone || boundNode?.timezone || "";
                const exitSummary = hasCustomProxy
                  ? `独立代理 ${bp.customProxyUrl?.replace(/^[a-zA-Z0-9+.-]+:\/\//, "")}`
                  : `出口: ${boundNode?.name || "主安全出口"}${effTz ? ` · ${effTz}` : ""}`;

                return (
                  <button
                    key={bp.id}
                    type="button"
                    disabled={disabled}
                    onClick={() =>
                      void handleResolve(key, "netguard_browser", {
                        browserProfileId: bp.id,
                      })
                    }
                    title={
                      !status?.browserInstalled
                        ? "请先安装 Fingerprint-Chromium 150 内核"
                        : needsGateway && !gatewayReady
                          ? "需先启动 AI NetGuard 安全网关"
                          : bp.name
                    }
                    className="flex w-full items-center justify-between gap-2 rounded-lg border border-[#eaecef] bg-[#fafbfc] px-3 py-2 text-left transition-colors hover:border-[#6ee7b7] hover:bg-[#ecfdf5]/50 disabled:opacity-55 cursor-pointer"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="truncate text-[0.78rem] font-semibold text-[#111827]">
                          {bp.name}
                        </span>
                        {isRunning && (
                          <Badge variant="success" className="text-[0.63rem]">
                            已运行
                          </Badge>
                        )}
                        <Badge
                          variant={
                            bp.fingerprintMode === "isolated_fingerprint"
                              ? "iris"
                              : "neutral"
                          }
                          className="text-[0.63rem]"
                        >
                          {bp.fingerprintMode === "isolated_fingerprint"
                            ? "独立指纹"
                            : "纯净对齐"}
                        </Badge>
                        {linkedAcc && (
                          <Badge variant="iris" className="max-w-[140px] truncate">
                            {linkedAcc.label || linkedAcc.email}
                          </Badge>
                        )}
                      </div>
                      <div className="mono-num mt-0.5 truncate text-[0.68rem] text-[#7c8495]">
                        {exitSummary}
                      </div>
                    </div>
                    <span className="shrink-0 text-[0.71rem] font-medium text-[#059669]">
                      {isBusy
                        ? "打开中..."
                        : !status?.browserInstalled
                          ? "未安装"
                          : needsGateway && !gatewayReady
                            ? "需网关"
                            : "打开 ->"}
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </section>

        {/* Section 2: AdsPower Profiles */}
        {adsSnapshot?.connected ? (
          <section className="flex flex-col gap-2 rounded-xl border border-[#eaecef] bg-white px-4 py-3 shadow-[0_1px_2px_rgba(15,23,42,0.03)]">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-1.5">
                <Sparkles className="h-3.5 w-3.5 text-[#6d5bd0]" aria-hidden="true" />
                <h2 className="text-[0.8rem] font-semibold text-[#111827]">
                  在 AdsPower 指纹环境中打开
                </h2>
                <Badge variant="success" className="mono-num">
                  {adsSnapshot.profiles.length} 个环境
                </Badge>
              </div>
              <Button
                variant="ghost"
                size="xs"
                disabled={loadingAds || busyKey !== null}
                onClick={() => void refreshAdsProfiles()}
              >
                <RefreshCw
                  className={`h-3 w-3 ${loadingAds ? "animate-spin" : ""}`}
                  aria-hidden="true"
                />
                刷新
              </Button>
            </div>

            {adsSnapshot.profiles.length > 4 && (
              <div className="relative">
                <Search
                  className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[#9ca3af]"
                  aria-hidden="true"
                />
                <Input
                  className="h-7 pl-8 text-[0.74rem]"
                  placeholder="搜索环境名称、#序号、分组或关联账号..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>
            )}

            {filteredProfiles.length === 0 ? (
              <div className="rounded-lg border border-dashed border-[#eaecef] bg-[#fafbfc] px-3 py-2.5 text-center text-[0.72rem] text-[#9ca3af]">
                未匹配到符合条件的 AdsPower 环境
              </div>
            ) : (
              <div className="flex max-h-[160px] flex-col gap-1.5 overflow-y-auto pr-0.5">
                {filteredProfiles.map((prof) => {
                  const linkedAcc = matchLinkedAccount(prof, accounts);
                  const key = `ads-${prof.userId}`;
                  const isBusy = busyKey === key;
                  return (
                    <button
                      key={prof.userId}
                      type="button"
                      disabled={!pick || busyKey !== null}
                      onClick={() =>
                        void handleResolve(key, "adspower", {
                          adspowerUserId: prof.userId,
                          adspowerSerialNumber: prof.serialNumber || null,
                          adspowerProfileName: prof.name || null,
                        })
                      }
                      className="flex w-full items-center justify-between gap-2 rounded-lg border border-[#eaecef] bg-[#fafbfc] px-3 py-2 text-left transition-colors hover:border-[#c4b5fd] hover:bg-[#f5f3ff]/60 disabled:opacity-50 cursor-pointer"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          {prof.serialNumber && (
                            <span className="mono-num rounded bg-[#eef2ff] px-1.5 py-0.5 text-[0.67rem] font-semibold text-[#4338ca]">
                              #{prof.serialNumber}
                            </span>
                          )}
                          <span className="truncate text-[0.78rem] font-semibold text-[#111827]">
                            {prof.name || prof.userId}
                          </span>
                          {linkedAcc && (
                            <Badge variant="iris" className="max-w-[140px] truncate">
                              {linkedAcc.label || linkedAcc.email}
                            </Badge>
                          )}
                        </div>
                        {(prof.groupName || prof.remark) && (
                          <div className="mt-0.5 truncate text-[0.68rem] text-[#7c8495]">
                            {[prof.groupName, prof.remark].filter(Boolean).join(" · ")}
                          </div>
                        )}
                      </div>
                      <span className="shrink-0 text-[0.71rem] font-medium text-[#6d5bd0]">
                        {isBusy ? "打开中..." : "打开 ->"}
                      </span>
                    </button>
                  );
                })}
              </div>
            )}
          </section>
        ) : (
          <section className="flex items-center justify-between gap-2 rounded-xl border border-[#eaecef] bg-white px-3.5 py-2 text-[0.71rem] text-[#7c8495] shadow-[0_1px_2px_rgba(15,23,42,0.02)]">
            <div className="flex min-w-0 items-center gap-1.5">
              <Sparkles className="h-3.5 w-3.5 shrink-0 text-[#9ca3af]" aria-hidden="true" />
              <span className="truncate">
                AdsPower 未连接（使用上方 AI NetGuard 内置指纹浏览器即可）
              </span>
            </div>
            <Button
              variant="ghost"
              size="xs"
              className="shrink-0"
              disabled={loadingAds || busyKey !== null}
              onClick={() => void refreshAdsProfiles()}
            >
              <RefreshCw
                className={`h-3 w-3 ${loadingAds ? "animate-spin" : ""}`}
                aria-hidden="true"
              />
              刷新
            </Button>
          </section>
        )}
      </div>

      {/* Footer: Fallback to Edge & Cancel */}
      <footer className="mt-2.5 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[#eaecef] bg-white px-3.5 py-2.5 shadow-[0_1px_2px_rgba(15,23,42,0.03)]">
        <div className="flex flex-wrap items-center gap-1.5">
          <Button
            variant="ghost"
            size="xs"
            disabled={!pick || busyKey !== null}
            onClick={() => void handleResolve("edge", "edge")}
          >
            <ExternalLink className="h-3 w-3" aria-hidden="true" />
            本次在 Edge 打开
          </Button>
          {pick?.host && (
            <Button
              variant="soft"
              size="xs"
              disabled={!pick || busyKey !== null}
              onClick={() =>
                void handleResolve("edge-allow", "edge_and_allow_domain", {
                  addEdgeBypassHost: true,
                })
              }
            >
              允许 {pick.host} 直通 Edge
            </Button>
          )}
        </div>
        <Button
          variant="outline"
          size="xs"
          disabled={!pick || busyKey !== null}
          onClick={() => void handleResolve("cancel", "cancel")}
        >
          取消 (Esc)
        </Button>
      </footer>
    </div>
  );
}
