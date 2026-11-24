import { useId, useState } from "react";
import {
  CheckCircle2,
  Compass,
  ExternalLink,
  FolderOpen,
  Globe,
  Plus,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldAlert,
  Trash2,
  X,
} from "lucide-react";
import type {
  AppConfig,
  UrlRouteEvent,
  UrlRouterConfig,
  UrlRouterMode,
  UrlRouterStatus,
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

const DEFAULT_INTERCEPT_DOMAINS = [
  "accounts.google.com",
  "myaccount.google.com",
  "gemini.google.com",
  "aistudio.google.com",
  "antigravity.google",
  "idx.google.com",
  "claude.ai",
  "console.anthropic.com",
  "anthropic.com",
  "chatgpt.com",
  "auth.openai.com",
  "platform.openai.com",
  "openai.com",
  "cursor.com",
  "authenticator.cursor.sh",
  "codeium.com",
  "windsurf.com",
  "x.ai",
  "grok.com",
  "perplexity.ai",
  "poe.com",
  "auth0.com",
  "challenges.cloudflare.com",
  "hcaptcha.com",
  "stripe.com",
  "checkout.stripe.com",
];

const DEFAULT_EDGE_BYPASS_DOMAINS = [
  "localhost",
  "127.0.0.1",
  "baidu.com",
  "weixin.qq.com",
  "qq.com",
  "feishu.cn",
  "dingtalk.com",
  "aliyun.com",
  "taobao.com",
  "jd.com",
  "zhihu.com",
  "bilibili.com",
  "163.com",
  "weibo.com",
  "csdn.net",
  "gitee.com",
  "deepseek.com",
  "moonshot.cn",
  "kimi.com",
  "doubao.com",
];

const DEFAULT_ROUTER_CONFIG: UrlRouterConfig = {
  mode: "intercept_list",
  interceptLoopbackOauth: true,
  fallbackBrowserPath: null,
  interceptDomains: DEFAULT_INTERCEPT_DOMAINS,
  edgeBypassDomains: DEFAULT_EDGE_BYPASS_DOMAINS,
};

interface UrlRouterViewProps {
  config: AppConfig;
  routerStatus: UrlRouterStatus | null;
  routeHistory: UrlRouteEvent[];
  dirty: boolean;
  busyAction: string | null;
  onConfigChange: (next: AppConfig) => void;
  onSave: () => Promise<void>;
  onRefreshStatus: () => Promise<void>;
  onRegister: () => Promise<void>;
  onUnregister: () => Promise<void>;
  onOpenDefaultApps: () => Promise<void>;
  onTestPicker: (url: string) => Promise<void>;
}

function cleanDomainEntry(raw: string): string {
  let s = raw.trim().toLowerCase();
  if (!s) return "";
  if (s.includes("://")) {
    try {
      s = new URL(s).hostname.toLowerCase();
    } catch {
      return "";
    }
  } else {
    s = s.split("/")[0] || "";
  }
  if (s.includes(":") && !s.startsWith("[")) {
    const [hostOnly, portPart] = s.split(":");
    if (hostOnly && /^\d+$/.test(portPart || "")) {
      s = hostOnly;
    }
  }
  return s.replace(/^\[|\]$/g, "").replace(/^\*\./, "").replace(/^\.+|\.+$/g, "");
}

export function UrlRouterView({
  config,
  routerStatus,
  routeHistory,
  dirty,
  busyAction,
  onConfigChange,
  onSave,
  onRefreshStatus,
  onRegister,
  onUnregister,
  onOpenDefaultApps,
  onTestPicker,
}: UrlRouterViewProps) {
  const uid = useId();
  const [newIntercept, setNewIntercept] = useState("");
  const [newBypass, setNewBypass] = useState("");
  const [testUrl, setTestUrl] = useState(
    "https://accounts.google.com/o/oauth2/v2/auth?client_id=demo&redirect_uri=http%3A%2F%2F127.0.0.1%3A54321%2Fcb",
  );

  const router: UrlRouterConfig = config.urlRouter ?? DEFAULT_ROUTER_CONFIG;

  const updateRouter = (patch: Partial<UrlRouterConfig>) => {
    onConfigChange({
      ...config,
      urlRouter: {
        ...router,
        ...patch,
      },
    });
  };

  const addDomain = (field: "interceptDomains" | "edgeBypassDomains", raw: string) => {
    const cleaned = cleanDomainEntry(raw);
    if (!cleaned) return;
    const current = router[field];
    if (!current.some((d) => d.toLowerCase() === cleaned)) {
      updateRouter({ [field]: [...current, cleaned] });
    }
    if (field === "interceptDomains") setNewIntercept("");
    else setNewBypass("");
  };

  const removeDomain = (field: "interceptDomains" | "edgeBypassDomains", domain: string) => {
    updateRouter({
      [field]: router[field].filter((d) => d !== domain),
    });
  };

  const isDefaultBoth = Boolean(
    routerStatus?.isDefaultHttp && routerStatus?.isDefaultHttps,
  );
  const isRegistered = Boolean(routerStatus?.registered);
  const exeMatches = routerStatus?.registeredExeMatches !== false;

  return (
    <div className="bento-sheet flex flex-col divide-y divide-[#eaecef] rounded-2xl border border-[#eaecef] bg-white shadow-[0_1px_3px_rgba(15,23,42,0.03)]">
      {/* Header */}
      <header className="flex flex-wrap items-center justify-between gap-3 px-6 py-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1
              id="main-heading"
              tabIndex={-1}
              className="text-[1.15rem] font-semibold tracking-tight text-[#111827] outline-none"
            >
              默认浏览器智能分流
            </h1>
            {isDefaultBoth ? (
              <Badge variant="success">默认接管中</Badge>
            ) : isRegistered ? (
              <Badge variant="warning">已注册 · 待系统设默认</Badge>
            ) : (
              <Badge variant="neutral">未注册</Badge>
            )}
          </div>
          <p className="mt-0.5 text-[0.76rem] text-[#7c8495]">
            国内/日常工作静默无感直进 Edge，AI 站点与 OAuth 登录跳转弹窗选 AdsPower 或 NetGuard 隔离环境
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => void onRefreshStatus()}
            disabled={busyAction !== null}
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${busyAction === "refresh" ? "animate-spin" : ""}`}
              aria-hidden="true"
            />
            刷新状态
          </Button>
          {dirty && (
            <Button
              variant="solid"
              size="sm"
              onClick={() => void onSave()}
              disabled={busyAction !== null}
            >
              保存规则
            </Button>
          )}
        </div>
      </header>

      {/* Top 3-Column Setup & Mode Strip */}
      <section className="grid grid-cols-1 divide-y divide-[#eaecef] md:grid-cols-3 md:divide-x md:divide-y-0">
        {/* Cell 1: Windows Registration */}
        <div className="flex flex-col justify-between gap-2.5 px-6 py-4">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[0.74rem] font-medium text-[#7c8495]">
              Windows 默认浏览器接管
            </span>
            {isDefaultBoth ? (
              <CheckCircle2 className="h-4 w-4 text-[#16a34a]" aria-hidden="true" />
            ) : (
              <Compass className="h-4 w-4 text-[#6d5bd0]" aria-hidden="true" />
            )}
          </div>
          <div className="text-[0.84rem] font-semibold text-[#111827]">
            {isDefaultBoth
              ? "已生效：HTTP / HTTPS 均由分流器接管"
              : isRegistered
                ? "第 2 步：在系统设置选为默认浏览器"
                : "第 1 步：先注册为系统可选浏览器"}
          </div>
          <div className="text-[0.71rem] leading-relaxed text-[#7c8495]">
            {isRegistered && !exeMatches
              ? "检测到当前安装路径与注册表不一致，请点下方「更新注册」"
              : `当前系统 HTTPS 默认：${routerStatus?.currentHttpsProgId || "未知"}`}
          </div>
          <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
            <Button
              variant={isRegistered && exeMatches ? "outline" : "solid"}
              size="xs"
              disabled={busyAction !== null}
              onClick={() => void onRegister()}
            >
              {isRegistered ? (exeMatches ? "重新写入注册" : "更新注册路径") : "一键注册"}
            </Button>
            <Button
              variant="soft"
              size="xs"
              disabled={busyAction !== null}
              onClick={() => void onOpenDefaultApps()}
            >
              <ExternalLink className="h-3 w-3" aria-hidden="true" />
              打开默认应用设置
            </Button>
            {isRegistered && (
              <Button
                variant="ghost"
                size="xs"
                disabled={busyAction !== null}
                onClick={() => void onUnregister()}
                title="移除 HKCU 注册项"
              >
                <Trash2 className="h-3 w-3" aria-hidden="true" />
                卸载
              </Button>
            )}
          </div>
        </div>

        {/* Cell 2: Routing Strategy */}
        <div className="flex flex-col justify-between gap-2.5 px-6 py-4">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[0.74rem] font-medium text-[#7c8495]">
              默认分流模式
            </span>
            <Shield className="h-4 w-4 text-[#6d5bd0]" aria-hidden="true" />
          </div>
          <Select
            value={router.mode}
            onValueChange={(v) => updateRouter({ mode: v as UrlRouterMode })}
          >
            <SelectTrigger aria-label="默认分流模式" className="h-8 text-[0.78rem]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="intercept_list" className="text-[0.78rem]">
                拦截名单弹窗 · 其余静默进 Edge (推荐)
              </SelectItem>
              <SelectItem value="allow_edge_list" className="text-[0.78rem]">
                国内白名单进 Edge · 其余全弹窗
              </SelectItem>
              <SelectItem value="always_ask" className="text-[0.78rem]">
                所有外部链接都弹窗选择
              </SelectItem>
            </SelectContent>
          </Select>

          <div className="flex items-center justify-between gap-2 rounded-lg border border-[#eaecef] bg-[#f8f9fb] px-3 py-2">
            <label
              htmlFor={`${uid}-oauth-loopback`}
              className="text-[0.72rem] leading-snug text-[#525866] cursor-pointer select-none"
            >
              自动拦截本地 OAuth 回调
              <span className="block text-[0.67rem] text-[#7c8495]">
                检测 redirect_uri=127.0.0.1 / localhost
              </span>
            </label>
            <Switch
              id={`${uid}-oauth-loopback`}
              size="sm"
              checked={router.interceptLoopbackOauth}
              onCheckedChange={(checked) =>
                updateRouter({ interceptLoopbackOauth: checked })
              }
            />
          </div>
        </div>

        {/* Cell 3: Fallback Edge Browser */}
        <div className="flex flex-col justify-between gap-2.5 px-6 py-4">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[0.74rem] font-medium text-[#7c8495]">
              日常工作兜底浏览器 (直通目标)
            </span>
            <Globe className="h-4 w-4 text-[#2563eb]" aria-hidden="true" />
          </div>
          <div className="flex flex-col gap-1">
            <label
              htmlFor={`${uid}-fallback-browser`}
              className="text-[0.7rem] text-[#7c8495]"
            >
              自定义浏览器 .exe（留空则自动探测 msedge.exe）
            </label>
            <Input
              id={`${uid}-fallback-browser`}
              className="mono-num h-8 text-[0.74rem]"
              placeholder={
                routerStatus?.fallbackBrowserPath ||
                "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
              }
              value={router.fallbackBrowserPath || ""}
              onChange={(e) =>
                updateRouter({
                  fallbackBrowserPath: e.target.value.trim() || null,
                })
              }
            />
          </div>
          <div className="mono-num truncate text-[0.69rem] text-[#7c8495]">
            {routerStatus?.fallbackBrowserPath
              ? `当前解析：${routerStatus.fallbackBrowserPath}`
              : "未检测到 msedge.exe / chrome.exe，请手动指定"}
          </div>
        </div>
      </section>

      {/* Domain Lists Grid */}
      <section className="grid grid-cols-1 divide-y divide-[#eaecef] lg:grid-cols-2 lg:divide-x lg:divide-y-0">
        {/* Intercept Domains */}
        <div className="flex flex-col gap-3 px-6 py-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-[#d97706]" aria-hidden="true" />
                <h2 className="text-[0.86rem] font-semibold text-[#111827]">
                  拦截并弹窗选择环境名单
                </h2>
                <Badge variant="warning" className="mono-num">
                  {router.interceptDomains.length}
                </Badge>
              </div>
              <p className="mt-0.5 text-[0.71rem] text-[#7c8495]">
                命中域名（含子域名）时弹窗选 AdsPower / NetGuard，防止泄露到 Edge
              </p>
            </div>
            <Button
              variant="ghost"
              size="xs"
              onClick={() =>
                updateRouter({ interceptDomains: [...DEFAULT_INTERCEPT_DOMAINS] })
              }
            >
              <RotateCcw className="h-3 w-3" aria-hidden="true" />
              恢复默认
            </Button>
          </div>

          <div className="flex items-center gap-2">
            <Input
              className="mono-num h-8 text-[0.75rem]"
              aria-label="添加拦截域名"
              placeholder="输入域名如 gemini.google.com"
              value={newIntercept}
              onChange={(e) => setNewIntercept(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  addDomain("interceptDomains", newIntercept);
                }
              }}
            />
            <Button
              variant="soft"
              size="sm"
              onClick={() => addDomain("interceptDomains", newIntercept)}
              disabled={!cleanDomainEntry(newIntercept)}
            >
              <Plus className="h-3.5 w-3.5" aria-hidden="true" />
              添加
            </Button>
          </div>

          <div className="flex max-h-[180px] flex-wrap gap-1.5 overflow-y-auto rounded-xl border border-[#eaecef] bg-[#fafbfc] p-2.5">
            {router.interceptDomains.length === 0 ? (
              <span className="text-[0.72rem] text-[#9ca3af]">暂无拦截域名</span>
            ) : (
              router.interceptDomains.map((d) => (
                <span
                  key={d}
                  className="mono-num inline-flex max-w-full items-center gap-1 rounded-md border border-[#fde68a] bg-[#fffbeb] px-2 py-0.5 text-[0.71rem] text-[#92400e]"
                >
                  <span className="truncate">{d}</span>
                  <button
                    type="button"
                    aria-label={`移除拦截域名 ${d}`}
                    onClick={() => removeDomain("interceptDomains", d)}
                    className="rounded p-0.5 hover:bg-[#fde68a]/60 cursor-pointer"
                  >
                    <X className="h-2.5 w-2.5" aria-hidden="true" />
                  </button>
                </span>
              ))
            )}
          </div>
        </div>

        {/* Edge Bypass Domains */}
        <div className="flex flex-col gap-3 px-6 py-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="flex items-center gap-2">
                <FolderOpen className="h-4 w-4 text-[#2563eb]" aria-hidden="true" />
                <h2 className="text-[0.86rem] font-semibold text-[#111827]">
                  静默直通 Edge 白名单（优先级最高）
                </h2>
                <Badge variant="iris" className="mono-num">
                  {router.edgeBypassDomains.length}
                </Badge>
              </div>
              <p className="mt-0.5 text-[0.71rem] text-[#7c8495]">
                国内服务、企业内网与工作站点直接秒开 Edge，不打扰也绝不混入指纹环境
              </p>
            </div>
            <Button
              variant="ghost"
              size="xs"
              onClick={() =>
                updateRouter({ edgeBypassDomains: [...DEFAULT_EDGE_BYPASS_DOMAINS] })
              }
            >
              <RotateCcw className="h-3 w-3" aria-hidden="true" />
              恢复默认
            </Button>
          </div>

          <div className="flex items-center gap-2">
            <Input
              className="mono-num h-8 text-[0.75rem]"
              aria-label="添加直通 Edge 域名"
              placeholder="输入域名如 feishu.cn"
              value={newBypass}
              onChange={(e) => setNewBypass(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  addDomain("edgeBypassDomains", newBypass);
                }
              }}
            />
            <Button
              variant="outline"
              size="sm"
              onClick={() => addDomain("edgeBypassDomains", newBypass)}
              disabled={!cleanDomainEntry(newBypass)}
            >
              <Plus className="h-3.5 w-3.5" aria-hidden="true" />
              添加
            </Button>
          </div>

          <div className="flex max-h-[180px] flex-wrap gap-1.5 overflow-y-auto rounded-xl border border-[#eaecef] bg-[#fafbfc] p-2.5">
            {router.edgeBypassDomains.length === 0 ? (
              <span className="text-[0.72rem] text-[#9ca3af]">暂无白名单域名</span>
            ) : (
              router.edgeBypassDomains.map((d) => (
                <span
                  key={d}
                  className="mono-num inline-flex max-w-full items-center gap-1 rounded-md border border-[#dbeafe] bg-[#eff6ff] px-2 py-0.5 text-[0.71rem] text-[#1d4ed8]"
                >
                  <span className="truncate">{d}</span>
                  <button
                    type="button"
                    aria-label={`移除直通域名 ${d}`}
                    onClick={() => removeDomain("edgeBypassDomains", d)}
                    className="rounded p-0.5 hover:bg-[#dbeafe]/70 cursor-pointer"
                  >
                    <X className="h-2.5 w-2.5" aria-hidden="true" />
                  </button>
                </span>
              ))
            )}
          </div>
        </div>
      </section>

      {/* Live Test & Recent History */}
      <section className="flex flex-col gap-3 px-6 py-4">
        <div className="flex flex-wrap items-center gap-2">
          <label
            htmlFor={`${uid}-test-url`}
            className="text-[0.74rem] font-medium text-[#525866]"
          >
            模拟弹窗测试
          </label>
          <Input
            id={`${uid}-test-url`}
            className="mono-num h-8 min-w-[240px] flex-1 text-[0.74rem]"
            value={testUrl}
            onChange={(e) => setTestUrl(e.target.value)}
            placeholder="https://accounts.google.com/o/oauth2/v2/auth?..."
          />
          <Button
            variant="solid"
            size="sm"
            disabled={!testUrl.trim() || busyAction !== null}
            onClick={() => void onTestPicker(testUrl.trim())}
          >
            <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
            测试分流弹窗
          </Button>
        </div>

        <div className="flex flex-col gap-1.5">
          <div className="text-[0.74rem] font-medium text-[#7c8495]">
            最近拦截分发记录（已自动剥离 OAuth 密钥参数）
          </div>
          {routeHistory.length === 0 ? (
            <div className="rounded-xl border border-dashed border-[#eaecef] bg-[#fafbfc] px-4 py-3 text-[0.73rem] text-[#9ca3af]">
              暂无本次运行拦截记录；注册并设为 Windows 默认浏览器后，外部 AI/OAuth 链接会在这里留下分发摘要
            </div>
          ) : (
            <div className="flex max-h-[150px] flex-col divide-y divide-[#f1f3f5] overflow-y-auto rounded-xl border border-[#eaecef]">
              {routeHistory.slice(0, 15).map((ev, idx) => (
                <div
                  key={`${ev.time}-${ev.host}-${idx}`}
                  className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-[0.73rem]"
                >
                  <div className="flex min-w-0 flex-1 items-center gap-2">
                    <span className="mono-num shrink-0 text-[0.69rem] text-[#9ca3af]">
                      {ev.time}
                    </span>
                    <Badge variant="neutral" className="shrink-0">
                      {ev.action}
                    </Badge>
                    <span className="mono-num truncate text-[#111827]" title={ev.displayUrl}>
                      {ev.displayUrl}
                    </span>
                  </div>
                  <span className="mono-num shrink-0 text-[0.7rem] text-[#525866]">
                    → {ev.target}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
