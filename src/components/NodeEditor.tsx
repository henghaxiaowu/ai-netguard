import { useEffect, useId, useState } from "react";
import {
  Plus,
  Trash2,
  Link2,
  Copy,
  Check,
  Code2,
  ChevronRight,
  AlertTriangle,
  Share2,
  Server,
  Globe,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { cn } from "@/lib/utils";
import type { AppConfig, NodeProfile, OutboundMode, ProxyProtocol } from "../types";
import { api } from "../api";

interface Props {
  config: AppConfig;
  dirty: boolean;
  secondaryNodePorts?: Record<string, number>;
  onUpdateConfig: (next: AppConfig) => void;
  onSave: () => Promise<void>;
  onNotify: (msg: string) => void;
  onQuickLaunchNodeBrowser?: (node: NodeProfile) => void;
}

const PROTOCOLS: { value: ProxyProtocol; label: string }[] = [
  { value: "vless", label: "VLESS (Reality / TLS)" },
  { value: "hysteria2", label: "Hysteria2" },
  { value: "shadowsocks", label: "Shadowsocks" },
  { value: "trojan", label: "Trojan" },
  { value: "socks", label: "SOCKS5 (静态 ISP)" },
  { value: "http", label: "HTTP/HTTPS 代理" },
];

const TIMEZONE_PRESETS = [
  "Asia/Seoul",
  "Asia/Tokyo",
  "Asia/Singapore",
  "America/Los_Angeles",
  "America/New_York",
  "Europe/London",
  "Europe/Berlin",
  "Australia/Sydney",
];

const LOCALE_PRESETS = ["ko-KR", "ja-JP", "en-US", "en-GB", "de-DE", "en-AU", "fr-FR"];

const OUTBOUND_OVERRIDE_LABELS: Record<OutboundMode, string> = {
  physical_bypass: "物理旁路",
  upstream_detour: "上游串联",
  default_route: "默认路由",
};

export function NodeEditor({
  config,
  dirty,
  secondaryNodePorts,
  onUpdateConfig,
  onSave,
  onNotify,
  onQuickLaunchNodeBrowser,
}: Props) {
  const uid = useId();
  const [uriInput, setUriInput] = useState("");
  const [vpsProto, setVpsProto] = useState<"vless-reality" | "hysteria2">("hysteria2");
  const [vpsPort, setVpsPort] = useState(443);
  const [vpsScript, setVpsScript] = useState("");
  const [copied, setCopied] = useState(false);

  const selected = config.nodes.find((n) => n.id === config.activeNodeId) || config.nodes[0];
  const needsAuthAttention =
    !!selected &&
    ((selected.allowInsecure && !selected.certificateSha256) || !selected.server.trim());
  const [authOpen, setAuthOpen] = useState(needsAuthAttention);

  useEffect(() => {
    if (needsAuthAttention) {
      setAuthOpen(true);
    }
  }, [selected?.id, needsAuthAttention]);

  const updateNodes = (nodes: NodeProfile[], activeNodeId: string) => {
    onUpdateConfig({ ...config, nodes, activeNodeId });
  };

  const updateSelected = (patch: Partial<NodeProfile>) => {
    if (!selected) return;
    const next = config.nodes.map((n) => (n.id === selected.id ? { ...n, ...patch } : n));
    updateNodes(next, config.activeNodeId);
  };

  const addBlankNode = () => {
    const id = `node-${Date.now()}`;
    const created: NodeProfile = {
      id,
      name: "新出口节点",
      protocol: "vless",
      server: "",
      port: 443,
      security: "reality",
      fingerprint: "chrome",
      timezone: "Asia/Seoul",
      locale: "ko-KR",
    };
    updateNodes([...config.nodes, created], id);
    setAuthOpen(true);
  };

  const removeSelected = () => {
    if (!selected || config.nodes.length <= 1) return;
    const next = config.nodes.filter((n) => n.id !== selected.id);
    updateNodes(next, next[0].id);
  };

  const handleImportUri = async () => {
    const trimmed = uriInput.trim();
    if (!trimmed) return;
    try {
      const parsed = await api.parseNodeUri(trimmed);
      updateNodes([...config.nodes, parsed], parsed.id);
      setUriInput("");
      onNotify(`已导入节点: ${parsed.name}`);
    } catch (err) {
      onNotify(`导入失败: ${String(err)}`);
    }
  };

  const handleGenerateVps = async () => {
    try {
      const script = await api.generateVpsScript(vpsProto, vpsPort);
      setVpsScript(script);
    } catch (err) {
      onNotify(`生成失败: ${String(err)}`);
    }
  };

  const copyScript = async () => {
    if (!vpsScript) return;
    await navigator.clipboard.writeText(vpsScript);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  const fid = (name: string) => `${uid}-${name}`;

  const tzVal = selected?.timezone || "Asia/Seoul";
  const tzOptions = TIMEZONE_PRESETS.includes(tzVal) ? TIMEZONE_PRESETS : [tzVal, ...TIMEZONE_PRESETS];
  const locVal = selected?.locale || "ko-KR";
  const locOptions = LOCALE_PRESETS.includes(locVal) ? LOCALE_PRESETS : [locVal, ...LOCALE_PRESETS];

  return (
    <div className="bento-sheet flex flex-col divide-y divide-[#eaecef] rounded-2xl border border-[#eaecef] bg-white shadow-[0_1px_3px_rgba(15,23,42,0.03)]">
      {/* Page Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 px-6 py-4">
        <div>
          <h1
            id="main-heading"
            tabIndex={-1}
            className="vt-page-title text-[1.2rem] font-semibold tracking-[-0.02em] text-[#111827] outline-none"
          >
            出口与共存路由
          </h1>
          <p className="mt-0.5 text-[0.76rem] text-[#7c8495]">
            管理出口节点与出站策略
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={addBlankNode}>
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            新建节点
          </Button>
          <Button
            variant="solid"
            size="sm"
            disabled={!dirty}
            onClick={onSave}
          >
            保存配置
          </Button>
        </div>
      </header>

      {/* Top Row: Coexistence Routing & Link Import */}
      <section className="grid grid-cols-1 divide-y divide-[#eaecef] lg:grid-cols-2 lg:divide-x lg:divide-y-0">
        <div className="flex flex-col gap-3 p-5 px-6">
          <div className="flex items-center gap-2 text-[0.82rem] font-semibold text-[#111827]">
            <span className="inline-grid h-6 w-6 place-items-center rounded-md bg-[#f0edfc] text-[#6d5bd0]">
              <Share2 className="h-3.5 w-3.5" aria-hidden="true" />
            </span>
            共存路由模式
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <label htmlFor={fid("outboundMode")} className="text-[0.71rem] font-medium text-[#7c8495]">
                出站路由
              </label>
              <Select
                value={config.outboundMode}
                onValueChange={(v) =>
                  onUpdateConfig({
                    ...config,
                    outboundMode: v as AppConfig["outboundMode"],
                  })
                }
              >
                <SelectTrigger id={fid("outboundMode")}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="physical_bypass">物理网卡旁路 (/32 推荐)</SelectItem>
                  <SelectItem value="upstream_detour">经现有代理串联出站</SelectItem>
                  <SelectItem value="default_route">系统默认路由</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex flex-col gap-1.5">
              <label htmlFor={fid("killSwitch")} className="text-[0.71rem] font-medium text-[#7c8495]">
                异常策略
              </label>
              <Select
                value={config.killSwitch}
                onValueChange={(v) =>
                  onUpdateConfig({
                    ...config,
                    killSwitch: v as AppConfig["killSwitch"],
                  })
                }
              >
                <SelectTrigger id={fid("killSwitch")}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="fail_closed">严格熔断 (阻断直连)</SelectItem>
                  <SelectItem value="monitor_only">仅告警不断网</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {config.outboundMode === "upstream_detour" && (
            <div className="grid grid-cols-1 gap-2.5 pt-1 sm:grid-cols-3">
              <div className="flex flex-col gap-1">
                <label htmlFor={fid("upProto")} className="text-[0.69rem] text-[#7c8495]">
                  上游协议
                </label>
                <Select
                  value={config.upstreamProxy.protocol}
                  onValueChange={(v) =>
                    onUpdateConfig({
                      ...config,
                      upstreamProxy: {
                        ...config.upstreamProxy,
                        enabled: true,
                        protocol: v as "socks" | "http",
                      },
                    })
                  }
                >
                  <SelectTrigger id={fid("upProto")}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="socks">SOCKS5</SelectItem>
                    <SelectItem value="http">HTTP</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex flex-col gap-1">
                <label htmlFor={fid("upAddr")} className="text-[0.69rem] text-[#7c8495]">
                  上游地址
                </label>
                <Input
                  id={fid("upAddr")}
                  className="mono-num"
                  value={config.upstreamProxy.server}
                  onChange={(e) =>
                    onUpdateConfig({
                      ...config,
                      upstreamProxy: {
                        ...config.upstreamProxy,
                        enabled: true,
                        server: e.target.value,
                      },
                    })
                  }
                />
              </div>
              <div className="flex flex-col gap-1">
                <label htmlFor={fid("upPort")} className="text-[0.69rem] text-[#7c8495]">
                  端口
                </label>
                <Input
                  id={fid("upPort")}
                  type="number"
                  className="mono-num"
                  value={config.upstreamProxy.port}
                  onChange={(e) =>
                    onUpdateConfig({
                      ...config,
                      upstreamProxy: {
                        ...config.upstreamProxy,
                        enabled: true,
                        port: Number(e.target.value) || 7890,
                      },
                    })
                  }
                />
              </div>
            </div>
          )}
        </div>

        <div className="flex flex-col gap-3 p-5 px-6">
          <div className="flex items-center gap-2 text-[0.82rem] font-semibold text-[#111827]">
            <span className="inline-grid h-6 w-6 place-items-center rounded-md bg-[#f0edfc] text-[#6d5bd0]">
              <Link2 className="h-3.5 w-3.5" aria-hidden="true" />
            </span>
            链接导入
          </div>
          <div className="flex items-center gap-2 pt-2">
            <label htmlFor={fid("uriInput")} className="visually-hidden">
              粘贴节点分享链接
            </label>
            <Input
              id={fid("uriInput")}
              className="mono-num flex-1"
              placeholder="粘贴节点分享链接 (vless:// / hy2:// / ss:// / trojan:// / socks5://)"
              value={uriInput}
              onChange={(e) => setUriInput(e.target.value)}
            />
            <Button variant="outline" onClick={handleImportUri}>
              解析导入
            </Button>
          </div>
        </div>
      </section>

      {/* Main Split: Egress Nodes List & Selected Node Form */}
      <section className="grid grid-cols-1 divide-y divide-[#eaecef] lg:grid-cols-[minmax(0,1.05fr)_minmax(0,1.95fr)] lg:divide-x lg:divide-y-0">
        {/* Left Node Switcher */}
        <div className="flex flex-col gap-3 p-5 px-6">
          <h2 className="text-[0.84rem] font-semibold text-[#111827]">出口节点</h2>
          <fieldset className="flex flex-col gap-2">
            <legend className="visually-hidden">选择活跃出口节点</legend>
            {config.nodes.map((n) => {
              const active = n.id === selected?.id;
              return (
                <label
                  key={n.id}
                  className={cn(
                    "flex cursor-pointer items-center justify-between gap-2.5 rounded-xl border px-3 py-2.5 transition-colors has-[>input:focus-visible]:outline-2 has-[>input:focus-visible]:outline-[#5b48c4]",
                    active
                      ? "border-[#dcd4fb] bg-[#f4f1fd]"
                      : "border-[#eaecef] bg-white hover:bg-[#f9fafb]",
                  )}
                >
                  <input
                    type="radio"
                    name={fid("activeNode")}
                    value={n.id}
                    checked={active}
                    onChange={() => updateNodes(config.nodes, n.id)}
                    className="visually-hidden"
                  />
                  <div className="flex min-w-0 items-center gap-2">
                    <Server
                      className={cn(
                        "h-4 w-4 shrink-0",
                        active ? "text-[#6d5bd0]" : "text-[#9ca3af]",
                      )}
                      aria-hidden="true"
                    />
                    <span className="truncate text-[0.79rem] font-medium text-[#111827]">
                      {n.name}
                    </span>
                  </div>
                  <div className="flex shrink-0 items-center gap-1.5">
                    {n.outboundMode && (
                      <Badge variant="iris" className="px-1.5 text-[0.62rem]">
                        {OUTBOUND_OVERRIDE_LABELS[n.outboundMode]}
                      </Badge>
                    )}
                    {!active && secondaryNodePorts?.[n.id] ? (
                      <Badge variant="neutral" className="mono-num px-1.5 text-[0.63rem]">
                        :{secondaryNodePorts[n.id]}
                      </Badge>
                    ) : null}
                    <Badge variant="neutral" className="mono-num uppercase px-1.5 text-[0.65rem]">
                      {n.protocol}
                    </Badge>
                    {active ? (
                      <Badge variant="success">当前出口</Badge>
                    ) : (
                      <Badge variant="neutral">备用</Badge>
                    )}
                  </div>
                </label>
              );
            })}
          </fieldset>
        </div>

        {/* Right Node Configuration Form */}
        {selected && (
          <div className="flex flex-col gap-4 p-5 px-6">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-[0.84rem] font-semibold text-[#111827]">节点配置</h2>
              <div className="flex flex-wrap items-center gap-2">
                {onQuickLaunchNodeBrowser && (
                  <Button
                    variant="soft"
                    size="xs"
                    onClick={() => onQuickLaunchNodeBrowser(selected)}
                  >
                    <Globe className="h-3 w-3" aria-hidden="true" />
                    用此节点启动浏览器
                  </Button>
                )}
                <Button
                  variant="destructive-outline"
                  size="xs"
                  disabled={config.nodes.length <= 1}
                  onClick={removeSelected}
                >
                  <Trash2 className="h-3 w-3" aria-hidden="true" />
                  删除节点
                </Button>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-x-4 gap-y-3 sm:grid-cols-2">
              <div className="flex flex-col gap-1">
                <label htmlFor={fid("name")} className="text-[0.71rem] font-medium text-[#7c8495]">
                  节点名称
                </label>
                <Input
                  id={fid("name")}
                  value={selected.name}
                  onChange={(e) => updateSelected({ name: e.target.value })}
                />
              </div>

              <div className="flex flex-col gap-1">
                <label htmlFor={fid("protocol")} className="text-[0.71rem] font-medium text-[#7c8495]">
                  协议
                </label>
                <Select
                  value={selected.protocol}
                  onValueChange={(v) => updateSelected({ protocol: v as ProxyProtocol })}
                >
                  <SelectTrigger id={fid("protocol")}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PROTOCOLS.map((p) => (
                      <SelectItem key={p.value} value={p.value}>
                        {p.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="flex flex-col gap-1">
                <label htmlFor={fid("server")} className="text-[0.71rem] font-medium text-[#7c8495]">
                  服务器地址
                </label>
                <Input
                  id={fid("server")}
                  className="mono-num"
                  placeholder="proxy.example.com"
                  value={selected.server}
                  onChange={(e) => updateSelected({ server: e.target.value })}
                />
              </div>

              <div className="flex flex-col gap-1">
                <label htmlFor={fid("port")} className="text-[0.71rem] font-medium text-[#7c8495]">
                  端口
                </label>
                <Input
                  id={fid("port")}
                  type="number"
                  className="mono-num"
                  value={selected.port}
                  onChange={(e) =>
                    updateSelected({ port: Number(e.target.value) || 443 })
                  }
                />
              </div>

              <div className="flex flex-col gap-1">
                <label htmlFor={fid("expectedIp")} className="text-[0.71rem] font-medium text-[#7c8495]">
                  预期出口 IP
                </label>
                <Input
                  id={fid("expectedIp")}
                  className="mono-num"
                  placeholder="203.0.113.42"
                  value={selected.expectedIp || ""}
                  onChange={(e) => updateSelected({ expectedIp: e.target.value })}
                />
              </div>

              <div className="flex flex-col gap-1">
                <label htmlFor={fid("expectedCountry")} className="text-[0.71rem] font-medium text-[#7c8495]">
                  预期国家代码
                </label>
                <Input
                  id={fid("expectedCountry")}
                  className="mono-num"
                  placeholder="KR"
                  value={selected.expectedCountry || ""}
                  onChange={(e) =>
                    updateSelected({ expectedCountry: e.target.value.toUpperCase() })
                  }
                />
              </div>

              <div className="flex flex-col gap-1">
                <label htmlFor={fid("tz")} className="text-[0.71rem] font-medium text-[#7c8495]">
                  时区
                </label>
                <Select
                  value={tzVal}
                  onValueChange={(v) => updateSelected({ timezone: v })}
                >
                  <SelectTrigger id={fid("tz")} className="mono-num">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {tzOptions.map((tz) => (
                      <SelectItem key={tz} value={tz} className="mono-num">
                        {tz}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="flex flex-col gap-1">
                <label htmlFor={fid("locale")} className="text-[0.71rem] font-medium text-[#7c8495]">
                  语言
                </label>
                <Select
                  value={locVal}
                  onValueChange={(v) => updateSelected({ locale: v })}
                >
                  <SelectTrigger id={fid("locale")} className="mono-num">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {locOptions.map((loc) => (
                      <SelectItem key={loc} value={loc} className="mono-num">
                        {loc}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="flex flex-col gap-1 sm:col-span-2">
                <label htmlFor={fid("nodeOutboundMode")} className="text-[0.71rem] font-medium text-[#7c8495]">
                  节点出站覆盖（可单独覆盖全局共存策略，互不影响）
                </label>
                <Select
                  value={selected.outboundMode || "follow_global"}
                  onValueChange={(v) =>
                    updateSelected({
                      outboundMode: v === "follow_global" ? undefined : (v as OutboundMode),
                    })
                  }
                >
                  <SelectTrigger id={fid("nodeOutboundMode")}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="follow_global">
                      跟随全局共存路由（当前：{OUTBOUND_OVERRIDE_LABELS[config.outboundMode]}）
                    </SelectItem>
                    <SelectItem value="physical_bypass">
                      强制物理网卡直连绕过 Clash (/32 免疫 Clash 全局与 TUN)
                    </SelectItem>
                    <SelectItem value="upstream_detour">
                      强制经上游代理串联 ({config.upstreamProxy.server}:{config.upstreamProxy.port})
                    </SelectItem>
                    <SelectItem value="default_route">
                      系统默认路由
                    </SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-[0.69rem] text-[#7c8495]">
                  {(selected.outboundMode || config.outboundMode) === "physical_bypass"
                    ? "该节点会绑定真实物理网卡并自动写入 /32 主机旁路路由，即使 Clash 开启全局 / TUN 模式也不会被劫持。"
                    : (selected.outboundMode || config.outboundMode) === "upstream_detour"
                      ? `该节点流量将先经过上游代理 ${config.upstreamProxy.server}:${config.upstreamProxy.port} 再落地目标 IP；请确保上方 Clash 节点本身可直连且能连通。`
                      : "跟随系统默认路由表出站（若外部软件开启全局 TUN，可能会走入外部 TUN）。"}
                </p>
              </div>
            </div>

            {/* Collapsible Authentication & Protocol Options */}
            <Collapsible open={authOpen} onOpenChange={setAuthOpen} className="pt-1">
              <CollapsibleTrigger asChild>
                <button
                  type="button"
                  className="inline-flex items-center gap-1.5 rounded-md py-1 text-[0.76rem] font-medium text-[#525866] hover:text-[#111827] cursor-pointer"
                >
                  <ChevronRight
                    className={cn(
                      "h-3.5 w-3.5 transition-transform duration-150",
                      authOpen && "rotate-90",
                    )}
                    aria-hidden="true"
                  />
                  认证选项
                  {selected.allowInsecure && !selected.certificateSha256 && (
                    <Badge variant="warning" className="ml-1">
                      跳过 TLS 验证
                    </Badge>
                  )}
                </button>
              </CollapsibleTrigger>

              <CollapsibleContent className="mt-2.5 grid grid-cols-1 gap-x-4 gap-y-3 rounded-xl border border-[#eaecef] bg-[#f9fafb] p-3.5 sm:grid-cols-2">
                {(selected.protocol === "vless" || selected.protocol === "trojan") && (
                  <>
                    {selected.protocol === "vless" ? (
                      <div className="flex flex-col gap-1">
                        <label htmlFor={fid("uuid")} className="text-[0.7rem] text-[#7c8495]">
                          UUID
                        </label>
                        <Input
                          id={fid("uuid")}
                          className="mono-num"
                          value={selected.uuid || ""}
                          onChange={(e) => updateSelected({ uuid: e.target.value })}
                        />
                      </div>
                    ) : (
                      <div className="flex flex-col gap-1">
                        <label htmlFor={fid("trojanPass")} className="text-[0.7rem] text-[#7c8495]">
                          Trojan 密码
                        </label>
                        <Input
                          id={fid("trojanPass")}
                          type="password"
                          className="mono-num"
                          value={selected.password || ""}
                          onChange={(e) => updateSelected({ password: e.target.value })}
                        />
                      </div>
                    )}

                    <div className="flex flex-col gap-1">
                      <label htmlFor={fid("security")} className="text-[0.7rem] text-[#7c8495]">
                        传输安全
                      </label>
                      <Select
                        value={selected.security || "reality"}
                        onValueChange={(v) =>
                          updateSelected({ security: v as "none" | "tls" | "reality" })
                        }
                      >
                        <SelectTrigger id={fid("security")}>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="reality">Reality (推荐用于 VPS)</SelectItem>
                          <SelectItem value="tls">TLS</SelectItem>
                          <SelectItem value="none">None</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="flex flex-col gap-1">
                      <label htmlFor={fid("sni")} className="text-[0.7rem] text-[#7c8495]">
                        SNI (Server Name)
                      </label>
                      <Input
                        id={fid("sni")}
                        className="mono-num"
                        placeholder="www.microsoft.com"
                        value={selected.sni || ""}
                        onChange={(e) => updateSelected({ sni: e.target.value })}
                      />
                    </div>

                    {selected.protocol === "vless" && selected.security === "reality" && (
                      <>
                        <div className="flex flex-col gap-1">
                          <label htmlFor={fid("pbk")} className="text-[0.7rem] text-[#7c8495]">
                            Reality Public Key (pbk)
                          </label>
                          <Input
                            id={fid("pbk")}
                            className="mono-num"
                            value={selected.publicKey || ""}
                            onChange={(e) => updateSelected({ publicKey: e.target.value })}
                          />
                        </div>
                        <div className="flex flex-col gap-1">
                          <label htmlFor={fid("sid")} className="text-[0.7rem] text-[#7c8495]">
                            Reality Short ID (sid)
                          </label>
                          <Input
                            id={fid("sid")}
                            className="mono-num"
                            value={selected.shortId || ""}
                            onChange={(e) => updateSelected({ shortId: e.target.value })}
                          />
                        </div>
                        <div className="flex flex-col gap-1">
                          <label htmlFor={fid("flow")} className="text-[0.7rem] text-[#7c8495]">
                            Flow
                          </label>
                          <Input
                            id={fid("flow")}
                            className="mono-num"
                            placeholder="xtls-rprx-vision"
                            value={selected.flow || ""}
                            onChange={(e) => updateSelected({ flow: e.target.value })}
                          />
                        </div>
                      </>
                    )}
                  </>
                )}

                {selected.protocol === "shadowsocks" && (
                  <>
                    <div className="flex flex-col gap-1">
                      <label htmlFor={fid("ssMethod")} className="text-[0.7rem] text-[#7c8495]">
                        加密方式
                      </label>
                      <Input
                        id={fid("ssMethod")}
                        className="mono-num"
                        placeholder="2022-blake3-aes-128-gcm"
                        value={selected.method || ""}
                        onChange={(e) => updateSelected({ method: e.target.value })}
                      />
                    </div>
                    <div className="flex flex-col gap-1">
                      <label htmlFor={fid("ssPass")} className="text-[0.7rem] text-[#7c8495]">
                        密码
                      </label>
                      <Input
                        id={fid("ssPass")}
                        type="password"
                        className="mono-num"
                        value={selected.password || ""}
                        onChange={(e) => updateSelected({ password: e.target.value })}
                      />
                    </div>
                  </>
                )}

                {selected.protocol === "hysteria2" && (
                  <>
                    <div className="flex flex-col gap-1">
                      <label htmlFor={fid("hy2Pass")} className="text-[0.7rem] text-[#7c8495]">
                        认证密码
                      </label>
                      <Input
                        id={fid("hy2Pass")}
                        type="password"
                        className="mono-num"
                        value={selected.password || ""}
                        onChange={(e) => updateSelected({ password: e.target.value })}
                      />
                    </div>
                    <div className="flex flex-col gap-1">
                      <label htmlFor={fid("hy2Sni")} className="text-[0.7rem] text-[#7c8495]">
                        SNI
                      </label>
                      <Input
                        id={fid("hy2Sni")}
                        className="mono-num"
                        value={selected.sni || ""}
                        onChange={(e) => updateSelected({ sni: e.target.value })}
                      />
                    </div>
                    <div className="flex flex-col gap-1 sm:col-span-2">
                      <label htmlFor={fid("hy2Pin")} className="text-[0.7rem] text-[#7c8495]">
                        TLS 证书公钥指纹 (SPKI SHA-256 / pinSHA256)
                      </label>
                      <Input
                        id={fid("hy2Pin")}
                        className="mono-num"
                        placeholder="sha256/... 或 44 位 Base64"
                        value={selected.certificateSha256 || ""}
                        onChange={(e) =>
                          updateSelected({ certificateSha256: e.target.value || undefined })
                        }
                      />
                    </div>
                    {selected.allowInsecure && !selected.certificateSha256 && (
                      <div className="flex items-center gap-1.5 text-[0.72rem] text-[#92400e] sm:col-span-2">
                        <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        当前节点启用了 insecure=1，建议改用 SPKI SHA-256 指纹固定
                      </div>
                    )}
                  </>
                )}

                {(selected.protocol === "socks" || selected.protocol === "http") && (
                  <>
                    <div className="flex flex-col gap-1">
                      <label htmlFor={fid("proxyUser")} className="text-[0.7rem] text-[#7c8495]">
                        用户名（可选）
                      </label>
                      <Input
                        id={fid("proxyUser")}
                        className="mono-num"
                        value={selected.username || ""}
                        onChange={(e) => updateSelected({ username: e.target.value })}
                      />
                    </div>
                    <div className="flex flex-col gap-1">
                      <label htmlFor={fid("proxyPass")} className="text-[0.7rem] text-[#7c8495]">
                        密码（可选）
                      </label>
                      <Input
                        id={fid("proxyPass")}
                        type="password"
                        className="mono-num"
                        value={selected.password || ""}
                        onChange={(e) => updateSelected({ password: e.target.value })}
                      />
                    </div>
                  </>
                )}

                {/* Custom timezone/locale override fields */}
                <div className="flex flex-col gap-1">
                  <label htmlFor={fid("customTz")} className="text-[0.7rem] text-[#7c8495]">
                    自定义时区 (IANA)
                  </label>
                  <Input
                    id={fid("customTz")}
                    className="mono-num"
                    placeholder="Asia/Seoul"
                    value={selected.timezone || ""}
                    onChange={(e) => updateSelected({ timezone: e.target.value })}
                  />
                </div>
                <div className="flex flex-col gap-1">
                  <label htmlFor={fid("customLocale")} className="text-[0.7rem] text-[#7c8495]">
                    自定义语言 (--lang)
                  </label>
                  <Input
                    id={fid("customLocale")}
                    className="mono-num"
                    placeholder="ko-KR"
                    value={selected.locale || ""}
                    onChange={(e) => updateSelected({ locale: e.target.value })}
                  />
                </div>
              </CollapsibleContent>
            </Collapsible>
          </div>
        )}
      </section>

      {/* Bottom Bar: VPS Deploy Script */}
      <section className="flex flex-col gap-3 p-5 px-6">
        <div className="flex items-center gap-2 text-[0.82rem] font-semibold text-[#111827]">
          <span className="inline-grid h-6 w-6 place-items-center rounded-md bg-[#f0edfc] text-[#6d5bd0]">
            <Code2 className="h-3.5 w-3.5" aria-hidden="true" />
          </span>
          VPS 部署脚本
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex flex-1 items-center gap-2 min-w-[14rem]">
            <label htmlFor={fid("vpsProto")} className="text-[0.74rem] text-[#7c8495] shrink-0">
              协议
            </label>
            <Select
              value={vpsProto}
              onValueChange={(v) => setVpsProto(v as "vless-reality" | "hysteria2")}
            >
              <SelectTrigger id={fid("vpsProto")}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="hysteria2">Hysteria2</SelectItem>
                <SelectItem value="vless-reality">VLESS + Reality (TCP)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex flex-1 items-center gap-2 min-w-[10rem]">
            <label htmlFor={fid("vpsPort")} className="text-[0.74rem] text-[#7c8495] shrink-0">
              端口
            </label>
            <Input
              id={fid("vpsPort")}
              type="number"
              className="mono-num"
              value={vpsPort}
              onChange={(e) => setVpsPort(Number(e.target.value) || 443)}
            />
          </div>

          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={handleGenerateVps}>
              生成脚本
            </Button>
            {vpsScript && (
              <Button variant="soft" size="sm" onClick={copyScript}>
                {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                {copied ? "已复制" : "复制"}
              </Button>
            )}
          </div>
        </div>

        {vpsScript && (
          <pre className="app-scroll max-h-56 overflow-y-auto rounded-xl border border-[#27272a] bg-[#18181b] p-3.5 text-[0.72rem] leading-relaxed text-[#e4e4e7] mono-num">
            {vpsScript}
          </pre>
        )}
      </section>
    </div>
  );
}
