import { useMemo, useState } from "react";
import { geoGraticule10, geoMercator, geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import type { Topology, GeometryCollection } from "topojson-specification";
import worldAtlas from "world-atlas/countries-110m.json";
import { MapPin, Activity, Share2 } from "lucide-react";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { ExitIpInfo, NodeProfile } from "../types";

interface ExitIpMapProps {
  exitIp?: ExitIpInfo;
  activeNode?: NodeProfile;
  running: boolean;
  blockedByKillSwitch: boolean;
  compact?: boolean;
}

type MapViewMode = "world" | "focus";

interface GeoPreset {
  lat: number;
  lon: number;
  label: string;
}

const COUNTRY_CODE_TO_NUMERIC_ID: Record<string, string> = {
  KR: "410",
  JP: "392",
  US: "840",
  GB: "826",
  UK: "826",
  DE: "276",
  FR: "250",
  NL: "528",
  CA: "124",
  AU: "036",
  CH: "756",
  IE: "372",
  TW: "158",
  CN: "156",
  IN: "356",
  ID: "360",
  TH: "764",
  VN: "704",
  MY: "458",
  PH: "608",
};

const COORD_FALLBACK_BY_COUNTRY: Record<string, GeoPreset> = {
  KR: { lat: 37.5665, lon: 126.978, label: "韩国 · 首尔" },
  JP: { lat: 35.6762, lon: 139.6503, label: "日本 · 东京" },
  US: { lat: 37.7749, lon: -122.4194, label: "美国 · 美西" },
  SG: { lat: 1.3521, lon: 103.8198, label: "新加坡" },
  TW: { lat: 25.033, lon: 121.5654, label: "中国台湾 · 台北" },
  HK: { lat: 22.3193, lon: 114.1694, label: "中国香港" },
  GB: { lat: 51.5072, lon: -0.1276, label: "英国 · 伦敦" },
  DE: { lat: 50.1109, lon: 8.6821, label: "德国 · 法兰克福" },
  NL: { lat: 52.3676, lon: 4.9041, label: "荷兰 · 阿姆斯特丹" },
  CA: { lat: 43.6532, lon: -79.3832, label: "加拿大 · 多伦多" },
  AU: { lat: -33.8688, lon: 151.2093, label: "澳大利亚 · 悉尼" },
  FR: { lat: 48.8566, lon: 2.3522, label: "法国 · 巴黎" },
};

const COORD_FALLBACK_BY_TZ: Record<string, GeoPreset> = {
  "Asia/Seoul": COORD_FALLBACK_BY_COUNTRY.KR,
  "Asia/Tokyo": COORD_FALLBACK_BY_COUNTRY.JP,
  "Asia/Singapore": COORD_FALLBACK_BY_COUNTRY.SG,
  "Asia/Taipei": COORD_FALLBACK_BY_COUNTRY.TW,
  "Asia/Hong_Kong": COORD_FALLBACK_BY_COUNTRY.HK,
  "America/Los_Angeles": COORD_FALLBACK_BY_COUNTRY.US,
  "America/New_York": { lat: 40.7128, lon: -74.006, label: "美国 · 美东" },
  "Europe/London": COORD_FALLBACK_BY_COUNTRY.GB,
  "Europe/Berlin": COORD_FALLBACK_BY_COUNTRY.DE,
  "Europe/Amsterdam": COORD_FALLBACK_BY_COUNTRY.NL,
};

function formatCoord(lat: number, lon: number): string {
  const ns = lat >= 0 ? "N" : "S";
  const ew = lon >= 0 ? "E" : "W";
  return `${Math.abs(lat).toFixed(2)}°${ns} · ${Math.abs(lon).toFixed(2)}°${ew}`;
}

export function ExitIpMap({
  exitIp,
  activeNode,
  running,
  blockedByKillSwitch,
  compact = false,
}: ExitIpMapProps) {
  const [viewMode, setViewMode] = useState<MapViewMode>("focus");

  const width = compact ? 520 : 620;
  const height = compact ? 186 : 228;

  const target = useMemo(() => {
    const cc = (exitIp?.countryCode || activeNode?.expectedCountry || "KR").toUpperCase();
    const tz = exitIp?.timezone || activeNode?.timezone || "Asia/Seoul";
    const preset =
      COORD_FALLBACK_BY_COUNTRY[cc] ||
      COORD_FALLBACK_BY_TZ[tz] ||
      COORD_FALLBACK_BY_COUNTRY.KR;

    if (
      exitIp?.latitude !== undefined &&
      exitIp?.longitude !== undefined &&
      Number.isFinite(exitIp.latitude) &&
      Number.isFinite(exitIp.longitude)
    ) {
      const countryPart = exitIp.countryCode === "KR" ? "韩国" : exitIp.country || cc;
      const cityPart = exitIp.city === "Seoul" ? "首尔" : exitIp.city || exitIp.region;
      const label = [countryPart, cityPart].filter(Boolean).join(" · ") || exitIp.ip;
      return {
        lat: exitIp.latitude,
        lon: exitIp.longitude,
        label,
        countryCode: cc,
        live: true,
      };
    }

    return {
      lat: preset.lat,
      lon: preset.lon,
      label: preset.label,
      countryCode: cc,
      live: false,
    };
  }, [exitIp, activeNode]);

  const mapData = useMemo(() => {
    const topology = worldAtlas as unknown as Topology<{
      countries: GeometryCollection<{ name?: string }>;
      land: GeometryCollection;
    }>;
    const countries = feature(topology, topology.objects.countries);
    const inhabited = {
      ...countries,
      features: countries.features.filter((f) => String(f.id) !== "010"),
    };

    const projection =
      viewMode === "world"
        ? geoNaturalEarth1().fitExtent(
            [
              [14, 14],
              [width - 14, height - 14],
            ],
            inhabited,
          )
        : geoMercator()
            .center([target.lon - 2.2, target.lat - 0.9])
            .scale(compact ? 660 : 760)
            .translate([width * 0.43, height * 0.52]);

    const pathGen = geoPath(projection);
    const activeCountryId = COUNTRY_CODE_TO_NUMERIC_ID[target.countryCode];

    const graticulePath = pathGen(geoGraticule10()) || "";
    const countryShapes = inhabited.features.map((feat) => ({
      id: String(feat.id ?? ""),
      name: feat.properties?.name || "",
      isTarget: activeCountryId !== undefined && String(feat.id) === activeCountryId,
      d: pathGen(feat) || "",
    }));

    const targetPoint = projection([target.lon, target.lat]);

    return {
      graticulePath,
      countryShapes,
      targetPoint,
    };
  }, [viewMode, target, width, height, compact]);

  const pinState = blockedByKillSwitch
    ? "danger"
    : running && exitIp
      ? "live"
      : "idle";

  const statusText =
    pinState === "danger"
      ? "熔断拦截中"
      : pinState === "live"
        ? target.live
          ? "实时定位已核验"
          : "出口已连通"
        : "节点预设坐标";

  const pinColor =
    pinState === "danger" ? "#dc2626" : pinState === "live" ? "#6d5bd0" : "#d97706";
  const ringColor =
    pinState === "danger"
      ? "rgba(220, 38, 38, 0.35)"
      : pinState === "live"
        ? "rgba(109, 91, 208, 0.38)"
        : "rgba(217, 119, 6, 0.35)";

  return (
    <figure className="flex flex-col gap-2.5 min-w-0">
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-[0.84rem] font-semibold text-[#111827]">出口位置</h2>
        {!compact && (
          <Tabs
            value={viewMode}
            onValueChange={(v) => setViewMode(v as MapViewMode)}
          >
            <TabsList aria-label="地图视角">
              <TabsTrigger value="world">全球</TabsTrigger>
              <TabsTrigger value="focus">区域</TabsTrigger>
            </TabsList>
          </Tabs>
        )}
      </div>

      <Tooltip>
        <TooltipTrigger asChild>
          <div
            tabIndex={0}
            className="relative w-full overflow-hidden rounded-xl border border-[#eaecef] bg-[#f4f5f8] cursor-default focus-visible:outline-2 focus-visible:outline-[#5b48c4]"
            style={{ aspectRatio: `${width} / ${height}` }}
          >
            <svg
              className="block h-full w-full"
              viewBox={`0 0 ${width} ${height}`}
              preserveAspectRatio="xMidYMid slice"
              role="img"
              aria-labelledby="netguard-map-title"
            >
              <title id="netguard-map-title">
                {`出口位置地图：${target.label}（${statusText}）`}
              </title>

              <defs>
                <radialGradient id="ngMapMist" cx="52%" cy="48%" r="65%">
                  <stop offset="0%" stopColor="rgba(109, 91, 208, 0.06)" />
                  <stop offset="100%" stopColor="rgba(226, 230, 238, 0.25)" />
                </radialGradient>
              </defs>

              <rect x="0" y="0" width={width} height={height} fill="url(#ngMapMist)" />

              {mapData.graticulePath && (
                <path
                  d={mapData.graticulePath}
                  fill="none"
                  stroke="rgba(148, 163, 184, 0.16)"
                  strokeWidth="0.65"
                  strokeDasharray="2 3"
                />
              )}

              <g>
                {mapData.countryShapes.map((c, i) => (
                  <path
                    key={c.id || i}
                    d={c.d}
                    fill={
                      c.isTarget
                        ? "rgba(109, 91, 208, 0.18)"
                        : "#e3e6ee"
                    }
                    stroke={c.isTarget ? "#6d5bd0" : "#cfd5e2"}
                    strokeWidth={c.isTarget ? "1.15" : "0.7"}
                  />
                ))}
              </g>

              {mapData.targetPoint && (
                <g
                  transform={`translate(${mapData.targetPoint[0]}, ${mapData.targetPoint[1]})`}
                >
                  {pinState !== "idle" && (
                    <circle
                      r="17"
                      fill="none"
                      stroke={ringColor}
                      strokeWidth="1.6"
                      className="map-pin-ring"
                    />
                  )}
                  <circle
                    r="5"
                    fill={pinColor}
                    stroke="#ffffff"
                    strokeWidth="2"
                  />

                  {(() => {
                    const calloutTitle = target.label;
                    const calloutSub = exitIp?.ip || activeNode?.server || "待配置节点";
                    const boxWidth = compact
                      ? Math.min(144, Math.max(106, Math.max(calloutTitle.length * 10, calloutSub.length * 6.2) + 20))
                      : Math.min(126, Math.max(66, calloutTitle.length * 11 + 20));
                    const boxHeight = compact ? 36 : 24;
                    const px = mapData.targetPoint[0];
                    const py = mapData.targetPoint[1];
                    const flipLeft = px + boxWidth + 32 > width;
                    const tx = flipLeft ? -(boxWidth + 24) : 28;
                    const ty = Math.max(10 - py, -36);

                    const stemX = tx < 0 ? tx + boxWidth : tx;
                    const stemY = ty + boxHeight / 2;

                    return (
                      <g>
                        <line
                          x1="0"
                          y1="0"
                          x2={stemX}
                          y2={stemY}
                          stroke="#8f83df"
                          strokeWidth="1"
                        />
                        <g transform={`translate(${tx}, ${ty})`}>
                          <rect
                            x="0"
                            y="0"
                            width={boxWidth}
                            height={boxHeight}
                            rx="7"
                            fill="rgba(244, 241, 253, 0.96)"
                            stroke="#d6cff9"
                            strokeWidth="1"
                          />
                          {compact ? (
                            <>
                              <text
                                x="10"
                                y="14.5"
                                fontSize="10"
                                fontWeight="600"
                                fill="#1e1b4b"
                              >
                                {calloutTitle}
                              </text>
                              <text
                                x="10"
                                y="27.5"
                                fontSize="9.2"
                                fontFamily="var(--font-mono)"
                                fill="#4338ca"
                              >
                                {calloutSub}
                              </text>
                            </>
                          ) : (
                            <text
                              x={boxWidth / 2}
                              y="15.5"
                              textAnchor="middle"
                              fontSize="10"
                              fontWeight="600"
                              fill="#4338ca"
                            >
                              {calloutTitle.split("·").pop()?.trim() || calloutTitle}
                            </text>
                          )}
                        </g>
                      </g>
                    );
                  })()}
                </g>
              )}
            </svg>
          </div>
        </TooltipTrigger>
        <TooltipContent side="top" align="center">
          <div className="flex flex-col gap-1">
            <div className="flex items-center justify-between gap-4 font-semibold text-white">
              <span>{target.label}</span>
              <span className="mono-num text-[#a5b4fc]">{formatCoord(target.lat, target.lon)}</span>
            </div>
            <div className="flex flex-wrap gap-3 text-[0.68rem] text-[#d1d5db] mono-num">
              <span>IP: {exitIp?.ip || activeNode?.server || "--"}</span>
              {exitIp?.asn && <span>{exitIp.asn}</span>}
              {exitIp?.timezone && <span>{exitIp.timezone}</span>}
              {exitIp?.latencyMs !== undefined && <span>{exitIp.latencyMs} ms</span>}
            </div>
          </div>
        </TooltipContent>
      </Tooltip>

      {compact && (
        <div className="flex flex-wrap items-center gap-2 pt-0.5">
          <Badge variant="iris" className="font-medium py-1 px-2.5 rounded-lg">
            <MapPin className="h-3 w-3 text-[#6d5bd0]" aria-hidden="true" />
            {target.label}
          </Badge>
          <Badge variant="iris" className="font-medium mono-num py-1 px-2.5 rounded-lg">
            <Share2 className="h-3 w-3 text-[#6d5bd0]" aria-hidden="true" />
            {exitIp?.ip || activeNode?.server || "--"}
          </Badge>
          <Badge variant="iris" className="font-medium mono-num py-1 px-2.5 rounded-lg">
            <Activity className="h-3 w-3 text-[#6d5bd0]" aria-hidden="true" />
            延迟 {exitIp?.latencyMs ? `${exitIp.latencyMs} ms` : "--"}
          </Badge>
        </div>
      )}

      <figcaption className="visually-hidden">
        {`出口地理定位：${target.label}，${statusText}，坐标 ${formatCoord(target.lat, target.lon)}`}
      </figcaption>
    </figure>
  );
}
