import type { AccountQuotaConfig, AccountQuotaPool, AccountRecord } from "../types";

export interface EvaluatedQuotaPool {
  pool: AccountQuotaPool;
  effectivePct: number;
  isCooling: boolean;
  isRefilled: boolean;
  remainingMs: number;
  countdownText: string | null;
}

export interface EvaluatedExpiry {
  daysLeft: number;
  state: "expired" | "soon" | "ok";
  label: string;
}

export interface EvaluatedAccountQuota {
  enabled: boolean;
  planTier: string;
  expiry: EvaluatedExpiry | null;
  pools: EvaluatedQuotaPool[];
  hasAvailablePool: boolean;
  allExhausted: boolean;
  isExpiringSoonOrExpired: boolean;
}

export function createAntigravityQuotaPreset(): AccountQuotaConfig {
  return {
    enabled: true,
    planTier: "PRO",
    expiresAt: null,
    pools: [
      { id: "claude-gpt", label: "Claude / GPT", remainingPct: 100, resetHours: 5, resetAt: null },
      { id: "gemini-pro", label: "Gemini Pro", remainingPct: 100, resetHours: 5, resetAt: null },
      { id: "gemini-flash", label: "Gemini Flash", remainingPct: 100, resetHours: 5, resetAt: null },
    ],
  };
}

export function createClaudeQuotaPreset(): AccountQuotaConfig {
  return {
    enabled: true,
    planTier: "PRO",
    expiresAt: null,
    pools: [
      { id: "window-5h", label: "5h 窗口", remainingPct: 100, resetHours: 5, resetAt: null },
      { id: "weekly", label: "每周限额", remainingPct: 100, resetHours: 168, resetAt: null },
    ],
  };
}

export function createSingleQuotaPreset(): AccountQuotaConfig {
  return {
    enabled: true,
    planTier: "PRO",
    expiresAt: null,
    pools: [
      { id: "main", label: "主额度", remainingPct: 100, resetHours: 24, resetAt: null },
    ],
  };
}

export function formatCountdown(ms: number): string {
  if (ms <= 0) return "已就绪";
  const totalMinutes = Math.floor(ms / 60_000);
  if (totalMinutes < 1) return "<1m";
  const totalHours = Math.floor(totalMinutes / 60);
  const mins = totalMinutes % 60;
  if (totalHours >= 24) {
    const days = Math.floor(totalHours / 24);
    const hrs = totalHours % 24;
    return hrs > 0 ? `${days}d ${hrs}h` : `${days}d`;
  }
  if (totalHours > 0) {
    return mins > 0 ? `${totalHours}h ${mins}m` : `${totalHours}h`;
  }
  return `${mins}m`;
}

export function evaluateQuotaPool(
  pool: AccountQuotaPool,
  nowMs: number,
): EvaluatedQuotaPool {
  const clamped = Math.max(0, Math.min(100, Math.round(pool.remainingPct)));
  const resetStr = pool.resetAt?.trim() || "";
  if (resetStr) {
    const ts = Date.parse(resetStr);
    if (!Number.isNaN(ts)) {
      if (ts <= nowMs) {
        return {
          pool,
          effectivePct: 100,
          isCooling: false,
          isRefilled: clamped < 100,
          remainingMs: 0,
          countdownText: null,
        };
      }
      const remainingMs = ts - nowMs;
      return {
        pool,
        effectivePct: clamped,
        isCooling: true,
        isRefilled: false,
        remainingMs,
        countdownText: formatCountdown(remainingMs),
      };
    }
  }
  return {
    pool,
    effectivePct: clamped,
    isCooling: false,
    isRefilled: false,
    remainingMs: 0,
    countdownText: null,
  };
}

export function evaluateExpiry(
  expiresAt: string | null | undefined,
  nowMs: number,
): EvaluatedExpiry | null {
  const raw = expiresAt?.trim() || "";
  if (!raw) return null;
  const m = raw.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);
  let expDayMs: number;
  if (m) {
    expDayMs = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])).getTime();
  } else {
    const parsed = new Date(raw);
    if (Number.isNaN(parsed.getTime())) return null;
    expDayMs = new Date(
      parsed.getFullYear(),
      parsed.getMonth(),
      parsed.getDate(),
    ).getTime();
  }
  const now = new Date(nowMs);
  const todayMs = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const daysLeft = Math.round((expDayMs - todayMs) / 86_400_000);
  if (daysLeft < 0) {
    return { daysLeft, state: "expired", label: `已过期 ${Math.abs(daysLeft)} 天` };
  }
  if (daysLeft === 0) {
    return { daysLeft, state: "soon", label: "今日到期" };
  }
  if (daysLeft <= 7) {
    return { daysLeft, state: "soon", label: `剩 ${daysLeft} 天` };
  }
  return { daysLeft, state: "ok", label: `剩 ${daysLeft} 天` };
}

export function evaluateAccountQuota(
  acc: AccountRecord,
  nowMs: number,
): EvaluatedAccountQuota {
  const q = acc.quota;
  if (!q || !q.enabled || !Array.isArray(q.pools) || q.pools.length === 0) {
    return {
      enabled: false,
      planTier: q?.planTier?.trim() || "",
      expiry: evaluateExpiry(q?.expiresAt, nowMs),
      pools: [],
      hasAvailablePool: false,
      allExhausted: false,
      isExpiringSoonOrExpired: false,
    };
  }
  const pools = q.pools.map((p) => evaluateQuotaPool(p, nowMs));
  const hasAvailablePool = pools.some((p) => p.effectivePct > 0);
  const allExhausted = pools.every((p) => p.effectivePct <= 0);
  const expiry = evaluateExpiry(q.expiresAt, nowMs);
  const isExpiringSoonOrExpired =
    expiry !== null && (expiry.state === "expired" || expiry.state === "soon");

  return {
    enabled: true,
    planTier: q.planTier?.trim() || "",
    expiry,
    pools,
    hasAvailablePool,
    allExhausted,
    isExpiringSoonOrExpired,
  };
}

export function hasFutureResetTimer(acc: AccountRecord, nowMs: number): boolean {
  if (!acc.quota?.enabled) return false;
  return acc.quota.pools.some((p) => {
    const raw = p.resetAt?.trim();
    if (!raw) return false;
    const ts = Date.parse(raw);
    return !Number.isNaN(ts) && ts > nowMs;
  });
}

export function isoToLocalDatetimeInput(iso?: string | null): string {
  const raw = iso?.trim();
  if (!raw) return "";
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function localDatetimeInputToIso(val: string): string | null {
  const trimmed = val.trim();
  if (!trimmed) return null;
  const d = new Date(trimmed);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}
