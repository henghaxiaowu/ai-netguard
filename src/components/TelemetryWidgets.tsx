import { cn } from "@/lib/utils";

interface SparklineProps {
  samples: number[];
  tone?: "ok" | "warn" | "danger" | "idle";
}

/**
 * Vitaly-inspired inline telemetry sparkline driven strictly by observed RTT samples.
 */
export function LatencySparkline({ samples, tone = "ok" }: SparklineProps) {
  const stroke =
    tone === "danger"
      ? "#dc2626"
      : tone === "warn"
        ? "#d97706"
        : tone === "idle"
          ? "#9ca3af"
          : "#16a34a";

  if (samples.length < 2) {
    return (
      <svg width="56" height="22" viewBox="0 0 56 22" aria-hidden="true" className="shrink-0">
        <line
          x1="4"
          y1="12"
          x2="48"
          y2="12"
          stroke={samples.length === 1 ? stroke : "#cbd5e1"}
          strokeOpacity={samples.length === 1 ? "0.4" : "0.65"}
          strokeWidth="1.4"
          strokeDasharray="3 3"
        />
        {samples.length === 1 && <circle cx="51" cy="12" r="2.5" fill={stroke} />}
      </svg>
    );
  }

  const pts = samples.slice(-14);

  const min = Math.min(...pts);
  const max = Math.max(...pts);
  const span = Math.max(8, max - min);
  const coords = pts.map((v, i) => {
    const x = 3 + (i / (pts.length - 1)) * 50;
    const y = 18 - ((v - min) / span) * 13;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  const lastX = 53;
  const lastY = 18 - ((pts[pts.length - 1] - min) / span) * 13;

  return (
    <svg width="56" height="22" viewBox="0 0 56 22" aria-hidden="true" className="shrink-0">
      <polyline
        fill="none"
        stroke={stroke}
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
        points={coords.join(" ")}
      />
      <circle cx={lastX} cy={lastY} r="2.2" fill={stroke} />
    </svg>
  );
}

interface SegmentedMeterProps {
  total?: number;
  states?: Array<"pass" | "warn" | "fail" | "pending" | "active" | "idle">;
}

/**
 * MailPulse-inspired compact segmented block meter communicating count & ratio visually.
 */
export function SegmentedMeter({ total = 8, states }: SegmentedMeterProps) {
  const list =
    states && states.length > 0
      ? states.slice(0, total)
      : Array.from({ length: total }, () => "idle" as const);

  return (
    <div className="inline-flex items-center gap-[3px]" aria-hidden="true">
      {list.map((st, idx) => (
        <span
          key={idx}
          className={cn(
            "inline-block h-2.5 w-1.5 rounded-[2px] transition-colors",
            st === "pass" && "bg-[#16a34a]",
            st === "active" && "bg-[#6d5bd0]",
            st === "warn" && "bg-[#d97706]",
            st === "fail" && "bg-[#dc2626]",
            st === "pending" && "bg-[#d1d5db]",
            st === "idle" && "bg-[#e5e7eb]",
          )}
        />
      ))}
    </div>
  );
}
