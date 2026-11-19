import React from "react";

interface CrestProps {
  size?: number;
  className?: string;
  color?: string;
}

/**
 * Refined AI NetGuard crest combining a subtle security shield contour
 * with an editorial concave 4-point spark aligned with Claude's warm motif.
 */
export const ClaudeStarburst: React.FC<CrestProps> = ({
  size = 20,
  className,
  color = "currentColor",
}) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    className={className}
    aria-hidden="true"
  >
    <path
      d="M12 2.25C14.85 3.95 17.65 4.55 19.9 4.8C20.25 11.4 18.25 17.45 12 21.55C5.75 17.45 3.75 11.4 4.1 4.8C6.35 4.55 9.15 3.95 12 2.25Z"
      stroke={color}
      strokeWidth="1.65"
      strokeLinejoin="round"
    />
    <path
      d="M12 6.85C12.34 9.75 13.65 11.06 16.55 11.4C13.65 11.74 12.34 13.05 12 15.95C11.66 13.05 10.35 11.74 7.45 11.4C10.35 11.06 11.66 9.75 12 6.85Z"
      fill={color}
    />
    <circle cx="16.25" cy="7.45" r="0.95" fill={color} opacity="0.82" />
  </svg>
);

/**
 * Editorial precision telemetry meridian engraving used inside hero status bands.
 */
export const HeroAtelierBackdrop: React.FC = () => (
  <svg
    className="hero-backdrop-svg"
    viewBox="0 0 460 160"
    fill="none"
    preserveAspectRatio="xMaxYMid slice"
    aria-hidden="true"
  >
    <circle
      cx="372"
      cy="80"
      r="128"
      stroke="currentColor"
      strokeWidth="0.9"
      strokeDasharray="3 6"
    />
    <circle cx="372" cy="80" r="90" stroke="currentColor" strokeWidth="0.9" opacity="0.8" />
    <circle cx="372" cy="80" r="52" stroke="currentColor" strokeWidth="1" opacity="0.95" />
    <line x1="218" y1="80" x2="454" y2="80" stroke="currentColor" strokeWidth="0.7" opacity="0.45" />
    <line x1="372" y1="6" x2="372" y2="154" stroke="currentColor" strokeWidth="0.7" opacity="0.45" />
    <path
      d="M196 150 C 254 114, 308 118, 372 80 C 402 62, 424 34, 444 10"
      stroke="currentColor"
      strokeWidth="1.25"
    />
    <circle cx="372" cy="80" r="3.2" fill="currentColor" opacity="0.85" />
    <circle cx="282" cy="116" r="2.2" fill="currentColor" opacity="0.55" />
  </svg>
);
