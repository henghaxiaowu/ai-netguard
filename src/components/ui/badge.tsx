import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[0.69rem] font-semibold leading-tight whitespace-nowrap tabular border transition-colors",
  {
    variants: {
      variant: {
        success:
          "bg-[#ecfdf3] text-[#15803d] border-[#bbf7d0]",
        iris:
          "bg-[#f0edfc] text-[#5b48c4] border-[#dcd4fb]",
        neutral:
          "bg-[#f3f4f6] text-[#4b5563] border-[#e5e7eb]",
        warning:
          "bg-[#fffbeb] text-[#92400e] border-[#fde68a]",
        danger:
          "bg-[#fef2f2] text-[#dc2626] border-[#fecaca]",
        obsidian:
          "bg-[#111827] text-[#f9fafb] border-[#1f2937]",
      },
    },
    defaultVariants: {
      variant: "neutral",
    },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <span className={cn(badgeVariants({ variant, className }))} {...props} />
  );
}
