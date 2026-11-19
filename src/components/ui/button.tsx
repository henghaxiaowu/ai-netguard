import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-lg font-medium transition-[background-color,border-color,color,box-shadow,transform] duration-150 motion-safe:active:scale-[0.985] disabled:pointer-events-none disabled:opacity-45 cursor-pointer select-none focus-visible:outline-2 focus-visible:outline-[#5b48c4] focus-visible:outline-offset-2",
  {
    variants: {
      variant: {
        solid:
          "bg-[#6d5bd0] text-white border border-[#5b48c4] shadow-[0_1px_2px_rgba(91,72,196,0.28)] hover:bg-[#5f4dc4]",
        soft:
          "bg-[#f0edfc] text-[#5b48c4] border border-[#dcd4fb] hover:bg-[#e6e0fb] hover:border-[#c8bcf9]",
        outline:
          "bg-white text-[#111827] border border-[#dce0e6] shadow-[0_1px_2px_rgba(15,23,42,0.04)] hover:bg-[#f8f9fb] hover:border-[#cfd5de]",
        destructive:
          "bg-[#fef2f2] text-[#dc2626] border border-[#fecaca] hover:bg-[#fee2e2] hover:border-[#fca5a5]",
        "destructive-outline":
          "bg-white text-[#dc2626] border border-[#fecaca] hover:bg-[#fef2f2] hover:border-[#fca5a5]",
        emerald:
          "bg-[#16a34a] text-white border border-[#15803d] shadow-[0_1px_2px_rgba(22,163,74,0.25)] hover:bg-[#15803d]",
        ghost:
          "bg-transparent text-[#525866] border border-transparent hover:bg-[#f3f4f6] hover:text-[#111827]",
      },
      size: {
        default: "min-h-8 px-3 py-1.5 text-[0.765rem]",
        sm: "min-h-7 px-2.5 py-1 text-[0.725rem]",
        xs: "min-h-6 px-2 py-0.5 text-[0.7rem] rounded-md",
        icon: "h-7 w-7 p-0",
      },
    },
    defaultVariants: {
      variant: "outline",
      size: "default",
    },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, type = "button", ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  ),
);
Button.displayName = "Button";
