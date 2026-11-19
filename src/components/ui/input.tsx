import * as React from "react";
import { cn } from "@/lib/utils";

export const Input = React.forwardRef<
  HTMLInputElement,
  React.InputHTMLAttributes<HTMLInputElement>
>(({ className, type = "text", ...props }, ref) => (
  <input
    ref={ref}
    type={type}
    className={cn(
      "flex min-h-8 w-full rounded-lg border border-[#dce0e6] bg-white px-2.5 py-1.5 text-[0.765rem] text-[#111827] shadow-[0_1px_1px_rgba(15,23,42,0.02)] placeholder:text-[#9ca3af] transition-colors hover:border-[#c3cad6] focus-visible:outline-2 focus-visible:outline-[#5b48c4] focus-visible:outline-offset-1 disabled:cursor-not-allowed disabled:opacity-50",
      className,
    )}
    {...props}
  />
));
Input.displayName = "Input";
