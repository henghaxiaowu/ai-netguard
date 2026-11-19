import * as React from "react";
import * as SwitchPrimitive from "@radix-ui/react-switch";
import { cn } from "@/lib/utils";

interface SwitchProps
  extends React.ComponentPropsWithoutRef<typeof SwitchPrimitive.Root> {
  size?: "default" | "sm";
}

export const Switch = React.forwardRef<
  React.ElementRef<typeof SwitchPrimitive.Root>,
  SwitchProps
>(({ className, size = "default", ...props }, ref) => (
  <SwitchPrimitive.Root
    ref={ref}
    className={cn(
      "peer inline-flex shrink-0 cursor-pointer items-center rounded-full border border-transparent p-0.5 transition-colors duration-150 focus-visible:outline-2 focus-visible:outline-[#5b48c4] focus-visible:outline-offset-2 disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:bg-[#6d5bd0] data-[state=unchecked]:bg-[#d4d8df]",
      size === "sm" ? "h-[1.05rem] w-[1.85rem]" : "h-[1.35rem] w-[2.375rem]",
      className,
    )}
    {...props}
  >
    <SwitchPrimitive.Thumb
      className={cn(
        "pointer-events-none block rounded-full bg-white shadow-[0_1px_2px_rgba(15,23,42,0.24)] ring-0 transition-transform duration-150 data-[state=unchecked]:translate-x-0",
        size === "sm"
          ? "h-[0.8rem] w-[0.8rem] data-[state=checked]:translate-x-[0.8rem]"
          : "h-[1.05rem] w-[1.05rem] data-[state=checked]:translate-x-[1.02rem]",
      )}
    />
  </SwitchPrimitive.Root>
));
Switch.displayName = SwitchPrimitive.Root.displayName;
