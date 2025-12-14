import * as React from "react";
import { cn } from "@/lib/utils"; // if you have cn helper; otherwise remove cn usage

export const Input = React.forwardRef<
  HTMLInputElement,
  React.InputHTMLAttributes<HTMLInputElement>
>(({ className, ...props }, ref) => {
  return (
    <input
      ref={ref}
      className={cn(
        "flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm",
        className
      )}
      {...props}
    />
  );
});

Input.displayName = "Input";
