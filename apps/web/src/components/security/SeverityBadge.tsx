import type { ReactNode } from "react";
import { AlertTriangleIcon, HelpCircleIcon } from "lucide-react";

import { cn, label, levelStyle } from "@/lib/format";

/**
 * Severity, in the one visual language the whole product speaks.
 *
 * Not `Badge` from the shadcn set, and that is deliberate rather than an
 * oversight. That component's variants are about *chrome* -- default, secondary,
 * destructive -- and a security severity is not chrome: `destructive` means
 * "this button deletes something", while CRITICAL means "an attacker can reach
 * your data". Rendering both through one component would eventually make a
 * cancel button and a public storage account the same colour.
 */
export function SeverityBadge({
  level,
  children,
  className,
  size = "default",
}: {
  level: string;
  children?: ReactNode;
  className?: string;
  size?: "default" | "sm";
}) {
  const unknown = level?.toUpperCase() === "UNKNOWN";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border font-medium whitespace-nowrap",
        size === "sm" ? "px-1.5 py-0 text-[11px]" : "px-2 py-0.5 text-xs",
        levelStyle(level),
        className,
      )}
    >
      {/* UNKNOWN carries a mark as well as a colour. Someone who cannot
          separate the hues still has to be able to tell "we could not look"
          from "we looked and it was fine" -- that distinction is the product's
          whole claim to honesty, and colour alone would hide it from them. */}
      {unknown && <HelpCircleIcon className="size-3 shrink-0" aria-hidden />}
      {children ?? label(level)}
    </span>
  );
}

/**
 * The UNKNOWN state, said in full.
 *
 * Used where there is room for a sentence rather than a badge. A security
 * product that renders "we could not tell" as a quiet grey pill has technically
 * disclosed it; this makes it something the reader actually stops on.
 */
export function UnknownNote({
  reason,
  className,
}: {
  reason?: string | null;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex items-start gap-2.5 rounded-lg border border-dashed border-unknown-border bg-unknown-bg px-3 py-2.5",
        className,
      )}
    >
      <AlertTriangleIcon className="mt-0.5 size-4 shrink-0 text-unknown" aria-hidden />
      <div className="min-w-0 text-sm">
        <p className="font-medium text-unknown">Not enough evidence to judge this</p>
        <p className="mt-0.5 text-muted-foreground">
          {reason ??
            "CloudGuard could not collect what this check reads, so it has no verdict — this is neither a pass nor a failure."}
        </p>
      </div>
    </div>
  );
}
