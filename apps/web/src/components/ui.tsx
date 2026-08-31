/**
 * The seam between CloudGuard's own vocabulary and the shadcn primitives.
 *
 * Every page in this product imports from here, and did so before shadcn/ui
 * existed in the tree. Rewriting twenty pages and swapping the component
 * library underneath them in one move would have made a regression in either
 * impossible to attribute to the other -- so this module keeps its old shape
 * and answers it with the new components.
 *
 * What stays here permanently is the *security* vocabulary: `Badge` takes a
 * severity, not a variant, and `StatusPill` knows that a verified fix and an
 * accepted risk are different kinds of closed. Those are product decisions and
 * do not belong in a vendored primitive. Everything else is a thin pass-through
 * and should be imported from `@/components/ui/*` directly in new code.
 */
import type { ReactNode } from "react";

import { Button as ShadButton } from "@/components/ui/button";
import { Input as ShadInput } from "@/components/ui/input";
import {
  Select as ShadSelect,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Card as ShadCard, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { EmptyState as SharedEmptyState, ErrorState } from "@/components/common/states";
import { cn, label } from "@/lib/format";

export { SeverityBadge as Badge };
export { SharedEmptyState as EmptyState };

/**
 * A finding or scan's state.
 *
 * Not the severity scale, and the separation is load-bearing: RESOLVED here
 * means *a scan observed the fix*, while ACCEPTED_RISK means a person decided
 * to live with it. Rendering the second as a success would let a dashboard
 * report risk that was waved through as risk that was fixed.
 */
export function StatusPill({ status }: { status: string }) {
  const tone =
    status === "RESOLVED" || status === "COMPLETED" || status === "DONE"
      ? "bg-ok-bg text-ok border-ok-border"
      : status === "FAILED"
        ? "bg-critical-bg text-critical border-critical-border"
        : status === "PARTIAL"
          ? "bg-medium-bg text-medium border-medium-border"
          : status === "ACCEPTED_RISK"
            ? "bg-unknown-bg text-unknown border-unknown-border"
            : "bg-muted text-muted-foreground border-border";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        tone,
      )}
    >
      {label(status)}
    </span>
  );
}

/**
 * The old card API, over shadcn's composed one.
 *
 * Kept because ~20 call sites pass `title`/`subtitle`/`action` as props. New
 * code should compose `CardHeader`/`CardTitle`/`CardContent` directly, which is
 * what the shadcn rules ask for and what gives a card a footer.
 */
export function Card({
  children,
  className,
  title,
  subtitle,
  action,
}: {
  children: ReactNode;
  className?: string;
  title?: ReactNode;
  subtitle?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <ShadCard className={className}>
      {(title || action) && (
        <CardHeader>
          {title && <CardTitle>{title}</CardTitle>}
          {subtitle && <CardDescription>{subtitle}</CardDescription>}
          {action && <div className="col-start-2 row-span-2 row-start-1 self-start justify-self-end">{action}</div>}
        </CardHeader>
      )}
      <CardContent className={title || action ? undefined : "pt-6"}>{children}</CardContent>
    </ShadCard>
  );
}

/** The old variant names, mapped onto shadcn's. */
export function Button({
  variant = "primary",
  ...props
  // ``Omit`` rather than an intersection: intersecting two ``variant`` unions
  // leaves only their overlap, which silently drops every name this shim
  // exists to translate.
}: Omit<React.ComponentProps<typeof ShadButton>, "variant"> & {
  variant?: "primary" | "secondary" | "ghost" | "danger" | "outline" | "link";
}) {
  const mapped = {
    primary: "default",
    secondary: "outline",
    ghost: "ghost",
    danger: "destructive",
    outline: "outline",
    link: "link",
  } as const;
  return <ShadButton variant={mapped[variant] ?? "default"} {...props} />;
}

export function Field({
  label: text,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-sm font-medium text-foreground">{text}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-muted-foreground">{hint}</span>}
    </label>
  );
}

export function Input(props: React.ComponentProps<typeof ShadInput>) {
  return <ShadInput {...props} />;
}

/**
 * A native `select`, still.
 *
 * shadcn's `Select` is a listbox with its own open state, and swapping it in
 * here would change the API every call site uses (`value` + `onChange` with an
 * event) into one they do not pass. The pages that need the richer control
 * compose it directly; this keeps the plain ones working and styled.
 */
export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      {...props}
      className={cn(
        "h-9 rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs",
        "focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none",
        "disabled:cursor-not-allowed disabled:opacity-50",
        props.className,
      )}
    />
  );
}

export { ShadSelect, SelectContent, SelectItem, SelectTrigger, SelectValue };

/**
 * Retained for the handful of places where a page is genuinely waiting on an
 * action rather than loading a view -- a button mid-submit, a scan being
 * queued. Anything rendering a *page* should use a skeleton instead: a spinner
 * says "wait", and a skeleton says what is coming.
 */
export function Spinner({ text }: { text?: string }) {
  return (
    <div className="flex items-center gap-3 py-8 text-sm text-muted-foreground">
      <span className="size-4 animate-spin rounded-full border-2 border-muted border-t-foreground" />
      {text}
    </div>
  );
}

export function LoadingRows({ rows = 4 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-2">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-10 w-full" />
      ))}
    </div>
  );
}

export function ErrorNote({
  message,
  onRetry,
  impact,
}: {
  message: string;
  onRetry?: () => void;
  impact?: ReactNode;
}) {
  return <ErrorState title={message} impact={impact} onRetry={onRetry} />;
}
