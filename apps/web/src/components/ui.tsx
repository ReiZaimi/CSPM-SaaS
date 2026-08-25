import type { ReactNode } from "react";
import { cn, levelStyle, label } from "@/lib/format";

export function Badge({
  level,
  children,
  className,
}: {
  level: string;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium",
        levelStyle(level),
        className,
      )}
    >
      {children ?? label(level)}
    </span>
  );
}

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
            : "bg-stone-100 text-stone-700 border-stone-200";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium",
        tone,
      )}
    >
      {label(status)}
    </span>
  );
}

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
    <section
      className={cn("rounded-xl border border-stone-200 bg-white shadow-sm", className)}
    >
      {(title || action) && (
        <header className="flex items-start justify-between gap-4 border-b border-stone-100 px-5 py-4">
          <div>
            {title && <h2 className="text-sm font-semibold text-stone-900">{title}</h2>}
            {subtitle && <p className="mt-1 text-xs text-stone-500">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      <div className="px-5 py-4">{children}</div>
    </section>
  );
}

export function Button({
  children,
  variant = "primary",
  className,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
}) {
  const variants = {
    primary: "bg-stone-900 text-white hover:bg-stone-800 disabled:bg-stone-300",
    secondary:
      "bg-white text-stone-800 border border-stone-300 hover:bg-stone-50 disabled:text-stone-400",
    ghost: "text-stone-600 hover:bg-stone-100 hover:text-stone-900",
    danger: "bg-critical text-white hover:bg-red-800",
  };
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium",
        "transition-colors disabled:cursor-not-allowed",
        variants[variant],
        className,
      )}
      {...props}
    >
      {children}
    </button>
  );
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
      <span className="mb-1.5 block text-sm font-medium text-stone-700">{text}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-stone-500">{hint}</span>}
    </label>
  );
}

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={cn(
        "w-full rounded-lg border border-stone-300 px-3 py-2 text-sm",
        "focus:border-stone-500 focus:outline-none focus:ring-1 focus:ring-stone-500",
        props.className,
      )}
    />
  );
}

export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      {...props}
      className={cn(
        "rounded-lg border border-stone-300 bg-white px-3 py-2 text-sm",
        "focus:border-stone-500 focus:outline-none focus:ring-1 focus:ring-stone-500",
        props.className,
      )}
    />
  );
}

export function EmptyState({ title, detail, action }: {
  title: string;
  detail?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-stone-300 bg-white px-6 py-14 text-center">
      <p className="text-sm font-medium text-stone-700">{title}</p>
      {detail && <p className="mt-1 max-w-md text-sm text-stone-500">{detail}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function Spinner({ text }: { text?: string }) {
  return (
    <div className="flex items-center gap-3 px-1 py-8 text-sm text-stone-500">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-stone-300 border-t-stone-600" />
      {text}
    </div>
  );
}

export function ErrorNote({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="rounded-lg border border-critical-border bg-critical-bg px-4 py-3 text-sm text-critical">
      <p>{message}</p>
      {onRetry && (
        <button onClick={onRetry} className="mt-2 font-medium underline underline-offset-2">
          Try again
        </button>
      )}
    </div>
  );
}
