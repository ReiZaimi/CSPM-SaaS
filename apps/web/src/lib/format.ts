import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { Level } from "./types";

export const cn = (...inputs: ClassValue[]) => twMerge(clsx(inputs));

/**
 * Severity colours, defined once.
 *
 * UNKNOWN gets its own visual treatment rather than borrowing LOW's. Making a
 * gap in knowledge look like a clean result is the single most misleading thing
 * a security dashboard can do.
 */
const LEVEL_STYLES: Record<Level, string> = {
  CRITICAL: "bg-critical-bg text-critical border-critical-border",
  HIGH: "bg-high-bg text-high border-high-border",
  MEDIUM: "bg-medium-bg text-medium border-medium-border",
  LOW: "bg-low-bg text-low border-low-border",
  UNKNOWN: "bg-unknown-bg text-unknown border-unknown-border border-dashed",
};

export const levelStyle = (level: string) =>
  LEVEL_STYLES[(level as Level) ?? "UNKNOWN"] ?? LEVEL_STYLES.UNKNOWN;

export function scoreColor(score: number): string {
  if (score >= 85) return "text-ok";
  if (score >= 60) return "text-medium";
  if (score >= 40) return "text-high";
  return "text-critical";
}

export const STATUS_LABELS: Record<string, string> = {
  OPEN: "Open",
  IN_PROGRESS: "In progress",
  RESOLVED: "Verified fixed",
  ACCEPTED_RISK: "Risk accepted",
  FALSE_POSITIVE: "False positive",
  QUEUED: "Queued",
  DISCOVERING: "Discovering resources",
  NORMALIZING: "Normalizing",
  EVALUATING: "Running security rules",
  CALCULATING_RISK: "Calculating risk",
  COMPLETED: "Completed",
  PARTIAL: "Completed with gaps",
  FAILED: "Failed",
  CANCELLED: "Cancelled",
  TODO: "To do",
  DONE: "Done",
};

export const label = (value: string) =>
  STATUS_LABELS[value] ??
  value.replace(/_/g, " ").toLowerCase().replace(/^./, (c) => c.toUpperCase());

export function formatDate(value: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export function formatDateTime(value: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatEffort(minutes: number): string {
  if (minutes < 60) return `${minutes} min`;
  const hours = minutes / 60;
  if (hours < 8) return `${hours % 1 === 0 ? hours : hours.toFixed(1)} hr`;
  return `${Math.round(hours / 8)} day${hours >= 16 ? "s" : ""}`;
}

export const resourceTypeLabel = (type: string) =>
  type.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
