import { Link } from "react-router-dom";

import { SeverityBadge } from "@/components/security/SeverityBadge";
import { cn } from "@/lib/format";

const LEVELS = [
  { level: "CRITICAL", label: "Critical" },
  { level: "HIGH", label: "High" },
  { level: "MEDIUM", label: "Medium" },
  { level: "LOW", label: "Low" },
] as const;

/**
 * What is open, by how serious it is on the asset it was found on.
 *
 * A strip rather than four cards. These are one measurement split four ways,
 * and giving each its own bordered box makes the reader compare containers
 * before they compare numbers.
 *
 * UNKNOWN sits at the end and is not a fifth severity — it is the count of
 * checks that reached no verdict, which is a different kind of fact and links
 * somewhere different. It is here rather than hidden with the coverage
 * detail because a reader counting problems must see the checks that could not
 * be answered in the same glance; UNKNOWN is never a pass.
 */
export function SeverityStrip({
  counts,
  unknown,
}: {
  counts: Record<string, number>;
  unknown: number;
}) {
  return (
    <section
      aria-label="Open findings by severity"
      className="grid grid-cols-2 gap-px overflow-hidden rounded-xl bg-border ring-1 ring-foreground/10 sm:grid-cols-3 lg:grid-cols-5"
    >
      {LEVELS.map(({ level, label }) => {
        const value = counts[level] ?? 0;
        return (
          <Link
            key={level}
            to={`/findings?severity=${level}`}
            className={cn(
              "group flex flex-col gap-2 bg-card px-4 py-3.5 transition-colors hover:bg-accent/50",
              "focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50",
            )}
          >
            <SeverityBadge level={level} size="sm">
              {label}
            </SeverityBadge>
            {/* A zero is not an alarm: muted, so the eye lands on the counts
                that have something in them. */}
            <span
              className={cn(
                "text-3xl font-semibold leading-none tabular-nums",
                value === 0 && "text-muted-foreground/60",
              )}
            >
              {value}
            </span>
          </Link>
        );
      })}

      <Link
        to="/scans"
        className={cn(
          "group flex flex-col gap-2 bg-card px-4 py-3.5 transition-colors hover:bg-accent/50",
          "focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50",
        )}
      >
        <SeverityBadge level="UNKNOWN" size="sm">
          No verdict
        </SeverityBadge>
        <span
          className={cn(
            "text-3xl font-semibold leading-none tabular-nums",
            unknown === 0 && "text-muted-foreground/60",
          )}
        >
          {unknown}
        </span>
      </Link>
    </section>
  );
}
