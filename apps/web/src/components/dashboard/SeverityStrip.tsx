import { Link } from "react-router-dom";

import type { PostureReading } from "@/lib/types";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Sparkline } from "@/components/charts/Sparkline";
import { useCountUp } from "@/lib/motion";
import { cn } from "@/lib/format";

const LEVELS = [
  { level: "CRITICAL", label: "Critical", tone: "var(--sev-critical)" },
  { level: "HIGH", label: "High", tone: "var(--sev-high)" },
  { level: "MEDIUM", label: "Medium", tone: "var(--sev-medium)" },
  { level: "LOW", label: "Low", tone: "var(--sev-low)" },
] as const;

/**
 * What is open, by how serious it is on the asset it was found on — and which
 * way each of those has been moving.
 *
 * A strip rather than four cards. These are one measurement split four ways,
 * and giving each its own bordered box makes the reader compare containers
 * before they compare numbers.
 *
 * The line under each count comes from the posture history the dashboard
 * already returns and previously rendered nowhere. It is the difference between
 * "one critical" and "one critical, and there were none last week" — the same
 * number, and a different Monday.
 *
 * UNKNOWN sits at the end and is not a fifth severity: it is the count of
 * checks that reached no verdict, which is a different kind of fact and links
 * somewhere different. It is here rather than further down because a reader
 * tallying what is wrong must see what could not be answered in the same
 * glance. UNKNOWN is never a pass.
 */
export function SeverityStrip({
  counts,
  unknown,
  history = [],
}: {
  counts: Record<string, number>;
  unknown: number;
  history?: PostureReading[];
}) {
  return (
    <section
      aria-label="Open findings by severity"
      className="grid grid-cols-2 gap-px overflow-hidden rounded-xl bg-border ring-1 ring-foreground/10 sm:grid-cols-3 lg:grid-cols-5"
    >
      {LEVELS.map(({ level, label, tone }) => (
        <Tile
          key={level}
          to={`/findings?severity=${level}`}
          badge={<SeverityBadge level={level} size="sm">{label}</SeverityBadge>}
          value={counts[level] ?? 0}
          series={history.map(
            (reading) => reading.findings_by_severity?.[level] ?? 0,
          )}
          seriesLabel={`${label} findings`}
          tone={tone}
        />
      ))}

      <Tile
        to="/scans"
        badge={
          <SeverityBadge level="UNKNOWN" size="sm">
            No verdict
          </SeverityBadge>
        }
        value={unknown}
        series={[]}
        seriesLabel="Checks that reached no verdict"
        tone="var(--sev-unknown)"
      />
    </section>
  );
}

/** Three readings, and at least two different values. */
function hasShape(series: number[]): boolean {
  return series.length > 2 && new Set(series).size > 1;
}

function Tile({
  to,
  badge,
  value,
  series,
  seriesLabel,
  tone,
}: {
  to: string;
  badge: React.ReactNode;
  value: number;
  series: number[];
  seriesLabel: string;
  tone: string;
}) {
  const shown = Math.round(useCountUp(value));

  return (
    <Link
      to={to}
      className={cn(
        "group flex flex-col gap-2 bg-card px-4 py-3.5 transition-colors hover:bg-accent/50",
        "focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50",
      )}
    >
      <span className="self-start">{badge}</span>
      <div className="flex items-end justify-between gap-3">
        {/* A zero is not an alarm: muted, so the eye lands on the counts that
            have something in them. */}
        <span
          className={cn(
            "text-3xl font-semibold leading-none tabular-nums",
            value === 0 && "text-muted-foreground/60",
          )}
        >
          {shown}
        </span>
        {/* Only when there is a shape to show. Two readings of the same number
            is a straight line that says nothing, and a line that says nothing
            in a security dashboard is worse than no line: a reader learns to
            skip the place trends live. */}
        {hasShape(series) && (
          <Sparkline
            values={series}
            label={seriesLabel}
            tone={tone}
            className="h-6 w-20 opacity-70 transition-opacity group-hover:opacity-100"
          />
        )}
      </div>
    </Link>
  );
}
