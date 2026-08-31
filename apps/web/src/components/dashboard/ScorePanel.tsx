import { Suspense, lazy } from "react";

import type { PostureReading } from "@/lib/types";
import { ScoreDelta } from "@/components/ScoreDelta";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, formatDateTime } from "@/lib/format";

/**
 * The chart, fetched after the panel it sits in.
 *
 * Recharts is by a wide margin the largest thing this app ships and it draws
 * one line on one screen. Loaded inline it made the score — the part somebody
 * came for — wait on a library that only decorates it.
 */
const ScoreTrend = lazy(() =>
  import("@/components/ScoreTrend").then((m) => ({ default: m.ScoreTrend })),
);

/** What a score *means*, so the number is not left to speak for itself. */
function band(score: number): { label: string; tone: string; bar: string } {
  if (score >= 85) return { label: "Good", tone: "text-ok", bar: "bg-ok" };
  if (score >= 60)
    return { label: "Needs attention", tone: "text-medium", bar: "bg-medium" };
  if (score >= 40) return { label: "Poor", tone: "text-high", bar: "bg-high" };
  return { label: "Critical", tone: "text-critical", bar: "bg-critical" };
}

/**
 * The dashboard's anchor: where the posture stands, and which way it is going.
 *
 * One panel rather than two cards, because they are one thought — a score
 * without its direction is a number somebody has to remember last week's value
 * to use. The score keeps the visual weight and the trend sits beside it as
 * context, which is the ranking a reader actually needs: *what* first, *since
 * when* second.
 *
 * The meter is a bar, not a gauge. A radial gauge spends a 150px square to
 * encode one fraction and reads as a speedometer; a bar encodes the same
 * fraction in a fifth of the space and leaves the digits as the loudest thing
 * on the page, which is what they should be.
 */
export function ScorePanel({
  score,
  delta,
  history,
  scannedAt,
}: {
  score: number;
  delta: number | null;
  history: PostureReading[];
  scannedAt: string | null;
}) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const { label, tone, bar } = band(clamped);

  return (
    <section
      aria-labelledby="posture-score"
      className="grid gap-px overflow-hidden rounded-xl bg-border ring-1 ring-foreground/10 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]"
    >
      <div className="flex flex-col justify-between gap-5 bg-card p-5">
        <div>
          <h2
            id="posture-score"
            className="text-xs font-medium uppercase tracking-wider text-muted-foreground"
          >
            Security score
          </h2>

          <div className="mt-3 flex items-baseline gap-2">
            <span
              className={cn(
                "text-6xl font-semibold leading-none tracking-tight tabular-nums",
                tone,
              )}
            >
              {clamped}
            </span>
            <span className="text-xl text-muted-foreground">/ 100</span>
          </div>

          <p className={cn("mt-2 text-sm font-medium", tone)}>{label}</p>
        </div>

        <div className="flex flex-col gap-3">
          <div
            className="h-1.5 w-full overflow-hidden rounded-full bg-muted"
            role="meter"
            aria-valuenow={clamped}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="Security score"
          >
            <div
              className={cn(
                "h-full rounded-full transition-[width] duration-700 ease-out",
                bar,
              )}
              style={{ width: `${clamped}%` }}
            />
          </div>

          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
            <ScoreDelta delta={delta} />
            {scannedAt && (
              <>
                <span aria-hidden>·</span>
                <span>assessed {formatDateTime(scannedAt)}</span>
              </>
            )}
          </div>

          <p className="text-xs leading-relaxed text-muted-foreground">
            Deducted against each finding's risk band — what it means on the
            asset it was found on — not the number of alerts raised.
          </p>
        </div>
      </div>

      <div className="flex flex-col gap-3 bg-card p-5">
        <h3 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
          Posture trend
        </h3>
        {/* Sized to the chart it replaces, so nothing moves under the reader
            when the line arrives. */}
        <Suspense fallback={<Skeleton className="h-40 w-full" />}>
          <ScoreTrend history={history} />
        </Suspense>
      </div>
    </section>
  );
}
