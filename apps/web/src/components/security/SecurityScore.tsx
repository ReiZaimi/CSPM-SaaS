import { ScoreDelta } from "@/components/ScoreDelta";
import { cn, formatDateTime, scoreColor } from "@/lib/format";

/** What a score *means*, so the number is not left to speak for itself. */
function band(score: number): { label: string; tone: string } {
  if (score >= 85) return { label: "Good", tone: "text-ok" };
  if (score >= 60) return { label: "Needs attention", tone: "text-medium" };
  if (score >= 40) return { label: "Poor", tone: "text-high" };
  return { label: "Critical", tone: "text-critical" };
}

/**
 * The headline number, and everything a reader needs to trust it.
 *
 * A bare `82` invites exactly two questions -- out of what, and since when --
 * and the old panel answered neither without the reader hunting. The score, the
 * scale, the band, the movement and the age of the reading are one block
 * because they are one thought.
 *
 * A horizontal meter rather than the old circular gauge. The gauge spent 150px
 * square to encode a single fraction, and its arc was the largest object on the
 * dashboard -- above the findings it is a summary *of*.
 */
export function SecurityScore({
  score,
  delta,
  scannedAt,
  className,
}: {
  score: number;
  delta?: number | null;
  scannedAt?: string | null;
  className?: string;
}) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const { label: bandLabel, tone } = band(clamped);

  return (
    <div className={cn("flex flex-col gap-3", className)}>
      <div className="flex items-baseline gap-2">
        <span className={cn("text-5xl font-semibold leading-none tabular-nums", tone)}>
          {clamped}
        </span>
        <span className="text-lg text-muted-foreground">/ 100</span>
        <span className={cn("ml-1 text-sm font-medium", tone)}>{bandLabel}</span>
      </div>

      {/* The proportion, given before the digits are finished being read. */}
      <div
        className="h-2 w-full overflow-hidden rounded-full bg-muted"
        role="meter"
        aria-valuenow={clamped}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Security score"
      >
        <div
          className={cn("h-full rounded-full transition-[width] duration-700 ease-out", {
            "bg-ok": clamped >= 85,
            "bg-medium": clamped >= 60 && clamped < 85,
            "bg-high": clamped >= 40 && clamped < 60,
            "bg-critical": clamped < 40,
          })}
          style={{ width: `${clamped}%` }}
        />
      </div>

      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
        <ScoreDelta delta={delta ?? null} />
        {scannedAt && (
          <>
            <span aria-hidden>·</span>
            <span>Last assessed {formatDateTime(scannedAt)}</span>
          </>
        )}
      </div>
    </div>
  );
}

/**
 * A finding's risk score, sized so it can lead a row or sit inside a sentence.
 *
 * Coloured by band rather than always neutral: the number is the ranking, and a
 * list of identical grey numbers makes the reader do the comparison themselves.
 */
export function RiskScore({
  score,
  size = "default",
  className,
}: {
  score: number | null;
  size?: "default" | "lg";
  className?: string;
}) {
  if (score === null) {
    return <span className={cn("text-muted-foreground tabular-nums", className)}>—</span>;
  }
  const value = Math.round(score);
  return (
    <span
      className={cn(
        "font-semibold tabular-nums",
        size === "lg" ? "text-3xl" : "text-sm",
        scoreColor(100 - value),
        className,
      )}
    >
      {value}
    </span>
  );
}
