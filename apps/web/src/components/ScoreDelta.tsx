import { useT } from "@/i18n";

/**
 * Movement since the previous reading.
 *
 * Four states, not two, and the distinctions are the point. The delta used to
 * be an estimate that reconstructed a prior score by adding back every fix ever
 * verified, so it could only ever be positive — and this rendered a green up
 * arrow unconditionally. Measuring it against the previous reading makes a
 * decline possible for the first time, at which point a hard-coded ↑ is a plain
 * untruth about the direction a customer's posture moved.
 *
 * "No previous scan" is kept separate from "no change" because they are
 * different facts: one is a comparison that could not be made, the other a
 * comparison that came out level.
 *
 * In its own module rather than beside `ScoreTrend`, and that is a bundling
 * decision rather than tidiness. This is a sentence and an arrow; that one
 * imports Recharts. While they shared a file, every page reaching for a delta
 * pulled the whole charting library behind it -- which is how 396 kB of chart
 * code ended up on the findings list, a page with no chart on it.
 */
export function ScoreDelta({ delta }: { delta: number | null }) {
  const t = useT();

  if (delta === null) {
    return <p className="mt-1 text-xs text-muted-foreground">{t.dashboard.noPreviousScan}</p>;
  }
  if (delta === 0) {
    return <p className="mt-1 text-xs text-muted-foreground">No change since last scan</p>;
  }

  const improved = delta > 0;
  return (
    <p
      className={
        improved
          ? "mt-1 inline-flex items-center gap-1 rounded-full bg-ok-bg px-2.5 py-1 text-xs font-medium text-ok"
          : "mt-1 inline-flex items-center gap-1 rounded-full bg-critical-bg px-2.5 py-1 text-xs font-medium text-critical"
      }
    >
      <span aria-hidden="true">{improved ? "\u2191" : "\u2193"}</span>{" "}
      {Math.abs(delta)}{" "}
      {improved ? t.dashboard.sinceLastScan : t.dashboard.scoreWorse}
    </p>
  );
}
