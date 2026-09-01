import { lazy, Suspense } from "react";

import type { Dashboard } from "@/lib/types";
import { Bars } from "@/components/charts/Bars";
import { DonutLegend, type Slice } from "@/components/charts/DonutLegend";
import { StackedBar } from "@/components/charts/StackedBar";
import { Skeleton } from "@/components/ui/skeleton";
import { label } from "@/lib/format";

/** Recharts is the largest thing this app ships; the ring waits for the page. */
const Donut = lazy(() =>
  import("@/components/charts/Donut").then((m) => ({ default: m.Donut })),
);

const SEVERITY_TONES: Record<string, string> = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
};

/**
 * The shape of what is open: how it splits by severity, what became of it, and
 * how it lands in risk bands once each finding is read against its asset.
 *
 * Three readings of one set, and each uses the form its question asks for:
 *
 * * **Severity is a composition**, so it is one stacked bar — five lengths on a
 *   shared line, compared exactly, in 8px of height.
 * * **Status is a whole divided in four**, which is the one case a ring is
 *   genuinely good at, and the accepted-risk slice is the reason it is here:
 *   most products fold "we decided to live with it" into "not open", and this
 *   one refuses to.
 * * **Risk bands are a ranking**, so bars from a common baseline. A band is not
 *   the rule's severity — it is what that finding means on that asset — which is
 *   why the two blocks rarely have the same shape and why both are shown.
 */
export function PostureBreakdown({
  bySeverity,
  byStatus,
  riskBands,
}: {
  bySeverity: Record<string, number>;
  byStatus: Record<string, number>;
  riskBands: Dashboard["risk_bands"];
}) {
  const severitySegments = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((level) => ({
    key: level,
    label: label(level),
    value: bySeverity[level] ?? 0,
    tone: SEVERITY_TONES[level],
  }));

  const statusSlices: Slice[] = [
    {
      key: "OPEN",
      label: "Open",
      value: byStatus.OPEN ?? 0,
      tone: "var(--sev-critical)",
    },
    {
      key: "IN_PROGRESS",
      label: "In progress",
      value: byStatus.IN_PROGRESS ?? 0,
      tone: "var(--sev-medium)",
    },
    {
      key: "RESOLVED",
      label: "Verified fixed",
      value: byStatus.RESOLVED ?? 0,
      tone: "var(--sev-ok)",
    },
    {
      key: "ACCEPTED_RISK",
      label: "Risk accepted",
      value: byStatus.ACCEPTED_RISK ?? 0,
      tone: "var(--sev-unknown)",
    },
  ].filter((slice) => slice.value > 0);

  const statusTotal = statusSlices.reduce((sum, slice) => sum + slice.value, 0);

  // Measured against the whole set rather than against the largest band, so a
  // band holding one finding of two reads as half the problem instead of
  // filling the track. Against the largest, a quiet estate draws the same wall
  // of red as a burning one.
  const bandTotal = Object.values(riskBands).reduce(
    (sum, count) => sum + (count ?? 0),
    0,
  );
  const bandBars = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((level) => ({
    key: level,
    label: label(level),
    value: riskBands[level] ?? 0,
    of: bandTotal || undefined,
    // The denominator is the same on every row here, so printing it four times
    // would spend a column repeating one fact.
    hideDenominator: true,
    tone: SEVERITY_TONES[level],
    to: `/risks?level=${level}`,
  }));

  return (
    <section
      aria-labelledby="posture-breakdown"
      className="grid gap-px overflow-hidden rounded-xl bg-border ring-1 ring-foreground/10 lg:grid-cols-3"
    >
      <h2 id="posture-breakdown" className="sr-only">
        What is open, broken down
      </h2>

      <Block title="Severity mix" hint="What the rules judged, in the abstract">
        <StackedBar
          segments={severitySegments}
          ariaLabel="Open findings by severity"
        />
      </Block>

      <Block title="Where findings stand" hint="Accepted risk is counted, never absorbed">
        {statusTotal === 0 ? (
          <p className="text-xs text-muted-foreground">
            No findings have been raised yet.
          </p>
        ) : (
          <div className="flex items-center gap-4">
            <Suspense fallback={<Skeleton className="size-28 rounded-full" />}>
              <Donut
                slices={statusSlices}
                centerValue={String(statusTotal)}
                centerLabel="findings"
                ariaLabel="Findings by status"
                className="size-28 shrink-0"
              />
            </Suspense>
            <DonutLegend slices={statusSlices} className="min-w-0 flex-1" />
          </div>
        )}
      </Block>

      <Block title="Risk bands" hint="What each means on the asset it was found on">
        <Bars bars={bandBars} ariaLabel="Open findings by risk band" />
      </Block>
    </section>
  );
}

function Block({
  title,
  hint,
  children,
}: {
  title: string;
  hint: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-3 bg-card p-5">
      <div>
        <h3 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
          {title}
        </h3>
        <p className="mt-1 text-xs text-muted-foreground/80">{hint}</p>
      </div>
      {children}
    </div>
  );
}
