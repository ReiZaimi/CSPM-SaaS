import { lazy, Suspense, useState } from "react";
import { Link } from "react-router-dom";
import {
  CheckIcon,
  ClockIcon,
  TriangleAlertIcon,
} from "lucide-react";

import type { Dashboard } from "@/lib/types";
import { groupCauses } from "@/lib/collectionErrors";
import { DonutLegend, type Slice } from "@/components/charts/DonutLegend";
import { Skeleton } from "@/components/ui/skeleton";
import { buttonVariants } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn, label } from "@/lib/format";

type Category = NonNullable<Dashboard["coverage"]["categories"]>[number];

/** Recharts is lazy everywhere in this app; a ring is not worth blocking on. */
const Donut = lazy(() =>
  import("@/components/charts/Donut").then((m) => ({ default: m.Donut })),
);

/**
 * How much of the environment the numbers above were actually formed from.
 *
 * Most security products hide this. A coverage figure is an admission that the
 * scan did not see everything, and the temptation is to report the score and
 * let the reader assume it was complete — which is how a customer ends up
 * trusting an 84 computed over the half of their estate CloudGuard could read.
 *
 * Four separate facts, and they are not interchangeable: what fraction of
 * checks reached a verdict, which categories of evidence could not be read,
 * how old the readings are, and how much of the estate CloudGuard could not
 * classify. A fully covered estate can be three weeks stale, and a fresh
 * reading can cover half of one.
 *
 * The last of those is the one the score used to quietly spend. Missing
 * evidence never becomes a finding, so it never reached the number; missing
 * *context* did, because the risk formula ranks an unknown criticality just
 * under High so an unlabelled asset never sorts below a labelled one. That
 * caution belongs to the ordering. Charging a posture number for it told a
 * customer their estate was worse when the honest sentence was that CloudGuard
 * could not tell — so it is stated here, as work they can do, instead.
 *
 * The percentage is never phrased as security. 94% coverage is not 94% secure;
 * it is the share of checks that reached *any* verdict, pass or fail.
 */
export function CoveragePanel({
  ratio,
  unknown,
  conclusive,
  categories = [],
  context,
  gaps = [],
  freshness,
}: {
  ratio: number | null;
  unknown: number;
  conclusive: number;
  categories?: Category[];
  context?: { unclassified: number; classified: number; ratio: number };
  gaps?: [string, string][];
  freshness?: { readings: number; stale_hours: number | null; unusable: number } | null;
}) {
  const pct = ratio === null ? null : Math.round(ratio * 100);
  const complete = unknown === 0 && gaps.length === 0;

  return (
    <section
      aria-labelledby="assessment-coverage"
      className="overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <div className="flex flex-wrap items-start justify-between gap-x-8 gap-y-4 px-5 py-4">
        <div className="min-w-0">
          <h2
            id="assessment-coverage"
            className="flex items-center gap-2 text-sm font-semibold"
          >
            Assessment coverage
            {complete ? (
              <CheckIcon className="size-4 text-ok" aria-hidden />
            ) : (
              <TriangleAlertIcon className="size-4 text-medium" aria-hidden />
            )}
          </h2>
          <p className="mt-0.5 max-w-xl text-xs leading-relaxed text-muted-foreground">
            {complete
              ? "Every applicable check reached a verdict from evidence CloudGuard could read."
              : "The share of checks that reached a verdict — not a security percentage. What could not be evaluated reports UNKNOWN, and UNKNOWN is never a pass."}
          </p>
        </div>

        <div className="flex items-center gap-5">
          {freshness && freshness.readings > 0 && (
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <ClockIcon className="size-3.5 shrink-0" aria-hidden />
              <span>
                oldest reading{" "}
                <span className="font-medium text-foreground">
                  {formatAge(freshness.stale_hours)}
                </span>
                {freshness.unusable > 0 && (
                  <>
                    {" · "}
                    <span className="font-medium text-medium">
                      {freshness.unusable} unusable
                    </span>
                  </>
                )}
              </span>
            </div>
          )}

          {/* A ring, because this genuinely is a whole divided in two: checks
              that reached a verdict, and checks that could not. The percentage
              in the middle is the same number the sentence uses. */}
          {pct !== null && (
            <div className="flex items-center gap-4">
              <Suspense fallback={<Skeleton className="size-24 rounded-full" />}>
                <Donut
                  slices={verdictSlices(conclusive, unknown)}
                  centerValue={`${pct}%`}
                  centerLabel="verdicts"
                  ariaLabel={`${conclusive} checks reached a verdict, ${unknown} did not`}
                  className="size-24 shrink-0"
                />
              </Suspense>
              <DonutLegend
                slices={verdictSlices(conclusive, unknown)}
                className="shrink-0"
              />
            </div>
          )}
        </div>
      </div>

      {pct !== null && (
        <div
          className="h-1 w-full bg-muted"
          role="meter"
          aria-valuenow={pct}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Assessment coverage"
        >
          <div
            className={cn(
              "h-full transition-[width] duration-700",
              pct >= 95 ? "bg-ok" : pct >= 75 ? "bg-medium" : "bg-high",
            )}
            style={{ width: `${pct}%` }}
          />
        </div>
      )}

      {categories.length > 0 && (
        <ul className="flex flex-wrap gap-x-5 gap-y-2 border-t px-5 py-3">
          {categories.map((category) => (
            <CategoryChip key={category.name} category={category} />
          ))}
        </ul>
      )}

      {context && context.unclassified > 0 && (
        <div className="border-t border-dashed px-5 py-3">
          <p className="text-xs leading-relaxed text-muted-foreground">
            <span className="font-medium text-foreground">
              {context.unclassified} of{" "}
              {context.unclassified + context.classified} open risks
            </span>{" "}
            sit on assets CloudGuard could not classify. They are ranked as
            though they matter, so nothing important hides behind a missing
            label — but the score is only charged for what was established.{" "}
            <Link
              to="/settings"
              className="font-medium text-foreground underline underline-offset-2"
            >
              Tell CloudGuard what these subscriptions hold
            </Link>{" "}
            and the number will move to match.
          </p>
        </div>
      )}

      {gaps.length > 0 && (
        <div className="flex flex-col gap-2.5 border-t border-dashed bg-medium-bg/30 px-5 py-4">
          <p className="text-xs font-medium text-medium">
            {gaps.length} {gaps.length === 1 ? "category" : "categories"} could not
            be collected
          </p>
          <ul className="flex flex-col gap-2.5">
            {gaps.map(([category, reason]) => (
              <li key={category} className="text-xs leading-relaxed">
                <span className="font-medium capitalize">{label(category)}</span>
                <ul className="mt-1 flex flex-col gap-1.5">
                  {groupCauses(reason).map((cause) => (
                    <GapCause
                      key={cause.message}
                      keys={cause.keys}
                      message={cause.message}
                    />
                  ))}
                </ul>
              </li>
            ))}
          </ul>
          <Link
            to="/scans"
            className={cn(
              buttonVariants({ variant: "outline", size: "sm" }),
              "self-start",
            )}
          >
            View scan detail
          </Link>
        </div>
      )}
    </section>
  );
}

/**
 * One category of evidence, and whether the scan got all of it.
 *
 * PARTIAL counts as incomplete rather than as read: a truncated listing cannot
 * support "none of them are public", which is the same rule the engine applies
 * one layer up. The tick and the warning triangle carry the meaning as well as
 * the colour, so the distinction survives a reader who cannot separate green
 * from amber.
 */
function CategoryChip({ category }: { category: Category }) {
  const clean = category.incomplete === 0;

  return (
    <li>
      <Tooltip>
        <TooltipTrigger
          render={
            <span className="flex cursor-default items-center gap-1.5 text-xs" />
          }
        >
          {clean ? (
            <CheckIcon className="size-3.5 shrink-0 text-ok" aria-hidden />
          ) : (
            <TriangleAlertIcon className="size-3.5 shrink-0 text-medium" aria-hidden />
          )}
          <span className={clean ? "text-muted-foreground" : "font-medium"}>
            {label(category.name)}
          </span>
        </TooltipTrigger>
        <TooltipContent>
          {clean
            ? `${category.readings} reading${category.readings === 1 ? "" : "s"}, all complete`
            : `${category.incomplete} of ${category.readings} reading${
                category.readings === 1 ? "" : "s"
              } incomplete — checks over this evidence report UNKNOWN`}
        </TooltipContent>
      </Tooltip>
    </li>
  );
}

/**
 * One cause, and everything it stopped.
 *
 * The provider reports a failure per evidence key, and a single missing admin
 * consent fails several of them with the same nine-hundred-character sentence.
 * Identical causes are stated once with the keys they cost named beside them,
 * and the provider's own words are kept — clipped, with the rest one click
 * away. Kept rather than paraphrased: this is the text an administrator will
 * search for, and a summary of an Azure error is not an Azure error.
 */
function GapCause({ keys, message }: { keys: string[]; message: string }) {
  const [expanded, setExpanded] = useState(false);
  const long = message.length > 180;

  return (
    <li>
      {keys.length > 0 && (
        <span className="font-medium text-foreground">{keys.join(", ")}</span>
      )}
      <span className="text-muted-foreground">
        {keys.length > 0 && " — "}
        {long && !expanded ? `${message.slice(0, 180).trimEnd()}…` : message}
      </span>
      {long && (
        <button
          type="button"
          onClick={() => setExpanded((value) => !value)}
          className="ml-1.5 whitespace-nowrap underline underline-offset-2 transition-colors hover:text-foreground"
        >
          {expanded ? "Show less" : "Show the whole message"}
        </button>
      )}
    </li>
  );
}

/**
 * The two things a check can be: answered, or not.
 *
 * Two slices and no third, because "unknown" is not a middle state between pass
 * and fail — it is the absence of a verdict, and the whole point of the panel
 * is that it is never counted as either.
 */
function verdictSlices(conclusive: number, unknown: number): Slice[] {
  return [
    {
      key: "conclusive",
      label: "Reached a verdict",
      value: conclusive,
      tone: "var(--sev-ok)",
    },
    {
      key: "unknown",
      label: "No verdict",
      value: unknown,
      tone: "var(--sev-unknown)",
    },
  ].filter((slice) => slice.value > 0);
}

function formatAge(hours: number | null): string {
  if (hours === null) return "—";
  if (hours < 1) return "under an hour old";
  if (hours < 48) return `${Math.round(hours)} hours old`;
  return `${Math.round(hours / 24)} days old`;
}
