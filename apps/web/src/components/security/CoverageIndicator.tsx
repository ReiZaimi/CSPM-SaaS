import { Link } from "react-router-dom";
import { CheckCircle2Icon, ClockIcon, TriangleAlertIcon } from "lucide-react";

import { buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { cn } from "@/lib/format";

/**
 * How much of the environment the verdicts above were actually formed from.
 *
 * Most security products hide this. A coverage figure is an admission that the
 * scan did not see everything, and the temptation is to report the score and
 * let the reader assume it was complete -- which is exactly how a customer ends
 * up trusting a 94 that was computed over the half of their estate CloudGuard
 * could read.
 *
 * So it gets a card rather than a tile, and it says three separate things:
 * what fraction of checks reached a verdict, how old the underlying readings
 * are, and which categories could not be collected. The third is the one people
 * act on, and it was previously a wall of `category: raw error` text.
 */
export function CoverageIndicator({
  ratio,
  unknown,
  conclusive,
  gaps = [],
  freshness,
  className,
}: {
  ratio: number | null;
  unknown: number;
  conclusive: number;
  gaps?: [string, string][];
  freshness?: { readings: number; stale_hours: number | null; unusable: number } | null;
  className?: string;
}) {
  const pct = ratio === null ? null : Math.round(ratio * 100);
  const complete = unknown === 0 && gaps.length === 0;

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Assessment coverage
          {complete ? (
            <CheckCircle2Icon className="size-4 text-ok" aria-hidden />
          ) : (
            <TriangleAlertIcon className="size-4 text-medium" aria-hidden />
          )}
        </CardTitle>
        <CardDescription>
          {complete
            ? "Every applicable check reached a verdict from evidence CloudGuard could read."
            : "Some checks could not reach a verdict. Those report UNKNOWN — never a pass."}
        </CardDescription>
      </CardHeader>

      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-wrap items-end gap-x-8 gap-y-3">
          <div>
            <p className="text-3xl font-semibold tabular-nums">
              {pct === null ? "—" : `${pct}%`}
            </p>
            <p className="text-xs text-muted-foreground">
              {conclusive} conclusive · {unknown} unknown
            </p>
          </div>

          {freshness && freshness.readings > 0 && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <ClockIcon className="size-3.5" aria-hidden />
              <span>
                Oldest reading{" "}
                <span className="font-medium text-foreground">
                  {formatAge(freshness.stale_hours)}
                </span>{" "}
                old
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
        </div>

        {pct !== null && (
          <div
            className="h-1.5 w-full overflow-hidden rounded-full bg-muted"
            role="meter"
            aria-valuenow={pct}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="Assessment coverage"
          >
            <div
              className={cn(
                "h-full rounded-full transition-[width] duration-700",
                pct >= 95 ? "bg-ok" : pct >= 75 ? "bg-medium" : "bg-high",
              )}
              style={{ width: `${pct}%` }}
            />
          </div>
        )}

        {gaps.length > 0 && (
          <div className="flex flex-col gap-2 rounded-lg border border-dashed border-medium-border bg-medium-bg/40 p-3">
            <p className="text-xs font-medium text-medium">
              {gaps.length} {gaps.length === 1 ? "category" : "categories"} could not be
              collected
            </p>
            <ul className="flex flex-col gap-1.5">
              {gaps.map(([category, reason]) => (
                <li key={category} className="text-xs leading-relaxed">
                  <span className="font-medium capitalize">{category}</span>
                  <span className="text-muted-foreground"> — {reason}</span>
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
      </CardContent>
    </Card>
  );
}

function formatAge(hours: number | null): string {
  if (hours === null) return "—";
  if (hours < 1) return "under an hour";
  if (hours < 48) return `${Math.round(hours)} hours`;
  return `${Math.round(hours / 24)} days`;
}
