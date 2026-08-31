import { Link } from "react-router-dom";
import { ArrowRightIcon } from "lucide-react";

import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/format";

/**
 * Whether any of this is actually getting fixed.
 *
 * Two numbers, and the distinction between them is the point. The rate is every
 * finding ever raised that a later scan observed passing; the count beside it is
 * how many of those landed in the last thirty days. A single percentage cannot
 * tell a team that fixed everything last year from one fixing things this week.
 *
 * Both are *verified* — a scan saw the check pass. Nothing here counts a task
 * somebody marked done, because marking work done is a claim and this panel
 * exists to answer whether the claims came true.
 */
export function RemediationProgress({
  rate,
  verifiedLast30Days,
  openFindings,
}: {
  rate: number;
  verifiedLast30Days: number;
  openFindings: number;
}) {
  const pct = Math.round(Math.max(0, Math.min(1, rate)) * 100);

  return (
    <section
      aria-labelledby="remediation-progress"
      className="flex flex-col overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <header className="flex items-start justify-between gap-4 px-5 py-4">
        <div>
          <h2 id="remediation-progress" className="text-sm font-semibold">
            Remediation
          </h2>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Fixes a later scan observed — never work somebody marked done
          </p>
        </div>
        <Link
          to="/remediation"
          className={cn(buttonVariants({ variant: "ghost", size: "sm" }), "shrink-0")}
        >
          Queue
          <ArrowRightIcon data-icon="inline-end" />
        </Link>
      </header>

      <div className="flex flex-col gap-4 border-t px-5 py-4">
        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-semibold leading-none tabular-nums">
            {pct}%
          </span>
          <span className="text-xs text-muted-foreground">
            of findings ever raised are verified fixed
          </span>
        </div>

        <div
          className="h-1.5 w-full overflow-hidden rounded-full bg-muted"
          role="meter"
          aria-valuenow={pct}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Share of findings verified fixed"
        >
          <div
            className="h-full rounded-full bg-ok transition-[width] duration-700 ease-out"
            style={{ width: `${pct}%` }}
          />
        </div>

        <dl className="grid grid-cols-2 gap-4">
          <div>
            <dt className="text-xs text-muted-foreground">
              Verified fixed · last 30 days
            </dt>
            <dd className="mt-1 text-xl font-semibold tabular-nums">
              {verifiedLast30Days}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">Still open</dt>
            <dd className="mt-1 text-xl font-semibold tabular-nums">
              <Link to="/findings" className="hover:underline">
                {openFindings}
              </Link>
            </dd>
          </div>
        </dl>
      </div>
    </section>
  );
}
