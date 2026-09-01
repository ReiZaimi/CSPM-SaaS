import { Link } from "react-router-dom";
import { ArrowRightIcon } from "lucide-react";

import type { ComplianceFramework } from "@/lib/types";
import { Bars } from "@/components/charts/Bars";
import { buttonVariants } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/format";

/**
 * Where each framework stands, as evidence rather than as a verdict.
 *
 * Bars, because this is a ranking across frameworks and a ranking is compared
 * along a shared baseline. One neutral colour for all of them on purpose: these
 * are four measurements of the same kind, and giving each framework its own hue
 * would invite the reader to think the colours meant something about the
 * frameworks.
 *
 * The sentence under it is not decoration. A covered control means specific
 * misconfigurations were absent at the last scan; it is not a statement that a
 * requirement is met in law, and a green bar in a compliance panel is exactly
 * where that gets forgotten.
 */
export function ComplianceSummary({
  frameworks,
  loading,
}: {
  frameworks: ComplianceFramework[] | undefined;
  loading: boolean;
}) {
  const rows = Array.isArray(frameworks) ? frameworks : [];

  return (
    <section
      aria-labelledby="compliance-summary"
      className="flex flex-col overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <header className="flex items-start justify-between gap-4 px-5 py-4">
        <div>
          <h2 id="compliance-summary" className="text-sm font-semibold">
            Compliance coverage
          </h2>
          <p className="mt-0.5 text-xs text-muted-foreground">
            The share of controls CloudGuard reached a conclusion on
          </p>
        </div>
        <Link
          to="/compliance"
          className={cn(buttonVariants({ variant: "ghost", size: "sm" }), "shrink-0")}
        >
          Frameworks
          <ArrowRightIcon data-icon="inline-end" />
        </Link>
      </header>

      <div className="flex flex-1 flex-col gap-3 border-t px-5 py-4">
        {loading && (
          <div className="flex flex-col gap-2.5">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-4 w-full" />
            ))}
          </div>
        )}

        {!loading && rows.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No framework has been assessed yet. Coverage appears once a scan has
            run against the rule catalogue.
          </p>
        )}

        {!loading && rows.length > 0 && (
          <>
            <Bars
              ariaLabel="Assessable coverage by framework"
              bars={rows.map((framework) => ({
                key: framework.id,
                label: framework.short_name,
                // Null is not zero: a framework nothing has been assessed
                // against has no ratio, and 0% would read as total failure.
                value:
                  framework.coverage_ratio === null
                    ? 0
                    : Math.round(framework.coverage_ratio * 100),
                of: 100,
                tone: "var(--foreground)",
                to: `/compliance/${framework.id}`,
              }))}
            />
            <p className="text-xs leading-relaxed text-muted-foreground">
              Evidence, not a verdict. A covered control means specific
              misconfigurations were absent at the last scan — not that a
              requirement is met in law or that an audit would pass.
            </p>
          </>
        )}
      </div>
    </section>
  );
}
