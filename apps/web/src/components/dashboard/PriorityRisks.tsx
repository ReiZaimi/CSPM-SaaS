import { Link } from "react-router-dom";
import { ArrowRightIcon, RadarIcon, RouteIcon } from "lucide-react";

import type { Dashboard } from "@/lib/types";
import { RiskScore } from "@/components/security/SecurityScore";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { stagger } from "@/lib/motion";
import { cn } from "@/lib/format";

type Risk = Dashboard["top_risks"][number];

/**
 * What to go and deal with, ranked by what it would cost rather than by how
 * loudly it fired.
 *
 * The ranking is the product's whole argument, and a list that showed only
 * titles and numbers asked the reader to take it on trust: why does a HIGH
 * outrank the CRITICAL beneath it? So each row carries the terms the score was
 * actually built from — internet exposure, data sensitivity, asset criticality
 * — which are the same components the risk detail page shows the arithmetic
 * for. A rank is then a reason rather than an assertion.
 *
 * A scenario is marked as one. It groups findings that are already counted
 * individually, and a reader who does not know that will go looking for a
 * misconfiguration that does not exist on any single asset.
 */
export function PriorityRisks({ risks }: { risks: Risk[] }) {
  return (
    <section
      aria-labelledby="priority-risks"
      className="flex flex-col overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <header className="flex items-start justify-between gap-4 px-5 py-4">
        <div>
          <h2 id="priority-risks" className="text-sm font-semibold">
            Priority risks
          </h2>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Ranked by what each would cost this business, not by how many alerts
            fired
          </p>
        </div>
        <Link
          to="/risks"
          className={cn(buttonVariants({ variant: "ghost", size: "sm" }), "shrink-0")}
        >
          All risks
          <ArrowRightIcon data-icon="inline-end" />
        </Link>
      </header>

      {risks.length === 0 ? (
        <p className="border-t px-5 py-8 text-center text-sm text-muted-foreground">
          Nothing is currently ranked as a risk. Every check that reached a
          verdict passed — the coverage note above says how much of the estate
          that covers.
        </p>
      ) : (
        <ol className="border-t">
          {risks.map((risk, index) => (
            <li
              key={risk.id}
              className="[animation:cg-rise_260ms_ease-out_both]"
              style={stagger(index)}
            >
              <Link
                to={`/risks/${risk.id}`}
                className="group flex items-start gap-4 border-b px-5 py-3.5 transition-colors last:border-0 hover:bg-accent/50 focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
              >
                <span className="mt-1 w-3 shrink-0 text-xs tabular-nums text-muted-foreground">
                  {index + 1}
                </span>

                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge level={risk.risk_level} size="sm" />
                    {risk.kind === "ATTACK_PATH" && (
                      <Badge variant="secondary" className="gap-1 font-normal">
                        <RouteIcon className="size-3" aria-hidden />
                        Route
                      </Badge>
                    )}
                  </div>
                  <p className="mt-1.5 truncate text-sm font-medium">{risk.title}</p>
                  <RiskContext risk={risk} />
                </div>

                <div className="flex shrink-0 items-center gap-2">
                  <RiskScore score={Number(risk.risk_score)} />
                  <ArrowRightIcon
                    className="size-4 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100"
                    aria-hidden
                  />
                </div>
              </Link>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

/**
 * Why this one outranks the next.
 *
 * Only the components that raise a score are named, and only when they are
 * high enough to be the reason — listing "exposure: LOW" beside a critical risk
 * would spend a line saying nothing. UNKNOWN is stated rather than skipped: not
 * knowing whether an asset is exposed is itself part of why a risk ranks where
 * it does.
 */
function RiskContext({ risk }: { risk: Risk }) {
  const facts = [
    { label: "Internet-facing", level: risk.internet_exposure },
    { label: "Sensitive data", level: risk.data_sensitivity },
    { label: "Business-critical", level: risk.asset_criticality },
  ].filter(
    (fact) =>
      fact.level === "CRITICAL" || fact.level === "HIGH" || fact.level === "UNKNOWN",
  );

  if (facts.length === 0) return null;

  return (
    <ul className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
      {facts.map((fact) => (
        <li key={fact.label} className="flex items-center gap-1.5">
          <RadarIcon className="size-3 shrink-0" aria-hidden />
          {fact.level === "UNKNOWN" ? `${fact.label}: not known` : fact.label}
        </li>
      ))}
    </ul>
  );
}
