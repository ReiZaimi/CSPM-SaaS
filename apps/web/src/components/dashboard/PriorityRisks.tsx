import { Link } from "react-router-dom";
import {
  ArrowRightIcon,
  DatabaseIcon,
  GlobeIcon,
  RouteIcon,
  ShieldAlertIcon,
} from "lucide-react";

import type { Dashboard } from "@/lib/types";
import { RiskScore } from "@/components/security/SecurityScore";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { stagger } from "@/lib/motion";
import { cn, levelStyle } from "@/lib/format";

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
 * A row leads with a severity-tinted mark instead of an ordinal. The rank is
 * already the reading order, and the tint carries the one thing a reader scans
 * for down a list of five; a scenario keeps its own mark, because it groups
 * findings that are already counted individually and a reader who does not know
 * that will go looking for a misconfiguration that exists on no single asset.
 */
export function PriorityRisks({ risks }: { risks: Risk[] }) {
  return (
    <Card
      role="region"
      aria-labelledby="priority-risks"
      className="gap-0 py-0 [--card-spacing:--spacing(5)]"
    >
      <CardHeader className="py-4">
        <CardTitle id="priority-risks" className="text-sm font-semibold">
          Priority risks
        </CardTitle>
        <CardDescription className="text-xs">
          Ranked by what each would cost this business, not by how many alerts
          fired
        </CardDescription>
        <CardAction>
          <Link
            to="/risks"
            className={cn(buttonVariants({ variant: "ghost", size: "sm" }), "shrink-0")}
          >
            All risks
            <ArrowRightIcon data-icon="inline-end" />
          </Link>
        </CardAction>
      </CardHeader>

      {risks.length === 0 ? (
        <CardContent className="border-t py-8">
          <p className="text-center text-sm text-muted-foreground">
            Nothing is currently ranked as a risk. Every check that reached a
            verdict passed — the coverage note above says how much of the estate
            that covers.
          </p>
        </CardContent>
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
                className="group flex items-center gap-3 border-b px-5 py-3 transition-colors last:border-0 hover:bg-accent/50 focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
              >
                <RiskMark risk={risk} />

                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{risk.title}</p>
                  <RiskContext risk={risk} />
                </div>

                <div className="flex shrink-0 items-center gap-2.5">
                  <RiskScore score={Number(risk.risk_score)} />
                  <SeverityBadge level={risk.risk_level} size="sm" />
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
    </Card>
  );
}

/**
 * The severity-tinted mark a row leads with.
 *
 * It borrows `levelStyle` rather than inventing a second palette, so a row's
 * mark and its badge can never disagree about what CRITICAL looks like. A
 * scenario keeps the route mark it has always had: what the tile says is *what
 * kind of thing this is*, and the tint says how bad.
 */
function RiskMark({ risk }: { risk: Risk }) {
  const Icon = risk.kind === "ATTACK_PATH" ? RouteIcon : ShieldAlertIcon;
  return (
    <span
      className={cn(
        "flex size-9 shrink-0 items-center justify-center rounded-lg border",
        levelStyle(risk.risk_level),
      )}
      aria-hidden
    >
      <Icon className="size-4" />
    </span>
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
    { label: "Internet-facing", level: risk.internet_exposure, Icon: GlobeIcon },
    { label: "Sensitive data", level: risk.data_sensitivity, Icon: DatabaseIcon },
    { label: "Business-critical", level: risk.asset_criticality, Icon: ShieldAlertIcon },
  ].filter(
    (fact) =>
      fact.level === "CRITICAL" || fact.level === "HIGH" || fact.level === "UNKNOWN",
  );

  if (risk.kind === "ATTACK_PATH" && facts.length === 0) {
    return (
      <p className="mt-0.5 truncate text-xs text-muted-foreground">
        Scenario — findings already counted individually below
      </p>
    );
  }

  if (facts.length === 0) return null;

  return (
    <ul className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
      {risk.kind === "ATTACK_PATH" && (
        <li className="flex items-center gap-1.5">
          <RouteIcon className="size-3 shrink-0" aria-hidden />
          Scenario
        </li>
      )}
      {facts.map((fact) => (
        <li key={fact.label} className="flex items-center gap-1.5">
          <fact.Icon className="size-3 shrink-0" aria-hidden />
          {fact.level === "UNKNOWN" ? `${fact.label}: not known` : fact.label}
        </li>
      ))}
    </ul>
  );
}
