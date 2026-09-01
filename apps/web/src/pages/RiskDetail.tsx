import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeftIcon, RadarIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import type { RiskDetail } from "@/lib/types";
import { useT } from "@/i18n";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { StatusPill } from "@/components/security/StatusPill";
import { AttackPathRoute } from "@/components/graph/AttackPathRoute";
import {
  Breadcrumbs,
  DetailSkeleton,
  EmptyState,
  ErrorState,
} from "@/components/common/states";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/format";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

/**
 * One risk, and the findings it was built from.
 *
 * The list ranks a route above the findings inside it, which is the whole
 * reason both live in one table -- and it asks the reader to take that on
 * trust, because nothing there says *which* findings the route is made of. A
 * scenario scored 96 sitting above a finding scored 84 is an assertion until
 * its members are named and each one can be opened.
 *
 * The arithmetic is shown in the terms the score was actually built from, and
 * the two formulas are kept apart for the same reason the list cards are:
 * showing a scenario the six weighted components would invite the reader to
 * check numbers that were never used.
 */
export function RiskDetailPage() {
  const t = useT();
  const { riskId } = useParams();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["risk", riskId],
    queryFn: () =>
      api.get<RiskDetail>(`/api/v1/risks/${riskId}`).then((r) => r.data),
  });

  if (isLoading) return <DetailSkeleton />;

  if (error) {
    // A deleted risk is an ordinary thing -- the scan that raised it was
    // purged -- and reads as a broken product unless it is named as such.
    const missing = error instanceof ApiError && error.status === 404;
    return (
      <div className="flex flex-col gap-4">
        <BackLink label={t.risks.backToRisks} />
        <ErrorState
          title={missing ? t.risks.notFound : "Could not load this risk"}
          detail={
            missing
              ? t.risks.notFoundDetail
              : "CloudGuard could not reach its own API."
          }
          impact={
            missing
              ? undefined
              : "Nothing about your environment has changed — this is a problem displaying it."
          }
          onRetry={missing ? undefined : () => refetch()}
          action={
            missing ? (
              <Link
                to="/risks"
                className={buttonVariants({ variant: "outline" })}
              >
                {t.risks.backToRisks}
              </Link>
            ) : undefined
          }
        />
      </div>
    );
  }

  if (!data) return null;

  const scenario = data.kind !== "FINDING";
  const breakdown = data.score_breakdown;
  const components = breakdown.components ?? {};
  const capped = (breakdown.uncapped ?? 0) > 100;

  return (
    <div className="flex flex-col gap-6">
      <Breadcrumbs
        trail={[
          { label: t.risks.title, to: "/risks" },
          { label: data.title },
        ]}
      />

      <div>
        <div className="flex flex-wrap items-center gap-3">
          <SeverityBadge level={data.risk_level} />
          <StatusPill status={data.status} />
          {/* Says which formula scored this, so the arithmetic below is read
              against the right one. */}
          {scenario && (
            <Badge variant="outline">
              {data.kind === "ESCALATION"
                ? t.risks.escalationBadge
                : t.risks.scenarioBadge}
            </Badge>
          )}
        </div>
        <div className="mt-3 flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-2xl font-semibold tracking-tight text-foreground">
              {data.title}
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted-foreground">
              {data.description}
            </p>
          </div>
          <div className="shrink-0 text-right">
            <p className="text-4xl font-semibold tabular-nums text-foreground">
              {Number(data.risk_score).toFixed(0)}
            </p>
            <p className="text-xs text-muted-foreground">risk score</p>
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="flex flex-col gap-6 lg:col-span-2">
          {scenario && data.path.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>{t.risks.routeLabel}</CardTitle>
                <CardDescription>
                  {data.kind === "ESCALATION"
                    ? t.risks.escalationIntro
                    : t.risks.scenarioIntro}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <AttackPathRoute steps={data.path} />
              </CardContent>
            </Card>
          )}

          {/* The part the list cannot show. */}
          <Card>
            <CardHeader>
              <CardTitle>{t.risks.builtFrom}</CardTitle>
              <CardDescription>
                {scenario ? t.risks.builtFromScenario : t.risks.builtFromFinding}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {data.findings.length === 0 ? (
                <EmptyState
                  icon={RadarIcon}
                  title={t.risks.noMembers}
                  detail={t.risks.noMembersDetail}
                />
              ) : (
                <ul className="divide-y divide-border rounded-lg border border-border">
                  {data.findings.map((finding) => (
                    <li key={finding.id} className="px-4 py-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge level={finding.severity} size="sm" />
                        <StatusPill status={finding.status} />
                        <code className="text-[11px] text-muted-foreground">
                          {finding.rule_id}
                        </code>
                      </div>
                      <Link
                        to={`/findings/${finding.id}`}
                        className="mt-1 block text-sm font-medium text-foreground underline-offset-4 hover:underline"
                      >
                        {finding.title}
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="flex flex-col gap-6">
          <Card>
            <CardHeader>
              <CardTitle>{t.risks.theArithmetic}</CardTitle>
            </CardHeader>
            <CardContent>
              {scenario ? (
                /* Floored at the worst member and amplified for being short.
                   The six weighted components do not apply, and showing them
                   would be working that was never done. */
                <dl className="flex flex-col gap-2 text-xs">
                  <Row
                    label={t.risks.worstMember}
                    value={breakdown.worst_member ?? "—"}
                  />
                  <Row
                    label={t.risks.amplifier}
                    value={`+${breakdown.amplifier ?? 0}`}
                  />
                  <Row
                    label="Hops"
                    value={breakdown.hops ?? data.path.length}
                  />
                  {capped && (
                    <p className="mt-1 text-xs text-muted-foreground">
                      {breakdown.uncapped} before the ceiling. {t.risks.cappedNote}
                    </p>
                  )}
                </dl>
              ) : (
                <ul className="flex flex-col gap-1.5">
                  {Object.entries(components).map(([name, component]) => (
                    <li
                      key={name}
                      className="flex items-center justify-between gap-3 text-xs"
                    >
                      <span className="text-muted-foreground">
                        {name.replace(/_/g, " ")}
                        <span className="ml-1">
                          ({component.value} × {component.weight})
                        </span>
                      </span>
                      <span className="font-medium tabular-nums text-foreground">
                        {component.contribution.toFixed(1)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          {/* The factors, for a finding risk. A scenario was not scored from
              them, so it does not get a panel inviting them to be read. */}
          {!scenario && (
            <Card>
              <CardHeader>
                <CardTitle>What was weighed</CardTitle>
              </CardHeader>
              <CardContent>
                <dl className="flex flex-col gap-2 text-xs">
                  <Row
                    label="Asset criticality"
                    value={<SeverityBadge level={data.asset_criticality} size="sm" />}
                  />
                  <Row
                    label="Data sensitivity"
                    value={<SeverityBadge level={data.data_sensitivity} size="sm" />}
                  />
                  <Row
                    label="Internet exposure"
                    value={<SeverityBadge level={data.internet_exposure} size="sm" />}
                  />
                  <Row label="Exploitability" value={`${data.exploitability}/5`} />
                  <Row label="Business impact" value={data.business_impact} />
                </dl>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function BackLink({ label }: { label: string }) {
  return (
    <Link
      to="/risks"
      className={cn(
        buttonVariants({ variant: "ghost", size: "sm" }),
        "-ml-2 self-start text-muted-foreground",
      )}
    >
      <ArrowLeftIcon data-icon="inline-start" />
      {label}
    </Link>
  );
}

function Row({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="font-medium tabular-nums text-foreground">{value}</dd>
    </div>
  );
}
