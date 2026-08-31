import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeftIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { ComplianceControl, ComplianceFrameworkDetail } from "@/lib/types";
import { useT } from "@/i18n";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { formatPercent } from "@/lib/format";
import {
  CoverageBar,
  ControlStatusPill,
  EvidenceNotice,
} from "@/components/compliance";
import { DetailSkeleton, ErrorState } from "@/components/common/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

/**
 * One framework, control by control.
 *
 * Controls are grouped by the framework's own sections rather than sorted by
 * status. Someone arrives here holding an auditor's spreadsheet in that order,
 * and reordering by severity would make them hunt.
 */
export function ComplianceFrameworkPage() {
  const t = useT();
  const { frameworkId } = useParams<{ frameworkId: string }>();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["compliance", frameworkId],
    queryFn: () =>
      api
        .get<ComplianceFrameworkDetail>(
          `/api/v1/compliance/${encodeURIComponent(frameworkId ?? "")}`,
        )
        .then((r) => r.data),
    enabled: Boolean(frameworkId),
  });

  if (isLoading) return <DetailSkeleton />;
  if (error || !data) {
    return (
      <ErrorState
        title="Could not load this page"
        detail="CloudGuard could not reach its own API."
        impact="Nothing about your environment has changed — this is a problem displaying it."
        onRetry={() => refetch()}
      />
    );
  }

  const groups = groupBySection(data.controls);

  return (
    <div className="flex flex-col gap-5">
      <div>
        <Button
          variant="ghost"
          size="sm"
          className="-ml-2 mb-1 text-muted-foreground"
          render={<Link to="/compliance" />}
        >
          <ArrowLeftIcon data-icon="inline-start" />
          {t.compliance.backToFrameworks}
        </Button>
        <h1 className="text-xl font-semibold tracking-tight">{data.name}</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {data.version} · {data.authority}
        </p>
      </div>

      <EvidenceNotice />

      <Card>
        <CardContent>
          <div className="flex flex-wrap items-start justify-between gap-6">
            <div className="min-w-[16rem] flex-1">
              <CoverageBar
                counts={data.status_counts}
                total={data.control_count}
              />
            </div>
            <div className="text-right">
              <p className="text-3xl font-semibold tabular-nums tracking-tight text-foreground">
                {formatPercent(data.coverage_ratio)}
              </p>
              <p className="text-[11px] uppercase tracking-wide text-muted-foreground">
                {t.compliance.coverage}
              </p>
            </div>
          </div>
        </CardContent>
        <CardFooter className="flex-col items-start gap-2 border-t pt-4">
          <p className="text-xs leading-relaxed text-muted-foreground">
            {t.compliance.coverageHelp}
          </p>
          {!data.assessed && (
            <p className="text-xs text-muted-foreground">
              No scan has completed yet, so nothing here has been assessed.
            </p>
          )}
        </CardFooter>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t.compliance.scopeNote}</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm leading-relaxed text-muted-foreground">
            {data.scope_note}
          </p>
          <p className="mt-3 text-xs leading-relaxed text-muted-foreground">
            {t.compliance.ownWording}{" "}
            <a
              href={data.url}
              target="_blank"
              rel="noreferrer noopener"
              className="font-medium underline underline-offset-2 hover:text-foreground"
            >
              {t.compliance.source} →
            </a>
          </p>
        </CardContent>
      </Card>

      {groups.map(([group, controls]) => (
        <section key={group}>
          <h2 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
            {group}
          </h2>
          <div className="flex flex-col gap-2">
            {controls.map((control) => (
              <ControlRow key={control.id} control={control} />
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

/** Preserves catalogue order rather than sorting group names alphabetically —
 *  frameworks number their sections for a reason. */
function groupBySection(
  controls: ComplianceControl[],
): [string, ComplianceControl[]][] {
  const groups = new Map<string, ComplianceControl[]>();
  for (const control of controls) {
    const existing = groups.get(control.group);
    if (existing) existing.push(control);
    else groups.set(control.group, [control]);
  }
  return [...groups.entries()];
}

function ControlRow({ control }: { control: ComplianceControl }) {
  const t = useT();

  return (
    <Card className="py-4">
      <CardContent className="px-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <code className="text-xs font-medium text-muted-foreground">
                {control.id}
              </code>
              {/* Not a status: it says CloudGuard cannot speak to this control
                  at all, which is a different thing from having looked and
                  found nothing wrong. */}
              {!control.technically_assessable && (
                <Badge
                  variant="secondary"
                  title={t.compliance.notAssessableHelp}
                >
                  {t.compliance.notAssessable}
                </Badge>
              )}
            </div>
            <p className="mt-1 text-sm text-foreground">{control.title}</p>
          </div>
          <ControlStatusPill status={control.status} />
        </div>

        {control.rules.length > 0 ? (
          <div className="mt-3 border-t pt-3">
            <p className="text-[11px] uppercase tracking-wide text-muted-foreground">
              {t.compliance.evidenceFrom}
            </p>
            <ul className="mt-2 flex flex-col gap-1.5">
              {control.rules.map((rule) => (
                <li
                  key={rule.rule_id}
                  className="flex flex-wrap items-center gap-2 text-xs"
                >
                  <SeverityBadge level={rule.severity} size="sm" />
                  <code className="text-muted-foreground">{rule.rule_id}</code>
                  <span className="text-muted-foreground">{rule.name}</span>
                  {rule.open_finding_count > 0 && (
                    <Link
                      to={`/findings?rule_id=${encodeURIComponent(rule.rule_id)}`}
                      className="font-medium text-critical underline underline-offset-2"
                    >
                      {rule.open_finding_count} open
                    </Link>
                  )}
                  {rule.open_finding_count === 0 && rule.unknown_count > 0 && (
                    <span className="text-unknown">
                      {rule.unknown_count} could not be evaluated
                    </span>
                  )}
                  {!rule.evaluated && (
                    <span className="text-muted-foreground">
                      did not run in the last scan
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <p className="mt-3 border-t pt-3 text-xs text-muted-foreground">
            {control.technically_assessable
              ? t.compliance.noRules
              : t.compliance.notAssessableHelp}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
