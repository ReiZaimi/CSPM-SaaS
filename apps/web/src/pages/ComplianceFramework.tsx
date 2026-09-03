import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
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
import { Breadcrumbs, DetailSkeleton, ErrorState } from "@/components/common/states";
import { Badge } from "@/components/ui/badge";
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
        <Breadcrumbs
          className="mb-2"
          trail={[
            { label: t.compliance.title, to: "/compliance" },
            { label: data.name },
          ]}
        />
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
                  {/* And why, which is the half that was missing. This is the
                      one verdict on the page a reader cannot act on from the
                      verdict alone -- failing points at findings, passing needs
                      nothing, not-covered is a fact about CloudGuard. "Three
                      could not be evaluated" points nowhere, and the sentence
                      that answers it has been in the coverage ledger since
                      UNKNOWN became a recorded outcome.

                      On its own line: these are sentences rather than labels,
                      and wrapping them into the badge row would push the rule
                      name off the end on the narrow column this sits in. */}
                  {rule.unknown_reasons?.length > 0 && (
                    <ul className="w-full flex flex-col gap-0.5 pl-1">
                      {rule.unknown_reasons.map((reason) => (
                        <li
                          key={reason}
                          className="border-l-2 border-unknown-border pl-2 text-[11px] leading-relaxed text-muted-foreground"
                        >
                          {reason}
                        </li>
                      ))}
                    </ul>
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
