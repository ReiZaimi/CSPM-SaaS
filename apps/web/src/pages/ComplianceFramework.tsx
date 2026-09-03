import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { DownloadIcon } from "lucide-react";

import { api } from "@/lib/api";
import type {
  ComplianceControl,
  ComplianceFrameworkDetail,
  ControlReading,
} from "@/lib/types";
import { useT } from "@/i18n";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { saveBlob } from "@/lib/download";
import { formatDateTime, formatPercent, formatRelative } from "@/lib/format";
import { Button } from "@/components/ui/button";
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
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h1 className="text-xl font-semibold tracking-tight">{data.name}</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              {data.version} · {data.authority}
            </p>
            {/* Which reading of the estate this is an assessment of. A page
                that did not say so is a compliance claim with no date on it,
                and the export carries the same line for the same reason. */}
            {data.assessment && (
              <p className="mt-1 text-xs text-muted-foreground">
                {t.compliance.assessedFrom}{" "}
                {formatDateTime(data.assessment.completed_at)}
                {data.assessment.scan_status === "PARTIAL" && (
                  <span className="text-unknown"> · {t.compliance.assessedPartial}</span>
                )}
              </p>
            )}
          </div>
          <ExportControls frameworkId={data.id} />
        </div>
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

        <ControlReadings readings={control.readings ?? []} />
      </CardContent>
    </Card>
  );
}


/**
 * The export, which is where the chain this page draws actually ends.
 *
 * Two formats because the two readers are different: CSV goes into the
 * spreadsheet an audit is run from, JSON into a GRC platform that would
 * otherwise have somebody retyping it. Fetched with the caller's token rather
 * than linked, because the token lives in memory and a plain anchor would
 * arrive unauthenticated -- the same reason the reports page does it this way.
 */
function ExportControls({ frameworkId }: { frameworkId: string }) {
  const t = useT();
  const [failure, setFailure] = useState<string | null>(null);

  const download = useMutation({
    mutationFn: async (format: "csv" | "json") => {
      const blob = await api.document(
        `/api/v1/compliance/${encodeURIComponent(frameworkId)}/export?format=${format}`,
      );
      return { blob, format };
    },
    onSuccess: ({ blob, format }) => {
      setFailure(null);
      saveBlob(blob, `cloudguard-${frameworkId}.${format}`);
    },
    onError: (err) =>
      setFailure(err instanceof Error ? err.message : t.compliance.exportFailed),
  });

  return (
    <div className="flex shrink-0 flex-col items-end gap-1">
      <div className="flex items-center gap-2">
        <Button
          variant="secondary"
          size="sm"
          disabled={download.isPending}
          onClick={() => download.mutate("csv")}
        >
          <DownloadIcon data-icon="inline-start" />
          {download.isPending ? t.compliance.exporting : t.compliance.exportCsv}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          disabled={download.isPending}
          onClick={() => download.mutate("json")}
        >
          {t.compliance.exportJson}
        </Button>
      </div>
      <p className="max-w-xs text-right text-[11px] leading-relaxed text-muted-foreground">
        {failure ?? t.compliance.exportHelp}
      </p>
    </div>
  );
}

/**
 * The readings under a control, which is the half a compliance screen usually
 * leaves out.
 *
 * A finding cites the readings behind it, so "how do you know this is wrong"
 * was answerable. "How do you know this is met" was not: a passing control has
 * no findings, so it had no citations at all and the green row was a claim with
 * nothing behind it.
 *
 * The oldest read and the worst outcome, never an average. A control is only as
 * current and as complete as the least of the things it rests on, and averaging
 * would let forty-nine good subscriptions hide the one nobody could read.
 */
function ControlReadings({ readings }: { readings: ControlReading[] }) {
  const t = useT();
  if (readings.length === 0) return null;

  return (
    <div className="mt-3 border-t pt-3">
      <p className="text-[11px] uppercase tracking-wide text-muted-foreground">
        {t.compliance.readFrom}
      </p>
      <ul className="mt-2 flex flex-col gap-1">
        {readings.map((reading) => (
          <li
            key={reading.evidence_key}
            className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-[11px] leading-relaxed"
          >
            <code className="text-foreground">{reading.evidence_key}</code>
            {reading.outcome === null ? (
              // Not a failure, and it must not read as one: nothing collected
              // this at all, which is how a control ends up green on nothing.
              <span className="text-unknown">{t.compliance.readingNever}</span>
            ) : (
              <>
                <span
                  className={
                    reading.outcome === "COMPLETE"
                      ? "text-muted-foreground"
                      : "text-unknown"
                  }
                  title={reading.permissions.join(", ")}
                >
                  {reading.outcome.toLowerCase()}
                </span>
                <span className="text-muted-foreground">
                  {formatRelative(reading.collected_at)}
                </span>
                <span className="text-muted-foreground">
                  {reading.scopes}{" "}
                  {reading.scopes === 1
                    ? t.compliance.readingScopes
                    : t.compliance.readingScopesPlural}
                </span>
                {!reading.retained && (
                  // The citation is still true; the bytes behind it have aged
                  // out of retention. Saying which is the difference between
                  // provenance and a dead link.
                  <span className="text-muted-foreground">
                    · {t.compliance.readingPruned}
                  </span>
                )}
              </>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
