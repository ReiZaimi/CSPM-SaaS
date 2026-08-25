import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type { FindingDetail } from "@/lib/types";
import { useT } from "@/i18n";
import {
  Badge,
  Button,
  Card,
  ErrorNote,
  Field,
  Input,
  Spinner,
  StatusPill,
} from "@/components/ui";
import { formatDateTime, formatEffort, resourceTypeLabel } from "@/lib/format";

/**
 * The page the whole product is really about. It must answer, in order:
 * WHAT is wrong, WHY it matters, HOW BAD it is, HOW to fix it, and DID the fix
 * work (UI.md section 3).
 */
export function FindingDetailPage() {
  const t = useT();
  const { findingId } = useParams();
  const queryClient = useQueryClient();
  const [notice, setNotice] = useState<string | null>(null);
  const [acceptReason, setAcceptReason] = useState("");
  const [showAccept, setShowAccept] = useState(false);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["finding", findingId],
    queryFn: () => api.get<FindingDetail>(`/api/v1/findings/${findingId}`).then((r) => r.data),
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["finding", findingId] });
    queryClient.invalidateQueries({ queryKey: ["findings"] });
    queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  };

  const rescan = useMutation({
    mutationFn: () => api.post<{ message: string }>(`/api/v1/findings/${findingId}/rescan`),
    onSuccess: ({ data }) => {
      setNotice(data.message);
      invalidate();
    },
    onError: (err) => setNotice(err instanceof ApiError ? err.message : "Could not start rescan"),
  });

  const markInProgress = useMutation({
    mutationFn: () =>
      api.post(`/api/v1/findings/${findingId}/status?new_status=IN_PROGRESS`),
    onSuccess: invalidate,
  });

  const accept = useMutation({
    mutationFn: () =>
      api.post(`/api/v1/findings/${findingId}/accept-risk`, { reason: acceptReason }),
    onSuccess: () => {
      setShowAccept(false);
      setAcceptReason("");
      invalidate();
    },
    onError: (err) => setNotice(err instanceof ApiError ? err.message : "Could not accept risk"),
  });

  if (isLoading) return <Spinner text={t.common.loading} />;
  if (error) return <ErrorNote message={t.common.error} onRetry={() => refetch()} />;
  if (!data) return null;

  const components = data.risk?.score_breakdown?.components ?? {};

  return (
    <div className="space-y-6">
      <Link to="/findings" className="text-sm text-stone-500 hover:text-stone-900">
        ← {t.findings.title}
      </Link>

      {/* WHAT */}
      <div>
        <div className="flex flex-wrap items-center gap-3">
          <Badge level={data.severity} />
          <StatusPill status={data.status} />
          <span className="text-xs text-stone-400">
            {data.rule_id} · v{data.rule_version}
          </span>
        </div>
        <h1 className="mt-3 text-2xl font-semibold tracking-tight text-stone-900">
          {data.title}
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-relaxed text-stone-600">
          {data.description}
        </p>
      </div>

      {data.status === "RESOLVED" && (
        <div className="rounded-lg border border-ok-border bg-ok-bg px-4 py-3 text-sm text-ok">
          <strong>Verified fixed.</strong> A scan on {formatDateTime(data.resolved_at)} confirmed
          this issue no longer exists.
        </div>
      )}

      {notice && (
        <div className="rounded-lg border border-stone-200 bg-white px-4 py-3 text-sm text-stone-700">
          {notice}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          {/* WHY */}
          {data.rationale && (
            <Card title={t.findings.whyItMatters}>
              <p className="text-sm leading-relaxed text-stone-700">{data.rationale}</p>
            </Card>
          )}

          {/* EVIDENCE */}
          <Card title={t.findings.evidence} subtitle="Exactly what CloudGuard observed">
            <pre className="overflow-x-auto rounded-lg bg-stone-900 p-4 text-xs leading-relaxed text-stone-100">
              {JSON.stringify(data.evidence, null, 2)}
            </pre>
          </Card>

          {/* HOW TO FIX */}
          <Card
            title={t.findings.howToFix}
            subtitle={
              data.estimated_effort_minutes
                ? `${t.findings.effort}: ${formatEffort(data.estimated_effort_minutes)}`
                : undefined
            }
          >
            <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed text-stone-700">
              {data.remediation}
            </pre>
          </Card>

          {/* DID THE FIX WORK */}
          <Card title="Verify the fix">
            <p className="text-sm text-stone-600">{t.findings.cannotResolveManually}</p>
            <div className="mt-4 flex flex-wrap gap-2">
              <Button onClick={() => rescan.mutate()} disabled={rescan.isPending}>
                {rescan.isPending ? t.common.loading : t.findings.rescan}
              </Button>
              {data.status === "OPEN" && (
                <Button variant="secondary" onClick={() => markInProgress.mutate()}>
                  {t.findings.markInProgress}
                </Button>
              )}
              {data.status !== "ACCEPTED_RISK" && data.status !== "RESOLVED" && (
                <Button variant="ghost" onClick={() => setShowAccept((v) => !v)}>
                  {t.findings.acceptRisk}
                </Button>
              )}
            </div>

            {showAccept && (
              <form
                className="mt-4 border-t border-stone-100 pt-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  accept.mutate();
                }}
              >
                <Field
                  label={t.findings.acceptReason}
                  hint="Recorded in the audit log. Accepted risks stay visible — they are never hidden."
                >
                  <Input
                    required
                    minLength={10}
                    value={acceptReason}
                    onChange={(e) => setAcceptReason(e.target.value)}
                    placeholder="Compensating control in place: WAF restricts source addresses"
                  />
                </Field>
                <div className="mt-3 flex gap-2">
                  <Button type="submit" variant="danger" disabled={accept.isPending}>
                    {t.findings.confirm}
                  </Button>
                  <Button type="button" variant="ghost" onClick={() => setShowAccept(false)}>
                    {t.findings.cancel}
                  </Button>
                </div>
              </form>
            )}
          </Card>
        </div>

        <div className="space-y-6">
          {/* HOW BAD */}
          {data.risk && (
            <Card title={t.findings.riskScore}>
              <div className="flex items-baseline gap-2">
                <span className="text-4xl font-semibold tabular-nums text-stone-900">
                  {Number(data.risk.risk_score).toFixed(0)}
                </span>
                <Badge level={data.risk.risk_level} />
              </div>

              <p className="mt-4 text-xs font-medium text-stone-500">
                {t.findings.scoreBreakdown}
              </p>
              <ul className="mt-2 space-y-1.5">
                {Object.entries(components).map(([name, component]) => (
                  <li key={name} className="flex items-center justify-between gap-3 text-xs">
                    <span className="text-stone-600">
                      {name.replace(/_/g, " ")}
                      <span className="ml-1 text-stone-400">
                        ({component.value} × {component.weight})
                      </span>
                    </span>
                    <span className="font-medium tabular-nums text-stone-800">
                      {component.contribution.toFixed(1)}
                    </span>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          {data.resource && (
            <Card title={t.findings.asset}>
              <Link
                to={`/assets/${data.resource.id}`}
                className="text-sm font-medium text-stone-900 hover:underline"
              >
                {data.resource.name}
              </Link>
              <dl className="mt-3 space-y-2 text-xs">
                <Row label="Type" value={resourceTypeLabel(data.resource.resource_type)} />
                <Row label="Environment" value={data.resource.environment ?? "—"} />
                <Row label="Region" value={data.resource.region ?? "—"} />
                <Row label="Criticality" value={<Badge level={data.resource.criticality} />} />
                <Row label="Data sensitivity" value={<Badge level={data.resource.data_sensitivity} />} />
                <Row label="Internet exposure" value={<Badge level={data.resource.public_exposure} />} />
              </dl>
            </Card>
          )}

          <Card title="Timeline">
            <dl className="space-y-2 text-xs">
              <Row label={t.findings.firstSeen} value={formatDateTime(data.first_detected_at)} />
              <Row label={t.findings.lastSeen} value={formatDateTime(data.last_detected_at)} />
              {data.resolved_at && (
                <Row label={t.findings.resolvedBy} value={formatDateTime(data.resolved_at)} />
              )}
            </dl>
          </Card>

          {data.compliance_mappings && Object.keys(data.compliance_mappings).length > 0 && (
            <Card
              title={t.findings.compliance}
              subtitle="Evidence toward these controls — not a compliance claim"
            >
              <ul className="space-y-2">
                {Object.entries(data.compliance_mappings).map(([framework, controls]) => (
                  <li key={framework} className="text-xs">
                    <span className="font-medium text-stone-700">
                      {framework.replace(/_/g, " ")}
                    </span>
                    <span className="ml-2 text-stone-500">{controls.join(", ")}</span>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-stone-500">{label}</dt>
      <dd className="font-medium text-stone-800">{value}</dd>
    </div>
  );
}
