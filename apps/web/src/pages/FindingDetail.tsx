import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeftIcon, CircleCheckIcon, InfoIcon } from "lucide-react";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type { FindingDetail } from "@/lib/types";
import { useT } from "@/i18n";
import { StatusPill } from "@/components/security/StatusPill";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { DetailSkeleton, ErrorState } from "@/components/common/states";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { RemediationPanel } from "@/components/security/RemediationPanel";
import { VerificationPanel } from "@/components/security/VerificationPanel";
import { FindingTimeline } from "@/components/security/FindingTimeline";
import { formatDateTime, resourceTypeLabel } from "@/lib/format";

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
    queryFn: () =>
      api
        .get<FindingDetail>(`/api/v1/findings/${findingId}`)
        .then((r) => r.data),
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["finding", findingId] });
    queryClient.invalidateQueries({ queryKey: ["findings"] });
    queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  };

  const rescan = useMutation({
    mutationFn: () =>
      api.post<{ message: string }>(`/api/v1/findings/${findingId}/rescan`),
    onSuccess: ({ data }) => {
      setNotice(data.message);
      invalidate();
    },
    onError: (err) =>
      setNotice(
        err instanceof ApiError ? err.message : "Could not start rescan",
      ),
  });

  const markInProgress = useMutation({
    mutationFn: () =>
      api.post(`/api/v1/findings/${findingId}/status?new_status=IN_PROGRESS`),
    onSuccess: invalidate,
  });

  const accept = useMutation({
    mutationFn: () =>
      api.post(`/api/v1/findings/${findingId}/accept-risk`, {
        reason: acceptReason,
      }),
    onSuccess: () => {
      setShowAccept(false);
      setAcceptReason("");
      invalidate();
    },
    onError: (err) =>
      setNotice(
        err instanceof ApiError ? err.message : "Could not accept risk",
      ),
  });

  if (isLoading) return <DetailSkeleton />;
  if (error)
    return (
      <ErrorState
        title="Could not load this finding"
        detail="CloudGuard could not reach its own API."
        impact="Nothing about your environment has changed — this is a problem displaying it."
        onRetry={() => refetch()}
      />
    );
  if (!data) return null;

  const components = data.risk?.score_breakdown?.components ?? {};

  return (
    <div className="flex flex-col gap-6">
      <Button
        variant="ghost"
        size="sm"
        className="-ml-2 self-start text-muted-foreground"
        render={<Link to="/findings" />}
      >
        <ArrowLeftIcon data-icon="inline-start" />
        {t.findings.title}
      </Button>

      {/* WHAT */}
      <div>
        <div className="flex flex-wrap items-center gap-3">
          <SeverityBadge level={data.severity} />
          <StatusPill status={data.status} />
          <span className="text-xs text-muted-foreground">
            {data.rule_id} · v{data.rule_version}
          </span>
        </div>
        <h1 className="mt-3 text-2xl font-semibold tracking-tight text-foreground">
          {data.title}
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted-foreground">
          {data.description}
        </p>
      </div>

      {/* Not a generic success: it names the scan date, because "verified"
          here means an instrument looked again and not that somebody said so. */}
      {data.status === "RESOLVED" && (
        <Alert className="border-ok-border bg-ok-bg text-ok">
          <CircleCheckIcon />
          <AlertTitle>Verified fixed</AlertTitle>
          <AlertDescription className="text-foreground">
            A scan on {formatDateTime(data.resolved_at)} confirmed this issue no
            longer exists.
          </AlertDescription>
        </Alert>
      )}

      {notice && (
        <Alert>
          <InfoIcon />
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="flex flex-col gap-6 lg:col-span-2">
          {/* WHY */}
          {data.rationale && (
            <Card>
              <CardHeader>
                <CardTitle>{t.findings.whyItMatters}</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm leading-relaxed text-foreground">
                  {data.rationale}
                </p>
              </CardContent>
            </Card>
          )}

          {/* EVIDENCE */}
          <Card>
            <CardHeader>
              <CardTitle>{t.findings.evidence}</CardTitle>
              <CardDescription>
                Exactly what CloudGuard observed
              </CardDescription>
            </CardHeader>
            <CardContent>
              <pre className="overflow-x-auto rounded-lg border bg-muted/60 p-3 font-mono text-xs leading-relaxed">
                {JSON.stringify(data.evidence, null, 2)}
              </pre>
            </CardContent>
          </Card>

          {/* HOW TO FIX */}
          <RemediationPanel
            remediation={data.remediation}
            spec={data.remediation_spec}
            effortMinutes={data.estimated_effort_minutes}
          />

          {/* DID IT WORK — only once somebody has claimed it did. */}
          {data.verification && (
            <VerificationPanel verification={data.verification} />
          )}

          {/* DID THE FIX WORK */}
          <Card>
            <CardHeader>
              <CardTitle>Verify the fix</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                {t.findings.cannotResolveManually}
              </p>
              <div className="mt-4 flex flex-wrap gap-2">
                <Button
                  onClick={() => rescan.mutate()}
                  disabled={rescan.isPending}
                >
                  {rescan.isPending && <Spinner data-icon="inline-start" />}
                  {rescan.isPending ? t.common.loading : t.findings.rescan}
                </Button>
                {data.status === "OPEN" && (
                  <Button
                    variant="secondary"
                    disabled={markInProgress.isPending}
                    onClick={() => markInProgress.mutate()}
                  >
                    {t.findings.markInProgress}
                  </Button>
                )}
                {data.status !== "ACCEPTED_RISK" &&
                  data.status !== "RESOLVED" && (
                    <Button
                      variant="ghost"
                      onClick={() => setShowAccept((v) => !v)}
                    >
                      {t.findings.acceptRisk}
                    </Button>
                  )}
              </div>

              {showAccept && (
                <form
                  className="mt-4 border-t pt-4"
                  onSubmit={(e) => {
                    e.preventDefault();
                    accept.mutate();
                  }}
                >
                  <Field>
                    <FieldLabel htmlFor="accept-reason">
                      {t.findings.acceptReason}
                    </FieldLabel>
                    <Input
                      id="accept-reason"
                      required
                      minLength={10}
                      value={acceptReason}
                      onChange={(e) => setAcceptReason(e.target.value)}
                      placeholder="Compensating control in place: WAF restricts source addresses"
                    />
                    <FieldDescription>
                      Recorded in the audit log. Accepted risks stay visible —
                      they are never hidden.
                    </FieldDescription>
                  </Field>
                  <div className="mt-3 flex gap-2">
                    <Button
                      type="submit"
                      variant="destructive"
                      disabled={accept.isPending}
                    >
                      {accept.isPending && <Spinner data-icon="inline-start" />}
                      {t.findings.confirm}
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      onClick={() => setShowAccept(false)}
                    >
                      {t.findings.cancel}
                    </Button>
                  </div>
                </form>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="flex flex-col gap-6">
          {data.timeline && data.timeline.length > 0 && (
            <FindingTimeline events={data.timeline} />
          )}
          {/* HOW BAD */}
          {data.risk && (
            <Card>
              <CardHeader>
                <CardTitle>{t.findings.riskScore}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-baseline gap-2">
                  <span className="text-4xl font-semibold tabular-nums text-foreground">
                    {Number(data.risk.risk_score).toFixed(0)}
                  </span>
                  <SeverityBadge level={data.risk.risk_level} />
                </div>

                <p className="mt-4 text-xs font-medium text-muted-foreground">
                  {t.findings.scoreBreakdown}
                </p>
                <ul className="mt-2 flex flex-col gap-1.5">
                  {Object.entries(components).map(([name, component]) => (
                    <li
                      key={name}
                      className="flex items-center justify-between gap-3 text-xs"
                    >
                      <span className="text-muted-foreground">
                        {name.replace(/_/g, " ")}
                        <span className="ml-1 text-muted-foreground">
                          ({component.value} × {component.weight})
                        </span>
                      </span>
                      <span className="font-medium tabular-nums text-foreground">
                        {component.contribution.toFixed(1)}
                      </span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}

          {data.resource && (
            <Card>
              <CardHeader>
                <CardTitle>{t.findings.asset}</CardTitle>
              </CardHeader>
              <CardContent>
                <Link
                  to={`/assets/${data.resource.id}`}
                  className="text-sm font-medium text-foreground hover:underline"
                >
                  {data.resource.name}
                </Link>
                <dl className="mt-3 flex flex-col gap-2 text-xs">
                  <Row
                    label="Type"
                    value={resourceTypeLabel(data.resource.resource_type)}
                  />
                  <Row
                    label="Environment"
                    value={data.resource.environment ?? "—"}
                  />
                  <Row label="Region" value={data.resource.region ?? "—"} />
                  <Row
                    label="Criticality"
                    value={
                      <SeverityBadge
                        level={data.resource.criticality}
                        size="sm"
                      />
                    }
                  />
                  <Row
                    label="Data sensitivity"
                    value={
                      <SeverityBadge
                        level={data.resource.data_sensitivity}
                        size="sm"
                      />
                    }
                  />
                  <Row
                    label="Internet exposure"
                    value={
                      <SeverityBadge
                        level={data.resource.public_exposure}
                        size="sm"
                      />
                    }
                  />
                </dl>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle>Timeline</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="flex flex-col gap-2 text-xs">
                <Row
                  label={t.findings.firstSeen}
                  value={formatDateTime(data.first_detected_at)}
                />
                <Row
                  label={t.findings.lastSeen}
                  value={formatDateTime(data.last_detected_at)}
                />
                {data.resolved_at && (
                  <Row
                    label={t.findings.resolvedBy}
                    value={formatDateTime(data.resolved_at)}
                  />
                )}
              </dl>
            </CardContent>
          </Card>

          {data.compliance_mappings &&
            Object.keys(data.compliance_mappings).length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>{t.findings.compliance}</CardTitle>
                  <CardDescription>
                    Evidence toward these controls — not a compliance claim
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="flex flex-col gap-2">
                    {Object.entries(data.compliance_mappings).map(
                      ([framework, controls]) => (
                        <li key={framework} className="text-xs">
                          <Link
                            to={`/compliance/${encodeURIComponent(framework)}`}
                            className="font-medium text-foreground underline underline-offset-2 hover:text-foreground"
                          >
                            {framework.replace(/_/g, " ")}
                          </Link>
                          <span className="ml-2 text-muted-foreground">
                            {controls.join(", ")}
                          </span>
                        </li>
                      ),
                    )}
                  </ul>
                </CardContent>
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
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="font-medium text-foreground">{value}</dd>
    </div>
  );
}
