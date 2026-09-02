import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { CircleCheckIcon } from "lucide-react";
import { toast } from "sonner";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type { FindingAttackPath, FindingDetail } from "@/lib/types";
import { useT } from "@/i18n";
import { StatusPill } from "@/components/security/StatusPill";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Breadcrumbs, DetailSkeleton, ErrorState } from "@/components/common/states";
import { CodeBlock } from "@/components/common/CodeBlock";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Badge } from "@/components/ui/badge";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { AttackPathRoute } from "@/components/graph/AttackPathRoute";
import { RemediationPanel } from "@/components/security/RemediationPanel";
import { TrackFix } from "@/components/security/TrackFix";
import { VerificationPanel } from "@/components/security/VerificationPanel";
import { FindingTimeline } from "@/components/security/FindingTimeline";
import { cn, formatDateTime, resourceTypeLabel } from "@/lib/format";

/**
 * The page the whole product is really about. It must answer, in order:
 * WHAT is wrong, WHY it matters, HOW BAD it is, HOW to fix it, and DID the fix
 * work (UI.md section 3).
 */
export function FindingDetailPage() {
  const t = useT();
  const { findingId } = useParams();
  const queryClient = useQueryClient();
  const [acceptReason, setAcceptReason] = useState("");
  const [showAccept, setShowAccept] = useState(false);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["finding", findingId],
    queryFn: () =>
      api
        .get<FindingDetail>(`/api/v1/findings/${findingId}`)
        .then((r) => r.data),
  });

  /**
   * Whether this finding is part of something larger.
   *
   * A separate request rather than a field on the finding: it costs a graph
   * build, and the page that answers "what is wrong" must not wait on one. It
   * is asked for only once there is an answer to attach it to, and a finding
   * with no asset never asks at all.
   */
  const paths = useQuery({
    queryKey: ["finding-attack-paths", findingId],
    queryFn: () =>
      api
        .get<FindingAttackPath[]>(`/api/v1/findings/${findingId}/attack-paths`)
        .then((r) => r.data),
    enabled: Boolean(data?.resource),
    retry: false,
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["finding", findingId] });
    queryClient.invalidateQueries({ queryKey: ["findings"] });
    queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  };

  // Every action on this page is asynchronous and none of them navigate, so
  // each one has to say out loud what it did. Two of them used to say nothing
  // at all: marking a finding in progress and accepting a risk both changed the
  // record and left the reader looking at an unchanged screen.
  const rescan = useMutation({
    mutationFn: () =>
      api.post<{ message: string }>(`/api/v1/findings/${findingId}/rescan`),
    onSuccess: ({ data }) => {
      toast.success("Rescan requested", { description: data.message });
      invalidate();
    },
    onError: (err) =>
      toast.error("Could not start a rescan", {
        description:
          err instanceof ApiError ? err.message : "The API rejected the request.",
      }),
  });

  const markInProgress = useMutation({
    mutationFn: () =>
      api.post(`/api/v1/findings/${findingId}/status?new_status=IN_PROGRESS`),
    onSuccess: () => {
      toast.success("Marked in progress", {
        description:
          "The finding stays open until a scan observes the fix — a status is intent, not proof.",
      });
      invalidate();
    },
    onError: (err) =>
      toast.error("Could not change the status", {
        description:
          err instanceof ApiError ? err.message : "The API rejected the change.",
      }),
  });

  const accept = useMutation({
    mutationFn: () =>
      api.post(`/api/v1/findings/${findingId}/accept-risk`, {
        reason: acceptReason,
      }),
    onSuccess: () => {
      setShowAccept(false);
      setAcceptReason("");
      toast.success("Risk accepted", {
        description:
          "Recorded in the audit log with your reason. It stays visible and is counted in its own right, never as a fix.",
      });
      invalidate();
    },
    onError: (err) =>
      toast.error("Could not accept this risk", {
        description:
          err instanceof ApiError ? err.message : "The API rejected the request.",
      }),
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
      <Breadcrumbs
        trail={[
          { label: t.findings.title, to: "/findings" },
          { label: data.title },
        ]}
      />

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
          <EvidencePanel evidence={data.evidence} />

          {/* WHAT IT IS PART OF */}
          <AttackPathContext
            paths={paths.data}
            loading={paths.isLoading}
            hasAsset={Boolean(data.resource)}
          />

          {/* HOW TO FIX */}
          <RemediationPanel
            remediation={data.remediation}
            spec={data.remediation_spec}
            effortMinutes={data.estimated_effort_minutes}
            footer={
              <TrackFix
                findingId={data.id}
                status={data.status}
                effortMinutes={data.estimated_effort_minutes}
              />
            }
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

/**
 * What CloudGuard actually saw, and a way to take it with you.
 *
 * The raw capture is the reason a reader believes the finding, so it stays --
 * unsummarised, in the provider's own words. What changes is that it no longer
 * runs to four screens unasked: a long capture is clipped to a readable height
 * with the rest one click away, and it can be copied whole into a ticket, which
 * is what most people were selecting it by hand to do.
 */
function EvidencePanel({ evidence }: { evidence: unknown }) {
  const t = useT();
  const [expanded, setExpanded] = useState(false);
  const json = JSON.stringify(evidence, null, 2);
  // Roughly two screens of a small monospace font. Below this there is nothing
  // to gain by hiding any of it.
  const long = json.split("\n").length > 24;

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t.findings.evidence}</CardTitle>
        <CardDescription>Exactly what CloudGuard observed</CardDescription>
      </CardHeader>
      <CardContent>
        <Collapsible open={expanded || !long} onOpenChange={setExpanded}>
          <div className="relative">
            <CollapsibleContent
              className={cn(
                "overflow-hidden",
                // Clipped rather than scrolled: a nested scroll area inside a
                // page that also scrolls is how a reader loses the wheel.
                !expanded && long && "max-h-64",
              )}
              // Kept in the DOM when clipped, so the browser's own find still
              // reaches the part that is out of view.
              keepMounted
            >
              <CodeBlock code={json} label="Copy this evidence" />
            </CollapsibleContent>
            {!expanded && long && (
              <div
                className="pointer-events-none absolute inset-x-0 bottom-0 h-16 rounded-b-lg bg-gradient-to-t from-card to-transparent"
                aria-hidden
              />
            )}
          </div>
          {long && (
            <CollapsibleTrigger
              render={
                <Button variant="outline" size="sm" className="mt-3" />
              }
            >
              {expanded ? "Show less" : "Show the whole capture"}
            </CollapsibleTrigger>
          )}
        </Collapsible>
      </CardContent>
    </Card>
  );
}

/**
 * Whether this finding is one fault or one link in a route.
 *
 * The findings list ranks problems one at a time, which is the right order for
 * triage and the wrong story for a reader deciding how urgent one is: a medium
 * misconfiguration on a jump box that stands between the internet and customer
 * data is not a medium problem. This is the only place on the page that can say
 * so, and it says where on the route the asset sits, because that decides what
 * to do — an entry point is how somebody gets in, a target is what they came
 * for, and a hop in between is usually the cheapest place to cut.
 */
function AttackPathContext({
  paths,
  loading,
  hasAsset,
}: {
  paths: FindingAttackPath[] | undefined;
  loading: boolean;
  hasAsset: boolean;
}) {
  // A tenant-wide finding has no asset, so there is no route to be on and
  // nothing worth saying about one.
  if (!hasAsset) return null;

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Attack paths</CardTitle>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-20 w-full" />
        </CardContent>
      </Card>
    );
  }

  const routes = paths ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Attack paths</CardTitle>
        <CardDescription>
          {routes.length === 0
            ? "Whether this asset stands between something exposed and something sensitive"
            : `This asset is on ${routes.length} route${routes.length === 1 ? "" : "s"} from an exposed asset to a sensitive one`}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        {routes.length === 0 ? (
          // Not an all-clear, and it does not read as one. What counts as
          // sensitive is something the customer declares, so an estate that
          // has declared nothing produces no routes at all.
          <p className="text-sm leading-relaxed text-muted-foreground">
            CloudGuard traced no route from an internet-facing asset to a
            sensitive one through this one. What counts as sensitive is
            declared per subscription in Settings — an estate where nothing has
            been classified will also show none.
          </p>
        ) : (
          routes.slice(0, 2).map((path) => (
            <div key={`${path.entry.id}->${path.target.id}`}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-sm font-medium">
                  {path.entry.name}
                  <span className="mx-1.5 text-muted-foreground">→</span>
                  {path.target.name}
                </p>
                <Badge variant="secondary" className="font-normal">
                  {ROLE_LABEL[path.asset_role]}
                </Badge>
              </div>
              <AttackPathRoute
                className="mt-3"
                steps={path.steps}
                cutIndex={path.steps.findIndex(
                  (step) =>
                    path.cheapest_break?.source_id === step.source_id &&
                    path.cheapest_break?.target_id === step.target_id,
                )}
              />
            </div>
          ))
        )}

        {routes.length > 0 && (
          <Link
            to="/attack-paths"
            className="text-sm text-foreground underline underline-offset-2"
          >
            {routes.length > 2
              ? `See all ${routes.length} routes`
              : "See every route in this estate"}
          </Link>
        )}
      </CardContent>
    </Card>
  );
}

/** Where on the route this finding's asset sits. */
const ROLE_LABEL: Record<FindingAttackPath["asset_role"], string> = {
  ENTRY: "This asset is the way in",
  STEP: "This asset is a link in the route",
  TARGET: "This asset is the target",
};
