import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { CircleCheckIcon } from "lucide-react";
import { toast } from "sonner";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type {
  EvidenceCitation,
  FindingAttackPath,
  FindingDetail,
  FindingProvenance,
} from "@/lib/types";
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
import {
  cn,
  formatDateTime,
  formatRelative,
  outcomeStyle,
  resourceTypeLabel,
} from "@/lib/format";

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

  /**
   * How CloudGuard knows.
   *
   * A separate request for the same reason the routes are: the page answering
   * "what is wrong" must not wait on a question most readers never ask. Unlike
   * the routes it is asked for every finding, because a tenant-wide finding has
   * provenance even though it has no asset.
   */
  const provenance = useQuery({
    queryKey: ["finding-provenance", findingId],
    queryFn: () =>
      api
        .get<FindingProvenance>(`/api/v1/findings/${findingId}/provenance`)
        .then((r) => r.data),
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

          {/* WHAT IS ALREADY IN THE WAY */}
          <ControlsPanel controls={data.evidence.compensating_controls} />

          {/* EVIDENCE */}
          <EvidencePanel evidence={data.evidence} />

          {/* WHERE THAT EVIDENCE CAME FROM */}
          <ProvenancePanel
            provenance={provenance.data}
            loading={provenance.isLoading}
          />

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
/**
 * Defences that lowered this finding's score without closing it.
 *
 * Shown above the raw evidence rather than inside it, because it answers a
 * question a reader asks before they read anything: why is an administrator
 * with no second factor not at the top of the list? A score arrived at through
 * a rule nobody can see is the kind a customer stops trusting.
 *
 * The panel is deliberately not reassuring. Each of these can be switched off,
 * rescoped, or have the affected account excluded in a change nobody reviews,
 * and the misconfiguration underneath it is untouched — so the finding is still
 * open and the copy says why.
 */
function ControlsPanel({
  controls,
}: {
  controls?: FindingDetail["evidence"]["compensating_controls"];
}) {
  const t = useT();
  if (!controls?.length) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t.findings.controlsTitle}</CardTitle>
        <CardDescription>{t.findings.controlsHelp}</CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="flex flex-col gap-3">
          {controls.map((control) => (
            <li
              key={control.id}
              className="rounded-lg border border-ok-border bg-ok-bg/40 px-4 py-3"
            >
              <p className="text-sm font-medium text-foreground">{control.name}</p>
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                {control.detail}
              </p>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

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
 * Where the evidence above came from.
 *
 * The excerpt says what the rule saw. This says which listing produced it, when
 * the provider was actually read, under which permission, and whether the bytes
 * are still held — which is the difference between a claim a customer has to
 * accept and one they can check.
 *
 * Sat directly under the excerpt rather than in its own tab, because the two
 * are one thought: a reader who has just looked at a capture and wondered where
 * it came from should not have to go looking.
 */
function ProvenancePanel({
  provenance,
  loading,
}: {
  provenance?: FindingProvenance;
  loading: boolean;
}) {
  const t = useT();

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>{t.findings.provenance}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <Skeleton className="h-4 w-2/3" />
          <Skeleton className="h-4 w-1/2" />
        </CardContent>
      </Card>
    );
  }

  // A failed request is not an absent citation: saying "not recorded" here
  // would invent a fact about the finding out of a network error. Absent data
  // is the whole test -- a failed first fetch leaves it undefined, and a failed
  // *refetch* leaves the last good answer in place, which is the one that
  // should stay on screen rather than being hidden because a later request
  // fell over.
  if (!provenance) return null;

  const citations = provenance.evidence;

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t.findings.provenance}</CardTitle>
        <CardDescription>{t.findings.provenanceIntro}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {citations === null ? (
          // `null` and `[]` are different answers and the page must not blur
          // them. This one is about CloudGuard, not about the finding.
          <p className="text-sm text-muted-foreground">
            {t.findings.provenanceUnrecorded}
          </p>
        ) : citations.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {t.findings.provenanceNone}
          </p>
        ) : (
          <ul className="space-y-2">
            {citations.map((citation) => (
              <Citation key={citation.evidence_key} citation={citation} />
            ))}
          </ul>
        )}

        <p className="text-xs text-muted-foreground">
          {t.findings.provenanceRule
            .replace("{rule}", provenance.rule_id)
            .replace("{version}", provenance.rule_version)}
        </p>
      </CardContent>
    </Card>
  );
}

/** One reading, with the four things that make it checkable. */
function Citation({ citation }: { citation: EvidenceCitation }) {
  const t = useT();
  // A reading whose scan has been pruned has no outcome left to show. Rendered
  // as absent rather than as SKIPPED: "we no longer hold that" is not a verdict
  // the collector ever reached.
  const outcome = citation.outcome;

  return (
    <li className="rounded-lg border border-border bg-muted/40 px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <code className="text-sm font-medium text-foreground">
          {citation.evidence_key}
        </code>
        {outcome && (
          <Badge
            variant="outline"
            className={cn("border text-xs", outcomeStyle(outcome))}
          >
            {outcome}
          </Badge>
        )}
        {typeof citation.item_count === "number" && (
          <span className="text-xs text-muted-foreground">
            {t.findings.provenanceItems.replace(
              "{count}",
              String(citation.item_count),
            )}
          </span>
        )}
      </div>

      <dl className="mt-2 grid gap-x-6 gap-y-1 text-xs sm:grid-cols-2">
        <div className="flex gap-2">
          <dt className="text-muted-foreground">{t.findings.provenanceRead}</dt>
          {/* Relative first, because the question is "how current is this",
              and the exact moment on hover for whoever needs to cite it. */}
          <dd className="text-foreground" title={formatDateTime(citation.collected_at)}>
            {formatRelative(citation.collected_at)}
          </dd>
        </div>
        <div className="flex gap-2">
          <dt className="text-muted-foreground">
            {t.findings.provenancePayload}
          </dt>
          <dd className="text-foreground">
            {citation.payload_available
              ? t.findings.provenanceHeld
              : t.findings.provenancePruned}
          </dd>
        </div>
      </dl>

      {citation.permissions.length > 0 && (
        <p className="mt-2 text-xs text-muted-foreground">
          {t.findings.provenanceUnder}{" "}
          {citation.permissions.map((permission) => (
            <code key={permission} className="text-foreground">
              {permission}
            </code>
          ))}
        </p>
      )}

      {citation.endpoints.length > 0 && (
        // The call and the contract. Shown because an absent field in the
        // capture above is two different answers -- a setting nobody set, and
        // an api-version too old to return it -- and only this tells them
        // apart. The path is a template, so the tail is the readable part.
        <ul className="mt-2 space-y-0.5">
          {citation.endpoints.map((endpoint) => (
            <li
              key={`${endpoint.path}-${endpoint.api_version}`}
              className="font-mono text-[11px] text-muted-foreground"
              title={endpoint.path}
            >
              {endpoint.path.replace(/^https?:\/\/[^/]+/, "")}
              <span className="text-foreground">
                {" "}
                ?api-version={endpoint.api_version}
              </span>
            </li>
          ))}
        </ul>
      )}

      {citation.content_hash && (
        // Truncated because nobody reads sixty-four hex characters, and shown
        // at all because it is what makes the reading identifiable: two scans
        // citing the same hash read byte-identical bytes.
        <p
          className="mt-1 font-mono text-[11px] text-muted-foreground"
          title={citation.content_hash}
        >
          sha256 {citation.content_hash.slice(0, 12)}…
        </p>
      )}
    </li>
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
