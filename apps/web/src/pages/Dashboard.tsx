import { Suspense, lazy } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowRightIcon,
  CloudOffIcon,
  GitCompareArrowsIcon,
  RouteIcon,
  ScanLineIcon,
  ScissorsIcon,
} from "lucide-react";

import { ApiError, api, auth } from "@/lib/api";
import { supabaseSignOut } from "@/lib/supabase";
import type { AttackPath, ChangeEvent, CloudAccount, Dashboard } from "@/lib/types";
import { useT } from "@/i18n";
/**
 * The chart, fetched after the page it sits on.
 *
 * Recharts is by a wide margin the largest thing this app ships, and it draws
 * one panel on one screen. Loading it inline made the dashboard's numbers --
 * the part somebody actually came for -- wait on a library that only decorates
 * them. Split out, the score renders immediately and the line fills in.
 */
const ScoreTrend = lazy(() =>
  import("@/components/ScoreTrend").then((m) => ({ default: m.ScoreTrend })),
);
import { SecurityScore, RiskScore } from "@/components/security/SecurityScore";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { CoverageIndicator } from "@/components/security/CoverageIndicator";
import { StatusPill } from "@/components/security/StatusPill";
import {
  DashboardSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { Button, buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, formatDate, formatDateTime } from "@/lib/format";

/**
 * The page that answers "how secure am I right now".
 *
 * Read top to bottom it is one argument: here is the score and which way it is
 * moving, here is what it is made of, here are the specific things to go and
 * fix, and here is how much of your environment CloudGuard could actually see
 * while forming the opinion. The last of those used to be a small tile beside
 * three others; it is now given equal weight to the score, because a score
 * computed over half an environment is a different claim from the same number
 * computed over all of it.
 */
export function DashboardPage() {
  const t = useT();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api.get<Dashboard>("/api/v1/dashboard").then((r) => r.data),
    refetchInterval: 20_000,
    retry: false, // a 401 will not fix itself; surface it immediately
  });

  const accounts = useQuery({
    queryKey: ["cloud-accounts"],
    queryFn: () => api.get<CloudAccount[]>("/api/v1/cloud-accounts").then((r) => r.data),
    retry: false,
  });

  // The two readings the dashboard was missing, and each is a different kind of
  // question from the score. "What is wrong together" ranks by how few hops
  // separate the internet from something worth taking, and "what moved" is the
  // only thing here that is about the last week rather than about right now.
  // Both are asked for small and fail quietly: a dashboard that cannot draw its
  // last panel is still a dashboard.
  const paths = useQuery({
    queryKey: ["dashboard-attack-paths"],
    queryFn: () =>
      api.get<AttackPath[]>("/api/v1/attack-paths?limit=3").then((r) => r.data),
    retry: false,
  });

  const changes = useQuery({
    queryKey: ["dashboard-changes"],
    queryFn: () =>
      api.get<ChangeEvent[]>("/api/v1/changes?days=7&limit=5").then((r) => r.data),
    retry: false,
  });

  if (isLoading) return <DashboardSkeleton />;
  if (error) return <DashboardError error={error} onRetry={() => refetch()} />;
  if (!data) return null;

  if (!data.last_scan) {
    const hasConnection = (accounts.data?.length ?? 0) > 0;
    return (
      <div className="flex flex-col gap-4">
        <PageHeader title={t.dashboard.title} />
        <EmptyState
          icon={hasConnection ? ScanLineIcon : CloudOffIcon}
          title={hasConnection ? t.dashboard.noScans : "Connect your cloud environment"}
          detail={
            hasConnection
              ? t.dashboard.noScansHelp
              : "CloudGuard needs read access to your Azure environment before it can assess anything. It holds no credential of yours and performs no writes."
          }
          action={
            <Link
              to={hasConnection ? "/scans" : "/connections"}
              className={buttonVariants()}
            >
              {hasConnection ? t.dashboard.runFirstScan : t.connection.connectAzure}
            </Link>
          }
        />
      </div>
    );
  }

  const severity = data.findings_by_severity;
  const gaps = Object.entries(data.last_scan.collection_errors ?? {});

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title={t.dashboard.title}
        description={`Last assessed ${formatDateTime(data.last_scan.completed_at)}`}
        actions={
          <>
            <Link to="/scans" className={buttonVariants({ variant: "outline" })}>
              {t.scans.runScan}
            </Link>
            {/* The two things anyone does with a posture: read it again, or
                write it down. This page is where the second decision gets
                made -- somebody looking at a score is the person who wants it
                on paper -- and until now nothing here said reports existed. */}
            <Link to="/reports" className={buttonVariants({ variant: "ghost" })}>
              {t.reports.title}
              <ArrowRightIcon data-icon="inline-end" />
            </Link>
          </>
        }
      />

      {/* Posture ---------------------------------------------------------- */}
      <div className="grid gap-4 lg:grid-cols-12">
        <Card className="lg:col-span-5">
          <CardHeader>
            <CardTitle>{t.dashboard.score}</CardTitle>
            <CardDescription>
              Deducted against each finding's risk band, not the number of alerts
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-5">
            <SecurityScore
              score={data.security_score}
              delta={data.score_delta}
              scannedAt={data.last_scan.completed_at}
            />
            <Separator />
            {/* Sized to the chart it replaces, so the card does not resize
                under the reader when the line arrives. */}
            <Suspense fallback={<Skeleton className="h-48 w-full" />}>
              <ScoreTrend history={data.history ?? []} />
            </Suspense>
          </CardContent>
        </Card>

        <Card className="lg:col-span-7">
          <CardHeader>
            <CardTitle>Open findings</CardTitle>
            <CardDescription>
              What is currently wrong, by how serious it is on the asset it was found on
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <SeverityTile label={t.dashboard.critical} value={severity.CRITICAL ?? 0} level="CRITICAL" />
              <SeverityTile label={t.dashboard.high} value={severity.HIGH ?? 0} level="HIGH" />
              <SeverityTile label={t.dashboard.medium} value={severity.MEDIUM ?? 0} level="MEDIUM" />
              <SeverityTile label={t.dashboard.low} value={severity.LOW ?? 0} level="LOW" />
            </div>

            <Separator />

            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
              <Metric label={t.dashboard.assets} value={data.asset_count} to="/assets" />
              <Metric
                label={t.dashboard.openFindings}
                value={data.open_finding_count}
                to="/findings"
              />
              <Metric
                label={t.dashboard.remediation}
                value={data.verified_resolved_last_30_days}
                hint={t.dashboard.resolvedRecently}
              />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* What CloudGuard could see --------------------------------------- */}
      <CoverageIndicator
        ratio={data.coverage.ratio}
        unknown={data.coverage.unknown}
        conclusive={data.coverage.conclusive}
        gaps={gaps}
        freshness={data.evidence_freshness ?? null}
      />

      {/* What to do next -------------------------------------------------- */}
      <Card>
        <CardHeader>
          <CardTitle>{t.dashboard.topRisks}</CardTitle>
          <CardDescription>
            Ranked by risk to your business, not by how many alerts fired
          </CardDescription>
          <Link
            to="/risks"
            className={cn(
              buttonVariants({ variant: "ghost", size: "sm" }),
              "col-start-2 row-span-2 row-start-1 self-start justify-self-end",
            )}
          >
            View all
            <ArrowRightIcon data-icon="inline-end" />
          </Link>
        </CardHeader>
        <CardContent className="px-0">
          {data.top_risks.length === 0 ? (
            <p className="px-6 py-8 text-center text-sm text-muted-foreground">
              {t.dashboard.allClear}
            </p>
          ) : (
            <ol>
              {data.top_risks.map((risk, index) => (
                <li key={risk.id}>
                  {/* The risk itself, not the list it came from. Ranking five
                      risks and then sending every one of them to the same
                      unfiltered table made the reader find their way back to
                      the row they had just clicked. */}
                  <Link
                    to={`/risks/${risk.id}`}
                    className="group flex items-center gap-3 border-b px-6 py-3 transition-colors last:border-0 hover:bg-accent/50"
                  >
                    <span className="w-4 shrink-0 text-xs tabular-nums text-muted-foreground">
                      {index + 1}
                    </span>
                    <SeverityBadge level={risk.risk_level} />
                    <span className="flex-1 truncate text-sm">{risk.title}</span>
                    <RiskScore score={Number(risk.risk_score)} />
                    <ArrowRightIcon
                      className="size-4 shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100"
                      aria-hidden
                    />
                  </Link>
                </li>
              ))}
            </ol>
          )}
        </CardContent>
      </Card>

      {/* What is wrong together, and what moved --------------------------- */}
      <div className="grid gap-4 lg:grid-cols-2">
        <AttackPathsPanel paths={paths.data} />
        <RecentChangesPanel events={changes.data} />
      </div>

      {/* Where the numbers came from ------------------------------------- */}
      <Card>
        <CardHeader>
          <CardTitle>{t.dashboard.lastScan}</CardTitle>
          <Link
            to="/scans"
            className={cn(
              buttonVariants({ variant: "ghost", size: "sm" }),
              "col-start-2 row-span-2 row-start-1 self-start justify-self-end",
            )}
          >
            Scan history
            <ArrowRightIcon data-icon="inline-end" />
          </Link>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-x-8 gap-y-3 text-sm">
          <StatusPill status={data.last_scan.status} />
          <InlineStat label="Finished" value={formatDateTime(data.last_scan.completed_at)} />
          <InlineStat label={t.scans.resources} value={data.last_scan.resource_count} />
          <InlineStat label={t.scans.rules} value={data.last_scan.rule_count} />
          <InlineStat label={t.scans.findings} value={data.last_scan.finding_count} />
        </CardContent>
      </Card>
    </div>
  );
}

/**
 * A failed dashboard load used to render "Something went wrong", which told the
 * reader nothing and sent them to the browser console. The API already returns a
 * machine-readable code and a written message in every error envelope, so show
 * them — and for an expired session, offer the action that actually fixes it.
 */
function DashboardError({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const t = useT();
  const apiError = error instanceof ApiError ? error : null;
  const isAuth = apiError?.status === 401;

  return (
    <div className="mx-auto max-w-lg">
      <ErrorState
        title={isAuth ? "Your session has expired" : t.dashboard.couldNotLoad}
        detail={
          isAuth
            ? "Sign in again to continue — your data is untouched."
            : apiError?.message ?? "The API could not be reached."
        }
        impact={
          isAuth
            ? undefined
            : "This is a problem loading the page, not a change in your posture — nothing has been reassessed."
        }
        onRetry={isAuth ? undefined : onRetry}
        action={
          isAuth ? (
            <Button
              size="sm"
              onClick={() => {
                auth.signOut();
                void supabaseSignOut();
              }}
            >
              {t.dashboard.signInAgain}
            </Button>
          ) : apiError ? (
            <span className="font-mono text-xs text-muted-foreground">
              {apiError.code} · HTTP {apiError.status}
            </span>
          ) : undefined
        }
      />
    </div>
  );
}

/**
 * The shortest routes, named rather than counted.
 *
 * Three at most, and each one says where it starts, what it reaches and how
 * many links are in between -- because the number of paths is not a thing
 * anybody can act on and "internet → jump box → identity → customer data" is.
 */
function AttackPathsPanel({ paths }: { paths: AttackPath[] | undefined }) {
  const t = useT();
  // Guarded rather than trusted: this panel is the least important thing on
  // the page and must never be the reason it fails to render.
  const rows = Array.isArray(paths) ? paths.slice(0, 3) : [];

  return (
    <Card className="flex flex-col">
      <CardHeader>
        <CardTitle>{t.attackPaths.title}</CardTitle>
        <CardDescription>
          What is wrong together — ranked by how few hops separate the internet
          from something worth taking
        </CardDescription>
        <Link
          to="/attack-paths"
          className={cn(
            buttonVariants({ variant: "ghost", size: "sm" }),
            "col-start-2 row-span-2 row-start-1 self-start justify-self-end",
          )}
        >
          View all
          <ArrowRightIcon data-icon="inline-end" />
        </Link>
      </CardHeader>
      <CardContent className="flex-1 px-0">
        {rows.length === 0 ? (
          <p className="px-6 pb-2 text-sm leading-relaxed text-muted-foreground">
            No route from an exposed asset to a sensitive one in the last scan.
            What counts as sensitive is something you declare, so the attack
            paths page says what CloudGuard had to work with.
          </p>
        ) : (
          <ol>
            {rows.map((path) => (
              <li key={`${path.entry.id}->${path.target.id}`}>
                <Link
                  to="/attack-paths"
                  className="flex items-start gap-3 border-b px-6 py-3 transition-colors last:border-0 hover:bg-accent/50"
                >
                  <RouteIcon
                    className="mt-0.5 size-4 shrink-0 text-muted-foreground"
                    aria-hidden
                  />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm">
                      {path.entry.name}
                      <span className="mx-1.5 text-muted-foreground">→</span>
                      {path.target.name}
                    </p>
                    {path.cheapest_break && (
                      <p className="mt-0.5 flex items-center gap-1 truncate text-xs text-ok">
                        <ScissorsIcon className="size-3 shrink-0" aria-hidden />
                        {path.cheapest_break.description}
                      </p>
                    )}
                  </div>
                  <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
                    {path.hops}{" "}
                    {path.hops === 1 ? t.attackPaths.oneHop : t.attackPaths.hops}
                  </span>
                </Link>
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * What moved this week.
 *
 * Everything else on this page is a photograph of now. This is the only panel
 * that answers the question somebody actually asks after a week away, and it
 * is deliberately small: five rows and a way through to the feed.
 */
function RecentChangesPanel({ events }: { events: ChangeEvent[] | undefined }) {
  const t = useT();
  const rows = Array.isArray(events) ? events.slice(0, 5) : [];

  return (
    <Card className="flex flex-col">
      <CardHeader>
        <CardTitle>{t.changes.title}</CardTitle>
        <CardDescription>
          What moved in the last seven days, newest first
        </CardDescription>
        <Link
          to="/changes"
          className={cn(
            buttonVariants({ variant: "ghost", size: "sm" }),
            "col-start-2 row-span-2 row-start-1 self-start justify-self-end",
          )}
        >
          View all
          <ArrowRightIcon data-icon="inline-end" />
        </Link>
      </CardHeader>
      <CardContent className="flex-1 px-0">
        {rows.length === 0 ? (
          <p className="px-6 pb-2 text-sm leading-relaxed text-muted-foreground">
            {t.changes.empty}. A scan that finds nothing different writes
            nothing here, so this is a quiet week rather than a gap.
          </p>
        ) : (
          <ol>
            {rows.map((event) => (
              <li key={event.id}>
                <Link
                  to="/changes"
                  className="flex items-center gap-3 border-b px-6 py-3 transition-colors last:border-0 hover:bg-accent/50"
                >
                  <GitCompareArrowsIcon
                    className="size-4 shrink-0 text-muted-foreground"
                    aria-hidden
                  />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm">{event.asset.name}</p>
                    <p className="truncate text-xs text-muted-foreground">
                      {t.changes.kind[event.change]}
                      {event.previous_value && event.current_value && (
                        <>
                          {" · "}
                          {event.previous_value} → {event.current_value}
                        </>
                      )}
                    </p>
                  </div>
                  <span className="shrink-0 text-xs text-muted-foreground">
                    {formatDate(event.observed_at)}
                  </span>
                </Link>
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}

function InlineStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 font-medium tabular-nums">{value}</dd>
    </div>
  );
}

/** A number that is also a way in. Every count on this page is a question. */
function Metric({
  label,
  value,
  hint,
  to,
}: {
  label: string;
  value: number;
  hint?: string;
  to?: string;
}) {
  const body = (
    <>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums">{value}</p>
      {hint && <p className="mt-0.5 text-xs leading-snug text-muted-foreground">{hint}</p>}
    </>
  );
  if (!to) return <div>{body}</div>;
  return (
    <Link
      to={to}
      className="-m-2 rounded-md p-2 transition-colors hover:bg-accent/50 focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
    >
      {body}
    </Link>
  );
}

function SeverityTile({
  label,
  value,
  level,
}: {
  label: string;
  value: number;
  level: string;
}) {
  return (
    <Link
      to={`/findings?severity=${level}`}
      className={cn(
        "rounded-lg border px-3 py-3 text-center transition-colors hover:bg-accent/50",
        "focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50",
        // A zero is not an alarm. Muting it keeps the reader's eye on the
        // counts that have something in them.
        value === 0 && "opacity-60",
      )}
    >
      <p className="text-2xl font-semibold tabular-nums">{value}</p>
      <div className="mt-1.5 flex justify-center">
        <SeverityBadge level={level} size="sm">
          {label}
        </SeverityBadge>
      </div>
    </Link>
  );
}
