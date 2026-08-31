import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowRightIcon, CloudOffIcon, ScanLineIcon } from "lucide-react";

import { ApiError, api, auth } from "@/lib/api";
import { supabaseSignOut } from "@/lib/supabase";
import type { CloudAccount, Dashboard } from "@/lib/types";
import { useT } from "@/i18n";
import { ScoreTrend } from "@/components/ScoreTrend";
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
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { cn, formatDateTime } from "@/lib/format";

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
            <Button render={<Link to={hasConnection ? "/scans" : "/connections"} />}>
              {hasConnection ? t.dashboard.runFirstScan : t.connection.connectAzure}
            </Button>
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
          <Button variant="outline" render={<Link to="/scans" />}>
            {t.scans.runScan}
          </Button>
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
            <ScoreTrend history={data.history ?? []} />
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
          <Button
            variant="ghost"
            size="sm"
            className="col-start-2 row-span-2 row-start-1 self-start justify-self-end"
            render={<Link to="/risks" />}
          >
            View all
            <ArrowRightIcon data-icon="inline-end" />
          </Button>
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
                  <Link
                    to="/risks"
                    className="flex items-center gap-3 border-b px-6 py-3 transition-colors last:border-0 hover:bg-accent/50"
                  >
                    <span className="w-4 shrink-0 text-xs tabular-nums text-muted-foreground">
                      {index + 1}
                    </span>
                    <SeverityBadge level={risk.risk_level} />
                    <span className="flex-1 truncate text-sm">{risk.title}</span>
                    <RiskScore score={Number(risk.risk_score)} />
                  </Link>
                </li>
              ))}
            </ol>
          )}
        </CardContent>
      </Card>

      {/* Where the numbers came from ------------------------------------- */}
      <Card>
        <CardHeader>
          <CardTitle>{t.dashboard.lastScan}</CardTitle>
          <Button
            variant="ghost"
            size="sm"
            className="col-start-2 row-span-2 row-start-1 self-start justify-self-end"
            render={<Link to="/scans" />}
          >
            Scan history
            <ArrowRightIcon data-icon="inline-end" />
          </Button>
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
