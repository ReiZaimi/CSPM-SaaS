import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { CloudOffIcon, ScanLineIcon } from "lucide-react";

import { ApiError, api, auth } from "@/lib/api";
import { supabaseSignOut } from "@/lib/supabase";
import type {
  AttackPath,
  ChangeEvent,
  CloudAccount,
  ComplianceFramework,
  Dashboard,
  Scan,
} from "@/lib/types";
import { useT } from "@/i18n";
import { PostureHeader } from "@/components/dashboard/PostureHeader";
import { ScorePanel } from "@/components/dashboard/ScorePanel";
import { SeverityStrip } from "@/components/dashboard/SeverityStrip";
import { PostureBreakdown } from "@/components/dashboard/PostureBreakdown";
import { ComplianceSummary } from "@/components/dashboard/ComplianceSummary";
import { CoveragePanel } from "@/components/dashboard/CoveragePanel";
import { PriorityRisks } from "@/components/dashboard/PriorityRisks";
import { AttackPathPanel } from "@/components/dashboard/AttackPathPanel";
import { RemediationProgress } from "@/components/dashboard/RemediationProgress";
import { RecentChanges } from "@/components/dashboard/RecentChanges";
import { DashboardSkeleton, EmptyState, ErrorState } from "@/components/common/states";
import { Button, buttonVariants } from "@/components/ui/button";

/** Scan statuses that mean CloudGuard is reading the cloud right now. */
const RUNNING = new Set([
  "QUEUED",
  "DISCOVERING",
  "NORMALIZING",
  "EVALUATING",
  "CALCULATING_RISK",
]);

/**
 * The page that answers "how secure am I right now", read top to bottom as one
 * argument rather than as a wall of cards.
 *
 * The order is the argument, and each step is the precondition for the next:
 *
 *   where the posture stands, and which way it is moving      (score, trend)
 *   what that number is made of                               (severity)
 *   how much of the estate the opinion was formed from        (coverage)
 *   what to deal with, and what those faults form together    (risks, path)
 *   whether any of it is actually getting fixed               (remediation)
 *   what moved while you were away                            (changes)
 *
 * Coverage sits third on purpose. A score computed over half an environment is
 * a different claim from the same number computed over all of it, and a reader
 * who has already acted on the risks below has been told too late.
 *
 * Inventory counts — assets, subscriptions, resources — are deliberately not on
 * this page as headline figures. They are true and they answer a different
 * question, and every pixel one takes is a pixel not spent on what is wrong.
 *
 * Three requests, not one. The dashboard aggregate is a set of database
 * aggregates and answers quickly; attack paths cost a graph build and changes
 * are a windowed feed, so folding them into the primary payload would make the
 * numbers everybody came for wait on the two panels nobody scrolls to first.
 * Both fail quietly: a dashboard that cannot draw its last panel is still a
 * dashboard.
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

  const paths = useQuery({
    queryKey: ["dashboard-attack-paths"],
    queryFn: () =>
      api.get<AttackPath[]>("/api/v1/attack-paths?limit=1").then((r) => r.data),
    retry: false,
  });

  const changes = useQuery({
    queryKey: ["dashboard-changes"],
    queryFn: () =>
      api.get<ChangeEvent[]>("/api/v1/changes?days=7&limit=5").then((r) => r.data),
    retry: false,
  });

  const compliance = useQuery({
    queryKey: ["compliance"],
    queryFn: () =>
      api.get<ComplianceFramework[]>("/api/v1/compliance").then((r) => r.data),
    retry: false,
  });

  // Whether a scan is in flight, which changes what the freshness pill means:
  // numbers about to move are not the same as numbers going stale.
  const scans = useQuery({
    queryKey: ["scans", "indicator"],
    queryFn: () => api.get<Scan[]>("/api/v1/scans?limit=5").then((r) => r.data),
    retry: false,
  });

  if (isLoading) return <DashboardSkeleton />;
  if (error) return <DashboardError error={error} onRetry={() => refetch()} />;
  if (!data) return null;

  if (!data.last_scan) {
    const hasConnection = (accounts.data?.length ?? 0) > 0;
    return (
      <div className="flex flex-col gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">
            {t.dashboard.title}
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Your cloud security posture, and what CloudGuard could see while
            forming it.
          </p>
        </div>
        {/* No score is rendered before a scan exists. A number over no evidence
            is a number about nothing, and a reassuring one is worse. */}
        <EmptyState
          icon={hasConnection ? ScanLineIcon : CloudOffIcon}
          title={
            hasConnection
              ? "Your posture is ready to be assessed"
              : "Connect your cloud environment"
          }
          detail={
            hasConnection
              ? "CloudGuard is connected but has not read this environment yet. Nothing here is scored until a scan has."
              : "CloudGuard needs read access to your Azure environment before it can assess anything. It holds no credential of yours and performs no writes."
          }
          action={
            <Link
              to={hasConnection ? "/scans" : "/connections/new"}
              className={buttonVariants()}
            >
              {hasConnection ? t.dashboard.runFirstScan : t.connection.connectCloud}
            </Link>
          }
        />
      </div>
    );
  }

  const scanning = Array.isArray(scans.data)
    ? scans.data.some((scan) => RUNNING.has(scan.status))
    : false;
  const gaps = Object.entries(data.last_scan.collection_errors ?? {});

  return (
    <div className="flex flex-col gap-4">
      <PostureHeader
        scannedAt={data.last_scan.completed_at}
        staleHours={data.evidence_freshness?.stale_hours ?? null}
        scanning={scanning}
      />

      {/* 1 — where we stand, and which way it is going */}
      <ScorePanel
        score={data.security_score}
        delta={data.score_delta}
        history={data.history ?? []}
        scannedAt={data.last_scan.completed_at}
      />

      {/* 2 — what that number is made of */}
      <SeverityStrip
        counts={data.findings_by_severity}
        unknown={data.coverage.unknown}
        history={data.history ?? []}
      />

      {/* 2b — the shape of what is open: mix, standing, and risk bands */}
      <PostureBreakdown
        bySeverity={data.findings_by_severity}
        byStatus={data.findings_by_status}
        riskBands={data.risk_bands}
      />

      {/* 3 — how much of the estate the opinion was formed from */}
      <CoveragePanel
        ratio={data.coverage.ratio}
        unknown={data.coverage.unknown}
        conclusive={data.coverage.conclusive}
        categories={data.coverage.categories}
        context={data.coverage.context}
        gaps={gaps}
        freshness={data.evidence_freshness ?? null}
      />

      {/* 4 — what to deal with, and what those faults form together */}
      <div className="grid gap-4 lg:grid-cols-2">
        <PriorityRisks risks={data.top_risks} />
        <AttackPathPanel
          paths={paths.data}
          loading={paths.isLoading}
          history={data.history ?? []}
        />
      </div>

      {/* 5 — whether any of it is being fixed, and what moved meanwhile */}
      <div className="grid gap-4 lg:grid-cols-2">
        <RemediationProgress
          rate={data.remediation_rate}
          verifiedLast30Days={data.verified_resolved_last_30_days}
          openFindings={data.open_finding_count}
          activity={data.remediation_activity ?? []}
        />
        <RecentChanges events={changes.data} loading={changes.isLoading} />
      </div>

      {/* 6 — what the evidence adds up to for somebody who reports on it */}
      <ComplianceSummary
        frameworks={
          Array.isArray(compliance.data) ? compliance.data : undefined
        }
        loading={compliance.isLoading}
      />
    </div>
  );
}

/**
 * A failed dashboard load used to render "Something went wrong", which told the
 * reader nothing and sent them to the browser console. The API returns a
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
