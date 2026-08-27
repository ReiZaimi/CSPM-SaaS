import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ApiError, api, auth } from "@/lib/api";
import { supabaseSignOut } from "@/lib/supabase";
import type { CloudAccount, Dashboard } from "@/lib/types";
import { useT } from "@/i18n";
import { Badge, Button, Card, EmptyState, Spinner, StatusPill } from "@/components/ui";
import { ScoreRing } from "@/components/ScoreRing";
import { formatDateTime } from "@/lib/format";

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

  if (isLoading) return <Spinner text={t.common.loading} />;
  if (error) return <DashboardError error={error} onRetry={() => refetch()} />;
  if (!data) return null;

  if (!data.last_scan) {
    const hasConnection = (accounts.data?.length ?? 0) > 0;
    return (
      <EmptyState
        title={t.dashboard.noScans}
        detail={t.dashboard.noScansHelp}
        action={
          <Link to={hasConnection ? "/scans" : "/connections"}>
            <Button>
              {hasConnection ? t.dashboard.runFirstScan : t.connection.connectAzure}
            </Button>
          </Link>
        }
      />
    );
  }

  const severity = data.findings_by_severity;
  const coveragePct =
    data.coverage.ratio === null ? null : Math.round(data.coverage.ratio * 100);

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-stone-900">
            {t.dashboard.title}
          </h1>
          <p className="mt-1 text-sm text-stone-500">
            Last assessed {formatDateTime(data.last_scan.completed_at)}
          </p>
        </div>
        <Link to="/scans">
          <Button variant="secondary">{t.scans.runScan}</Button>
        </Link>
      </header>

      <div className="grid gap-5 lg:grid-cols-12">
        {/* Score ---------------------------------------------------------- */}
        <Card className="lg:col-span-4">
          <div className="flex flex-col items-center py-2">
            <ScoreRing score={data.security_score} />

            <p className="mt-4 text-sm font-medium text-stone-700">
              {t.dashboard.score}
            </p>

            {data.score_delta !== null && data.score_delta !== 0 ? (
              <p className="mt-1 inline-flex items-center gap-1 rounded-full bg-ok-bg px-2.5 py-1 text-xs font-medium text-ok">
                <span aria-hidden="true">↑</span> {data.score_delta}{" "}
                {t.dashboard.sinceLastScan}
              </p>
            ) : (
              <p className="mt-1 text-xs text-stone-400">No change since last scan</p>
            )}
          </div>

          <dl className="mt-5 grid grid-cols-2 divide-x divide-stone-100 border-t border-stone-100 pt-4 text-center">
            <Stat label={t.dashboard.assets} value={data.asset_count} />
            <Stat label={t.dashboard.openFindings} value={data.open_finding_count} />
          </dl>
        </Card>

        {/* Severity + secondary metrics ----------------------------------- */}
        <div className="space-y-5 lg:col-span-8">
          <Card
            title="Open findings by severity"
            subtitle="Counted against each finding's risk band, not the rule's raw severity"
          >
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <SeverityTile label={t.dashboard.critical} value={severity.CRITICAL ?? 0} level="CRITICAL" />
              <SeverityTile label={t.dashboard.high} value={severity.HIGH ?? 0} level="HIGH" />
              <SeverityTile label={t.dashboard.medium} value={severity.MEDIUM ?? 0} level="MEDIUM" />
              <SeverityTile label={t.dashboard.low} value={severity.LOW ?? 0} level="LOW" />
            </div>
          </Card>

          <div className="grid gap-5 sm:grid-cols-2">
            <Card>
              <p className="text-xs font-medium uppercase tracking-wide text-stone-500">
                {t.dashboard.remediation}
              </p>
              <p className="mt-2 text-3xl font-semibold tabular-nums text-stone-900">
                {data.verified_resolved_last_30_days}
              </p>
              <p className="mt-1 text-xs leading-relaxed text-stone-500">
                {t.dashboard.resolvedRecently}
              </p>
            </Card>

            <Card>
              <p className="text-xs font-medium uppercase tracking-wide text-stone-500">
                {t.dashboard.coverage}
              </p>
              <p className="mt-2 text-3xl font-semibold tabular-nums text-stone-900">
                {coveragePct === null ? "—" : `${coveragePct}%`}
              </p>
              {coveragePct !== null && (
                <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-stone-100">
                  <div
                    className="h-full rounded-full bg-stone-700 transition-[width] duration-700"
                    style={{ width: `${coveragePct}%` }}
                  />
                </div>
              )}
              <p className="mt-2 text-xs leading-relaxed text-stone-500">
                {data.coverage.unknown > 0
                  ? `${data.coverage.unknown} ${
                      data.coverage.unknown === 1 ? "check" : "checks"
                    } couldn't be assessed`
                  : "Everything applicable was assessed"}
              </p>
            </Card>
          </div>
        </div>
      </div>

      {/* Top risks -------------------------------------------------------- */}
      <Card
        title={t.dashboard.topRisks}
        subtitle="Ranked by risk to your business, not by how many alerts fired"
        action={
          <Link
            to="/findings"
            className="text-sm font-medium text-stone-500 transition hover:text-stone-900"
          >
            View all →
          </Link>
        }
      >
        {data.top_risks.length === 0 ? (
          <p className="py-8 text-center text-sm text-stone-500">{t.dashboard.allClear}</p>
        ) : (
          <ol className="divide-y divide-stone-100">
            {data.top_risks.map((risk, index) => (
              <li key={risk.id}>
                <Link
                  to="/findings"
                  className="-mx-2 flex items-center gap-4 rounded-lg px-2 py-3 transition hover:bg-stone-50"
                >
                  <span className="w-5 shrink-0 text-sm tabular-nums text-stone-400">
                    {index + 1}
                  </span>
                  <Badge level={risk.risk_level} />
                  <span className="flex-1 truncate text-sm text-stone-800">
                    {risk.title}
                  </span>
                  <span className="shrink-0 text-sm font-semibold tabular-nums text-stone-700">
                    {Number(risk.risk_score).toFixed(0)}
                  </span>
                </Link>
              </li>
            ))}
          </ol>
        )}
      </Card>

      {/* Last scan -------------------------------------------------------- */}
      <Card title={t.dashboard.lastScan}>
        <div className="flex flex-wrap items-center gap-x-10 gap-y-4 text-sm">
          <StatusPill status={data.last_scan.status} />
          <Stat inline label="Finished" value={formatDateTime(data.last_scan.completed_at)} />
          <Stat inline label={t.scans.resources} value={data.last_scan.resource_count} />
          <Stat inline label={t.scans.rules} value={data.last_scan.rule_count} />
          <Stat inline label={t.scans.findings} value={data.last_scan.finding_count} />
        </div>

        {Object.keys(data.last_scan.collection_errors).length > 0 && (
          <div className="mt-4 rounded-lg border border-medium-border bg-medium-bg px-4 py-3">
            <p className="text-sm font-medium text-medium">{t.scans.partial}</p>
            <ul className="mt-2 space-y-1">
              {Object.entries(data.last_scan.collection_errors).map(([category, reason]) => (
                <li key={category} className="text-xs text-stone-700">
                  <strong>{category}</strong>: {reason}
                </li>
              ))}
            </ul>
          </div>
        )}
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
    <div className="mx-auto max-w-lg rounded-xl border border-critical-border bg-white p-6 shadow-sm">
      <h2 className="text-base font-semibold text-stone-900">
        {isAuth ? "Your session has expired" : t.dashboard.couldNotLoad}
      </h2>

      <p className="mt-2 text-sm leading-relaxed text-stone-600">
        {isAuth
          ? "Sign in again to continue — your data is untouched."
          : apiError?.message ?? "The API could not be reached."}
      </p>

      {apiError && !isAuth && (
        <p className="mt-3 rounded-lg bg-stone-50 px-3 py-2 font-mono text-xs text-stone-500">
          {apiError.code} · HTTP {apiError.status}
        </p>
      )}

      <div className="mt-5 flex gap-2">
        {isAuth ? (
          <Button
            onClick={() => {
              auth.signOut();
              void supabaseSignOut();
            }}
          >
            {t.dashboard.signInAgain}
          </Button>
        ) : (
          <Button onClick={onRetry}>{t.common.retry}</Button>
        )}
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  inline = false,
}: {
  label: string;
  value: string | number;
  inline?: boolean;
}) {
  return (
    <div className={inline ? "" : "px-2"}>
      <dt className="text-xs font-medium text-stone-500">{label}</dt>
      <dd className="mt-0.5 text-sm font-semibold tabular-nums text-stone-900">{value}</dd>
    </div>
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
    <div className="rounded-lg border border-stone-200 bg-white px-3 py-4 text-center transition hover:border-stone-300">
      <p className="text-3xl font-semibold tabular-nums text-stone-900">{value}</p>
      <div className="mt-2 flex justify-center">
        <Badge level={level}>{label}</Badge>
      </div>
    </div>
  );
}
