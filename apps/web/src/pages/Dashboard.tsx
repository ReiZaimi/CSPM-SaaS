import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { CloudAccount, Dashboard } from "@/lib/types";
import { useT } from "@/i18n";
import { Badge, Button, Card, EmptyState, ErrorNote, Spinner, StatusPill } from "@/components/ui";
import { formatDateTime, scoreColor } from "@/lib/format";

export function DashboardPage() {
  const t = useT();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api.get<Dashboard>("/api/v1/dashboard").then((r) => r.data),
    refetchInterval: 20_000,
  });

  const accounts = useQuery({
    queryKey: ["cloud-accounts"],
    queryFn: () => api.get<CloudAccount[]>("/api/v1/cloud-accounts").then((r) => r.data),
  });

  if (isLoading) return <Spinner text={t.common.loading} />;
  if (error) return <ErrorNote message={t.common.error} onRetry={() => refetch()} />;
  if (!data) return null;

  if (!data.last_scan) {
    const hasConnection = (accounts.data?.length ?? 0) > 0;
    return (
      <EmptyState
        title={t.dashboard.noScans}
        detail={t.dashboard.noScansHelp}
        action={
          <Link to={hasConnection ? "/scans" : "/connections"}>
            <Button>{hasConnection ? t.dashboard.runFirstScan : t.connect.createConnection}</Button>
          </Link>
        }
      />
    );
  }

  const severity = data.findings_by_severity;

  return (
    <div className="space-y-6">
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <p className="text-sm font-medium text-stone-500">{t.dashboard.score}</p>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-5xl font-semibold tabular-nums ${scoreColor(data.security_score)}`}>
              {data.security_score}
            </span>
            <span className="text-sm text-stone-400">{t.dashboard.outOf}</span>
          </div>
          {data.score_delta !== null && data.score_delta !== 0 && (
            <p className="mt-2 text-sm text-ok">
              +{data.score_delta} {t.dashboard.sinceLastScan}
            </p>
          )}
          <div className="mt-5 grid grid-cols-2 gap-3 border-t border-stone-100 pt-4 text-sm">
            <Stat label={t.dashboard.assets} value={data.asset_count} />
            <Stat label="Open findings" value={data.open_finding_count} />
          </div>
        </Card>

        <Card className="lg:col-span-2" title="Open findings by severity">
          <div className="grid grid-cols-4 gap-3">
            <SeverityTile label={t.dashboard.critical} value={severity.CRITICAL ?? 0} level="CRITICAL" />
            <SeverityTile label={t.dashboard.high} value={severity.HIGH ?? 0} level="HIGH" />
            <SeverityTile label={t.dashboard.medium} value={severity.MEDIUM ?? 0} level="MEDIUM" />
            <SeverityTile label={t.dashboard.low} value={severity.LOW ?? 0} level="LOW" />
          </div>

          <div className="mt-5 grid gap-4 border-t border-stone-100 pt-4 sm:grid-cols-2">
            <div>
              <p className="text-xs font-medium text-stone-500">{t.dashboard.remediation}</p>
              <p className="mt-1 text-sm text-stone-800">
                <span className="text-2xl font-semibold tabular-nums">
                  {data.verified_resolved_last_30_days}
                </span>{" "}
                <span className="text-stone-500">{t.dashboard.resolvedRecently}</span>
              </p>
            </div>
            <div>
              <p className="text-xs font-medium text-stone-500">{t.dashboard.coverage}</p>
              <p className="mt-1 text-sm">
                <span className="text-2xl font-semibold tabular-nums">
                  {data.coverage.ratio === null
                    ? "—"
                    : `${Math.round(data.coverage.ratio * 100)}%`}
                </span>
                {data.coverage.unknown > 0 && (
                  <span className="ml-2 text-stone-500">
                    {data.coverage.unknown} check{data.coverage.unknown === 1 ? "" : "s"} could not
                    be assessed
                  </span>
                )}
              </p>
              <p className="mt-1 text-xs leading-relaxed text-stone-500">
                {t.dashboard.coverageHelp}
              </p>
            </div>
          </div>
        </Card>
      </div>

      <Card
        title={t.dashboard.topRisks}
        subtitle="Ranked by risk to your business, not by how many alerts fired"
        action={
          <Link to="/findings" className="text-sm text-stone-500 hover:text-stone-900">
            View all
          </Link>
        }
      >
        {data.top_risks.length === 0 ? (
          <p className="py-6 text-center text-sm text-stone-500">{t.dashboard.allClear}</p>
        ) : (
          <ol className="divide-y divide-stone-100">
            {data.top_risks.map((risk, index) => (
              <li key={risk.id} className="flex items-center gap-4 py-3 first:pt-0 last:pb-0">
                <span className="w-5 text-sm tabular-nums text-stone-400">{index + 1}</span>
                <Badge level={risk.risk_level} />
                <span className="flex-1 text-sm text-stone-800">{risk.title}</span>
                <span className="text-sm font-medium tabular-nums text-stone-600">
                  {Number(risk.risk_score).toFixed(0)}
                </span>
              </li>
            ))}
          </ol>
        )}
      </Card>

      <Card title="Last scan">
        <div className="flex flex-wrap items-center gap-x-8 gap-y-3 text-sm">
          <StatusPill status={data.last_scan.status} />
          <Stat label="Completed" value={formatDateTime(data.last_scan.completed_at)} />
          <Stat label={t.scans.resources} value={data.last_scan.resource_count} />
          <Stat label={t.scans.rules} value={data.last_scan.rule_count} />
          <Stat label={t.scans.findings} value={data.last_scan.finding_count} />
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

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <p className="text-xs font-medium text-stone-500">{label}</p>
      <p className="mt-0.5 font-medium tabular-nums text-stone-900">{value}</p>
    </div>
  );
}

function SeverityTile({ label, value, level }: { label: string; value: number; level: string }) {
  return (
    <div className="rounded-lg border border-stone-200 px-3 py-3 text-center">
      <p className="text-2xl font-semibold tabular-nums text-stone-900">{value}</p>
      <div className="mt-1.5 flex justify-center">
        <Badge level={level}>{label}</Badge>
      </div>
    </div>
  );
}
