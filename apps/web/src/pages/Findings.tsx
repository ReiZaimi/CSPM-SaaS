import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";
import { useT } from "@/i18n";
import { Badge, Card, EmptyState, ErrorNote, Select, Spinner, StatusPill } from "@/components/ui";
import { formatDate, resourceTypeLabel } from "@/lib/format";

export function FindingsPage() {
  const t = useT();
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("OPEN");

  const params = new URLSearchParams();
  if (severity) params.set("severity", severity);
  if (status) params.set("status", status);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["findings", severity, status],
    queryFn: () =>
      api.get<Finding[]>(`/api/v1/findings?${params.toString()}`).then((r) => r.data),
  });

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold tracking-tight">{t.findings.title}</h1>
        <div className="flex gap-2">
          <Select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">{t.common.all} severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </Select>
          <Select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">{t.common.all} statuses</option>
            <option value="OPEN">Open</option>
            <option value="IN_PROGRESS">In progress</option>
            <option value="RESOLVED">Verified fixed</option>
            <option value="ACCEPTED_RISK">Risk accepted</option>
          </Select>
        </div>
      </div>

      {isLoading && <Spinner text={t.common.loading} />}
      {error && <ErrorNote message={t.common.error} onRetry={() => refetch()} />}

      {data && data.length === 0 && <EmptyState title={t.findings.empty} />}

      {data && data.length > 0 && (
        <Card className="overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-stone-200 bg-stone-50 text-left">
                <tr className="text-xs font-medium uppercase tracking-wide text-stone-500">
                  <th className="px-5 py-3">Finding</th>
                  <th className="px-5 py-3">{t.common.severity}</th>
                  <th className="px-5 py-3">{t.findings.asset}</th>
                  <th className="px-5 py-3 text-right">{t.findings.riskScore}</th>
                  <th className="px-5 py-3">{t.common.status}</th>
                  <th className="px-5 py-3">{t.findings.lastSeen}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-stone-100">
                {data.map((finding) => (
                  <tr key={finding.id} className="hover:bg-stone-50">
                    <td className="px-5 py-3">
                      <Link
                        to={`/findings/${finding.id}`}
                        className="font-medium text-stone-900 hover:underline"
                      >
                        {finding.title}
                      </Link>
                      <p className="mt-0.5 text-xs text-stone-500">{finding.rule_id}</p>
                    </td>
                    <td className="px-5 py-3">
                      <Badge level={finding.severity} />
                    </td>
                    <td className="px-5 py-3 text-stone-600">
                      {finding.resource ? (
                        <>
                          <span className="block">{finding.resource.name}</span>
                          <span className="text-xs text-stone-400">
                            {resourceTypeLabel(finding.resource.resource_type)}
                          </span>
                        </>
                      ) : (
                        <span className="text-stone-400">Tenant-wide</span>
                      )}
                    </td>
                    <td className="px-5 py-3 text-right font-medium tabular-nums">
                      {finding.risk_score === null ? "—" : Number(finding.risk_score).toFixed(0)}
                    </td>
                    <td className="px-5 py-3">
                      <StatusPill status={finding.status} />
                    </td>
                    <td className="px-5 py-3 text-stone-500">
                      {formatDate(finding.last_detected_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
