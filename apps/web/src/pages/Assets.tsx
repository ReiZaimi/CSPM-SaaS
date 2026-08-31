import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { Asset } from "@/lib/types";
import { useT } from "@/i18n";
import { Badge, Card, EmptyState, Input, Select } from "@/components/ui";
import { formatDate, resourceTypeLabel } from "@/lib/format";
import { ErrorState, TableSkeleton } from "@/components/common/states";

export function AssetsPage() {
  const t = useT();
  const [search, setSearch] = useState("");
  const [environment, setEnvironment] = useState("");
  const [exposure, setExposure] = useState("");

  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (environment) params.set("environment", environment);
  if (exposure) params.set("exposure", exposure);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["assets", search, environment, exposure],
    queryFn: () => api.get<Asset[]>(`/api/v1/assets?${params.toString()}`).then((r) => r.data),
  });

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold tracking-tight">{t.assets.title}</h1>
        <div className="flex flex-wrap gap-2">
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by name"
            className="w-52"
          />
          <Select value={environment} onChange={(e) => setEnvironment(e.target.value)}>
            <option value="">{t.common.all} environments</option>
            <option value="production">Production</option>
            <option value="development">Development</option>
          </Select>
          <Select value={exposure} onChange={(e) => setExposure(e.target.value)}>
            <option value="">{t.common.all} exposure</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="UNKNOWN">Unknown</option>
          </Select>
        </div>
      </div>

      {isLoading && <TableSkeleton />}
      {error && <ErrorState
          title="Could not load this page"
          detail="CloudGuard could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />}
      {data && data.length === 0 && <EmptyState title={t.assets.empty} />}

      {data && data.length > 0 && (
        <Card className="overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-stone-200 bg-stone-50 text-left">
                <tr className="text-xs font-medium uppercase tracking-wide text-stone-500">
                  <th className="px-5 py-3">Resource</th>
                  <th className="px-5 py-3">Type</th>
                  <th className="px-5 py-3">Environment</th>
                  <th className="px-5 py-3">Criticality</th>
                  <th className="px-5 py-3">Exposure</th>
                  <th className="px-5 py-3 text-right">{t.assets.openFindings}</th>
                  <th className="px-5 py-3">Last seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-stone-100">
                {data.map((asset) => (
                  <tr key={asset.id} className="hover:bg-stone-50">
                    <td className="px-5 py-3">
                      <Link
                        to={`/assets/${asset.id}`}
                        className="font-medium text-stone-900 hover:underline"
                      >
                        {asset.name}
                      </Link>
                    </td>
                    <td className="px-5 py-3 text-stone-600">
                      {resourceTypeLabel(asset.resource_type)}
                    </td>
                    <td className="px-5 py-3 text-stone-600">{asset.environment ?? "—"}</td>
                    <td className="px-5 py-3">
                      <Badge level={asset.criticality} />
                    </td>
                    <td className="px-5 py-3">
                      <Badge level={asset.public_exposure} />
                    </td>
                    <td className="px-5 py-3 text-right font-medium tabular-nums">
                      {asset.open_findings}
                    </td>
                    <td className="px-5 py-3 text-stone-500">{formatDate(asset.last_seen_at)}</td>
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
