import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { Risk } from "@/lib/types";
import { useT } from "@/i18n";
import { Badge, Card, EmptyState, ErrorNote, Spinner, StatusPill } from "@/components/ui";

export function RisksPage() {
  const t = useT();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["risks"],
    queryFn: () => api.get<Risk[]>("/api/v1/risks").then((r) => r.data),
  });

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{t.risks.title}</h1>
        <p className="mt-1 text-sm text-stone-500">
          A finding is what we observed. A risk is what it means for this asset, with this data,
          at this level of exposure.
        </p>
      </div>

      {isLoading && <Spinner text={t.common.loading} />}
      {error && <ErrorNote message={t.common.error} onRetry={() => refetch()} />}
      {data && data.length === 0 && <EmptyState title={t.risks.empty} />}

      <div className="space-y-3">
        {data?.map((risk) => (
          <Card key={risk.id}>
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <Badge level={risk.risk_level} />
                  <StatusPill status={risk.status} />
                </div>
                <p className="mt-2 text-sm font-medium text-stone-900">{risk.title}</p>
                <p className="mt-1 max-w-3xl text-sm text-stone-600">{risk.description}</p>
              </div>
              <div className="text-right">
                <p className="text-3xl font-semibold tabular-nums text-stone-900">
                  {Number(risk.risk_score).toFixed(0)}
                </p>
                <p className="text-xs text-stone-400">risk score</p>
              </div>
            </div>

            <div className="mt-4 flex flex-wrap gap-x-6 gap-y-2 border-t border-stone-100 pt-3 text-xs">
              <Factor label="Asset criticality" level={risk.asset_criticality} />
              <Factor label="Data sensitivity" level={risk.data_sensitivity} />
              <Factor label="Internet exposure" level={risk.internet_exposure} />
              <span className="text-stone-500">
                Exploitability <strong className="text-stone-800">{risk.exploitability}/5</strong>
              </span>
              <span className="text-stone-500">
                Business impact <strong className="text-stone-800">{risk.business_impact}</strong>
              </span>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}

function Factor({ label, level }: { label: string; level: string }) {
  return (
    <span className="flex items-center gap-1.5 text-stone-500">
      {label}
      <Badge level={level} className="text-[10px]" />
    </span>
  );
}
