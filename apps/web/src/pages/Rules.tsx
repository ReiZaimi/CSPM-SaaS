import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { Rule } from "@/lib/types";
import { useT } from "@/i18n";
import { Badge, Card, EmptyState, ErrorNote, Spinner } from "@/components/ui";
import { formatEffort, resourceTypeLabel } from "@/lib/format";

export function RulesPage() {
  const t = useT();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["rules"],
    queryFn: () => api.get<Rule[]>("/api/v1/rules").then((r) => r.data),
  });

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{t.rules.title}</h1>
        <p className="mt-1 text-sm text-stone-500">
          Every check CloudGuard runs. Rules are deterministic — the same environment always
          produces the same result.
        </p>
      </div>

      {isLoading && <Spinner text={t.common.loading} />}
      {error && <ErrorNote message={t.common.error} onRetry={() => refetch()} />}
      {data && data.length === 0 && <EmptyState title={t.rules.empty} />}

      <div className="space-y-3">
        {data?.map((rule) => (
          <Card key={rule.rule_id}>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge level={rule.severity} />
                  <code className="text-xs text-stone-400">{rule.rule_id}</code>
                  <span className="text-xs text-stone-400">v{rule.version}</span>
                  {rule.scope === "aggregate" && (
                    <span className="rounded bg-stone-100 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-stone-600">
                      Tenant-wide
                    </span>
                  )}
                </div>
                <p className="mt-2 text-sm font-medium text-stone-900">{rule.name}</p>
                <p className="mt-1 max-w-3xl text-sm text-stone-600">{rule.description}</p>
              </div>
              <div className="text-right text-xs text-stone-500">
                <p>Exploitability {rule.exploitability}/5</p>
                <p className="mt-0.5">{formatEffort(rule.estimated_effort_minutes)} to fix</p>
              </div>
            </div>

            <div className="mt-3 flex flex-wrap gap-x-6 gap-y-2 border-t border-stone-100 pt-3 text-xs">
              {rule.applies_to.length > 0 && (
                <span className="text-stone-500">
                  Applies to{" "}
                  <strong className="text-stone-700">
                    {rule.applies_to.map(resourceTypeLabel).join(", ")}
                  </strong>
                </span>
              )}
              {Object.entries(rule.compliance_mappings).map(([framework, controls]) => (
                <span key={framework} className="text-stone-500">
                  {framework.replace(/_/g, " ")}{" "}
                  <strong className="text-stone-700">{controls.join(", ")}</strong>
                </span>
              ))}
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
