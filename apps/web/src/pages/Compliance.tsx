import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { ComplianceFramework } from "@/lib/types";
import { useT } from "@/i18n";
import { Card, EmptyState } from "@/components/ui";
import { formatPercent } from "@/lib/format";
import { CoverageBar, EvidenceNotice } from "@/components/compliance";
import { ErrorState, TableSkeleton } from "@/components/common/states";

/**
 * Framework overview.
 *
 * The headline number is deliberately *assessable coverage*, not a compliance
 * percentage. "You are 78% GDPR compliant" is a sentence this product must
 * never produce — it is not true, it is not checkable, and someone would put it
 * in front of an auditor. "CloudGuard can speak to 9 of these 11 requirements"
 * is both true and useful.
 */
export function CompliancePage() {
  const t = useT();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["compliance"],
    queryFn: () =>
      api.get<ComplianceFramework[]>("/api/v1/compliance").then((r) => r.data),
  });

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{t.compliance.title}</h1>
        <p className="mt-1 max-w-3xl text-sm text-stone-500">{t.compliance.intro}</p>
      </div>

      <EvidenceNotice />

      {isLoading && <TableSkeleton />}
      {error && <ErrorState
          title="Could not load this page"
          detail="CloudGuard could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />}
      {data && data.length === 0 && <EmptyState title={t.compliance.empty} />}

      <div className="grid gap-4 md:grid-cols-2">
        {data?.map((framework) => (
          <FrameworkCard key={framework.id} framework={framework} />
        ))}
      </div>
    </div>
  );
}

function FrameworkCard({ framework }: { framework: ComplianceFramework }) {
  const t = useT();
  const counts = framework.status_counts;

  return (
    <Card className="flex h-full flex-col">
      <div className="flex-1">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-stone-900">{framework.short_name}</h2>
            <p className="mt-0.5 text-xs text-stone-500">
              {framework.name} · {framework.version}
            </p>
          </div>
          <div className="text-right">
            <p className="text-2xl font-semibold tabular-nums tracking-tight text-stone-900">
              {formatPercent(framework.coverage_ratio)}
            </p>
            <p className="text-[11px] uppercase tracking-wide text-stone-400">
              {t.compliance.coverage}
            </p>
          </div>
        </div>

        <p className="mt-3 text-sm leading-relaxed text-stone-600">{framework.summary}</p>

        <div className="mt-4">
          <CoverageBar counts={counts} total={framework.control_count} />
          <p className="mt-2 text-xs text-stone-500">
            {framework.control_count} {t.compliance.controls}
            {framework.open_finding_count > 0 && (
              <>
                {" · "}
                <span className="font-medium text-critical">
                  {framework.open_finding_count} {t.compliance.openFindings}
                </span>
              </>
            )}
          </p>
        </div>
      </div>

      <Link
        to={`/compliance/${encodeURIComponent(framework.id)}`}
        className="mt-4 inline-block text-sm font-medium text-stone-700 underline underline-offset-4 transition hover:text-stone-900"
      >
        {t.compliance.viewFramework} →
      </Link>
    </Card>
  );
}
