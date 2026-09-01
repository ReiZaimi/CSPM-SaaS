import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ClipboardCheckIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { ComplianceFramework } from "@/lib/types";
import { useT } from "@/i18n";
import { formatPercent } from "@/lib/format";
import { CoverageBar, EvidenceNotice } from "@/components/compliance";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

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
    <div className="flex flex-col gap-4">
      <PageHeader title={t.compliance.title} description={t.compliance.intro} />

      <EvidenceNotice />

      {isLoading && <CardsSkeleton count={4} />}

      {error && (
        <ErrorState
          title="Could not load the frameworks"
          detail="CloudGuard could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {data && data.length === 0 && (
        <EmptyState icon={ClipboardCheckIcon} title={t.compliance.empty} />
      )}

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
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <CardTitle className="text-sm">{framework.short_name}</CardTitle>
            <CardDescription>
              {framework.name} · {framework.version}
            </CardDescription>
          </div>
          <div className="shrink-0 text-right">
            <p className="text-2xl font-semibold tabular-nums tracking-tight text-foreground">
              {formatPercent(framework.coverage_ratio)}
            </p>
            <p className="text-[11px] uppercase tracking-wide text-muted-foreground">
              {t.compliance.coverage}
            </p>
          </div>
        </div>
      </CardHeader>

      <CardContent className="flex-1">
        <p className="text-sm leading-relaxed text-muted-foreground">
          {framework.summary}
        </p>

        <div className="mt-4">
          <CoverageBar counts={counts} total={framework.control_count} />
          <p className="mt-2 text-xs text-muted-foreground">
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
      </CardContent>

      <CardFooter>
        <Button
          variant="outline"
          size="sm"
          render={
            <Link to={`/compliance/${encodeURIComponent(framework.id)}`} />
          }
        >
          {t.compliance.viewFramework}
        </Button>
      </CardFooter>
    </Card>
  );
}
