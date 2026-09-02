import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { Level } from "@/lib/types";
import { useT } from "@/i18n";
import { StatusPill } from "@/components/security/StatusPill";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { formatDateTime, resourceTypeLabel } from "@/lib/format";
import { Breadcrumbs, DetailSkeleton, ErrorState } from "@/components/common/states";
import { CodeBlock } from "@/components/common/CodeBlock";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  ContextRow,
  type ContextFact,
} from "@/components/security/ContextProvenance";
import { BlastRadius } from "@/components/graph/BlastRadius";

interface AssetDetail {
  id: string;
  name: string;
  resource_type: string;
  provider: string;
  provider_resource_id: string;
  region: string | null;
  environment: string | null;
  criticality: Level;
  data_sensitivity: Level;
  public_exposure: Level;
  metadata: Record<string, unknown>;
  /**
   * The same three values again, each with where it came from. Kept beside the
   * flat fields rather than replacing them: those are what every list view and
   * filter reads.
   */
  context?: {
    criticality: ContextFact;
    data_sensitivity: ContextFact;
    environment: ContextFact;
  };
  first_seen_at: string;
  last_seen_at: string;
  findings: {
    id: string;
    rule_id: string;
    title: string;
    severity: string;
    status: string;
    risk_score: number | null;
  }[];
}

export function AssetDetailPage() {
  const t = useT();
  const { assetId } = useParams();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["asset", assetId],
    queryFn: () =>
      api.get<AssetDetail>(`/api/v1/assets/${assetId}`).then((r) => r.data),
  });

  if (isLoading) return <DetailSkeleton />;
  if (error)
    return (
      <ErrorState
        title="Could not load this page"
        detail="CloudGuard could not reach its own API."
        impact="Nothing about your environment has changed — this is a problem displaying it."
        onRetry={() => refetch()}
      />
    );
  if (!data) return null;

  return (
    <div className="flex flex-col gap-6">
      <Breadcrumbs
        trail={[{ label: t.assets.title, to: "/assets" }, { label: data.name }]}
      />

      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{data.name}</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {resourceTypeLabel(data.resource_type)}
          {data.region && ` · ${data.region}`}
          {data.environment && ` · ${data.environment}`}
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>Risk context</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="flex flex-col gap-3 text-sm">
              <ContextRow
                label="Criticality"
                fact={data.context?.criticality}
                fallback={<SeverityBadge level={data.criticality} size="sm" />}
              />
              <ContextRow
                label="Data sensitivity"
                fact={data.context?.data_sensitivity}
                fallback={
                  <SeverityBadge level={data.data_sensitivity} size="sm" />
                }
              />
              {/* Exposure has no provenance and needs none: it is read off the
                  configuration in the capture -- a public IP is attached or it
                  is not -- so there is nothing to attribute or declare. */}
              <Row
                label="Internet exposure"
                value={<SeverityBadge level={data.public_exposure} size="sm" />}
              />
              <Row label="Environment" value={data.environment ?? "—"} />
              <Row
                label="First seen"
                value={formatDateTime(data.first_seen_at)}
              />
              <Row
                label="Last seen"
                value={formatDateTime(data.last_seen_at)}
              />
            </dl>
          </CardContent>
          <CardFooter className="border-t pt-4">
            {/* The provider's own id, in full: it is what the customer can
                paste into their portal, and truncating it would make it
                useless for the one thing it is here for. */}
            <p className="break-all font-mono text-xs text-muted-foreground">
              {data.provider_resource_id}
            </p>
          </CardFooter>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Findings on this asset</CardTitle>
          </CardHeader>
          <CardContent>
            {data.findings.length === 0 ? (
              <p className="py-4 text-center text-sm text-muted-foreground">
                No findings on this asset.
              </p>
            ) : (
              <ul className="flex flex-col divide-y">
                {data.findings.map((finding) => (
                  <li
                    key={finding.id}
                    className="flex items-center gap-3 py-3 first:pt-0 last:pb-0"
                  >
                    <SeverityBadge level={finding.severity} size="sm" />
                    <Link
                      to={`/findings/${finding.id}`}
                      className="min-w-0 flex-1 truncate text-sm text-foreground hover:underline"
                    >
                      {finding.title}
                    </Link>
                    <StatusPill status={finding.status} />
                    <span className="w-10 text-right text-sm font-medium tabular-nums text-muted-foreground">
                      {finding.risk_score === null
                        ? "—"
                        : Number(finding.risk_score).toFixed(0)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      <BlastRadius
        providerResourceId={data.provider_resource_id}
        name={data.name}
      />

      <Card>
        <CardHeader>
          <CardTitle>Configuration</CardTitle>
          <CardDescription>
            As collected in the most recent snapshot
          </CardDescription>
        </CardHeader>
        <CardContent>
          <CodeBlock
            code={JSON.stringify(data.metadata, null, 2)}
            label="Copy this configuration"
          />
        </CardContent>
      </Card>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="font-medium text-foreground">{value}</dd>
    </div>
  );
}
