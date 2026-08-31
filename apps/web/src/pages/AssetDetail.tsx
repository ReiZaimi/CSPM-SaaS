import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { Level } from "@/lib/types";
import { useT } from "@/i18n";
import { Badge, Card, StatusPill } from "@/components/ui";
import { formatDateTime, resourceTypeLabel } from "@/lib/format";
import { DetailSkeleton, ErrorState } from "@/components/common/states";
import { ContextRow, type ContextFact } from "@/components/security/ContextProvenance";
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
    queryFn: () => api.get<AssetDetail>(`/api/v1/assets/${assetId}`).then((r) => r.data),
  });

  if (isLoading) return <DetailSkeleton />;
  if (error) return <ErrorState
          title="Could not load this page"
          detail="CloudGuard could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />;
  if (!data) return null;

  return (
    <div className="space-y-6">
      <Link to="/assets" className="text-sm text-muted-foreground hover:text-foreground">
        ← {t.assets.title}
      </Link>

      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{data.name}</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {resourceTypeLabel(data.resource_type)}
          {data.region && ` · ${data.region}`}
          {data.environment && ` · ${data.environment}`}
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Risk context" className="lg:col-span-1">
          <dl className="flex flex-col gap-3 text-sm">
            <ContextRow
              label="Criticality"
              fact={data.context?.criticality}
              fallback={<Badge level={data.criticality} />}
            />
            <ContextRow
              label="Data sensitivity"
              fact={data.context?.data_sensitivity}
              fallback={<Badge level={data.data_sensitivity} />}
            />
            {/* Exposure has no provenance and needs none: it is read off the
                configuration in the capture -- a public IP is attached or it is
                not -- so there is nothing to attribute and nothing to declare. */}
            <Row label="Internet exposure" value={<Badge level={data.public_exposure} />} />
            <Row label="Environment" value={data.environment ?? "—"} />
            <Row label="First seen" value={formatDateTime(data.first_seen_at)} />
            <Row label="Last seen" value={formatDateTime(data.last_seen_at)} />
          </dl>
          <p className="mt-4 break-all border-t border-border pt-3 text-xs text-muted-foreground">
            {data.provider_resource_id}
          </p>
        </Card>

        <Card title="Findings on this asset" className="lg:col-span-2">
          {data.findings.length === 0 ? (
            <p className="py-4 text-center text-sm text-muted-foreground">
              No findings on this asset.
            </p>
          ) : (
            <ul className="divide-y divide-border">
              {data.findings.map((finding) => (
                <li key={finding.id} className="flex items-center gap-3 py-3 first:pt-0">
                  <Badge level={finding.severity} />
                  <Link
                    to={`/findings/${finding.id}`}
                    className="flex-1 text-sm text-foreground hover:underline"
                  >
                    {finding.title}
                  </Link>
                  <StatusPill status={finding.status} />
                  <span className="w-10 text-right text-sm font-medium tabular-nums text-muted-foreground">
                    {finding.risk_score === null ? "—" : Number(finding.risk_score).toFixed(0)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <BlastRadius providerResourceId={data.provider_resource_id} name={data.name} />

      <Card title="Configuration" subtitle="As collected in the most recent snapshot">
        <pre className="overflow-x-auto rounded-lg border bg-muted/60 p-3 font-mono text-xs leading-relaxed">
          {JSON.stringify(data.metadata, null, 2)}
        </pre>
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
