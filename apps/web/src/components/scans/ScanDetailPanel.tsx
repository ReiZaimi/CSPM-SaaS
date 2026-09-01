import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { ScanDetail } from "@/lib/types";
import { useT } from "@/i18n";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { ScanProgress } from "@/components/scans/ScanProgress";
import { CollectionPanel } from "@/components/scans/CollectionPanel";
import { Skeleton } from "@/components/ui/skeleton";
import { label } from "@/lib/format";

/**
 * Scope, identity and severity breakdown for one scan.
 *
 * Loaded only when opened. The list renders every scan an organization has ever
 * run, and this reads two more tables and aggregates findings per row.
 */
export function ScanDetailPanel({ scanId }: { scanId: string }) {
  const t = useT();
  const detail = useQuery({
    queryKey: ["scan-detail", scanId],
    queryFn: () => api.get<ScanDetail>(`/api/v1/scans/${scanId}/detail`).then((r) => r.data),
  });

  if (detail.isLoading) return <Skeleton className="mt-3 h-24 w-full" />;
  if (!detail.data) return null;

  const { scope, findings_by_severity: severities } = detail.data;
  const scanned = detail.data.progress_total ?? 0;

  return (
    <div className="mt-3 grid gap-4 rounded-lg border bg-muted/40 px-4 py-3 sm:grid-cols-2">
      <div>
        <SectionLabel>{t.scans.scope}</SectionLabel>
        <dl className="mt-1.5 flex flex-col gap-1 text-xs">
          <Row label={t.connection.connectionName} value={scope.connection_name} />
          <Row label="Subscription" value={scope.subscription_name ?? scope.subscription_id} />
          <Row label="Tenant" value={scope.tenant_id} />
          <Row label={t.scans.evaluated} value={scanned ? String(scanned) : null} />
        </dl>
      </div>

      <div>
        <SectionLabel>{t.scans.identity}</SectionLabel>
        <dl className="mt-1.5 flex flex-col gap-1 text-xs">
          {/* The object id the customer can look up in their own directory
              and revoke — not an internal reference. */}
          <Row label="Service principal" value={scope.service_principal_object_id} />
          <Row label="Role" value={scope.role_version ? `Scanner ${scope.role_version}` : null} />
          {/* Read from `trigger`, not inferred from a missing user. Before
              scans could start themselves, a NULL user meant "scheduled" by
              elimination; now it can equally mean a manual scan whose user
              record has gone, and labelling that one "Scheduled" is a plain
              untruth about who asked. */}
          <Row
            label={t.scans.initiator}
            value={
              detail.data.trigger === "SCHEDULED"
                ? t.scans.scheduled
                : (detail.data.triggered_by_user_id ?? t.scans.manualUnknownUser)
            }
          />
        </dl>
      </div>

      {Object.keys(severities).length > 0 && (
        <div className="sm:col-span-2">
          <SectionLabel>{t.scans.breakdown}</SectionLabel>
          <div className="mt-2 flex flex-wrap gap-2">
            {Object.entries(severities).map(([severity, count]) => (
              <SeverityBadge key={severity} level={severity}>
                {label(severity)} {count}
              </SeverityBadge>
            ))}
          </div>
        </div>
      )}

      {(detail.data.stages?.length ?? 0) > 0 && (
        <div className="sm:col-span-2">
          <SectionLabel>Stages</SectionLabel>
          <div className="mt-2">
            <ScanProgress stages={detail.data.stages ?? []} />
          </div>
        </div>
      )}

      <div className="sm:col-span-2">
        <CollectionPanel scanId={scanId} />
      </div>
    </div>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
      {children}
    </p>
  );
}

function Row({ label: text, value }: { label: string; value: string | null }) {
  return (
    <div className="flex gap-2">
      <dt className="shrink-0 text-muted-foreground">{text}</dt>
      <dd className="min-w-0 truncate font-mono text-[11px] text-foreground">
        {value ?? "—"}
      </dd>
    </div>
  );
}
