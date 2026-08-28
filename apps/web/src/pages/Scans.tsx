import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type { CloudAccount, Scan, ScanDetail, WorkerStatus } from "@/lib/types";
import { useT } from "@/i18n";
import {
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Select,
  Spinner,
  StatusPill,
} from "@/components/ui";
import { formatDateTime, label } from "@/lib/format";
import { Badge } from "@/components/ui";

const IN_FLIGHT = ["QUEUED", "DISCOVERING", "NORMALIZING", "EVALUATING", "CALCULATING_RISK"];

export function ScansPage() {
  const t = useT();
  const queryClient = useQueryClient();
  const [accountId, setAccountId] = useState("");
  const [error, setError] = useState<string | null>(null);

  const accounts = useQuery({
    queryKey: ["cloud-accounts"],
    queryFn: () => api.get<CloudAccount[]>("/api/v1/cloud-accounts").then((r) => r.data),
  });

  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<Scan[]>("/api/v1/scans").then((r) => r.data),
    // Poll while a scan is in flight so progress is visible live, then stop.
    refetchInterval: (query) => {
      const rows = query.state.data as Scan[] | undefined;
      return rows?.some((s) => IN_FLIGHT.includes(s.status)) ? 2000 : false;
    },
  });

  const start = useMutation({
    mutationFn: (cloud_account_id: string) => api.post<Scan>("/api/v1/scans", { cloud_account_id }),
    onSuccess: () => {
      setError(null);
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "Could not start scan"),
  });

  const scannable = accounts.data?.filter((a) => a.is_scannable) ?? [];
  const selected = accountId || scannable[0]?.id || "";

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold tracking-tight">{t.scans.title}</h1>
        <div className="flex gap-2">
          <Select value={selected} onChange={(e) => setAccountId(e.target.value)}>
            {scannable.length === 0 && <option value="">No verified connections</option>}
            {scannable.map((account) => (
              <option key={account.id} value={account.id}>
                {account.account_name}
              </option>
            ))}
          </Select>
          <Button
            onClick={() => selected && start.mutate(selected)}
            disabled={!selected || start.isPending}
          >
            {t.scans.runScan}
          </Button>
        </div>
      </div>

      {error && <ErrorNote message={error} />}
      {scans.isLoading && <Spinner text={t.common.loading} />}
      {scans.data && scans.data.length === 0 && (
        <EmptyState
          title={t.scans.empty}
          detail="Once a connection is verified, run a scan to discover resources and assess them."
        />
      )}

      <div className="space-y-3">
        {scans.data?.map((scan) => (
          <ScanRow key={scan.id} scan={scan} />
        ))}
      </div>
    </div>
  );
}

function ScanRow({ scan }: { scan: Scan }) {
  const t = useT();
  const queryClient = useQueryClient();
  const running = IN_FLIGHT.includes(scan.status);

  const [open, setOpen] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  const cancel = useMutation({
    mutationFn: () => api.post<Scan>(`/api/v1/scans/${scan.id}/cancel`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scans"] }),
  });

  const remove = useMutation({
    mutationFn: (purge: boolean) =>
      api.del(`/api/v1/scans/${scan.id}?purge_findings=${purge}`),
    onSuccess: () => {
      setConfirmingDelete(false);
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      // Purging changes the findings and the score, so those go too.
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });

  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <StatusPill status={scan.status} />
          <span className="text-sm text-stone-500">
            {formatDateTime(scan.completed_at ?? scan.started_at ?? scan.created_at)}
          </span>
        </div>
        <div className="flex flex-wrap gap-x-8 gap-y-2 text-sm">
          {scan.duration_seconds != null && (
            <Stat label={t.scans.duration} value={formatDuration(scan.duration_seconds)} />
          )}
          <Stat label={t.scans.resources} value={scan.resource_count} />
          <Stat label={t.scans.rules} value={scan.rule_count} />
          <Stat label={t.scans.findings} value={scan.finding_count} />
        </div>
      </div>

      {running && (
        <div className="mt-4">
          <Progress status={scan.status} />
        </div>
      )}

      {/* Queued far longer than a worker takes to collect one. The progress bar
          above keeps implying imminent work, so the reason has to say
          otherwise -- this is almost always no worker running at all. */}
      {scan.stuck_in_queue && <StuckNote />}

      <div className="mt-3 flex flex-wrap items-center gap-2">
        {running && (
          <Button
            variant="secondary"
            onClick={() => cancel.mutate()}
            disabled={cancel.isPending}
          >
            {cancel.isPending ? t.scans.cancelling : t.scans.cancel}
          </Button>
        )}
        <Button variant="ghost" onClick={() => setOpen((v) => !v)}>
          {open ? t.scans.hideDetails : t.scans.details}
        </Button>
        {!running && (
          <Button
            variant="ghost"
            className="ml-auto text-critical hover:bg-critical-bg"
            onClick={() => setConfirmingDelete(true)}
          >
            {t.scans.deleteScan}
          </Button>
        )}
      </div>

      {confirmingDelete && (
        <DeleteScanConfirm
          scanId={scan.id}
          busy={remove.isPending}
          onCancel={() => setConfirmingDelete(false)}
          onConfirm={(purge) => remove.mutate(purge)}
        />
      )}

      {open && <ScanDetailPanel scanId={scan.id} />}

      {scan.error_message && (
        <p className="mt-3 rounded-lg border border-critical-border bg-critical-bg px-3 py-2 text-sm text-critical">
          {scan.error_message}
        </p>
      )}

      {Object.keys(scan.collection_errors).length > 0 && (
        <div className="mt-3 rounded-lg border border-medium-border bg-medium-bg px-3 py-2">
          <p className="text-xs font-medium text-medium">{t.scans.partial}</p>
          <ul className="mt-1.5 space-y-0.5">
            {Object.entries(scan.collection_errors).map(([category, reason]) => (
              <li key={category} className="text-xs text-stone-700">
                <strong>{category}</strong>: {reason}
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}

/** Live progress through the fixed pipeline: discover -> rules -> risk. */
function Progress({ status }: { status: string }) {
  const stages = ["DISCOVERING", "NORMALIZING", "EVALUATING", "CALCULATING_RISK"];
  const index = stages.indexOf(status);
  return (
    <div>
      <div className="flex gap-1">
        {stages.map((stage, i) => (
          <div
            key={stage}
            className={`h-1.5 flex-1 rounded-full ${
              i <= index ? "bg-stone-800" : "bg-stone-200"
            } ${i === index ? "animate-pulse" : ""}`}
          />
        ))}
      </div>
      <p className="mt-2 text-xs text-stone-500">{label(status)}</p>
    </div>
  );
}

function Stat({ label: text, value }: { label: string; value: number | string }) {
  return (
    <div>
      <p className="text-xs text-stone-500">{text}</p>
      <p className="font-medium tabular-nums text-stone-900">{value}</p>
    </div>
  );
}


/** Human duration. Minutes and seconds, because scans are minutes-long. */
function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return `${minutes}m ${String(rest).padStart(2, "0")}s`;
}

/**
 * Scope, identity and severity breakdown for one scan.
 *
 * Loaded only when opened. The list renders every scan an organization has
 * ever run, and this reads two more tables and aggregates findings per row.
 */
function ScanDetailPanel({ scanId }: { scanId: string }) {
  const t = useT();
  const detail = useQuery({
    queryKey: ["scan-detail", scanId],
    queryFn: () =>
      api.get<ScanDetail>(`/api/v1/scans/${scanId}/detail`).then((r) => r.data),
  });

  if (detail.isLoading) return <Spinner />;
  if (!detail.data) return null;

  const { scope, findings_by_severity: severities } = detail.data;
  const scanned = detail.data.progress_total ?? 0;

  return (
    <div className="mt-3 grid gap-4 rounded-lg border border-stone-200 bg-stone-50 px-4 py-3 sm:grid-cols-2">
      <div>
        <p className="text-[11px] font-medium uppercase tracking-wide text-stone-400">
          {t.scans.scope}
        </p>
        <dl className="mt-1.5 space-y-1 text-xs">
          <Row label={t.connection.connectionName} value={scope.connection_name} />
          <Row label="Subscription" value={scope.subscription_name ?? scope.subscription_id} />
          <Row label="Tenant" value={scope.tenant_id} />
          <Row label={t.scans.evaluated} value={scanned ? String(scanned) : null} />
        </dl>
      </div>

      <div>
        <p className="text-[11px] font-medium uppercase tracking-wide text-stone-400">
          {t.scans.identity}
        </p>
        <dl className="mt-1.5 space-y-1 text-xs">
          {/* The object id the customer can look up in their own directory
              and revoke — not an internal reference. */}
          <Row label="Service principal" value={scope.service_principal_object_id} />
          <Row label="Role" value={scope.role_version ? `Scanner ${scope.role_version}` : null} />
          <Row
            label={t.scans.initiator}
            value={detail.data.triggered_by_user_id ?? t.scans.scheduled}
          />
        </dl>
      </div>

      {Object.keys(severities).length > 0 && (
        <div className="sm:col-span-2">
          <p className="text-[11px] font-medium uppercase tracking-wide text-stone-400">
            {t.scans.breakdown}
          </p>
          <div className="mt-2 flex flex-wrap gap-2">
            {Object.entries(severities).map(([severity, count]) => (
              <Badge key={severity} level={severity}>
                {label(severity)} {count}
              </Badge>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Row({ label: text, value }: { label: string; value: string | null }) {
  return (
    <div className="flex gap-2">
      <dt className="shrink-0 text-stone-500">{text}</dt>
      <dd className="min-w-0 truncate font-mono text-[11px] text-stone-800">
        {value ?? "\u2014"}
      </dd>
    </div>
  );
}

/**
 * Deleting a scan is two different acts, so it asks which.
 *
 * The record is an execution log. The findings it raised are statements about
 * the environment, which is why `findings.scan_id` is ON DELETE SET NULL —
 * history can be pruned without discarding what was found. Purging is for a
 * run whose results the user considers wrong, and never touches resolved
 * findings: each is the evidence that a fix was verified.
 */
function DeleteScanConfirm({
  scanId,
  busy,
  onConfirm,
  onCancel,
}: {
  scanId: string;
  busy: boolean;
  onConfirm: (purge: boolean) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const detail = useQuery({
    queryKey: ["scan-detail", scanId],
    queryFn: () =>
      api.get<ScanDetail>(`/api/v1/scans/${scanId}/detail`).then((r) => r.data),
  });
  const purgeable = detail.data?.purgeable_finding_count ?? 0;

  return (
    <div className="mt-3 rounded-lg border border-critical-border bg-critical-bg px-4 py-3">
      <p className="text-sm font-medium text-critical">{t.scans.deleteTitle}</p>
      <div className="mt-3 space-y-2">
        <div>
          <Button variant="secondary" onClick={() => onConfirm(false)} disabled={busy}>
            {t.scans.deleteRecordOnly}
          </Button>
          <p className="mt-1 text-xs leading-relaxed text-stone-600">
            {t.scans.deleteRecordOnlyDetail}
          </p>
        </div>
        <div>
          <Button variant="danger" onClick={() => onConfirm(true)} disabled={busy}>
            {t.scans.deleteWithFindings}
            {purgeable > 0 && ` (${purgeable})`}
          </Button>
          <p className="mt-1 text-xs leading-relaxed text-stone-600">
            {t.scans.deleteWithFindingsDetail}
          </p>
        </div>
      </div>
      <Button variant="ghost" className="mt-3" onClick={onCancel} disabled={busy}>
        {t.findings.cancel}
      </Button>
    </div>
  );
}


/**
 * Why a scan is not moving, checked rather than guessed.
 *
 * `stuck_in_queue` is inferred from elapsed time, which is only ever a
 * suspicion. This asks the broker how many workers answer, which turns it into
 * a fact — and the fact matters, because the failure looks like success from
 * every other angle: the worker service reports Online, passes health checks,
 * and is simply running the wrong process.
 *
 * Queried only once a scan already looks stuck. A broker round trip on every
 * poll would be a cost paid by every healthy deployment.
 */
function StuckNote() {
  const t = useT();
  const status = useQuery({
    queryKey: ["worker-status"],
    queryFn: () =>
      api.get<WorkerStatus>("/api/v1/scans/worker-status").then((r) => r.data),
    staleTime: 30_000,
  });

  return (
    <div className="mt-3 rounded-lg border border-high-border bg-high-bg px-3 py-2">
      <p className="text-xs font-medium text-high">{t.scans.stuckTitle}</p>
      <p className="mt-1 text-xs leading-relaxed text-stone-700">
        {status.data ? status.data.detail : t.scans.stuckDetail}
      </p>
      {status.data && status.data.workers === 0 && (
        <p className="mt-1 text-xs leading-relaxed text-stone-600">
          {t.scans.stuckDetail}
        </p>
      )}
    </div>
  );
}
