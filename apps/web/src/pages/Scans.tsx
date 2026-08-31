import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type {
  CloudAccount,
  CollectionOutcome,
  CollectionReading,
  CollectionStatus,
  Scan,
  ScanDetail,
  WorkerStatus,
} from "@/lib/types";
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
import { formatDateTime, label, outcomeStyle } from "@/lib/format";
import { ScanProgress } from "@/components/scans/ScanProgress";
import { Badge } from "@/components/ui";
import { TableSkeleton } from "@/components/common/states";

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
      {scans.isLoading && <TableSkeleton />}
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
          <span className="text-sm text-muted-foreground">
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

      {running && <LiveProgress scanId={scan.id} status={scan.status} />}

      {/* Queued far longer than a worker takes to collect one. The progress bar
          above keeps implying imminent work, so the reason has to say
          otherwise -- this is almost always no worker running at all. */}
      {scan.stuck_in_queue && <StuckNote />}

      {/* Zero resources reads as a failure and is usually not one. The engine
          already knows which: a category that errored is recorded in
          collection_errors, so anything not listed there returned successfully
          and was simply empty. Saying so separates "nothing to assess" from
          "could not look", which the counters alone cannot. */}
      {!running && scan.status !== "FAILED" && scan.resource_count === 0 && (
        <div className="mt-3 rounded-lg border border-border bg-muted/40 px-3 py-2">
          <p className="text-xs font-medium text-foreground">{t.scans.nothingFound}</p>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            {Object.keys(scan.collection_errors).length > 0
              ? t.scans.nothingFoundPartial
              : t.scans.nothingFoundHelp}
          </p>
        </div>
      )}

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

      {/* A summary, not the full text of every failure. The reasons are
          sentences long and there is one per subscription per category, which
          on a tenant-wide scan turns the card into a wall nobody reads. The
          structured breakdown lives in Details. */}
      {Object.keys(scan.collection_errors).length > 0 && (
        <div className="mt-3 rounded-lg border border-medium-border bg-medium-bg px-3 py-2">
          <p className="text-xs font-medium text-medium">{t.scans.partial}</p>
          <ul className="mt-1.5 space-y-0.5">
            {Object.entries(scan.collection_errors)
              .slice(0, 3)
              .map(([scope, reason]) => (
                <li key={scope} className="text-xs text-foreground">
                  <strong>{scope}</strong>
                  <span className="text-muted-foreground"> — {firstSentence(reason)}</span>
                </li>
              ))}
          </ul>
          {Object.keys(scan.collection_errors).length > 3 && (
            <p className="mt-1 text-xs text-muted-foreground">
              and {Object.keys(scan.collection_errors).length - 3} more
            </p>
          )}
        </div>
      )}
    </Card>
  );
}

/**
 * Progress, read from the steps the scan is actually made of.
 *
 * Polled separately from the scan list and only while something is running.
 * The list refetches every two seconds to keep a status current; this reads a
 * second endpoint per open scan, and doing that for a page of finished scans
 * would be a request per card per tick for information that cannot change.
 */
function LiveProgress({ scanId, status }: { scanId: string; status: string }) {
  const detail = useQuery({
    queryKey: ["scan-detail", scanId],
    queryFn: () =>
      api.get<ScanDetail>(`/api/v1/scans/${scanId}/detail`).then((r) => r.data),
    refetchInterval: 3000,
  });

  const stages = detail.data?.stages ?? [];

  return (
    <div className="mt-4 rounded-lg border bg-muted/30 p-3">
      {stages.length > 0 ? (
        <ScanProgress stages={stages} />
      ) : (
        // Before PLAN has claimed anything there are no steps to show, and the
        // status is the only honest thing to say.
        <p className="text-xs text-muted-foreground">{label(status)}</p>
      )}
    </div>
  );
}

function Stat({ label: text, value }: { label: string; value: number | string }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{text}</p>
      <p className="font-medium tabular-nums text-foreground">{value}</p>
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
    <div className="mt-3 grid gap-4 rounded-lg border border-border bg-muted/40 px-4 py-3 sm:grid-cols-2">
      <div>
        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
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
        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          {t.scans.identity}
        </p>
        <dl className="mt-1.5 space-y-1 text-xs">
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
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
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

      {(detail.data.stages?.length ?? 0) > 0 && (
        <div className="sm:col-span-2">
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Stages
          </p>
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

function OutcomeBadge({ outcome }: { outcome: CollectionOutcome }) {
  const t = useT();
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${outcomeStyle(outcome)}`}
    >
      {outcomeLabel(t, outcome)}
    </span>
  );
}

/**
 * What the scan could and could not read.
 *
 * Reported apart from rule coverage next door: that says what the checks
 * concluded, this says whether they were entitled to conclude it. Fetched only
 * when the panel is open, because it is one request per scan and the list
 * renders dozens of cards.
 */
function CollectionPanel({ scanId }: { scanId: string }) {
  const t = useT();
  const status = useQuery({
    queryKey: ["scan-collection", scanId],
    queryFn: () =>
      api
        .get<CollectionStatus>(`/api/v1/scans/${scanId}/collection`)
        .then((r) => r.data),
  });

  if (status.isLoading) return <Spinner />;
  if (!status.data || status.data.total === 0) return null;

  const { tasks, total, complete, partial, failed, skipped } = status.data;
  const bySubscription = new Map<string, CollectionReading[]>();
  for (const task of tasks) {
    const key = task.subscription ?? task.cloud_account_id;
    bySubscription.set(key, [...(bySubscription.get(key) ?? []), task]);
  }

  return (
    <div>
      <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
        {t.scans.collectionTitle}
      </p>

      <p className="mt-1.5 text-xs text-muted-foreground">
        <span className="font-medium tabular-nums text-foreground">
          {complete}/{total}
        </span>{" "}
        {t.scans.collectionSummary}
        {partial > 0 && <> · {partial} {t.scans.collectionPartial}</>}
        {failed > 0 && <> · {failed} {t.scans.collectionFailed}</>}
        {skipped > 0 && <> · {skipped} {t.scans.collectionSkipped}</>}
      </p>

      {partial > 0 && (
        <p className="mt-1 text-xs leading-relaxed text-medium">{t.scans.partialHint}</p>
      )}

      <div className="mt-2 space-y-3">
        {[...bySubscription.entries()].map(([subscription, readings]) => (
          <div key={subscription}>
            {bySubscription.size > 1 && (
              <p className="text-xs font-medium text-foreground">{subscription}</p>
            )}
            <ul className="mt-1 divide-y divide-border rounded-lg border border-border bg-background">
              {readings.map((reading) => (
                <li
                  key={`${reading.cloud_account_id}-${reading.task}`}
                  className="flex flex-wrap items-start gap-x-3 gap-y-1 px-3 py-2"
                >
                  <span className="min-w-0 flex-1 font-mono text-[11px] text-foreground">
                    {reading.task}
                  </span>
                  {reading.outcome === "COMPLETE" && (
                    <span className="text-xs tabular-nums text-muted-foreground">
                      {reading.item_count}
                    </span>
                  )}
                  <OutcomeBadge outcome={reading.outcome} />
                  {reading.detail && (
                    <p className="w-full text-xs leading-relaxed text-muted-foreground">
                      {reading.detail}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

function outcomeLabel(t: ReturnType<typeof useT>, outcome: CollectionOutcome): string {
  return {
    COMPLETE: t.scans.outcomeComplete,
    PARTIAL: t.scans.outcomePartial,
    FAILED: t.scans.outcomeFailed,
    SKIPPED: t.scans.outcomeSkipped,
  }[outcome];
}

/** The first sentence of a multi-sentence remedy, for the summary line. */
function firstSentence(text: string): string {
  const cut = text.indexOf(". ");
  return cut === -1 ? text : `${text.slice(0, cut)}.`;
}

function Row({ label: text, value }: { label: string; value: string | null }) {
  return (
    <div className="flex gap-2">
      <dt className="shrink-0 text-muted-foreground">{text}</dt>
      <dd className="min-w-0 truncate font-mono text-[11px] text-foreground">
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
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            {t.scans.deleteRecordOnlyDetail}
          </p>
        </div>
        <div>
          <Button variant="danger" onClick={() => onConfirm(true)} disabled={busy}>
            {t.scans.deleteWithFindings}
            {purgeable > 0 && ` (${purgeable})`}
          </Button>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
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
      <p className="mt-1 text-xs leading-relaxed text-foreground">
        {status.data ? status.data.detail : t.scans.stuckDetail}
      </p>
      {status.data && status.data.workers === 0 && (
        <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
          {t.scans.stuckDetail}
        </p>
      )}
    </div>
  );
}
