import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type { CloudAccount, Scan } from "@/lib/types";
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
  const running = IN_FLIGHT.includes(scan.status);

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

function Stat({ label: text, value }: { label: string; value: number }) {
  return (
    <div>
      <p className="text-xs text-stone-500">{text}</p>
      <p className="font-medium tabular-nums text-stone-900">{value}</p>
    </div>
  );
}
