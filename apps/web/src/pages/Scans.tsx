import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ActivityIcon, PlayIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import type { CloudAccount, Scan } from "@/lib/types";
import { useT } from "@/i18n";
import { ScanCard } from "@/components/scans/ScanCard";
import { AutomaticScanning } from "@/components/scans/AutomaticScanning";
import { IN_FLIGHT } from "@/components/scans/status";
import { CardsSkeleton, EmptyState, PageHeader } from "@/components/common/states";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { SelectField } from "@/components/common/SelectField";
import { Spinner } from "@/components/ui/spinner";

/**
 * Every run, and the button that starts the next one.
 *
 * The page is a list and a control; a scan's own card is
 * `components/scans/ScanCard.tsx`, and everything it can open -- the stage
 * breakdown, what was and was not collected, the two-way delete -- lives beside
 * it. That split is not tidying: the card polls two endpoints on its own
 * schedule and the panels below it fetch only when opened, and keeping those
 * lifetimes in one 600-line file made it genuinely hard to see which request
 * fired when.
 */
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
    mutationFn: (cloud_account_id: string) =>
      api.post<Scan>("/api/v1/scans", { cloud_account_id }),
    onSuccess: () => {
      setError(null);
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "Could not start scan"),
  });

  const scannable = accounts.data?.filter((a) => a.is_scannable) ?? [];
  const selected = accountId || scannable[0]?.id || "";

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeader
          title={t.scans.title}
          description="Every time CloudGuard has read your environment, and what it could reach."
        />
        <div className="flex shrink-0 gap-2">
          {/* The subscription's name, not its row id. Closed, the primitive
              had no mounted option to read a label from and printed the UUID —
              an identifier the customer has never seen and cannot act on. */}
          <SelectField
            value={selected}
            onValueChange={(value) => setAccountId(value)}
            disabled={scannable.length === 0}
            ariaLabel="Subscription to scan"
            className="w-[200px]"
            placeholder="No verified connections"
            fallbackLabel={() => "Unknown subscription"}
            options={scannable.map((account) => ({
              value: account.id,
              label: account.account_name,
            }))}
          />
          <Button
            size="sm"
            onClick={() => selected && start.mutate(selected)}
            disabled={!selected || start.isPending}
          >
            {start.isPending ? <Spinner data-icon="inline-start" /> : <PlayIcon data-icon="inline-start" />}
            {t.scans.runScan}
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTitle>Could not start the scan</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* The clock, above the history it explains: a list of runs with no
          visible cadence makes the gaps between them look like something that
          happened rather than something that was chosen. */}
      <AutomaticScanning onError={setError} />

      {scans.isLoading && <CardsSkeleton />}

      {scans.data && scans.data.length === 0 && (
        <EmptyState
          icon={ActivityIcon}
          title={t.scans.empty}
          detail="Once a connection is verified, run a scan to discover resources and assess them."
        />
      )}

      <div className="flex flex-col gap-3">
        {scans.data?.map((scan) => (
          <ScanCard key={scan.id} scan={scan} />
        ))}
      </div>
    </div>
  );
}
