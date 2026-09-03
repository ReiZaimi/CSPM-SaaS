import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { ChevronDownIcon, CloudIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import type { CloudConnection, Scan } from "@/lib/types";
import { useT } from "@/i18n";
import { connectionStage, setupPath } from "@/lib/connectionStage";
import { cadenceSummary, lastReadAt, statusSummary } from "@/lib/connectionSummary";

import { AccessPanel } from "@/components/connections/AccessPanel";
import { ChangeEventsControl } from "@/components/connections/ChangeEventsControl";
import { DiscoveryRetry } from "@/components/connections/DiscoveryRetry";
import { ReadCadencePanel } from "@/components/connections/ReadCadencePanel";
import { RemoveConfirm } from "@/components/connections/RemoveConfirm";
import { SubscriptionScopeList } from "@/components/connections/SubscriptionScopeList";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn, formatRelative } from "@/lib/format";

/**
 * One connection, as a row that opens.
 *
 * A row rather than a card, because the question this page is skimmed for --
 * "is every environment being read, and how recently" -- is a comparison across
 * connections, and four stacked cards each 600 pixels tall answer it one
 * connection at a time. Everything needed for that comparison is in the closed
 * row; everything needed to *act* is behind the disclosure.
 *
 * The detail request only runs while the row is open. The list endpoint already
 * carries subscriptions, so a closed row needs nothing of its own, and setup --
 * the one thing that used to justify polling every card on this page -- now
 * lives in the wizard.
 */
export function ConnectionRow({
  connection: initial,
  defaultExpanded = false,
}: {
  connection: CloudConnection;
  defaultExpanded?: boolean;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState(defaultExpanded);
  const [error, setError] = useState<string | null>(null);
  const [confirmingRemove, setConfirmingRemove] = useState(false);

  const detail = useQuery({
    queryKey: ["cloud-connection", initial.id],
    queryFn: () =>
      api
        .get<CloudConnection>(`/api/v1/cloud-connections/${initial.id}`)
        .then((r) => r.data),
    initialData: initial,
    enabled: expanded,
    // The backend re-probes both grants and runs discovery on each read, so
    // this poll is what turns a role assigned a minute ago into a connection
    // that can scan. It stops once there is nothing left to wait for.
    refetchInterval: (query) => (query.state.data?.is_ready_to_scan ? false : 5000),
  });

  const connection = detail.data ?? initial;
  const subscriptions = connection.subscriptions ?? [];
  const scoped = subscriptions.filter((s) => s.in_scope);
  const stage = connectionStage(connection);
  const inSetup = stage === "consent" || stage === "deploy" || stage === "paused";
  const status = statusSummary(connection);
  const lastRead = lastReadAt(connection);

  // A scan is scoped to the whole connection: the worker resolves the
  // subscriptions beneath it, so any scannable one of them names the target
  // and a subscription discovered between queueing and running is still read.
  const scannable = subscriptions.find((s) => s.is_scannable);

  // A probe, not a refetch. Re-checking used to call `refetch()`, and the only
  // probe on the GET path runs while a connection is still unverified -- so on
  // a working connection the button re-read the same row and repainted the
  // same three lines. This endpoint asks Azure.
  const recheck = useMutation({
    mutationFn: () =>
      api
        .post<CloudConnection>(`/api/v1/cloud-connections/${connection.id}/recheck`)
        .then((r) => r.data),
    onSuccess: (fresh) => {
      if (fresh) queryClient.setQueryData(["cloud-connection", initial.id], fresh);
      queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
      setError(null);
    },
    onError: (err) =>
      setError(err instanceof ApiError ? err.message : "Could not re-check access"),
  });

  const scanNow = useMutation({
    mutationFn: () =>
      api.post<Scan>("/api/v1/scans", { cloud_account_id: scannable?.id }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      setError(null);
    },
    onError: (err) =>
      setError(err instanceof ApiError ? err.message : "Could not start the scan"),
  });

  const remove = useMutation({
    mutationFn: () => api.del(`/api/v1/cloud-connections/${connection.id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["cloud-connections"] }),
    onError: (err) =>
      setError(err instanceof Error ? err.message : "Could not remove the connection"),
  });

  return (
    <div className={cn("border-t border-border", expanded && "bg-muted/20")}>
      <div className="grid grid-cols-1 items-center gap-4 px-5 py-4 md:grid-cols-[minmax(0,2.2fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1.1fr)_auto]">
        <div className="flex min-w-0 items-start gap-3">
          <span className="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg border border-border bg-background text-muted-foreground">
            <CloudIcon className="size-4" />
          </span>
          <span className="min-w-0">
            <span className="block truncate text-sm font-medium text-foreground">
              {connection.name}
            </span>
            <span className="block truncate text-xs text-muted-foreground">
              {scopeSummary(connection)}
            </span>
          </span>
        </div>

        <div>
          <span
            className={cn(
              "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium",
              status.tone === "ok" && "border-ok-border bg-ok-bg text-ok",
              status.tone === "high" && "border-high-border bg-high-bg text-high",
              status.tone === "muted" && "border-border bg-muted text-muted-foreground",
            )}
          >
            <span
              className={cn(
                "size-1.5 rounded-full",
                status.tone === "ok" && "bg-ok",
                status.tone === "high" && "bg-high",
                status.tone === "muted" && "bg-muted-foreground",
              )}
            />
            {status.label}
          </span>
          <span className="mt-1 block truncate text-xs text-muted-foreground">
            {status.detail}
          </span>
        </div>

        <div>
          <span className="block text-sm text-foreground">
            {scoped.length} of {subscriptions.length}
          </span>
          <span className="block text-xs text-muted-foreground">
            {subscriptions.length > 0 && scoped.length === subscriptions.length
              ? t.connection.allInScope
              : t.connection.someInScope}
          </span>
        </div>

        <div>
          <span className="block text-sm text-foreground">
            {lastRead ? formatRelative(lastRead) : t.connection.cadenceNeverRead}
          </span>
          <span className="block truncate text-xs text-muted-foreground">
            {cadenceSummary(connection)}
          </span>
        </div>

        <div className="flex items-center justify-end gap-2">
          {/* Half-finished connections offer the step they stopped on instead
              of a scan they cannot run. */}
          {inSetup ? (
            <Link
              to={setupPath(connection.id)}
              className={cn(buttonVariants({ size: "sm" }))}
            >
              {stage === "paused" ? t.connection.resumeSetup : t.setup.continueSetup}
            </Link>
          ) : (
            <Button
              size="sm"
              variant="secondary"
              disabled={!scannable || scanNow.isPending}
              onClick={() => scanNow.mutate()}
            >
              {scanNow.isPending
                ? t.connection.scanStarting
                : scanNow.isSuccess
                  ? t.connection.scanQueued
                  : t.connection.scanNow}
            </Button>
          )}
          <Button
            variant="ghost"
            size="icon-sm"
            aria-expanded={expanded}
            aria-label={expanded ? t.connection.collapseRow : t.connection.expandRow}
            onClick={() => setExpanded((open) => !open)}
          >
            <ChevronDownIcon className={cn("transition-transform", expanded && "rotate-180")} />
          </Button>
        </div>
      </div>

      {expanded && (
        <div className="grid gap-6 border-t border-border px-5 py-5 lg:grid-cols-[minmax(0,1fr)_20rem] lg:items-start">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                {t.connection.subscriptionsHeading}
              </p>
              {connection.is_verified && subscriptions.length > 0 && (
                <DiscoveryRetry connection={connection} onError={setError} compact />
              )}
            </div>

            <div className="mt-3">
              {inSetup ? (
                <p className="text-sm leading-relaxed text-muted-foreground">
                  {connection.status_detail}
                </p>
              ) : subscriptions.length === 0 ? (
                <DiscoveryRetry connection={connection} onError={setError} />
              ) : (
                <SubscriptionScopeList connection={connection} onError={setError} />
              )}
            </div>

            {/* The thing a clock cannot do, kept beside the list it applies to
                rather than in the panel that only reports its state. */}
            {connection.is_ready_to_scan && (
              <ChangeEventsControl connection={connection} onError={setError} />
            )}
          </div>

          <div className="flex flex-col gap-4">
            <ReadCadencePanel
              connection={connection}
              onScanNow={() => scanNow.mutate()}
              scanning={scanNow.isPending}
            />
            <AccessPanel
              connection={connection}
              rechecking={recheck.isPending}
              onRecheck={() => recheck.mutate()}
            />

            <Button
              variant="ghost"
              className="text-critical hover:bg-critical-bg"
              onClick={() => setConfirmingRemove(true)}
            >
              {t.connection.remove}
            </Button>
            {/* The confirmation is a modal, so the button stays where it is
                rather than being replaced by a panel that pushed the rest of
                the connection off screen. */}
            <RemoveConfirm
              connectionId={connection.id}
              open={confirmingRemove}
              busy={remove.isPending}
              onOpenChange={setConfirmingRemove}
              onConfirm={() => remove.mutate()}
            />
          </div>

          {error && (
            <Alert variant="destructive" className="lg:col-span-2">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </div>
      )}
    </div>
  );
}

function scopeSummary(connection: CloudConnection): string {
  const scope =
    connection.scope_type === "TENANT_ROOT"
      ? "Entire tenant"
      : connection.scope_type === "MANAGEMENT_GROUP"
        ? `Management group ${connection.scope_id}`
        : `Subscription ${connection.scope_id}`;
  const tenant = connection.tenant_id ? ` · ${connection.tenant_id}` : "";
  return `${scope}${tenant} · ${connection.role_version}`;
}
