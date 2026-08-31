import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { CheckIcon, MinusIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { CloudConnection, DiscoveredSubscription } from "@/lib/types";
import { useT } from "@/i18n";
import { StatusPill } from "@/components/security/StatusPill";
import { ScheduleControl } from "@/components/connections/ScheduleControl";
import { RemoveConfirm } from "@/components/connections/RemoveConfirm";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { cn, formatDateTime } from "@/lib/format";

export /**
 * A single connection — live status, deploy button, subscription management.
 *
 * Polls the detail endpoint while the connection is not yet verified. The
 * backend does auto-validation on each poll, so the card advances by itself
 * once the customer completes the ARM deployment.
 */
function ConnectionCard({
  connection: initial,
}: {
  connection: CloudConnection;
  defaultExpanded: boolean;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [confirmingRemove, setConfirmingRemove] = useState(false);
  const [selection, setSelection] = useState<Record<string, boolean>>({});

  // Poll for live status — backend auto-validates on each GET
  const detail = useQuery({
    queryKey: ["cloud-connection", initial.id],
    queryFn: () =>
      api
        .get<CloudConnection>(`/api/v1/cloud-connections/${initial.id}`)
        .then((r) => r.data),
    initialData: initial,
    // Polls until the connection can actually be scanned, not merely until
    // both grants work. Discovery runs server-side inside this same request,
    // so stopping at is_verified stopped the only thing that would ever find
    // a subscription -- one transient failure and the connection sat verified
    // and empty forever.
    refetchInterval: (query) => (query.state.data?.is_ready_to_scan ? false : 5000),
    refetchIntervalInBackground: true,
  });

  const connection = detail.data ?? initial;
  const subscriptions = connection.subscriptions ?? [];
  const scoped = subscriptions.filter((s) => s.in_scope);

  const rediscover = useMutation({
    mutationFn: () =>
      api.post(`/api/v1/cloud-connections/${connection.id}/discover`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cloud-connection", connection.id] });
      queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
    },
    onError: (err) =>
      setError(err instanceof Error ? err.message : "Could not look for subscriptions"),
  });

  const saveScope = useMutation({
    mutationFn: () =>
      api.patch<DiscoveredSubscription[]>(
        `/api/v1/cloud-connections/${connection.id}/subscriptions`,
        { in_scope: selection },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cloud-connection", connection.id] });
      queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
      setSelection({});
    },
    onError: (err) =>
      setError(err instanceof Error ? err.message : "Could not save scope"),
  });

  const cancelled = connection.status === "DISABLED" && !connection.is_verified;
  // Setup is "in progress" from creation until the first successful probe.
  const inProgress = !connection.is_verified && !cancelled;

  const setCancelled = useMutation({
    mutationFn: (value: boolean) =>
      api.post(
        `/api/v1/cloud-connections/${connection.id}/${value ? "cancel" : "resume"}`,
      ),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["cloud-connections"] }),
    onError: (err) =>
      setError(err instanceof Error ? err.message : "Could not update the connection"),
  });

  const remove = useMutation({
    mutationFn: () => api.del(`/api/v1/cloud-connections/${connection.id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["cloud-connections"] }),
    onError: (err) =>
      setError(err instanceof Error ? err.message : "Could not remove the connection"),
  });

  const hasSelectionChanges = Object.keys(selection).length > 0;
  const checked = (row: DiscoveredSubscription) =>
    selection[row.subscription_id ?? ""] ?? row.in_scope;

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <CardTitle>{connection.name}</CardTitle>
            <CardDescription>{scopeSummary(connection)}</CardDescription>
          </div>
          <StatusPill status={connection.status} />
        </div>
      </CardHeader>

      <CardContent>
      {/* Status signals */}
      <div className="flex flex-wrap items-center gap-6 text-sm">
        <Signal
          label={t.connection.consentSignal}
          ok={connection.consent_status === "GRANTED"}
          detail={
            connection.consent_status === "GRANTED"
              ? t.connection.granted
              : t.connection.notGranted
          }
        />
        <Signal
          label={t.connection.accessSignal}
          ok={Boolean(connection.rbac_verified_at)}
          detail={
            connection.rbac_verified_at
              ? formatDateTime(connection.rbac_verified_at)
              : t.connection.notVerified
          }
        />
        <Signal
          label={t.connection.readySignal}
          ok={connection.is_ready_to_scan}
          detail={connection.is_ready_to_scan ? t.connection.yes : t.connection.notYet}
        />
      </div>

      {/* Not consented and no link to offer — the deployment cannot start a
          consent flow. Previously this rendered nothing at all: a card with
          three grey ticks and no explanation or button, which is the same
          dead end whether the cause is fixable or not. */}
      {!cancelled && connection.consent_status !== "GRANTED" && !connection.consent_url && (
        <Alert className="mt-4 border-high-border bg-high-bg text-high">
          <AlertTitle>{t.connection.cannotStartConsent}</AlertTitle>
          <AlertDescription className="text-foreground">
            {connection.status_detail}
          </AlertDescription>
        </Alert>
      )}

      {/* Consent step: not yet granted */}
      {!cancelled && connection.consent_status !== "GRANTED" && connection.consent_url && (
        <div className="mt-4 rounded-lg border border-border bg-muted/40 px-4 py-3">
          <p className="text-sm text-foreground">{connection.status_detail}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <Button
              render={
                <a
                  href={connection.consent_url}
                  target="_blank"
                  rel="noopener noreferrer"
                />
              }
            >
              {t.connection.openConsent}
            </Button>
            <CopyButton text={connection.consent_url} label={t.connection.copyConsentLink} />
          </div>
        </div>
      )}

      {/* Deploy step: consented but not yet verified */}
      {!cancelled &&
        connection.consent_status === "GRANTED" &&
        !connection.rbac_verified_at &&
        connection.template_url && (
          <div className="mt-4 rounded-lg border border-border bg-muted/40 px-4 py-3">
            <p className="text-sm text-foreground">{connection.status_detail}</p>
            <div className="mt-3">
              <Button
                render={
                  <a
                    href={connection.template_url}
                    target="_blank"
                    rel="noopener noreferrer"
                  />
                }
              >
                Deploy to Azure
              </Button>
            </div>
            {connection.deploy_stalled ? (
              /* Past the point where waiting explains it. A spinner here would
                 keep implying progress, and gives no way to tell a colleague
                 who has not got round to it from a deployment that failed or
                 landed at the wrong scope. */
              <p className="mt-3 text-xs leading-relaxed text-high">
                {connection.status_detail}
              </p>
            ) : (
              <WaitingNote text={t.connection.waitingForAccess} />
            )}
          </div>
        )}

      {/* Consented, but no template to deploy — CloudGuard is blocked, not
          waiting. A spinner here claimed progress that was not happening: the
          only thing that advances this state is the message being read and
          acted on, so it is shown as a problem with no spinner. */}
      {!cancelled &&
        connection.consent_status === "GRANTED" &&
        !connection.rbac_verified_at &&
        !connection.template_url && (
          <Alert className="mt-4 border-high-border bg-high-bg text-high">
            <AlertTitle>{t.connection.cannotDeployYet}</AlertTitle>
            <AlertDescription className="text-foreground">
              {connection.status_detail}
            </AlertDescription>
          </Alert>
        )}

      {/* Verified with nothing beneath it. Previously this rendered nothing:
          three green ticks, "Ready to scan: Yes", and an empty card. */}
      {connection.is_verified && subscriptions.length === 0 && (
        <div className="mt-4 rounded-lg border border-border bg-muted/40 px-4 py-3">
          <p className="text-sm font-medium text-foreground">
            {t.connection.noSubscriptionsTitle}
          </p>
          <p className="mt-1 text-sm text-muted-foreground">{t.connection.noSubscriptionsBody}</p>
          <Button
            className="mt-3"
            variant="secondary"
            disabled={rediscover.isPending}
            onClick={() => rediscover.mutate()}
          >
            {rediscover.isPending
              ? t.connection.lookingAgain
              : t.connection.lookAgain}
          </Button>
        </div>
      )}

      {/* Verified: show subscriptions */}
      {connection.is_verified && subscriptions.length > 0 && (
        <div className="mt-4 border-t border-border pt-3">
          <p className="text-xs text-muted-foreground">
            {scoped.length} of {subscriptions.length} {t.connection.inScopeCount}
            {connection.last_discovery_at && (
              <> · {t.connection.lastDiscovery} {formatDateTime(connection.last_discovery_at)}</>
            )}
          </p>
          <ul className="mt-2 divide-y divide-border rounded-lg border border-border">
            {subscriptions.map((sub) => (
              <li key={sub.id} className="flex items-center gap-3 px-4 py-2.5">
                <Checkbox
                  checked={checked(sub)}
                  onCheckedChange={(value) =>
                    setSelection({
                      ...selection,
                      [sub.subscription_id ?? ""]: value === true,
                    })
                  }
                  aria-label={`${t.connection.inScope}: ${sub.display_name}`}
                />
                <span className="flex-1">
                  <span className="block text-sm text-foreground">{sub.display_name}</span>
                  <code className="text-[11px] text-muted-foreground">{sub.subscription_id}</code>
                </span>
              </li>
            ))}
          </ul>
          {hasSelectionChanges && (
            <Button
              className="mt-3"
              onClick={() => saveScope.mutate()}
              disabled={saveScope.isPending}
            >
              {t.connection.saveScope}
            </Button>
          )}
        </div>
      )}

      {error && (
        <Alert variant="destructive" className="mt-3">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {connection.status_detail &&
        !error &&
        connection.consent_status === "GRANTED" &&
        connection.rbac_verified_at && (
          <p className="mt-3 text-sm text-muted-foreground">{connection.status_detail}</p>
        )}

      {/* Verified with subscriptions in scope. Scanning lives on another page,
          and nothing here said so — the flow ended on a green tick and left
          the customer to guess what came next. */}
      {connection.is_verified && scoped.length > 0 && (
        <Alert className="mt-4 border-ok-border bg-ok-bg text-ok">
          <AlertTitle>{t.connection.readyToScan}</AlertTitle>
          <AlertDescription className="text-foreground">
            <p>
              {scoped.length} {t.connection.inScopeCount}.
            </p>
            <Button className="mt-2" render={<Link to="/scans" />}>
              {t.connection.runFirstScan}
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {/* And the answer to "do I have to remember to do that?". Placed after
          the scan button rather than beside it: the first scan is the thing to
          do now, and the schedule is the thing that stops there being a next
          time somebody forgets. */}
      {connection.is_verified && scoped.length > 0 && (
        <ScheduleControl connection={connection} onError={setError} />
      )}

      {cancelled && (
        <div className="mt-4 rounded-lg border border-border bg-muted/40 px-4 py-3">
          <p className="text-sm font-medium text-foreground">
            {t.connection.setupCancelled}
          </p>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            {connection.status_detail}
          </p>
        </div>
      )}

      {/* Actions */}
      {confirmingRemove ? (
        <RemoveConfirm
          connectionId={connection.id}
          busy={remove.isPending}
          onConfirm={() => remove.mutate()}
          onCancel={() => setConfirmingRemove(false)}
        />
      ) : (
        <div className="mt-4 flex flex-wrap items-center gap-2">
          {inProgress && (
            <Button
              variant="secondary"
              onClick={() => setCancelled.mutate(true)}
              disabled={setCancelled.isPending}
            >
              {t.connection.cancelSetupAction}
            </Button>
          )}
          {cancelled && (
            <Button
              variant="secondary"
              onClick={() => setCancelled.mutate(false)}
              disabled={setCancelled.isPending}
            >
              {t.connection.resumeSetup}
            </Button>
          )}
          <Button
            variant="ghost"
            className="ml-auto text-critical hover:bg-critical-bg"
            onClick={() => setConfirmingRemove(true)}
          >
            {t.connection.remove}
          </Button>
        </div>
      )}
      </CardContent>
    </Card>
  );
}

function scopeSummary(connection: CloudConnection): string {
  const scope =
    connection.scope_type === "TENANT_ROOT"
      ? "Entire tenant"
      : connection.scope_type === "MANAGEMENT_GROUP"
        ? `Management group ${connection.scope_id}`
        : `Subscription ${connection.scope_id}`;
  const tenant = connection.tenant_id ? ` · Tenant ${connection.tenant_id}` : "";
  return `${scope} · ${connection.role_version}${tenant}`;
}

function Signal({ label, ok, detail }: { label: string; ok: boolean; detail: string }) {
  return (
    <div className="flex items-center gap-2">
      <span
        className={cn(
          "flex size-5 items-center justify-center rounded-full text-white",
          ok ? "bg-ok" : "bg-muted-foreground/40",
        )}
      >
        {/* An icon rather than a character, so the two states differ by shape
            as well as by colour. */}
        {ok ? <CheckIcon className="size-3" /> : <MinusIcon className="size-3" />}
      </span>
      <span>
        <span className="font-medium text-foreground">{label}</span>{" "}
        <span className="text-muted-foreground">{detail}</span>
      </span>
    </div>
  );
}

function WaitingNote({ text }: { text: string }) {
  return (
    <p className="mt-3 flex items-center gap-2 text-sm text-muted-foreground">
      <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-input border-t-foreground" />
      {text}
    </p>
  );
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const t = useT();
  const [copied, setCopied] = useState(false);

  return (
    <Button
      variant="secondary"
      onClick={() => {
        void navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }}
    >
      {copied ? t.connection.copied : label}
    </Button>
  );
}
