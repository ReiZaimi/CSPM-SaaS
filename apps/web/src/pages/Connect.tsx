import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "@/lib/api";
import type {
  CloudConnection,
  DiscoveredSubscription,
  Revocation,
  RevocationCheck,
} from "@/lib/types";
import { useT } from "@/i18n";
import { Button, Card, EmptyState, ErrorNote, Spinner, StatusPill } from "@/components/ui";
import { formatDateTime } from "@/lib/format";
import { ConnectionForm } from "@/components/ConnectWizard";

/**
 * The connections page.
 *
 * Lists existing connections with live status, and offers a form to create new
 * ones. After consent, the callback redirects here with `?id=<connection_id>`,
 * which auto-expands the matching card.
 */
export function ConnectPage() {
  const t = useT();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [showForm, setShowForm] = useState(false);

  const consentError = searchParams.get("consent_error");
  const expandedId = searchParams.get("id");

  const connections = useQuery({
    queryKey: ["cloud-connections"],
    queryFn: () =>
      api.get<CloudConnection[]>("/api/v1/cloud-connections").then((r) => r.data),
  });

  function handleCreated(id: string) {
    setShowForm(false);
    setSearchParams({ id });
    queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
  }

  function dismissError() {
    searchParams.delete("consent_error");
    setSearchParams(searchParams);
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{t.connection.title}</h1>
          <p className="mt-1 max-w-3xl text-sm text-stone-600">{t.connection.intro}</p>
        </div>
        {!showForm && (
          <Button onClick={() => setShowForm(true)}>
            {t.connection.connectAzure}
          </Button>
        )}
      </div>

      {consentError && (
        <ErrorNote
          message={`Consent failed: ${consentError}`}
          onRetry={dismissError}
        />
      )}

      {showForm && (
        <ConnectionForm
          onCreated={handleCreated}
          onClose={() => setShowForm(false)}
        />
      )}

      {connections.isLoading && <Spinner text={t.common.loading} />}
      {connections.data?.length === 0 && !showForm && (
        <EmptyState
          title={t.connection.noConnections}
          detail={t.connection.noConnectionsHelp}
          action={
            <Button onClick={() => setShowForm(true)}>
              {t.connection.connectAzure}
            </Button>
          }
        />
      )}

      {connections.data?.map((connection) => (
        <ConnectionCard
          key={connection.id}
          connection={connection}
          defaultExpanded={connection.id === expandedId}
        />
      ))}
    </div>
  );
}

/**
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
    refetchInterval: (query) => (query.state.data?.is_verified ? false : 5000),
    refetchIntervalInBackground: true,
  });

  const connection = detail.data ?? initial;
  const subscriptions = connection.subscriptions ?? [];
  const scoped = subscriptions.filter((s) => s.in_scope);

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
    <Card
      title={connection.name}
      subtitle={scopeSummary(connection)}
      action={<StatusPill status={connection.status} />}
    >
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
          ok={connection.is_verified}
          detail={connection.is_verified ? t.connection.yes : t.connection.notYet}
        />
      </div>

      {/* Not consented and no link to offer — the deployment cannot start a
          consent flow. Previously this rendered nothing at all: a card with
          three grey ticks and no explanation or button, which is the same
          dead end whether the cause is fixable or not. */}
      {!cancelled && connection.consent_status !== "GRANTED" && !connection.consent_url && (
        <div className="mt-4 rounded-lg border border-high-border bg-high-bg px-4 py-3">
          <p className="text-sm font-medium text-high">
            {t.connection.cannotStartConsent}
          </p>
          <p className="mt-1 text-xs leading-relaxed text-stone-700">
            {connection.status_detail}
          </p>
        </div>
      )}

      {/* Consent step: not yet granted */}
      {!cancelled && connection.consent_status !== "GRANTED" && connection.consent_url && (
        <div className="mt-4 rounded-lg border border-stone-200 bg-stone-50 px-4 py-3">
          <p className="text-sm text-stone-700">{connection.status_detail}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <a
              href={connection.consent_url}
              target="_blank"
              rel="noopener noreferrer"
            >
              <Button>{t.connection.openConsent}</Button>
            </a>
            <CopyButton text={connection.consent_url} label={t.connection.copyConsentLink} />
          </div>
        </div>
      )}

      {/* Deploy step: consented but not yet verified */}
      {!cancelled &&
        connection.consent_status === "GRANTED" &&
        !connection.rbac_verified_at &&
        connection.template_url && (
          <div className="mt-4 rounded-lg border border-stone-200 bg-stone-50 px-4 py-3">
            <p className="text-sm text-stone-700">{connection.status_detail}</p>
            <div className="mt-3">
              <a
                href={connection.template_url}
                target="_blank"
                rel="noopener noreferrer"
              >
                <Button>Deploy to Azure</Button>
              </a>
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
          <div className="mt-4 rounded-lg border border-high-border bg-high-bg px-4 py-3">
            <p className="text-sm font-medium text-high">
              {t.connection.cannotDeployYet}
            </p>
            <p className="mt-1 text-xs leading-relaxed text-stone-700">
              {connection.status_detail}
            </p>
          </div>
        )}

      {/* Verified: show subscriptions */}
      {connection.is_verified && subscriptions.length > 0 && (
        <div className="mt-4 border-t border-stone-100 pt-3">
          <p className="text-xs text-stone-500">
            {scoped.length} of {subscriptions.length} {t.connection.inScopeCount}
            {connection.last_discovery_at && (
              <> · {t.connection.lastDiscovery} {formatDateTime(connection.last_discovery_at)}</>
            )}
          </p>
          <ul className="mt-2 divide-y divide-stone-100 rounded-lg border border-stone-200">
            {subscriptions.map((sub) => (
              <li key={sub.id} className="flex items-center gap-3 px-4 py-2.5">
                <input
                  type="checkbox"
                  checked={checked(sub)}
                  onChange={(e) =>
                    setSelection({
                      ...selection,
                      [sub.subscription_id ?? ""]: e.target.checked,
                    })
                  }
                  aria-label={`${t.connection.inScope}: ${sub.display_name}`}
                />
                <span className="flex-1">
                  <span className="block text-sm text-stone-900">{sub.display_name}</span>
                  <code className="text-[11px] text-stone-400">{sub.subscription_id}</code>
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
        <div className="mt-3">
          <ErrorNote message={error} />
        </div>
      )}
      {connection.status_detail &&
        !error &&
        connection.consent_status === "GRANTED" &&
        connection.rbac_verified_at && (
          <p className="mt-3 text-sm text-stone-600">{connection.status_detail}</p>
        )}

      {/* Verified with subscriptions in scope. Scanning lives on another page,
          and nothing here said so — the flow ended on a green tick and left
          the customer to guess what came next. */}
      {connection.is_verified && scoped.length > 0 && (
        <div className="mt-4 rounded-lg border border-ok-border bg-ok-bg px-4 py-3">
          <p className="text-sm font-medium text-ok">{t.connection.readyToScan}</p>
          <p className="mt-1 text-xs leading-relaxed text-stone-700">
            {scoped.length} {t.connection.inScopeCount}.
          </p>
          <Link to="/scans" className="mt-3 inline-block">
            <Button>{t.connection.runFirstScan}</Button>
          </Link>
        </div>
      )}

      {cancelled && (
        <div className="mt-4 rounded-lg border border-stone-200 bg-stone-50 px-4 py-3">
          <p className="text-sm font-medium text-stone-800">
            {t.connection.setupCancelled}
          </p>
          <p className="mt-1 text-xs leading-relaxed text-stone-600">
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
    </Card>
  );
}

function RemoveConfirm({
  connectionId,
  busy,
  onConfirm,
  onCancel,
}: {
  connectionId: string;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [checked, setChecked] = useState<RevocationCheck | null>(null);

  const revocation = useQuery({
    queryKey: ["connection-revocation", connectionId],
    queryFn: () =>
      api
        .get<Revocation>(`/api/v1/cloud-connections/${connectionId}/revocation`)
        .then((r) => r.data),
  });

  const check = useMutation({
    mutationFn: () =>
      api.post<RevocationCheck>(
        `/api/v1/cloud-connections/${connectionId}/check-revoked`,
      ),
    onSuccess: ({ data }) => setChecked(data),
  });

  const steps = revocation.data?.steps ?? [];

  return (
    <div className="mt-4 rounded-lg border border-critical-border bg-critical-bg px-4 py-3">
      <p className="text-sm font-medium text-critical">{t.connection.removeTitle}</p>
      <p className="mt-1 text-xs leading-relaxed text-stone-700">
        {t.connection.removeDetail}
      </p>

      {/* Revocation sits inside the removal confirmation on purpose. It is the
          only moment the customer is thinking about ending this, and once the
          connection is deleted the principal id and scope needed to write these
          commands are gone with it. */}
      {steps.length > 0 && (
        <div className="mt-3 rounded-lg border border-stone-200 bg-white px-3 py-2.5">
          <p className="text-xs font-medium text-stone-800">{t.connection.revokeTitle}</p>
          <p className="mt-1 text-xs leading-relaxed text-stone-600">
            {t.connection.revokeIntro}
          </p>
          <ol className="mt-2 space-y-2">
            {steps.map((step) => (
              <li key={step.title}>
                <p className="text-xs font-medium text-stone-700">{step.title}</p>
                <p className="text-[11px] leading-relaxed text-stone-500">
                  {step.detail}
                </p>
                <pre className="mt-1 overflow-x-auto rounded bg-stone-900 px-2.5 py-1.5 text-[11px] text-stone-100">
                  {step.command}
                </pre>
              </li>
            ))}
          </ol>
          {revocation.data && (
            <p className="mt-2 text-[11px] leading-relaxed text-stone-500">
              {revocation.data.why_manual}
            </p>
          )}

          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Button
              variant="secondary"
              onClick={() => check.mutate()}
              disabled={check.isPending}
            >
              {check.isPending ? t.connection.checking : t.connection.checkRevoked}
            </Button>
            {checked && (
              <span
                className={
                  checked.revoked
                    ? "text-xs font-medium text-ok"
                    : "text-xs font-medium text-high"
                }
              >
                {checked.revoked ? t.connection.accessGone : t.connection.stillHasAccess}
              </span>
            )}
          </div>
          {checked && (
            <p className="mt-1 text-[11px] leading-relaxed text-stone-600">
              {checked.detail}
            </p>
          )}
        </div>
      )}

      <div className="mt-3 flex flex-wrap gap-2">
        <Button variant="danger" onClick={onConfirm} disabled={busy}>
          {busy ? t.connection.removing : t.connection.remove}
        </Button>
        <Button variant="secondary" onClick={onCancel}>
          {t.connection.keep}
        </Button>
      </div>
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
  const tenant = connection.tenant_id ? ` · Tenant ${connection.tenant_id}` : "";
  return `${scope} · ${connection.role_version}${tenant}`;
}

function Signal({ label, ok, detail }: { label: string; ok: boolean; detail: string }) {
  return (
    <div className="flex items-center gap-2">
      <span
        className={`flex h-5 w-5 items-center justify-center rounded-full text-[11px] font-bold text-white ${
          ok ? "bg-ok" : "bg-stone-300"
        }`}
      >
        {ok ? "✓" : "–"}
      </span>
      <span>
        <span className="font-medium text-stone-800">{label}</span>{" "}
        <span className="text-stone-500">{detail}</span>
      </span>
    </div>
  );
}

function WaitingNote({ text }: { text: string }) {
  return (
    <p className="mt-3 flex items-center gap-2 text-sm text-stone-500">
      <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-stone-300 border-t-stone-600" />
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
