import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { CloudConnection, DiscoveredSubscription } from "@/lib/types";
import { useT } from "@/i18n";
import { Button, Card, EmptyState, ErrorNote, Spinner, StatusPill } from "@/components/ui";
import { formatDateTime } from "@/lib/format";
import { ConnectWizard } from "@/components/ConnectWizard";

interface Permissions {
  graph_application_permissions: string[];
  azure_rbac_role: string;
  access_type: string;
  writes_performed: string;
}

/**
 * The trust screen.
 *
 * The customer is about to let a product they just met read their entire cloud
 * environment. This page's job is to make the exact scope of that legible
 * before they click anything, and to be honest that it is two separate grants —
 * the step customers most often miss is the second one.
 */
export function ConnectPage() {
  const t = useT();
  const queryClient = useQueryClient();
  const [wizard, setWizard] = useState<{ connectionId: string | null } | null>(null);

  const connections = useQuery({
    queryKey: ["cloud-connections"],
    queryFn: () =>
      api.get<CloudConnection[]>("/api/v1/cloud-connections").then((r) => r.data),
  });

  const permissions = useQuery({
    queryKey: ["azure-permissions"],
    queryFn: () =>
      api.get<Permissions>("/api/v1/cloud-accounts/azure/permissions").then((r) => r.data),
  });

  function closeWizard() {
    setWizard(null);
    queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{t.connection.title}</h1>
          <p className="mt-1 max-w-3xl text-sm text-stone-600">{t.connection.intro}</p>
        </div>
        {!wizard && (
          <Button onClick={() => setWizard({ connectionId: null })}>
            {t.connection.connectAzure}
          </Button>
        )}
      </div>

      {wizard && (
        <ConnectWizard
          connectionId={wizard.connectionId}
          onCreated={(id) => setWizard({ connectionId: id })}
          onClose={closeWizard}
        />
      )}

      {permissions.data && <AccessSummary permissions={permissions.data} />}

      {connections.isLoading && <Spinner text={t.common.loading} />}
      {connections.data?.length === 0 && !wizard && (
        <EmptyState
          title={t.connection.noConnections}
          detail={t.connection.noConnectionsHelp}
          action={
            <Button onClick={() => setWizard({ connectionId: null })}>
              {t.connection.connectAzure}
            </Button>
          }
        />
      )}

      {connections.data?.map((connection) => (
        <ConnectionCard
          key={connection.id}
          connection={connection}
          onResume={() => setWizard({ connectionId: connection.id })}
        />
      ))}
    </div>
  );
}

function AccessSummary({ permissions }: { permissions: Permissions }) {
  const t = useT();
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card title={t.connect.whatWeAccess}>
        <ul className="space-y-2 text-sm text-stone-700">
          {permissions.graph_application_permissions.map((permission) => (
            <li key={permission} className="flex items-start gap-2">
              <Dot className="text-ok" />
              <code className="text-xs">{permission}</code>
            </li>
          ))}
        </ul>
        <div className="mt-4 rounded-lg bg-stone-50 p-3">
          <p className="text-xs font-medium text-stone-700">{t.connect.whatWeCannot}</p>
          <p className="mt-1 text-xs text-stone-600">
            Create, modify, or delete anything. Read your data plane contents. Access
            subscriptions you have not granted. Access is{" "}
            <strong>{permissions.access_type}</strong> and writes performed are{" "}
            <strong>{permissions.writes_performed}</strong>.
          </p>
        </div>
      </Card>

      <Card title="No credential required">
        <p className="text-sm leading-relaxed text-stone-600">{t.connect.noSecrets}</p>
        <p className="mt-3 text-sm leading-relaxed text-stone-600">
          {t.connection.noGuidsNeeded}
        </p>
      </Card>
    </div>
  );
}

function ConnectionCard({
  connection,
  onResume,
}: {
  connection: CloudConnection;
  onResume: () => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [confirmingRemove, setConfirmingRemove] = useState(false);

  const subscriptions = useQuery({
    queryKey: ["connection-subscriptions", connection.id],
    queryFn: () =>
      api
        .get<DiscoveredSubscription[]>(
          `/api/v1/cloud-connections/${connection.id}/subscriptions`,
        )
        .then((r) => r.data),
    enabled: connection.is_verified,
  });

  const rediscover = useMutation({
    mutationFn: () =>
      api.post<DiscoveredSubscription[]>(
        `/api/v1/cloud-connections/${connection.id}/discover`,
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["connection-subscriptions", connection.id] });
      queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : "Discovery failed"),
  });

  const remove = useMutation({
    mutationFn: () => api.del(`/api/v1/cloud-connections/${connection.id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["cloud-connections"] }),
    onError: (err) =>
      setError(err instanceof Error ? err.message : "Could not remove the connection"),
  });

  const scoped = subscriptions.data?.filter((s) => s.in_scope) ?? [];

  return (
    <Card
      title={connection.name}
      subtitle={scopeSummary(connection)}
      action={<StatusPill status={connection.status} />}
    >
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

      {connection.is_verified && (
        <div className="mt-4 border-t border-stone-100 pt-3">
          <p className="text-xs text-stone-500">
            {scoped.length} of {subscriptions.data?.length ?? 0}{" "}
            {t.connection.inScopeCount} · {t.connection.lastDiscovery}{" "}
            {connection.last_discovery_at
              ? formatDateTime(connection.last_discovery_at)
              : t.connection.neverDiscovered}
          </p>
          <ul className="mt-2 flex flex-wrap gap-1.5">
            {subscriptions.data?.map((subscription) => (
              <li
                key={subscription.id}
                className={
                  subscription.in_scope
                    ? "rounded-full border border-stone-200 bg-white px-2.5 py-0.5 text-xs text-stone-700"
                    : "rounded-full border border-dashed border-stone-200 px-2.5 py-0.5 text-xs text-stone-400"
                }
              >
                {subscription.display_name}
              </li>
            ))}
          </ul>
        </div>
      )}

      {error && <div className="mt-3"><ErrorNote message={error} /></div>}
      {connection.status_detail && !error && (
        <p className="mt-3 text-sm text-stone-600">{connection.status_detail}</p>
      )}

      {confirmingRemove ? (
        <RemoveConfirm
          busy={remove.isPending}
          onConfirm={() => remove.mutate()}
          onCancel={() => setConfirmingRemove(false)}
        />
      ) : (
        <div className="mt-4 flex flex-wrap gap-2">
          {!connection.is_verified && (
            <Button onClick={onResume}>{t.connection.create}</Button>
          )}
          {connection.is_verified && (
            <>
              <Button
                variant="secondary"
                onClick={() => rediscover.mutate()}
                disabled={rediscover.isPending}
              >
                {rediscover.isPending ? t.connection.discovering : t.connection.rediscover}
              </Button>
              <Button variant="ghost" onClick={onResume}>
                {t.connection.stepSubscriptions}
              </Button>
            </>
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

/**
 * Removal, with what it costs stated before it happens.
 *
 * Deleting a connection cascades: discovered subscriptions, their assets, scan
 * history and findings all go. The second note matters as much as the first —
 * removing the row here revokes nothing in Azure, and a customer who believes
 * it does will leave CloudGuard holding read access to their tenant.
 */
function RemoveConfirm({
  busy,
  onConfirm,
  onCancel,
}: {
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const t = useT();
  return (
    <div className="mt-4 rounded-lg border border-critical-border bg-critical-bg px-4 py-3">
      <p className="text-sm font-medium text-critical">{t.connection.removeTitle}</p>
      <p className="mt-1 text-xs leading-relaxed text-stone-700">
        {t.connection.removeDetail}
      </p>
      <p className="mt-2 text-xs leading-relaxed text-stone-700">
        {t.connection.removeAzureNote}
      </p>
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
  const role =
    connection.permission_mode === "READER"
      ? "Reader"
      : `Custom role ${connection.role_version}`;
  const tenant = connection.tenant_id ? ` · Tenant ${connection.tenant_id}` : "";
  return `${scope} · ${role}${tenant}`;
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

function Dot({ className }: { className?: string }) {
  return <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-current ${className}`} />;
}
