import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type { CloudAccount } from "@/lib/types";
import { useT } from "@/i18n";
import { Button, Card, Field, Input, StatusPill, ErrorNote, Spinner } from "@/components/ui";
import { formatDateTime } from "@/lib/format";

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
  const [form, setForm] = useState({ account_name: "", tenant_id: "", subscription_id: "" });
  const [error, setError] = useState<string | null>(null);

  const accounts = useQuery({
    queryKey: ["cloud-accounts"],
    queryFn: () => api.get<CloudAccount[]>("/api/v1/cloud-accounts").then((r) => r.data),
  });

  const permissions = useQuery({
    queryKey: ["azure-permissions"],
    queryFn: () =>
      api.get<Permissions>("/api/v1/cloud-accounts/azure/permissions").then((r) => r.data),
  });

  const create = useMutation({
    mutationFn: (body: typeof form) => api.post<CloudAccount>("/api/v1/cloud-accounts", body),
    onSuccess: () => {
      setForm({ account_name: "", tenant_id: "", subscription_id: "" });
      setError(null);
      queryClient.invalidateQueries({ queryKey: ["cloud-accounts"] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "Could not add connection"),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{t.connect.title}</h1>
        <p className="mt-1 text-sm text-stone-600">{t.connect.readOnlyPromise}</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title={t.connect.whatWeAccess}>
          {permissions.isLoading && <Spinner />}
          {permissions.data && (
            <>
              <ul className="space-y-2 text-sm text-stone-700">
                {permissions.data.graph_application_permissions.map((permission) => (
                  <li key={permission} className="flex items-start gap-2">
                    <Dot className="text-ok" />
                    <code className="text-xs">{permission}</code>
                  </li>
                ))}
                <li className="flex items-start gap-2">
                  <Dot className="text-ok" />
                  <span className="text-xs">
                    Azure RBAC <code>{permissions.data.azure_rbac_role}</code> on the
                    subscriptions you choose
                  </span>
                </li>
              </ul>

              <div className="mt-4 rounded-lg bg-stone-50 p-3">
                <p className="text-xs font-medium text-stone-700">{t.connect.whatWeCannot}</p>
                <p className="mt-1 text-xs text-stone-600">
                  Create, modify, or delete anything. Read your data plane contents. Access
                  subscriptions you have not granted. Access is{" "}
                  <strong>{permissions.data.access_type}</strong> and writes performed are{" "}
                  <strong>{permissions.data.writes_performed}</strong>.
                </p>
              </div>
            </>
          )}
        </Card>

        <Card title="No credential required">
          <p className="text-sm leading-relaxed text-stone-600">{t.connect.noSecrets}</p>
          <ol className="mt-4 space-y-3">
            <Step n={1} title={t.connect.step1} detail={t.connect.step1Detail} />
            <Step n={2} title={t.connect.step2} detail={t.connect.step2Detail} />
            <Step n={3} title={t.connect.step3} detail={t.connect.step3Detail} />
          </ol>
        </Card>
      </div>

      <Card title="Add a subscription">
        <form
          className="grid gap-4 sm:grid-cols-3"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate(form);
          }}
        >
          <Field label={t.connect.accountName}>
            <Input
              required
              value={form.account_name}
              onChange={(e) => setForm({ ...form, account_name: e.target.value })}
              placeholder="Production"
            />
          </Field>
          <Field label={t.connect.tenantId} hint="Entra ID > Overview > Tenant ID">
            <Input
              required
              value={form.tenant_id}
              onChange={(e) => setForm({ ...form, tenant_id: e.target.value })}
              placeholder="00000000-0000-0000-0000-000000000000"
            />
          </Field>
          <Field label={t.connect.subscriptionId} hint="Subscriptions > your subscription">
            <Input
              value={form.subscription_id}
              onChange={(e) => setForm({ ...form, subscription_id: e.target.value })}
              placeholder="00000000-0000-0000-0000-000000000000"
            />
          </Field>
          <div className="sm:col-span-3">
            {error && <div className="mb-3"><ErrorNote message={error} /></div>}
            <Button type="submit" disabled={create.isPending}>
              {t.connect.createConnection}
            </Button>
          </div>
        </form>
      </Card>

      {accounts.isLoading && <Spinner text={t.common.loading} />}
      {accounts.data?.map((account) => (
        <ConnectionCard key={account.id} account={account} />
      ))}
    </div>
  );
}

function ConnectionCard({ account }: { account: CloudAccount }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [message, setMessage] = useState<string | null>(null);
  const [problems, setProblems] = useState<string[]>([]);

  const consent = useMutation({
    mutationFn: () =>
      api.post<{ consent_url: string }>(`/api/v1/cloud-accounts/${account.id}/consent-url`),
    onSuccess: ({ data }) => {
      // Opens Microsoft's own consent page. CloudGuard never sees the admin's
      // credentials -- Entra authenticates them and calls our callback.
      window.open(data.consent_url, "_blank", "noopener");
    },
    onError: (err) =>
      setMessage(err instanceof ApiError ? err.message : t.connect.notConfigured),
  });

  const validate = useMutation({
    mutationFn: () =>
      api.post<{ ok: boolean; detail: string; problems: string[]; permissions_verified: string[] }>(
        `/api/v1/cloud-accounts/${account.id}/validate`,
      ),
    onSuccess: ({ data }) => {
      setMessage(data.ok ? t.connect.verified : data.detail);
      setProblems(data.ok ? [] : data.problems);
      queryClient.invalidateQueries({ queryKey: ["cloud-accounts"] });
    },
    onError: (err) => setMessage(err instanceof ApiError ? err.message : "Verification failed"),
  });

  return (
    <Card
      title={account.account_name}
      subtitle={`Tenant ${account.tenant_id}${account.subscription_id ? ` · Subscription ${account.subscription_id}` : ""}`}
      action={<StatusPill status={account.status} />}
    >
      <div className="flex flex-wrap items-center gap-6 text-sm">
        <Signal
          label="Admin consent"
          ok={account.consent_status === "GRANTED"}
          detail={account.consent_status === "GRANTED" ? "Granted" : "Not granted"}
        />
        <Signal
          label="Reader role"
          ok={Boolean(account.rbac_verified_at)}
          detail={
            account.rbac_verified_at
              ? `Verified ${formatDateTime(account.rbac_verified_at)}`
              : "Not verified"
          }
        />
        <Signal
          label="Ready to scan"
          ok={account.is_scannable}
          detail={account.is_scannable ? "Yes" : "Not yet"}
        />
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        <Button variant="secondary" onClick={() => consent.mutate()} disabled={consent.isPending}>
          {t.connect.openConsent}
        </Button>
        <Button onClick={() => validate.mutate()} disabled={validate.isPending}>
          {validate.isPending ? t.common.loading : t.connect.verify}
        </Button>
      </div>

      {message && (
        <p
          className={`mt-3 text-sm ${account.is_scannable ? "text-ok" : "text-stone-700"}`}
        >
          {message}
        </p>
      )}
      {problems.length > 0 && (
        <ul className="mt-2 space-y-1">
          {problems.map((problem) => (
            <li key={problem} className="text-sm text-high">
              • {problem}
            </li>
          ))}
        </ul>
      )}
      {account.status_detail && !message && (
        <p className="mt-3 text-sm text-stone-600">{account.status_detail}</p>
      )}
    </Card>
  );
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

function Step({ n, title, detail }: { n: number; title: string; detail: string }) {
  return (
    <li className="flex gap-3">
      <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-stone-900 text-xs font-semibold text-white">
        {n}
      </span>
      <div>
        <p className="text-sm font-medium text-stone-800">{title}</p>
        <p className="mt-0.5 text-xs leading-relaxed text-stone-600">{detail}</p>
      </div>
    </li>
  );
}

function Dot({ className }: { className?: string }) {
  return <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-current ${className}`} />;
}
