import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, API_URL, ApiError } from "@/lib/api";
import type {
  ArtifactFormat,
  ArtifactLinks,
  CloudConnection,
  ConnectionOptions,
  ConnectionScope,
  DiscoveredSubscription,
  PermissionMode,
  ValidationResult,
} from "@/lib/types";
import { useT } from "@/i18n";
import { Button, Card, ErrorNote, Field, Input, Spinner } from "@/components/ui";
import { cn } from "@/lib/format";

/**
 * The connection wizard.
 *
 * Every step's completion is read from the server, never from local state. That
 * is not fussiness: consent happens in a different browser tab, and the read
 * access grant often happens on a different person's machine entirely. A wizard
 * that tracked its own progress would be wrong the moment either of those
 * finished somewhere else, and would strand a customer on a step they had
 * already completed.
 *
 * The two steps in the middle poll while they wait, so the flow advances by
 * itself rather than asking anyone to come back and press a button.
 */
type Step = 1 | 2 | 3 | 4 | 5;

const STEP_COUNT = 5;

export function ConnectWizard({
  connectionId,
  onCreated,
  onClose,
}: {
  connectionId: string | null;
  onCreated: (id: string) => void;
  onClose: () => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [confirmingCancel, setConfirmingCancel] = useState(false);

  const discard = useMutation({
    mutationFn: () => api.del(`/api/v1/cloud-connections/${connectionId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
      onClose();
    },
  });

  const options = useQuery({
    queryKey: ["connection-options"],
    queryFn: () =>
      api.get<ConnectionOptions>("/api/v1/cloud-connections/options").then((r) => r.data),
  });

  // Polls only while something is genuinely outstanding. Once both grants are
  // in, there is nothing left to wait for and the interval stops.
  const connection = useQuery({
    queryKey: ["cloud-connection", connectionId],
    queryFn: () =>
      api
        .get<CloudConnection>(`/api/v1/cloud-connections/${connectionId}`)
        .then((r) => r.data),
    enabled: Boolean(connectionId),
    refetchInterval: (query) => (query.state.data?.is_verified ? false : 5000),
    // The consent button opens Microsoft in a new tab, and the access script
    // runs in Cloud Shell in another one — so this tab is backgrounded for the
    // whole of both waits. Without this the polling stops precisely when it is
    // needed, and the customer returns to a wizard still showing step 2.
    refetchIntervalInBackground: true,
  });

  const step = currentStep(connection.data);

  // Nothing exists to discard until step 1 has been submitted, and once a
  // connection is verified it is no longer "setup in progress" — throwing it
  // away then is a heavier action that belongs on the connection's own card,
  // with the fuller warning about what goes with it.
  const canDiscard = Boolean(connectionId) && !connection.data?.is_verified;

  function requestCancel() {
    if (canDiscard) setConfirmingCancel(true);
    else onClose();
  }

  return (
    <Card
      title={`${t.connection.step} ${step} ${t.connection.of} ${STEP_COUNT} · ${stepTitle(step, t)}`}
      action={
        <button
          onClick={requestCancel}
          aria-label={t.connection.cancelSetup}
          className="text-sm text-stone-500 transition hover:text-stone-900"
        >
          ✕
        </button>
      }
    >
      <StepRail step={step} />

      {options.isLoading && <Spinner />}

      {options.data && !options.data.azure_configured && (
        <NotConfiguredNote detail={options.data.azure_problem} />
      )}

      {step === 1 && options.data && (
        <ScopeStep options={options.data} onCreated={onCreated} />
      )}
      {step === 2 && connection.data && <ConsentStep connection={connection.data} />}
      {step === 3 && connection.data && <AccessStep connection={connection.data} />}
      {step === 4 && connection.data && <VerifyStep connection={connection.data} />}
      {step === 5 && connection.data && (
        <SubscriptionsStep connection={connection.data} onClose={onClose} />
      )}

      <div className="mt-5 border-t border-stone-100 pt-4">
        {confirmingCancel ? (
          <div className="rounded-lg border border-stone-200 bg-stone-50 px-4 py-3">
            <p className="text-sm font-medium text-stone-900">
              {t.connection.discardTitle}
            </p>
            <p className="mt-1 text-xs leading-relaxed text-stone-600">
              {t.connection.discardDetail}
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              <Button
                variant="danger"
                onClick={() => discard.mutate()}
                disabled={discard.isPending}
              >
                {discard.isPending ? t.connection.discarding : t.connection.discard}
              </Button>
              <Button variant="secondary" onClick={onClose}>
                {t.connection.finishLater}
              </Button>
              <Button variant="ghost" onClick={() => setConfirmingCancel(false)}>
                {t.common.back}
              </Button>
            </div>
            {discard.isError && (
              <div className="mt-3">
                <ErrorNote message={t.common.error} />
              </div>
            )}
          </div>
        ) : (
          <Button variant="ghost" onClick={requestCancel}>
            {/* Three different situations, not two: nothing created yet is a
                plain cancel, a half-finished connection is setup to abandon,
                and a verified one is simply a panel to close. */}
            {!connectionId
              ? t.connection.cancel
              : canDiscard
                ? t.connection.cancelSetup
                : t.connection.close}
          </Button>
        )}
      </div>
    </Card>
  );
}

function currentStep(connection: CloudConnection | undefined): Step {
  if (!connection) return 1;
  if (connection.consent_status !== "GRANTED") return 2;
  if (!connection.rbac_verified_at) return 3;
  if (!connection.last_discovery_at) return 4;
  return 5;
}

function stepTitle(step: Step, t: ReturnType<typeof useT>): string {
  return [
    t.connection.stepScope,
    t.connection.stepConsent,
    t.connection.stepAccess,
    t.connection.stepVerify,
    t.connection.stepSubscriptions,
  ][step - 1];
}

function StepRail({ step }: { step: Step }) {
  return (
    <ol className="mb-5 flex gap-1.5" aria-label="Progress">
      {Array.from({ length: STEP_COUNT }, (_, i) => (
        <li
          key={i}
          className={cn(
            "h-1 flex-1 rounded-full",
            i + 1 < step ? "bg-ok" : i + 1 === step ? "bg-stone-900" : "bg-stone-200",
          )}
        />
      ))}
    </ol>
  );
}

/* -------------------------------------------------------------------------- */

function ScopeStep({
  options,
  onCreated,
}: {
  options: ConnectionOptions;
  onCreated: (id: string) => void;
}) {
  const t = useT();
  const [name, setName] = useState("");
  const [scopeType, setScopeType] = useState<ConnectionScope>("TENANT_ROOT");
  const [scopeId, setScopeId] = useState("");
  const [mode, setMode] = useState<PermissionMode>("READER");
  const [error, setError] = useState<string | null>(null);

  const scope = options.scopes.find((s) => s.value === scopeType);
  const needsScopeId = Boolean(scope?.requires_scope_id);

  const create = useMutation({
    mutationFn: () =>
      api.post<CloudConnection>("/api/v1/cloud-connections", {
        name,
        scope_type: scopeType,
        scope_id: needsScopeId ? scopeId : null,
        permission_mode: mode,
      }),
    onSuccess: ({ data }) => onCreated(data.id),
    onError: (err) =>
      setError(err instanceof ApiError ? err.message : "Could not create the connection"),
  });

  return (
    <form
      className="space-y-5"
      onSubmit={(e) => {
        e.preventDefault();
        setError(null);
        create.mutate();
      }}
    >
      <Field label={t.connection.connectionName}>
        <Input
          required
          autoFocus
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Acme production"
        />
      </Field>

      <ChoiceGroup
        legend={t.connection.scope}
        choices={options.scopes}
        value={scopeType}
        onChange={(v) => setScopeType(v as ConnectionScope)}
      />

      {needsScopeId && (
        <Field
          label={
            scopeType === "MANAGEMENT_GROUP"
              ? t.connection.managementGroupId
              : t.connection.subscriptionId
          }
        >
          <Input
            required
            value={scopeId}
            onChange={(e) => setScopeId(e.target.value)}
            placeholder={scopeType === "MANAGEMENT_GROUP" ? "platform-mg" : "00000000-…"}
          />
        </Field>
      )}

      <ChoiceGroup
        legend={t.connection.permissions}
        choices={options.permission_modes}
        value={mode}
        onChange={(v) => setMode(v as PermissionMode)}
      />

      {mode === "CUSTOM_ROLE" && <ActionList actions={options.arm_actions} />}

      <div className="rounded-lg border border-stone-200 bg-stone-50 px-4 py-3">
        <p className="text-xs font-medium text-stone-700">{t.connection.whoYouNeed}</p>
        <p className="mt-1 text-xs leading-relaxed text-stone-600">
          {t.connection.whoYouNeedDetail}
        </p>
        <p className="mt-2 text-xs leading-relaxed text-stone-600">
          {t.connection.noGuidsNeeded}
        </p>
      </div>

      {error && <ErrorNote message={error} />}

      <Button type="submit" disabled={create.isPending}>
        {t.connection.create}
      </Button>
    </form>
  );
}

function ChoiceGroup({
  legend,
  choices,
  value,
  onChange,
}: {
  legend: string;
  choices: ConnectionOptions["scopes"];
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <fieldset>
      <legend className="mb-2 text-sm font-medium text-stone-700">{legend}</legend>
      <div className="space-y-2">
        {choices.map((choice) => (
          <label
            key={choice.value}
            className={cn(
              "flex cursor-pointer gap-3 rounded-lg border px-4 py-3 transition",
              value === choice.value
                ? "border-stone-900 bg-stone-50"
                : "border-stone-200 hover:border-stone-300",
            )}
          >
            <input
              type="radio"
              className="mt-1"
              checked={value === choice.value}
              onChange={() => onChange(choice.value)}
            />
            <span>
              <span className="block text-sm font-medium text-stone-900">
                {choice.label}
              </span>
              <span className="mt-0.5 block text-xs leading-relaxed text-stone-600">
                {choice.detail}
              </span>
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

/** The whole least-privilege claim, itemised rather than summarised. */
function ActionList({ actions }: { actions: string[] }) {
  const t = useT();
  return (
    <div className="rounded-lg border border-stone-200 px-4 py-3">
      <p className="text-xs font-medium text-stone-700">
        {t.connection.whatItReads} ({actions.length})
      </p>
      <ul className="mt-2 max-h-40 space-y-0.5 overflow-y-auto">
        {actions.map((action) => (
          <li key={action} className="font-mono text-[11px] text-stone-600">
            {action}
          </li>
        ))}
      </ul>
      <p className="mt-2 text-xs leading-relaxed text-ok">{t.connection.noWriteActions}</p>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

function ConsentStep({ connection }: { connection: CloudConnection }) {
  const t = useT();
  const [url, setUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const options = useQuery({
    queryKey: ["connection-options"],
    queryFn: () =>
      api.get<ConnectionOptions>("/api/v1/cloud-connections/options").then((r) => r.data),
  });
  const configured = options.data?.azure_configured ?? true;

  const link = useMutation({
    mutationFn: () =>
      api.post<{ consent_url: string; expires_in_seconds: number }>(
        `/api/v1/cloud-connections/${connection.id}/consent-url`,
      ),
    onSuccess: ({ data }) => {
      setUrl(data.consent_url);
      // Microsoft's own consent page. CloudGuard never sees the admin's
      // credentials — Entra authenticates them and calls our callback.
      window.open(data.consent_url, "_blank", "noopener");
    },
    onError: (err) =>
      setError(err instanceof ApiError ? err.message : "Could not build the consent link"),
  });

  return (
    <div className="space-y-4">
      <p className="text-sm leading-relaxed text-stone-600">
        {t.connection.whoYouNeedDetail}
      </p>

      {!configured && <NotConfiguredNote detail={options.data?.azure_problem} />}

      <div className="flex flex-wrap gap-2">
        <Button onClick={() => link.mutate()} disabled={link.isPending || !configured}>
          {t.connection.openConsent}
        </Button>
        {url && <CopyButton text={url} label={t.connection.copyConsentLink} />}
      </div>

      <p className="text-xs text-stone-500">{t.connection.consentExpiry}</p>

      {error && <ErrorNote message={error} />}

      {/* Nothing is going to arrive while the server cannot start a consent
          flow, so a spinner would be claiming progress that is not happening. */}
      {configured && <WaitingNote text={t.connection.waitingForConsent} />}
    </div>
  );
}

/* -------------------------------------------------------------------------- */

function AccessStep({ connection }: { connection: CloudConnection }) {
  const t = useT();
  const [format, setFormat] = useState<ArtifactFormat>("cli");

  const links = useQuery({
    queryKey: ["connection-artifacts", connection.id],
    queryFn: () =>
      api
        .get<ArtifactLinks>(`/api/v1/cloud-connections/${connection.id}/artifacts`)
        .then((r) => r.data),
  });

  // The server returns an API-relative path; the base is the client's, the same
  // one every other request already uses.
  const path = links.data?.formats[format];
  const { body, error: artifactError, reload } = useArtifact(
    path ? `${API_URL}${path}` : undefined,
  );

  const labels: Record<ArtifactFormat, string> = {
    cli: t.connection.formatCli,
    bicep: t.connection.formatBicep,
    terraform: t.connection.formatTerraform,
  };

  return (
    <div className="space-y-4">
      <p className="text-sm leading-relaxed text-stone-600">{t.connection.accessIntro}</p>

      {links.data && (
        <dl className="grid gap-2 rounded-lg bg-stone-50 px-4 py-3 text-xs sm:grid-cols-2">
          <Detail label={t.connection.scopePath} value={links.data.scope_path} />
          <Detail label={t.connection.principalId} value={links.data.principal_id} />
        </dl>
      )}

      <div className="flex gap-1 border-b border-stone-200">
        {(Object.keys(labels) as ArtifactFormat[]).map((key) => (
          <button
            key={key}
            onClick={() => setFormat(key)}
            className={cn(
              "border-b-2 px-3 py-2 text-sm transition-colors",
              format === key
                ? "border-stone-900 font-medium text-stone-900"
                : "border-transparent text-stone-500 hover:text-stone-900",
            )}
          >
            {labels[key]}
          </button>
        ))}
      </div>

      {artifactError ? (
        <ErrorNote message={artifactError} onRetry={reload} />
      ) : body === null ? (
        <Spinner />
      ) : (
        <pre className="max-h-72 overflow-auto rounded-lg bg-stone-900 p-4 text-[11px] leading-relaxed text-stone-100">
          {body}
        </pre>
      )}

      <div className="flex flex-wrap gap-2">
        {body && <CopyButton text={body} label={t.connection.copyScript} />}
        {format === "cli" && links.data && (
          <a href={links.data.cloud_shell_url} target="_blank" rel="noreferrer noopener">
            <Button variant="secondary">{t.connection.cloudShell}</Button>
          </a>
        )}
      </div>

      <WaitingNote text={t.connection.waitingForAccess} />
    </div>
  );
}

/**
 * Fetches the artifact as text.
 *
 * Outside react-query because the response is a shell script or a Bicep file,
 * not the JSON envelope `api.get` unwraps.
 *
 * A failure used to be rendered *as the artifact* -- a comment line inside the
 * code block, indistinguishable at a glance from a script that had loaded. It
 * is an error now, with a retry, and an HTTP status is reported separately from
 * a network failure because the two have completely different causes.
 */
function useArtifact(url: string | undefined): {
  body: string | null;
  error: string | null;
  reload: () => void;
} {
  const [body, setBody] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!url) return;
    let cancelled = false;
    setBody(null);
    setError(null);

    fetch(url)
      .then(async (response) => {
        if (cancelled) return;
        const text = await response.text();
        if (cancelled) return;
        if (!response.ok) {
          setError(`The server could not build this artifact (${response.status}).`);
          return;
        }
        setBody(text);
      })
      .catch(() => {
        if (!cancelled) {
          setError("Could not reach the API to load this artifact.");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [url, attempt]);

  return { body, error, reload: () => setAttempt((n) => n + 1) };
}

/* -------------------------------------------------------------------------- */

function VerifyStep({ connection }: { connection: CloudConnection }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [result, setResult] = useState<ValidationResult | null>(null);

  const discover = useMutation({
    mutationFn: () =>
      api.post<DiscoveredSubscription[]>(
        `/api/v1/cloud-connections/${connection.id}/discover`,
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cloud-connection", connection.id] });
      queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
    },
  });

  const validate = useMutation({
    mutationFn: () =>
      api.post<ValidationResult>(`/api/v1/cloud-connections/${connection.id}/validate`),
    onSuccess: ({ data }) => {
      setResult(data);
      queryClient.invalidateQueries({ queryKey: ["cloud-connection", connection.id] });
      // Verification and discovery are one action from the customer's side.
      if (data.ok) discover.mutate();
    },
  });

  const busy = validate.isPending || discover.isPending;

  return (
    <div className="space-y-4">
      <Button onClick={() => validate.mutate()} disabled={busy}>
        {busy
          ? discover.isPending
            ? t.connection.discovering
            : t.connection.verifying
          : t.connection.verify}
      </Button>

      {result?.permissions_verified.map((permission) => (
        <p key={permission} className="text-sm text-ok">
          ✓ {permission}
        </p>
      ))}
      {result?.problems.map((problem) => (
        <p key={problem} className="text-sm text-high">
          • {problem}
        </p>
      ))}

      {!result && <WaitingNote text={t.connection.waitingForAccess} />}
    </div>
  );
}

/* -------------------------------------------------------------------------- */

function SubscriptionsStep({
  connection,
  onClose,
}: {
  connection: CloudConnection;
  onClose: () => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [selection, setSelection] = useState<Record<string, boolean>>({});

  const subscriptions = useQuery({
    queryKey: ["connection-subscriptions", connection.id],
    queryFn: () =>
      api
        .get<DiscoveredSubscription[]>(
          `/api/v1/cloud-connections/${connection.id}/subscriptions`,
        )
        .then((r) => r.data),
  });

  const save = useMutation({
    mutationFn: () =>
      api.patch<DiscoveredSubscription[]>(
        `/api/v1/cloud-connections/${connection.id}/subscriptions`,
        { in_scope: selection },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
      onClose();
    },
  });

  const rows = subscriptions.data ?? [];
  const checked = (row: DiscoveredSubscription) =>
    selection[row.subscription_id ?? ""] ?? row.in_scope;

  return (
    <div className="space-y-4">
      <p className="text-sm text-stone-600">
        <strong className="text-stone-900">{rows.length}</strong>{" "}
        {t.connection.discovered}
      </p>

      {subscriptions.isLoading && <Spinner />}

      <ul className="divide-y divide-stone-100 rounded-lg border border-stone-200">
        {rows.map((row) => (
          <li key={row.id} className="flex items-center gap-3 px-4 py-2.5">
            <input
              type="checkbox"
              checked={checked(row)}
              onChange={(e) =>
                setSelection({
                  ...selection,
                  [row.subscription_id ?? ""]: e.target.checked,
                })
              }
              aria-label={`${t.connection.inScope}: ${row.display_name}`}
            />
            <span className="flex-1">
              <span className="block text-sm text-stone-900">{row.display_name}</span>
              <code className="text-[11px] text-stone-400">{row.subscription_id}</code>
            </span>
          </li>
        ))}
      </ul>

      <Button onClick={() => save.mutate()} disabled={save.isPending}>
        {t.connection.saveScope}
      </Button>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

/**
 * A server-side gap, said plainly.
 *
 * Distinct from an ErrorNote because nothing the customer does will clear it:
 * this deployment has no Entra app identity, and the fix belongs to whoever
 * runs CloudGuard. Presenting it as a failed action would send them looking
 * through their own Azure tenant for a cause that is not there.
 */
function NotConfiguredNote({ detail }: { detail?: string | null }) {
  const t = useT();
  return (
    <div className="mb-4 rounded-lg border border-medium-border bg-medium-bg px-4 py-3">
      <p className="text-sm font-medium text-medium">{t.connection.notConfigured}</p>
      {/* The server's own diagnosis when it has one — it names the variable at
          fault, which a generic message cannot. */}
      {detail && (
        <p className="mt-1 font-mono text-xs leading-relaxed text-stone-700">{detail}</p>
      )}
      <p className="mt-2 text-xs leading-relaxed text-stone-700">
        {t.connection.notConfiguredDetail}
      </p>
    </div>
  );
}

function WaitingNote({ text }: { text: string }) {
  return (
    <p className="flex items-center gap-2 text-sm text-stone-500">
      <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-stone-300 border-t-stone-600" />
      {text}
    </p>
  );
}

function Detail({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div>
      <dt className="text-stone-500">{label}</dt>
      <dd className="break-all font-mono text-[11px] text-stone-800">{value ?? "—"}</dd>
    </div>
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
