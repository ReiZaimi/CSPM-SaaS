import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import type { CloudConnection, ConnectionScope } from "@/lib/types";
import { useT } from "@/i18n";
import { Button, Card, ErrorNote, Field, Input } from "@/components/ui";
import { cn } from "@/lib/format";

/**
 * Simplified connection form: name, scope, go.
 *
 * Creates the connection and immediately redirects the admin to Microsoft's
 * consent page. The consent URL comes back from the create call — no second
 * request, no separate step.
 */
export function ConnectionForm({
  onCreated,
  onClose,
}: {
  onCreated: (id: string) => void;
  onClose: () => void;
}) {
  const t = useT();
  const [name, setName] = useState("");
  const [scopeType, setScopeType] = useState<ConnectionScope>("TENANT_ROOT");
  const [scopeId, setScopeId] = useState("");
  const [error, setError] = useState<string | null>(null);

  const needsScopeId = scopeType !== "TENANT_ROOT";

  const create = useMutation({
    mutationFn: () =>
      api.post<CloudConnection>("/api/v1/cloud-connections", {
        name,
        scope_type: scopeType,
        scope_id: needsScopeId ? scopeId : null,
      }),
    onSuccess: ({ data }) => {
      onCreated(data.id);
      if (data.consent_url) {
        window.open(data.consent_url, "_blank", "noopener");
      }
    },
    onError: (err) =>
      setError(err instanceof ApiError ? err.message : "Could not create the connection"),
  });

  // Each option carries what it will take to *finish*, not just what it covers.
  // Azure RBAC inherits downward only, so being Owner of a subscription grants
  // nothing at the management group above it — and by default nobody, not even
  // a Global Administrator, holds rights at the tenant root. Choosing on
  // coverage alone sends people to a portal error at the last step, after
  // consent and after their administrator has already been involved.
  const scopes: {
    value: ConnectionScope;
    label: string;
    detail: string;
    requires: string;
  }[] = [
    {
      value: "TENANT_ROOT",
      label: "Entire tenant",
      detail: "Discover and scan every subscription in this directory.",
      requires:
        "Needs Owner at the tenant root management group. Most directories "
        + "must turn on Entra ID → Properties → Access management for Azure "
        + "resources first; without it this step fails in Azure Portal.",
    },
    {
      value: "MANAGEMENT_GROUP",
      label: "Management group",
      detail: "Limit to subscriptions under a specific management group.",
      requires: "Needs Owner or User Access Administrator on that management group.",
    },
    {
      value: "SUBSCRIPTION",
      label: "Single subscription",
      detail: "Scan one subscription only.",
      requires:
        "Needs Owner or User Access Administrator on that subscription — "
        + "usually the easiest to complete.",
    },
  ];

  return (
    <Card
      title={t.connection.connectAzure}
      action={
        <button
          onClick={onClose}
          aria-label={t.connection.cancel}
          className="text-sm text-stone-500 transition hover:text-stone-900"
        >
          ✕
        </button>
      }
    >
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

        <fieldset>
          <legend className="mb-2 text-sm font-medium text-stone-700">
            {t.connection.scope}
          </legend>
          <div className="space-y-2">
            {scopes.map((scope) => (
              <label
                key={scope.value}
                className={cn(
                  "flex cursor-pointer gap-3 rounded-lg border px-4 py-3 transition",
                  scopeType === scope.value
                    ? "border-stone-900 bg-stone-50"
                    : "border-stone-200 hover:border-stone-300",
                )}
              >
                <input
                  type="radio"
                  className="mt-1"
                  checked={scopeType === scope.value}
                  onChange={() => setScopeType(scope.value)}
                />
                <span>
                  <span className="block text-sm font-medium text-stone-900">
                    {scope.label}
                  </span>
                  <span className="mt-0.5 block text-xs leading-relaxed text-stone-600">
                    {scope.detail}
                  </span>
                  <span className="mt-1 block text-xs leading-relaxed text-stone-500">
                    {scope.requires}
                  </span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>

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

        <div className="flex flex-wrap gap-2">
          <Button type="submit" disabled={create.isPending}>
            {create.isPending ? "Creating\u2026" : t.connection.connectAzure}
          </Button>
          <Button type="button" variant="ghost" onClick={onClose}>
            {t.connection.cancel}
          </Button>
        </div>
      </form>
    </Card>
  );
}
