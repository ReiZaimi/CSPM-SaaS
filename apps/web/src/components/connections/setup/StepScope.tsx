import { useId, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";

import { api, ApiError } from "@/lib/api";
import type {
  CloudConnection,
  ConnectionScope,
  Provider,
  ProviderOption,
} from "@/lib/types";
import { useT } from "@/i18n";
import { needsScopeId, scopesFor } from "@/lib/connectionStage";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Spinner } from "@/components/ui/spinner";
import { cn } from "@/lib/format";

/**
 * Step one: cloud, name, scope, go.
 *
 * Creates the connection and hands the id back to the wizard, which navigates
 * to the connection's own setup URL. From that point the flow is resumable --
 * everything after this step is recorded on the server, and the browser is free
 * to leave for the provider's console and come back.
 *
 * Creating no longer opens the consent page itself. It used to `window.open`
 * the moment the connection existed, which a popup blocker eats often enough to
 * matter, and which assumes the person filling this form is the administrator --
 * frequently they are not, and the next step is now the place that asks.
 */
export function StepScope({
  provider,
  onProviderChange,
  onCreated,
}: {
  provider: Provider;
  onProviderChange: (provider: Provider) => void;
  onCreated: (id: string) => void;
}) {
  const t = useT();
  const nameId = useId();
  const scopeIdField = useId();
  const [name, setName] = useState("");
  const [scopeType, setScopeType] = useState<ConnectionScope>(
    () => scopesFor(provider)[0],
  );
  const [scopeId, setScopeId] = useState("");
  const [error, setError] = useState<string | null>(null);

  // Which clouds this deployment can actually connect. Asked rather than
  // assumed: an installation with no Entra app registration cannot start a
  // consent flow, and one that has not verified its AWS connector against a
  // live account must not be offering AWS at all.
  const providers = useQuery({
    queryKey: ["cloud-providers"],
    queryFn: () =>
      api
        .get<ProviderOption[]>("/api/v1/cloud-connections/providers")
        .then((r) => r.data),
  });

  const options = providers.data ?? [];
  const chosen = options.find((option) => option.id === provider);

  /**
   * Switching cloud resets the scope, in the handler rather than in an effect.
   *
   * The scope union spans both clouds, so a scope left over from the other one
   * would post a value the provider has never heard of. Doing it here rather
   * than syncing after the fact means there is no render in which the form
   * holds a scope its own radio group does not offer.
   */
  function chooseProvider(next: Provider) {
    onProviderChange(next);
    setScopeType(scopesFor(next)[0]);
    setScopeId("");
  }

  const scopeIdRequired = needsScopeId(provider, scopeType);

  const create = useMutation({
    mutationFn: () =>
      api.post<CloudConnection>("/api/v1/cloud-connections", {
        name,
        provider,
        scope_type: scopeType,
        scope_id: scopeIdRequired ? scopeId : null,
      }),
    onSuccess: ({ data }) => onCreated(data.id),
    onError: (err) =>
      setError(err instanceof ApiError ? err.message : "Could not create the connection"),
  });

  // Each option carries what it will take to *finish*, not just what it covers.
  //
  // Azure RBAC inherits downward only, so being Owner of a subscription grants
  // nothing at the management group above it — and by default nobody, not even
  // a Global Administrator, holds rights at the tenant root. AWS has the same
  // shape of trap in a different place: an organization-wide connection needs
  // the stack in every member account, not only in the management one.
  // Choosing on coverage alone sends people to a console error at the last
  // step, after their administrator has already been involved.
  const azureScopes = [
    {
      value: "TENANT_ROOT" as ConnectionScope,
      label: "Entire tenant",
      detail: "Discover and scan every subscription in this directory.",
      requires:
        "Needs Owner at the tenant root management group. Most directories "
        + "must turn on Entra ID → Properties → Access management for Azure "
        + "resources first; without it this step fails in Azure Portal.",
    },
    {
      value: "MANAGEMENT_GROUP" as ConnectionScope,
      label: "Management group",
      detail: "Limit to subscriptions under a specific management group.",
      requires: "Needs Owner or User Access Administrator on that management group.",
    },
    {
      value: "SUBSCRIPTION" as ConnectionScope,
      label: "Single subscription",
      detail: "Scan one subscription only.",
      requires:
        "Needs Owner or User Access Administrator on that subscription — "
        + "usually the easiest to complete.",
    },
  ];

  const awsScopes = [
    {
      value: "ORGANIZATION" as ConnectionScope,
      label: t.setup.aws.scopeOrganization,
      detail: t.setup.aws.scopeOrganizationDetail,
      requires: t.setup.aws.scopeOrganizationRequires,
    },
    {
      value: "ORGANIZATIONAL_UNIT" as ConnectionScope,
      label: t.setup.aws.scopeOrganizationalUnit,
      detail: t.setup.aws.scopeOrganizationalUnitDetail,
      requires: t.setup.aws.scopeOrganizationalUnitRequires,
    },
    {
      value: "ACCOUNT" as ConnectionScope,
      label: t.setup.aws.scopeAccount,
      detail: t.setup.aws.scopeAccountDetail,
      requires: t.setup.aws.scopeAccountRequires,
    },
  ];

  const scopes = provider === "aws" ? awsScopes : azureScopes;

  function scopeIdLabel(): string {
    if (provider === "aws") {
      if (scopeType === "ORGANIZATIONAL_UNIT") return t.setup.aws.organizationalUnitId;
      if (scopeType === "ACCOUNT") return t.setup.aws.accountId;
      return t.setup.aws.organizationId;
    }
    return scopeType === "MANAGEMENT_GROUP"
      ? t.connection.managementGroupId
      : t.connection.subscriptionId;
  }

  function scopeIdPlaceholder(): string {
    if (provider === "aws") {
      return scopeType === "ORGANIZATIONAL_UNIT" ? "ou-abcd-12345678" : "111122223333";
    }
    return scopeType === "MANAGEMENT_GROUP" ? "platform-mg" : "00000000-…";
  }

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setError(null);
        create.mutate();
      }}
    >
      <FieldGroup>
        <FieldSet>
          <FieldLegend variant="label">{t.connection.cloud}</FieldLegend>
          <RadioGroup
            value={provider}
            onValueChange={(value) => chooseProvider(value as Provider)}
          >
            {options.map((option) => (
              <FieldLabel
                key={option.id}
                htmlFor={`provider-${option.id}`}
                className={cn(
                  "flex cursor-pointer items-start gap-3 rounded-lg border px-4 py-3 transition",
                  provider === option.id
                    ? "border-foreground bg-muted/40"
                    : "hover:border-input",
                  // Unavailable is shown rather than hidden. A picker that held
                  // an option back answers "does this support AWS?" with
                  // nothing, and the reason is what tells an operator what to
                  // do about it.
                  !option.available && "cursor-not-allowed opacity-60",
                )}
              >
                <RadioGroupItem
                  id={`provider-${option.id}`}
                  value={option.id}
                  disabled={!option.available}
                  className="mt-1"
                />
                <span className="min-w-0">
                  <span className="block text-sm font-medium text-foreground">
                    {option.name}
                  </span>
                  {!option.available && option.unavailable_reason && (
                    <span className="mt-0.5 block text-xs leading-relaxed text-muted-foreground">
                      {option.unavailable_reason}
                    </span>
                  )}
                </span>
              </FieldLabel>
            ))}
          </RadioGroup>
        </FieldSet>

        <Field>
          <FieldLabel htmlFor={nameId}>{t.connection.connectionName}</FieldLabel>
          <Input
            id={nameId}
            required
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Acme production"
          />
        </Field>

        <FieldSet>
          <FieldLegend variant="label">{t.connection.scope}</FieldLegend>
          <RadioGroup
            value={scopeType}
            onValueChange={(value) => setScopeType(value as ConnectionScope)}
          >
            {scopes.map((scope) => (
              <FieldLabel
                key={scope.value}
                htmlFor={`scope-${scope.value}`}
                className={cn(
                  "flex cursor-pointer items-start gap-3 rounded-lg border px-4 py-3 transition",
                  scopeType === scope.value
                    ? "border-foreground bg-muted/40"
                    : "hover:border-input",
                )}
              >
                <RadioGroupItem
                  id={`scope-${scope.value}`}
                  value={scope.value}
                  className="mt-1"
                />
                <span className="min-w-0">
                  <span className="block text-sm font-medium text-foreground">
                    {scope.label}
                  </span>
                  <span className="mt-0.5 block text-xs leading-relaxed text-muted-foreground">
                    {scope.detail}
                  </span>
                  {/* What it will take to *finish*, not just what it covers --
                      see the note above the list. */}
                  <span className="mt-1 block text-xs leading-relaxed text-muted-foreground">
                    {scope.requires}
                  </span>
                </span>
              </FieldLabel>
            ))}
          </RadioGroup>
        </FieldSet>

        {scopeIdRequired && (
          <Field>
            <FieldLabel htmlFor={scopeIdField}>{scopeIdLabel()}</FieldLabel>
            <Input
              id={scopeIdField}
              required
              value={scopeId}
              onChange={(e) => setScopeId(e.target.value)}
              placeholder={scopeIdPlaceholder()}
            />
          </Field>
        )}

        <Field>
          <FieldLabel className="text-xs">{t.connection.whoYouNeed}</FieldLabel>
          <FieldDescription>
            {t.connection.whoYouNeedDetail}
            <span className="mt-2 block">{t.connection.noGuidsNeeded}</span>
          </FieldDescription>
        </Field>

        {error && (
          <Alert variant="destructive">
            <AlertTitle>Could not create the connection</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <div>
          <Button
            type="submit"
            disabled={create.isPending || !chosen?.available}
          >
            {create.isPending && <Spinner data-icon="inline-start" />}
            {create.isPending ? "Creating…" : t.connection.create}
          </Button>
        </div>
      </FieldGroup>
    </form>
  );
}
