import { useId, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { XIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import type { CloudConnection, ConnectionScope } from "@/lib/types";
import { useT } from "@/i18n";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
  const nameId = useId();
  const scopeIdField = useId();
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
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <CardTitle>{t.connection.connectAzure}</CardTitle>
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={onClose}
            aria-label={t.connection.cancel}
          >
            <XIcon />
          </Button>
        </div>
      </CardHeader>

      <CardContent>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            create.mutate();
          }}
        >
          <FieldGroup>
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
                      {/* What it will take to *finish*, not just what it
                          covers -- see the note above the list. */}
                      <span className="mt-1 block text-xs leading-relaxed text-muted-foreground">
                        {scope.requires}
                      </span>
                    </span>
                  </FieldLabel>
                ))}
              </RadioGroup>
            </FieldSet>

            {needsScopeId && (
              <Field>
                <FieldLabel htmlFor={scopeIdField}>
                  {scopeType === "MANAGEMENT_GROUP"
                    ? t.connection.managementGroupId
                    : t.connection.subscriptionId}
                </FieldLabel>
                <Input
                  id={scopeIdField}
                  required
                  value={scopeId}
                  onChange={(e) => setScopeId(e.target.value)}
                  placeholder={
                    scopeType === "MANAGEMENT_GROUP" ? "platform-mg" : "00000000-…"
                  }
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

            <div className="flex flex-wrap gap-2">
              <Button type="submit" disabled={create.isPending}>
                {create.isPending && <Spinner data-icon="inline-start" />}
                {create.isPending ? "Creating\u2026" : t.connection.connectAzure}
              </Button>
              <Button type="button" variant="ghost" onClick={onClose}>
                {t.connection.cancel}
              </Button>
            </div>
          </FieldGroup>
        </form>
      </CardContent>
    </Card>
  );
}
