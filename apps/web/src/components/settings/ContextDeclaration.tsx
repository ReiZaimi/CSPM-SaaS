import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, ApiError } from "@/lib/api";
import type { CloudAccount, ContextDeclaration, Level } from "@/lib/types";
import { useT } from "@/i18n";
import { formatDateTime } from "@/lib/format";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { SelectField } from "@/components/common/SelectField";
import { Skeleton } from "@/components/ui/skeleton";

const NOT_DECLARED = "none";

/**
 * The levels a customer may declare.
 *
 * UNKNOWN is deliberately absent. It is CloudGuard's own answer for "nothing
 * said anything", so offering it would let a customer assert an absence that
 * leaving the field unset already asserts -- and the API rejects it for the
 * same reason, so an option here would be a menu item that always fails.
 */
const LEVELS: Level[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

/**
 * What one subscription is for, as its owner says it.
 *
 * The single highest-leverage thing a customer can tell CloudGuard: the risk
 * engine multiplies severity by criticality, data sensitivity and exposure, and
 * until this existed those came from tags and guesses off resource names, with
 * no way for the person who actually knows to say otherwise.
 *
 * Saved as a whole statement rather than field by field, because that is what
 * the API stores. A field left unset is not "unknown" -- it is a claim
 * withdrawn, and CloudGuard goes back to working it out for itself.
 */
export function ContextDeclarationForm({ account }: { account: CloudAccount }) {
  const { data, isLoading } = useQuery({
    queryKey: ["account-context", account.id],
    queryFn: () =>
      api
        .get<ContextDeclaration | null>(`/api/v1/cloud-accounts/${account.id}/context`)
        .then((r) => r.data),
  });

  if (isLoading) {
    return (
      <div className="rounded-lg border p-4">
        <Skeleton className="h-4 w-48" />
        <Skeleton className="mt-3 h-8 w-full" />
      </div>
    );
  }

  // The form is mounted only once the declaration has arrived, and keyed on
  // the account, so its fields are seeded from props at first render. The
  // alternative -- mounting empty and writing the server's values back in an
  // effect -- shows a declared subscription as undeclared for one render, and
  // is the pattern React's set-state-in-effect rule points at.
  return <DeclarationFields key={account.id} account={account} declaration={data ?? null} />;
}

function DeclarationFields({
  account,
  declaration,
}: {
  account: CloudAccount;
  declaration: ContextDeclaration | null;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const key = ["account-context", account.id];

  const [environment, setEnvironment] = useState(declaration?.environment ?? "");
  const [criticality, setCriticality] = useState<string>(
    declaration?.criticality ?? NOT_DECLARED,
  );
  const [sensitivity, setSensitivity] = useState<string>(
    declaration?.data_sensitivity ?? NOT_DECLARED,
  );
  const [note, setNote] = useState(declaration?.note ?? "");
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const save = useMutation({
    mutationFn: () =>
      api.put<ContextDeclaration>(`/api/v1/cloud-accounts/${account.id}/context`, {
        environment: environment.trim() || null,
        criticality: criticality === NOT_DECLARED ? null : criticality,
        data_sensitivity: sensitivity === NOT_DECLARED ? null : sensitivity,
        note: note.trim() || null,
      }),
    onSuccess: ({ data }) => {
      setError(null);
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2000);
      queryClient.setQueryData(key, data);
    },
    onError: (err) =>
      setError(err instanceof ApiError ? err.message : t.settings.contextFailed),
  });

  const clear = useMutation({
    mutationFn: () => api.del(`/api/v1/cloud-accounts/${account.id}/context`),
    onSuccess: () => {
      setError(null);
      setEnvironment("");
      setCriticality(NOT_DECLARED);
      setSensitivity(NOT_DECLARED);
      setNote("");
      queryClient.setQueryData(key, null);
    },
    onError: (err) =>
      setError(err instanceof ApiError ? err.message : t.settings.contextFailed),
  });

  const declared = Boolean(declaration);

  return (
    <div className="rounded-lg border p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p className="text-sm font-medium text-foreground">{account.account_name}</p>
        <code className="text-[11px] text-muted-foreground">{account.subscription_id}</code>
      </div>

      <form
        className="mt-3 flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          save.mutate();
        }}
      >
        <div className="grid gap-3 sm:grid-cols-3">
          <Field>
            <FieldLabel htmlFor={`env-${account.id}`}>{t.settings.environment}</FieldLabel>
            <Input
              id={`env-${account.id}`}
              value={environment}
              maxLength={64}
              placeholder={t.settings.environmentPlaceholder}
              onChange={(event) => setEnvironment(event.target.value)}
            />
          </Field>

          <LevelField
            id={`crit-${account.id}`}
            label={t.settings.criticality}
            value={criticality}
            onChange={setCriticality}
          />

          <LevelField
            id={`sens-${account.id}`}
            label={t.settings.dataSensitivity}
            value={sensitivity}
            onChange={setSensitivity}
          />
        </div>

        <Field>
          <FieldLabel htmlFor={`note-${account.id}`}>{t.settings.note}</FieldLabel>
          <Input
            id={`note-${account.id}`}
            value={note}
            maxLength={2000}
            onChange={(event) => setNote(event.target.value)}
          />
          <FieldDescription>{t.settings.noteHelp}</FieldDescription>
        </Field>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" size="sm" disabled={save.isPending}>
            {save.isPending ? t.settings.saving : t.settings.declare}
          </Button>
          {/* Only offered where there is something to withdraw. On an
              undeclared subscription it would be a button that does nothing
              and reads as though it might. */}
          {declared && (
            <Button
              type="button"
              size="sm"
              variant="ghost"
              disabled={clear.isPending}
              onClick={() => clear.mutate()}
            >
              {clear.isPending ? t.settings.clearing : t.settings.clear}
            </Button>
          )}
          {saved && !save.isPending && (
            <span className="text-xs text-ok">{t.settings.saved}</span>
          )}
          {declared && declaration && (
            <span className="text-xs text-muted-foreground">
              {t.settings.declaredBy} {formatDateTime(declaration.declared_at)}
            </span>
          )}
        </div>
      </form>
    </div>
  );
}

function LevelField({
  id,
  label,
  value,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  const t = useT();
  return (
    <Field>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <SelectField
        id={id}
        value={value}
        onValueChange={(next) => onChange(next || NOT_DECLARED)}
        ariaLabel={label}
        options={[
          { value: NOT_DECLARED, label: t.settings.notDeclared },
          ...LEVELS.map((level) => ({
            value: level,
            label: level.charAt(0) + level.slice(1).toLowerCase(),
          })),
        ]}
      />
    </Field>
  );
}
