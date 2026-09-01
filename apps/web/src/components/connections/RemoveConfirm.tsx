import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { Revocation, RevocationCheck } from "@/lib/types";
import { useT } from "@/i18n";
import { Button } from "@/components/ui/button";

/**
 * Removing a connection, and the revocation it does not perform.
 *
 * CloudGuard cannot revoke its own access: the grant lives in the customer's
 * tenant and nothing here holds a credential that could withdraw it. So the
 * commands are generated for the customer to run, and "check" asks Azure
 * whether they did -- an answer, not an assurance.
 */
export function RemoveConfirm({
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
      <p className="mt-1 text-xs leading-relaxed text-foreground">
        {t.connection.removeDetail}
      </p>

      {/* Revocation sits inside the removal confirmation on purpose. It is the
          only moment the customer is thinking about ending this, and once the
          connection is deleted the principal id and scope needed to write these
          commands are gone with it. */}
      {steps.length > 0 && (
        <div className="mt-3 rounded-lg border border-border bg-background px-3 py-2.5">
          <p className="text-xs font-medium text-foreground">{t.connection.revokeTitle}</p>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            {t.connection.revokeIntro}
          </p>
          <ol className="mt-2 space-y-2">
            {steps.map((step) => (
              <li key={step.title}>
                <p className="text-xs font-medium text-foreground">{step.title}</p>
                <p className="text-[11px] leading-relaxed text-muted-foreground">
                  {step.detail}
                </p>
                <pre className="mt-1 overflow-x-auto rounded bg-stone-900 px-2.5 py-1.5 font-mono text-[11px] text-stone-100">
                  {step.command}
                </pre>
              </li>
            ))}
          </ol>
          {revocation.data && (
            <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
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
            <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
              {checked.detail}
            </p>
          )}
        </div>
      )}

      <div className="mt-3 flex flex-wrap gap-2">
        <Button variant="destructive" onClick={onConfirm} disabled={busy}>
          {busy ? t.connection.removing : t.connection.remove}
        </Button>
        <Button variant="secondary" onClick={onCancel}>
          {t.connection.keep}
        </Button>
      </div>
    </div>
  );
}
