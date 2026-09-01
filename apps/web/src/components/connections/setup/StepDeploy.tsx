import { useState } from "react";

import type { CloudConnection } from "@/lib/types";
import { useT } from "@/i18n";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/format";
import { WaitingNote } from "@/components/connections/setup/WaitingNote";

/**
 * Step three: the reader role.
 *
 * Consent proved CloudGuard may ask the directory who exists. This is the grant
 * that lets it read anything, and it is the step that fails -- the template is
 * pre-filled and cannot be typed wrong, so when nothing arrives the cause is
 * always one of scope, permission or propagation. Those three are named here
 * rather than left to a support conversation, in the order they are worth
 * checking.
 */
export function StepDeploy({
  connection,
  onRecheck,
  rechecking,
  onDiscard,
  discarding,
}: {
  connection: CloudConnection;
  onRecheck: () => void;
  rechecking: boolean;
  onDiscard: () => void;
  discarding: boolean;
}) {
  const t = useT();
  const [confirmingDiscard, setConfirmingDiscard] = useState(false);

  // Consented, but CloudGuard cannot produce a template. Nothing the customer
  // does in Azure advances this, so it is shown as a problem and not as a wait.
  if (!connection.template_url) {
    return (
      <Alert className="border-high-border bg-high-bg text-high">
        <AlertTitle>{t.connection.cannotDeployYet}</AlertTitle>
        <AlertDescription className="text-foreground">
          {connection.status_detail}
        </AlertDescription>
      </Alert>
    );
  }

  // The wrong-scope cause is worded for the scope this connection actually
  // covers. "The deployment landed somewhere else" is only useful if the reader
  // is told where it was supposed to land.
  const wrongScope =
    connection.scope_type === "TENANT_ROOT"
      ? t.setup.stalledScopeTenant
      : connection.scope_type === "MANAGEMENT_GROUP"
        ? t.setup.stalledScopeGroup
        : t.setup.stalledScopeSubscription;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h2 className="text-base font-semibold text-foreground">{t.setup.deployTitle}</h2>
        <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
          {t.setup.deployBody}
        </p>
      </div>

      <div>
        {/* See the note in StepConsent: this one leaves for Azure Portal. */}
        <a
          href={connection.template_url}
          target="_blank"
          rel="noopener noreferrer"
          className={cn(buttonVariants())}
        >
          {t.setup.deployToAzure}
        </a>
      </div>

      {connection.deploy_stalled ? (
        <div className="rounded-lg border border-high-border bg-high-bg px-4 py-3">
          <p className="text-sm font-medium text-high">{t.setup.stalledTitle}</p>
          <p className="mt-1 text-xs leading-relaxed text-foreground">
            {connection.status_detail ?? t.setup.stalledBody}
          </p>
          <ol className="mt-3 list-decimal space-y-2 pl-4 text-xs leading-relaxed text-foreground">
            <li>{t.setup.stalledPropagation}</li>
            <li>{wrongScope}</li>
            <li>{t.setup.stalledOwner}</li>
          </ol>
          <div className="mt-3 flex flex-wrap gap-2">
            <Button variant="secondary" onClick={onRecheck} disabled={rechecking}>
              {rechecking ? t.setup.checking : t.setup.checkAgain}
            </Button>
            {!confirmingDiscard && (
              <Button variant="ghost" onClick={() => setConfirmingDiscard(true)}>
                {t.setup.changeScope}
              </Button>
            )}
          </div>

          {/* Changing scope is a new connection, not an edit: the scope is what
              the consent state and the role assignment were both bound to.
              Nothing has been scanned yet, which is what makes discarding the
              cheap answer -- and what the confirmation says. */}
          {confirmingDiscard && (
            <div className="mt-3 rounded-lg border border-border bg-background px-3 py-2.5">
              <p className="text-xs font-medium text-foreground">
                {t.connection.discardTitle}
              </p>
              <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
                {t.connection.discardDetail}
              </p>
              <div className="mt-2 flex flex-wrap gap-2">
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={onDiscard}
                  disabled={discarding}
                >
                  {discarding ? t.connection.discarding : t.connection.discard}
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => setConfirmingDiscard(false)}
                >
                  {t.connection.keep}
                </Button>
              </div>
            </div>
          )}
        </div>
      ) : (
        <WaitingNote text={t.connection.waitingForAccess} />
      )}
    </div>
  );
}
