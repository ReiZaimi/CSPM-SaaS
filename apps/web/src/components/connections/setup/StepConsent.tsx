import { useState } from "react";

import type { CloudConnection } from "@/lib/types";
import { useT } from "@/i18n";
import { CopyButton } from "@/components/common/CopyButton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/format";
import { WaitingNote } from "@/components/connections/setup/WaitingNote";

/**
 * Step two: admin consent.
 *
 * The step that most often cannot be finished by the person looking at it.
 * Admin consent needs a Global Administrator, and the customer evaluating
 * CloudGuard usually is not one -- so the handoff is a first-class branch here
 * rather than a sentence of advice. Sending the link is a way of completing the
 * step, not a way of giving up on it.
 *
 * Nothing is polled from this component: the wizard re-reads the connection
 * every few seconds and this step disappears when consent lands, whether it was
 * granted in this browser or in someone else's an hour from now.
 */
export function StepConsent({
  connection,
  consentError,
  onDismissError,
}: {
  connection: CloudConnection;
  consentError: string | null;
  onDismissError: () => void;
}) {
  const t = useT();
  const [handoff, setHandoff] = useState(false);

  // Consent cannot be started at all -- no signed link to offer. A dead end
  // with a reason, rather than a button that would 404 at Microsoft.
  if (!connection.consent_url) {
    return (
      <Alert className="border-high-border bg-high-bg text-high">
        <AlertTitle>{t.connection.cannotStartConsent}</AlertTitle>
        <AlertDescription className="text-foreground">
          {connection.status_detail}
        </AlertDescription>
      </Alert>
    );
  }

  const message = `${t.setup.handoffMessage}\n\n${connection.consent_url}`;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h2 className="text-base font-semibold text-foreground">{t.setup.consentTitle}</h2>
        <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
          {t.setup.consentBody}
        </p>
      </div>

      {/* Azure's own reason for the last attempt, carried back through the
          callback. Shown inside the step it belongs to: the retry is the button
          directly beneath it, which a page-level banner could not say. */}
      {consentError && (
        <Alert variant="destructive">
          <AlertTitle>{t.setup.consentFailed}</AlertTitle>
          <AlertDescription>
            <p>{consentError}</p>
            <Button variant="outline" size="sm" className="mt-2" onClick={onDismissError}>
              {t.setup.consentRetry}
            </Button>
          </AlertDescription>
        </Alert>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {/* An anchor wearing the button's clothes, not a Button rendering an
            anchor: this leaves the application, and Base UI's Button expects a
            real <button> underneath it. */}
        <a
          href={connection.consent_url}
          target="_blank"
          rel="noopener noreferrer"
          className={cn(buttonVariants())}
        >
          {t.connection.openConsent}
        </a>
        {!handoff && (
          <Button type="button" variant="ghost" onClick={() => setHandoff(true)}>
            {t.setup.notAdmin}
          </Button>
        )}
      </div>

      <p className="text-xs text-muted-foreground">{t.connection.consentExpiry}</p>

      {handoff && (
        <div className="rounded-lg border border-border bg-muted/40 px-4 py-3">
          <p className="text-sm font-medium text-foreground">{t.setup.handoffTitle}</p>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            {t.setup.handoffBody}
          </p>
          {/* The link and a sentence explaining it, together. A bare URL pasted
              into a chat window asks a Global Administrator to approve
              something unexplained, which is the request they are right to
              refuse. */}
          <p className="mt-3 whitespace-pre-wrap break-words rounded-md border border-border bg-background px-3 py-2 text-xs leading-relaxed text-foreground">
            {message}
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <CopyButton text={message} label={t.setup.copyMessage} />
            <CopyButton
              text={connection.consent_url}
              label={t.connection.copyConsentLink}
              variant="ghost"
            />
          </div>
        </div>
      )}

      <WaitingNote text={t.connection.waitingForConsent} />
    </div>
  );
}
