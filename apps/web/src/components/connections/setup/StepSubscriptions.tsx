import { Link } from "react-router-dom";

import type { CloudConnection } from "@/lib/types";
import { useT } from "@/i18n";
import { DiscoveryRetry } from "@/components/connections/DiscoveryRetry";
import { SubscriptionScopeList } from "@/components/connections/SubscriptionScopeList";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/format";

/**
 * The last step: what CloudGuard found, and what it will read.
 *
 * Three states of one step rather than three steps. Discovery runs server-side
 * on every read of the connection, so between "verified" and "here is what is
 * beneath it" there is a gap of a few seconds -- occasionally of minutes, if
 * the grant landed at a narrower scope than the connection covers and the
 * answer is going to be nothing at all. The customer is in the same place
 * throughout; only what is on the page changes.
 */
export function StepSubscriptions({
  connection,
  onError,
}: {
  connection: CloudConnection;
  onError: (message: string) => void;
}) {
  const t = useT();
  const subscriptions = connection.subscriptions ?? [];
  const scoped = subscriptions.filter((s) => s.in_scope);

  if (subscriptions.length === 0) {
    return <DiscoveryRetry connection={connection} onError={onError} />;
  }

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h2 className="text-base font-semibold text-foreground">
          {connection.is_ready_to_scan ? t.setup.doneTitle : t.setup.reviewTitle}
        </h2>
        <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
          {t.setup.reviewBody}
        </p>
      </div>

      <SubscriptionScopeList connection={connection} onError={onError} />

      {/* Setup ends on a scan, not on a green tick. Scanning lives on another
          page and nothing used to say so, which left the last screen of the
          flow with no next step on it. */}
      {connection.is_ready_to_scan ? (
        <Alert className="border-ok-border bg-ok-bg text-ok">
          <AlertTitle>{t.connection.readyToScan}</AlertTitle>
          <AlertDescription className="text-foreground">
            <p>{t.setup.doneBody}</p>
            <div className="mt-2 flex flex-wrap gap-2">
              <Link to="/scans" className={cn(buttonVariants())}>
                {t.connection.runFirstScan}
              </Link>
              <Link
                to="/connections"
                className={cn(buttonVariants({ variant: "secondary" }))}
              >
                {t.setup.backToList}
              </Link>
            </div>
          </AlertDescription>
        </Alert>
      ) : (
        // Found something, but cannot scan it. Two different reasons, and the
        // difference matters: everything ticked off is a choice the reader made
        // and can undo in the list above, whereas rows that are in scope and
        // still unscannable are a grant that did not reach them.
        <Alert className="border-high-border bg-high-bg text-high">
          <AlertTitle>
            {scoped.length === 0
              ? t.setup.nothingInScopeTitle
              : t.connection.noSubscriptionsYet}
          </AlertTitle>
          <AlertDescription className="text-foreground">
            {scoped.length === 0
              ? t.setup.nothingInScopeBody
              : t.connection.noSubscriptionsYetHelp}
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
}
