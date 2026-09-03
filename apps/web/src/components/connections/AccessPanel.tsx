import { ArrowUpRightIcon } from "lucide-react";

import type { CloudConnection } from "@/lib/types";
import { useT } from "@/i18n";
import { Button, buttonVariants } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { collectionCategoryLabel, formatDate } from "@/lib/format";

/**
 * What CloudGuard was granted, and what it was not.
 *
 * The third line is the one worth having. Consent and the reader role are
 * facts the customer can check in their own portal; "write permission: none, by
 * design" is the product's central claim about itself, and stating it beside
 * the grants -- rather than in a marketing paragraph -- puts it where somebody
 * auditing this screen will actually read it.
 *
 * Re-checking is a real probe, not a cache read: the backend re-tests both
 * grants on every read of the connection, so this button asks Azure again. It
 * is what turns a role deleted in the portal last night into a connection that
 * says so.
 *
 * The reader role line is the one that had to stop lying. A deployed role older
 * than the one CloudGuard needs was printed in the same green as a current one,
 * because the version was rendered and never compared -- so a customer whose
 * database and key vault checks were all reporting "not known" had a screen
 * telling them their access was fine, and nowhere in the product said
 * otherwise. The backend has known this since role versions existed; this is
 * where it reaches somebody.
 */
export function AccessPanel({
  connection,
  onRecheck,
  rechecking,
}: {
  connection: CloudConnection;
  onRecheck: () => void;
  rechecking: boolean;
}) {
  const t = useT();

  return (
    <div className="rounded-xl border border-border bg-muted/30 p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        {t.connection.accessTitle}
      </p>

      <dl className="mt-3 space-y-2 text-sm">
        <Line label={t.connection.consentSignal}>
          {connection.consent_status === "GRANTED" ? (
            <span className="text-ok">
              {t.connection.granted}
              {connection.consented_at && ` ${formatDate(connection.consented_at)}`}
            </span>
          ) : (
            <span className="text-high">{t.connection.notGranted}</span>
          )}
        </Line>
        <Line label={t.connection.readerRole}>
          {!connection.rbac_verified_at ? (
            <span className="text-high">{t.connection.notVerified}</span>
          ) : connection.role_upgrade_available ? (
            // Deliberately not green, and deliberately not red either. The role
            // works -- most checks are running on it -- so painting it as a
            // failure would send somebody to fix an outage they do not have.
            // It is behind, which is its own state and reads as one.
            <span className="text-medium">
              {connection.role_version}, {t.connection.roleBehind} (
              {connection.role_required_version})
            </span>
          ) : (
            <span className="text-ok">
              {connection.role_version}, {t.connection.verifiedOn}{" "}
              {formatDate(connection.rbac_verified_at)}
            </span>
          )}
        </Line>
        <Line label={t.connection.writePermission}>{t.connection.noneByDesign}</Line>
      </dl>

      {connection.role_upgrade_available && (
        <Alert className="mt-4 border-medium-border bg-medium-bg text-medium">
          <AlertTitle>{t.connection.roleUpgradeTitle}</AlertTitle>
          <AlertDescription className="text-foreground">
            {t.connection.roleUpgradeBody}
            {/* Named rather than counted. "Two categories are degraded" is a
                number; "database and secrets checks" is the sentence that tells
                somebody whether this is urgent for them. */}
            {connection.degraded_categories.length > 0 && (
              <span className="mt-2 block">
                <span className="text-muted-foreground">
                  {t.connection.roleUpgradeAffects}:{" "}
                </span>
                {connection.degraded_categories
                  .map(collectionCategoryLabel)
                  .join(", ")}
              </span>
            )}
            {/* The same link the setup wizard uses. Redeploying is deploying
                again -- the template carries the current role definition -- so
                offering a different route here would be inventing a second way
                to do one thing. */}
            {connection.template_url && (
              <a
                href={connection.template_url}
                target="_blank"
                rel="noreferrer"
                className={buttonVariants({ variant: "default", size: "sm" }) + " mt-3"}
              >
                {t.connection.roleUpgradeAction}
                <ArrowUpRightIcon className="size-4" aria-hidden />
              </a>
            )}
          </AlertDescription>
        </Alert>
      )}

      <Button
        variant="secondary"
        size="sm"
        className="mt-4"
        onClick={onRecheck}
        disabled={rechecking}
      >
        {rechecking ? t.connection.checking : t.connection.recheckAccess}
      </Button>
    </div>
  );
}

function Line({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-0.5">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="text-right font-medium text-foreground">{children}</dd>
    </div>
  );
}
