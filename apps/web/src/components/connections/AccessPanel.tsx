import type { CloudConnection } from "@/lib/types";
import { useT } from "@/i18n";
import { Button } from "@/components/ui/button";
import { formatDate } from "@/lib/format";

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
          {connection.rbac_verified_at ? (
            <span className="text-ok">
              {connection.role_version}, {t.connection.verifiedOn}{" "}
              {formatDate(connection.rbac_verified_at)}
            </span>
          ) : (
            <span className="text-high">{t.connection.notVerified}</span>
          )}
        </Line>
        <Line label={t.connection.writePermission}>{t.connection.noneByDesign}</Line>
      </dl>

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
