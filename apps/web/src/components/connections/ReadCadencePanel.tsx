import { Link } from "react-router-dom";

import type { CloudConnection } from "@/lib/types";
import { useT } from "@/i18n";
import { cadenceLabel, lastReadAt } from "@/lib/connectionSummary";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn, formatRelative } from "@/lib/format";

/**
 * How often this environment is read, and by what.
 *
 * Two mechanisms, stated together because neither is the whole answer. The
 * clock bounds how stale the picture may get; change detection bounds how long
 * a change goes unnoticed, and a customer reading only one of them draws the
 * wrong conclusion about the other. "Last read" sits above both, because it is
 * the only line here that is a fact rather than an intention.
 *
 * The schedule is read here and changed on the scans page, where the history it
 * explains lives (DECISIONS.md §40). Stating it read-only is the difference
 * between a reader concluding the feature was dropped and knowing where it went.
 */
export function ReadCadencePanel({
  connection,
  onScanNow,
  scanning,
}: {
  connection: CloudConnection;
  onScanNow: () => void;
  scanning: boolean;
}) {
  const t = useT();
  const lastRead = lastReadAt(connection);

  return (
    <div className="rounded-xl border border-border bg-muted/30 p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        {t.connection.cadenceTitle}
      </p>

      <dl className="mt-3 space-y-2 text-sm">
        <Line label={t.connection.cadenceLastRead}>
          {lastRead ? formatRelative(lastRead) : t.connection.cadenceNeverRead}
        </Line>
        <Line label={t.connection.cadenceClock}>
          {cadenceLabel(connection.scan_interval_hours)}
        </Line>
        <Line label={t.connection.cadenceOnChange}>
          {connection.change_events_enabled ? (
            <span className="inline-flex items-center gap-1.5 text-ok">
              <span className="size-1.5 rounded-full bg-ok" />
              {t.connection.changeOn}
            </span>
          ) : (
            <span className="text-muted-foreground">{t.connection.changeOff}</span>
          )}
        </Line>
        {/* Only when something has been heard. "Last change heard: nothing yet"
            on a connection that is not listening reads as a failure rather than
            as a setting nobody turned on. */}
        {connection.change_events_enabled && (
          <Line label={t.connection.changeLastEvent}>
            {connection.last_change_event_at
              ? formatRelative(connection.last_change_event_at)
              : t.connection.changeNeverHeard}
          </Line>
        )}
      </dl>

      <div className="mt-4 flex flex-wrap gap-2">
        <Button
          size="sm"
          onClick={onScanNow}
          disabled={scanning || !connection.is_ready_to_scan}
        >
          {scanning ? t.connection.scanStarting : t.connection.scanNow}
        </Button>
        <Link
          to="/scans"
          className={cn(buttonVariants({ variant: "secondary", size: "sm" }))}
        >
          {t.connection.changeSchedule}
        </Link>
      </div>
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
