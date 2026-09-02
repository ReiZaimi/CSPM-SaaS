import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { ChangeEventSetup, CloudConnection } from "@/lib/types";
import { useT } from "@/i18n";
import { cn, formatDateTime } from "@/lib/format";
import { Button } from "@/components/ui/button";
import { CodeBlock } from "@/components/common/CodeBlock";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";

/**
 * Whether this connection reacts to change, and the commands that make it.
 *
 * Sits under the schedule rather than replacing it, because the two answer
 * different questions. A schedule promises the environment is re-read at least
 * this often; this promises a change is *noticed*, which is the difference
 * between finding an open port on Friday's scan and finding it three minutes
 * after somebody opened it.
 *
 * The copy carries one thing the toggle cannot: turning this on wires nothing
 * up. Creating the Event Grid subscription is a write in the customer's tenant,
 * and CloudGuard holds no write permission anywhere -- so it opens the webhook
 * and hands over the command. A switch that looked like it had done the work
 * would leave a customer believing they were monitored when nothing was ever
 * going to arrive.
 */
export function ChangeEventsControl({
  connection,
  onError,
}: {
  connection: CloudConnection;
  onError: (message: string) => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["change-events", connection.id],
    queryFn: () =>
      api
        .get<ChangeEventSetup>(
          `/api/v1/cloud-connections/${connection.id}/change-events`,
        )
        .then((r) => r.data),
  });

  const save = useMutation({
    mutationFn: (enabled: boolean) =>
      api.patch<ChangeEventSetup>(
        `/api/v1/cloud-connections/${connection.id}/change-events`,
        { enabled },
      ),
    onSuccess: (response) => {
      // Written straight into the cache rather than refetched: the PATCH
      // returns the same shape the GET does, and the commands appearing a
      // request later would read as the toggle not having taken.
      queryClient.setQueryData(["change-events", connection.id], response.data);
    },
    onError: (err) =>
      onError(
        err instanceof Error ? err.message : "Could not change this setting",
      ),
  });

  if (isLoading) {
    return (
      <div className="mt-4 rounded-lg border border-border bg-muted/40 px-4 py-3">
        <Skeleton className="h-4 w-40" />
        <Skeleton className="mt-2 h-3 w-full max-w-prose" />
      </div>
    );
  }

  if (!data) return null;

  const timing = t.connection.changeTiming
    .replace("{quiet}", String(data.quiet_period_minutes))
    .replace("{interval}", String(data.minimum_interval_minutes));

  return (
    <div className="mt-4 rounded-lg border border-border bg-muted/40 px-4 py-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm font-medium text-foreground">
            {t.connection.changeTitle}
          </p>
          <p className="mt-1 max-w-prose text-xs leading-relaxed text-muted-foreground">
            {t.connection.changeHelp}
          </p>
        </div>
        {/* The same reasoning as the schedule pill: listening is not a
            severity, so it does not borrow the severity scale. */}
        <span
          className={cn(
            "inline-flex shrink-0 items-center rounded-full border px-2 py-0.5 text-xs font-medium",
            data.enabled
              ? "border-ok-border bg-ok-bg text-ok"
              : "border-border bg-background text-muted-foreground",
          )}
        >
          {data.enabled ? t.connection.changeOn : t.connection.changeOff}
        </span>
      </div>

      {/* Nothing to deliver to. Offering the toggle here would open a webhook
          at an address that does not exist, so the state is named instead. */}
      {!data.webhook_url ? (
        <Alert className="mt-3 border-high-border bg-high-bg text-high">
          <AlertTitle>{t.connection.changeNoEndpoint}</AlertTitle>
          <AlertDescription className="text-foreground">
            {t.connection.changeNoEndpointHelp}
          </AlertDescription>
        </Alert>
      ) : (
        <>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <Button
              size="sm"
              variant={data.enabled ? "secondary" : "default"}
              disabled={save.isPending}
              onClick={() => save.mutate(!data.enabled)}
            >
              {data.enabled
                ? t.connection.changeDisable
                : t.connection.changeEnable}
            </Button>
            {save.isPending && (
              <span className="text-xs text-muted-foreground">
                {t.connection.changeSaving}
              </span>
            )}
            <span className="text-xs text-muted-foreground">
              {t.connection.changeLastEvent}:{" "}
              <strong className="font-medium text-foreground">
                {data.last_event_at
                  ? formatDateTime(data.last_event_at)
                  : t.connection.changeNeverHeard}
              </strong>
            </span>
          </div>

          {data.pending_since && (
            <p className="mt-2 text-xs leading-relaxed text-ok">
              {t.connection.changePending}
            </p>
          )}

          {data.enabled && (
            <>
              <p className="mt-3 text-xs leading-relaxed text-muted-foreground">
                {t.connection.changeNotWired}
              </p>

              {data.commands.length > 0 && (
                <div className="mt-3">
                  <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                    {t.connection.changeCommandsLabel}
                  </p>
                  <ul className="mt-2 flex flex-col gap-2">
                    {data.commands.map((entry) => (
                      <CommandRow
                        key={entry.subscription_id}
                        subscriptionId={entry.subscription_id}
                        command={entry.command}
                      />
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}

          <p className="mt-3 text-xs leading-relaxed text-muted-foreground">
            {timing}
          </p>
        </>
      )}
    </div>
  );
}

/**
 * One subscription's command.
 *
 * Shown in full rather than behind a copy button alone: a customer is being
 * asked to run this against their own tenant, and pasting a command they were
 * never shown is exactly the habit a security product should not be teaching.
 */
function CommandRow({
  subscriptionId,
  command,
}: {
  subscriptionId: string;
  command: string;
}) {
  const t = useT();

  return (
    <li className="rounded-md border border-border bg-background px-3 py-2">
      <code className="text-[11px] text-muted-foreground">{subscriptionId}</code>
      {/* One copy control, on the command itself. The text button that used to
          sit in this header copied the same string from a foot away, and two
          buttons for one command invited the reader to wonder what the other
          one copied. */}
      <CodeBlock
        code={command}
        className="mt-1 border-0 bg-transparent p-0 text-[11px] text-foreground"
        label={`${t.connection.changeCopyCommand}: ${subscriptionId}`}
      />
    </li>
  );
}
