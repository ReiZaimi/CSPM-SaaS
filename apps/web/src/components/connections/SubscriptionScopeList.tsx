import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ChevronDownIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { CloudConnection, DiscoveredSubscription } from "@/lib/types";
import { words } from "@/lib/vocabulary";
import { useT } from "@/i18n";
import { isNewSinceLastRead, lastReadAt } from "@/lib/connectionSummary";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { formatDate, formatDateTime } from "@/lib/format";

/** Rows shown before the list collapses into a disclosure. */
const VISIBLE = 4;

/**
 * What was found beneath the scope, and which of it CloudGuard reads.
 *
 * One component for the wizard and the connections list. The two show the same
 * list for the same reason -- deciding scope is not a setup-only act, since a
 * subscription created next month appears here on the next read -- and keeping
 * two copies meant a fix to the save behaviour landed on whichever one the
 * author happened to be looking at.
 *
 * Each row carries its own history: when it first appeared, whether it has been
 * read since it did, and when somebody took it out of scope. An estate of forty
 * subscriptions is otherwise forty identical lines, and the one that matters --
 * created last Tuesday, never scanned -- looks exactly like the other
 * thirty-nine.
 */
export function SubscriptionScopeList({
  connection,
  onError,
}: {
  connection: CloudConnection;
  onError: (message: string) => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  // Only the rows the reader has actually touched. A map of every row would
  // silently write back a stale answer for the ones discovery changed while
  // this list sat open.
  const [selection, setSelection] = useState<Record<string, boolean>>({});
  const [expanded, setExpanded] = useState(false);

  const subscriptions = connection.subscriptions ?? [];
  const scoped = subscriptions.filter((s) => s.in_scope);
  const vocabulary = words(connection.provider);
  const lastRead = lastReadAt(connection);
  const shown = expanded ? subscriptions : subscriptions.slice(0, VISIBLE);
  const hidden = subscriptions.length - shown.length;

  const saveScope = useMutation({
    mutationFn: () =>
      api.patch<DiscoveredSubscription[]>(
        `/api/v1/cloud-connections/${connection.id}/subscriptions`,
        { in_scope: selection },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cloud-connection", connection.id] });
      queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
      setSelection({});
    },
    onError: (err) =>
      onError(err instanceof Error ? err.message : "Could not save scope"),
  });

  const hasSelectionChanges = Object.keys(selection).length > 0;
  const checked = (row: DiscoveredSubscription) =>
    selection[row.subscription_id ?? ""] ?? row.in_scope;

  return (
    <div>
      <p className="text-xs text-muted-foreground">
        {scoped.length} of {subscriptions.length} {vocabulary.accounts}{" "}
        {t.connection.inScopeCount}
        {connection.last_discovery_at && (
          <> · {t.connection.lastDiscovery} {formatDateTime(connection.last_discovery_at)}</>
        )}
        <span className="mt-1 block">{t.connection.discoveryPromise}</span>
      </p>

      <ul className="mt-2 divide-y divide-border rounded-lg border border-border">
        {shown.map((sub) => (
          <li key={sub.id} className="flex items-center gap-3 px-4 py-2.5">
            <Checkbox
              checked={checked(sub)}
              onCheckedChange={(value) =>
                setSelection({
                  ...selection,
                  [sub.subscription_id ?? ""]: value === true,
                })
              }
              aria-label={`${t.connection.inScope}: ${sub.display_name}`}
            />
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm text-foreground">
                {sub.display_name}
              </span>
              <code className="text-[11px] text-muted-foreground">
                {sub.subscription_id}
              </code>
            </span>
            <SubscriptionNote subscription={sub} lastRead={lastRead} />
          </li>
        ))}
      </ul>

      {/* A long estate collapses rather than pushing the panels beside it off
          the screen. The count says what is behind the disclosure, because
          "show more" on a list about coverage is exactly where a reader is
          entitled to know how much they are not being shown. */}
      {hidden > 0 && (
        <Button
          variant="ghost"
          size="sm"
          className="mt-1 w-full justify-center text-muted-foreground"
          onClick={() => setExpanded(true)}
        >
          {hidden} {t.connection.moreSubscriptions} {vocabulary.accounts}
          <ChevronDownIcon data-icon="inline-end" />
        </Button>
      )}

      {hasSelectionChanges && (
        <Button
          className="mt-3"
          onClick={() => saveScope.mutate()}
          disabled={saveScope.isPending}
        >
          {t.connection.saveScope}
        </Button>
      )}

      <p className="mt-3 text-xs leading-relaxed text-muted-foreground">
        {t.connection.scopeFootnote}
      </p>
    </div>
  );
}

/**
 * The right-hand note on a subscription row.
 *
 * One line, and which line depends on what the reader most needs to know about
 * this row: that it is excluded, that it has never been read, or -- when
 * neither is remarkable -- simply when it first appeared.
 */
function SubscriptionNote({
  subscription,
  lastRead,
}: {
  subscription: DiscoveredSubscription;
  lastRead: string | null;
}) {
  const t = useT();

  if (!subscription.in_scope) {
    return (
      <span className="shrink-0 text-xs text-muted-foreground">
        {t.connection.excludedByYou}
        {subscription.scope_changed_at && `, ${formatDate(subscription.scope_changed_at)}`}
      </span>
    );
  }

  if (isNewSinceLastRead(subscription, lastRead)) {
    return (
      <span className="shrink-0 rounded-full border border-ok-border bg-ok-bg px-2 py-0.5 text-xs font-medium text-ok">
        {t.connection.newSinceLastRead}
      </span>
    );
  }

  if (!subscription.discovered_at) return null;

  return (
    <span className="shrink-0 text-xs text-muted-foreground">
      {t.connection.firstSeen} {formatDate(subscription.discovered_at)}
    </span>
  );
}
