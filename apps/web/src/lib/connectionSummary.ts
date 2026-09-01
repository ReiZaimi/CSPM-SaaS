import { connectionStage } from "@/lib/connectionStage";
import type { CloudConnection, DiscoveredSubscription } from "@/lib/types";

/**
 * The three sentences the connections list has to be able to say about a
 * connection without opening it: when it was last read, how often it is read,
 * and which of the things beneath it are new since then.
 *
 * All derived, none fetched. A row that needed its own request to say "12
 * minutes ago" would be one request per connection on a page that exists to be
 * skimmed.
 */

/**
 * When CloudGuard last read this environment.
 *
 * The latest read of any subscription beneath it, including ones now out of
 * scope: the question is when this environment was last looked at, and a
 * subscription excluded yesterday was still looked at last week.
 */
export function lastReadAt(connection: CloudConnection): string | null {
  const reads = (connection.subscriptions ?? [])
    .map((s) => s.last_scan_at)
    .filter((value): value is string => Boolean(value));
  if (reads.length === 0) return null;
  return reads.reduce((latest, value) => (value > latest ? value : latest));
}

/**
 * How often it is re-read, worded as an interval rather than a time of day.
 *
 * CloudGuard promises to read an environment at least this often; it does not
 * promise to start at a particular minute, and a label saying "daily at 02:00"
 * would be a promise the scheduler never made.
 */
export function cadenceLabel(hours: number | null): string {
  if (hours === null) return "Only when asked";
  if (hours === 6) return "Every 6 hours";
  if (hours === 24) return "Every day";
  if (hours === 72) return "Every 3 days";
  if (hours === 168) return "Every week";
  return `Every ${hours} hours`;
}

/**
 * The one-line summary under the last-read time: the clock, and the thing the
 * clock cannot do.
 */
export function cadenceSummary(connection: CloudConnection): string {
  const clock = cadenceLabel(connection.scan_interval_hours).toLowerCase();
  return connection.change_events_enabled ? `on change · ${clock}` : clock;
}

/**
 * A subscription discovered after this environment was last read.
 *
 * Worth marking because it is the case the product exists to prevent: an
 * environment created last Tuesday that nothing has ever scanned, sitting in a
 * list beside twelve that are green.
 */
export function isNewSinceLastRead(
  subscription: DiscoveredSubscription,
  lastRead: string | null,
): boolean {
  if (!subscription.discovered_at) return false;
  // Nothing has ever been read here, so "new since the last read" is not a
  // useful thing to say about any of them -- the whole connection is new.
  if (!lastRead) return false;
  return subscription.discovered_at > lastRead && !subscription.last_scan_at;
}

/**
 * What the status column says, in the words the reader needs.
 *
 * The raw enum is not those words: `ACTIVE` is true of a connection with
 * nothing in scope, and `PENDING` is true both of one waiting on an
 * administrator and of one whose deployment failed an hour ago. The label
 * answers "is CloudGuard reading this environment", and the line under it says
 * what to do about it when the answer is no.
 */
export function statusSummary(connection: CloudConnection): {
  label: string;
  detail: string;
  tone: "ok" | "high" | "muted";
} {
  const stage = connectionStage(connection);

  if (stage === "paused")
    return { label: "Paused", detail: "Setup was cancelled", tone: "muted" };
  if (stage === "consent" || stage === "deploy")
    return { label: "Setting up", detail: "Waiting on a grant", tone: "high" };
  if (connection.status === "ERROR")
    return {
      label: "Needs attention",
      detail: connection.status_detail ?? "Last read failed",
      tone: "high",
    };
  if (stage === "discover")
    return {
      label: "Nothing found",
      detail: "No subscription beneath this scope",
      tone: "high",
    };
  if (stage === "review")
    return {
      label: "Nothing in scope",
      detail: "Every subscription is unticked",
      tone: "high",
    };
  return {
    label: "Live",
    detail: connection.change_events_enabled
      ? "Listening for changes"
      : "Read on a schedule",
    tone: "ok",
  };
}
