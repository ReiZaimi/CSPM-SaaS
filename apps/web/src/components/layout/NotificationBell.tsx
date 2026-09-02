import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BellIcon, CircleCheckIcon, EyeOffIcon, ShieldAlertIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { AppNotification, NotificationKind } from "@/lib/types";
import { useT } from "@/i18n";
import { formatDateTime, formatRelative } from "@/lib/format";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";

/**
 * What happened that you have not seen.
 *
 * Deliberately not a second `/changes`. That page answers "what moved in the
 * environment" and is a property of the estate; this answers "what happened
 * since you last looked" and is a property of a reader — so the same scan gives
 * everyone the same changes and each person a different unread count.
 *
 * **No polling interval.** `ScanIndicator` beside it polls only while a scan is
 * in flight and explicitly refuses to poll a finished one overnight; there is no
 * "in flight" here, so an interval would be exactly that refused behaviour. A
 * refetch when the window regains focus is when a person could see it anyway,
 * and costs nothing while the tab is buried.
 */
export function NotificationBell() {
  const t = useT();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);

  const { data, error } = useQuery({
    queryKey: ["notifications"],
    queryFn: () =>
      api
        .get<AppNotification[]>("/api/v1/notifications")
        .then((r) => ({
          rows: r.data,
          unread: (r.meta as { unread?: number } | undefined)?.unread ?? 0,
        })),
    retry: false,
  });

  const markRead = useMutation({
    mutationFn: () => api.post("/api/v1/notifications/read"),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["notifications"] }),
  });

  const rows = data?.rows ?? [];
  const unread = data?.unread ?? 0;

  // Read on open, not on close: the panel being on screen is the moment the
  // news was seen, and marking on close would leave the badge lit behind
  // somebody who read everything and then navigated away instead of dismissing
  // the popover.
  //
  // An effect rather than a line in the open handler, because the count can
  // arrive *after* the click. Somebody who opens the bell the instant the page
  // loads would otherwise be marked read against an unread count of zero, and
  // the badge would light up behind a panel they were looking at.
  const marked = useRef(false);
  useEffect(() => {
    if (!open) {
      marked.current = false;
      return;
    }
    if (unread > 0 && !marked.current) {
      marked.current = true;
      markRead.mutate();
    }
    // `markRead` is a stable mutation object; including it would re-run this on
    // every render of a mutation that is itself the effect's only side effect.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, unread]);

  // A failed request is not an absence of news: rendering an empty bell would
  // say "all quiet" on the strength of a network error.
  //
  // Below the hooks, not above them. An early return before a `useEffect`
  // changes how many hooks run the moment a request fails, which React treats
  // as a different component -- and the failure mode is a crash on the render
  // *after* the one that went wrong.
  if (error) return null;

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger
        render={
          <Button
            variant="ghost"
            size="icon"
            className="relative"
            aria-label={
              unread > 0
                ? t.notifications.ariaUnread.replace("{count}", String(unread))
                : t.notifications.aria
            }
          />
        }
      >
        <BellIcon />
        {unread > 0 && (
          // A dot with a count, not a count alone: the number is only useful
          // once somebody has noticed the bell changed at all.
          <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-critical px-1 text-[10px] font-medium tabular-nums text-background">
            {unread > 9 ? "9+" : unread}
          </span>
        )}
      </PopoverTrigger>

      <PopoverContent align="end" className="w-[min(24rem,calc(100vw-2rem))] p-0">
        <div className="border-b px-3 py-2.5">
          <p className="text-sm font-medium">{t.notifications.title}</p>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {t.notifications.subtitle}
          </p>
        </div>

        {rows.length === 0 ? (
          <p className="px-3 py-6 text-center text-sm text-muted-foreground">
            {t.notifications.empty}
          </p>
        ) : (
          <ul className="max-h-96 divide-y overflow-y-auto">
            {rows.map((row) => (
              <li key={row.id}>
                <Row row={row} onNavigate={() => setOpen(false)} />
              </li>
            ))}
          </ul>
        )}
      </PopoverContent>
    </Popover>
  );
}

/**
 * One row. A link, never an action.
 *
 * Nothing is resolved, accepted or dismissed from here: those are decisions
 * about a finding, and a decision taken from a dropdown is one taken without
 * the evidence in front of you.
 */
function Row({
  row,
  onNavigate,
}: {
  row: AppNotification;
  onNavigate: () => void;
}) {
  const body = (
    <div className="flex gap-2.5 px-3 py-2.5">
      <KindIcon kind={row.kind} />
      <div className="min-w-0 flex-1">
        <p className="text-sm leading-snug text-foreground">{row.title}</p>
        {row.detail && (
          <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
            {row.detail}
          </p>
        )}
        <p
          className="mt-1 text-xs text-muted-foreground"
          title={formatDateTime(row.event_at)}
        >
          {formatRelative(row.event_at)}
        </p>
      </div>
    </div>
  );

  if (!row.link) return body;
  return (
    <Link to={row.link} onClick={onNavigate} className="block hover:bg-muted/60">
      {body}
    </Link>
  );
}

/**
 * The severity tokens, not shadcn's chrome ones.
 *
 * A verified fix is the one piece of good news the product sends, and painting
 * it the same colour as a reachable finding would make the bell read as uniform
 * bad news — which is how people stop opening it.
 */
function KindIcon({ kind }: { kind: NotificationKind }) {
  if (kind === "VERIFIED_FIX") {
    return <CircleCheckIcon className="mt-0.5 size-4 shrink-0 text-ok" />;
  }
  if (kind === "COVERAGE_DROP") {
    // UNKNOWN's colour, because that is what a failed reading produces: not a
    // problem found, but a question CloudGuard could not answer.
    return <EyeOffIcon className="mt-0.5 size-4 shrink-0 text-unknown" />;
  }
  return <ShieldAlertIcon className="mt-0.5 size-4 shrink-0 text-critical" />;
}
