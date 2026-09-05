import { Link } from "react-router-dom";
import {
  ArrowRightIcon,
  MinusIcon,
  PlusIcon,
  TrendingDownIcon,
  TrendingUpIcon,
} from "lucide-react";

import type { ChangeEvent } from "@/lib/types";
import { useT } from "@/i18n";
import { changeDirection } from "@/lib/changes";
import { stagger } from "@/lib/motion";
import { buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, formatDate } from "@/lib/format";

/**
 * What moved, in the week the rest of this page cannot see.
 *
 * Every other panel is a photograph of now. This is the only one that answers
 * the question somebody actually asks after a week of other people's
 * deployments, and it is deliberately short: five rows and a way through.
 *
 * It is drawn as a timeline because that is what it is — one sequence, read
 * newest first, with the date in its own gutter so a reader can see at a glance
 * whether the week's movement was one bad afternoon or a steady drift.
 *
 * A movement is coloured only when it *is* one. An attribute that changed into
 * UNKNOWN is a loss of knowledge, not an improvement — colouring it green would
 * be the one lie this product exists to refuse — so it renders neutral, as does
 * an asset simply appearing. The mark keeps its shape as well as its colour:
 * a reader who cannot separate the hues still has to be able to tell a
 * regression from an arrival.
 */
export function RecentChanges({
  events,
  loading,
}: {
  events: ChangeEvent[] | undefined;
  loading: boolean;
}) {
  const t = useT();
  const rows = Array.isArray(events) ? events.slice(0, 5) : [];

  return (
    <Card
      role="region"
      aria-labelledby="recent-changes"
      className="gap-0 py-0 [--card-spacing:--spacing(5)]"
    >
      <CardHeader className="py-4">
        <CardTitle id="recent-changes" className="text-sm font-semibold">
          Recent changes
        </CardTitle>
        <CardDescription className="text-xs">
          What moved in the last seven days, newest first
        </CardDescription>
        <CardAction>
          <Link
            to="/changes"
            className={cn(buttonVariants({ variant: "ghost", size: "sm" }), "shrink-0")}
          >
            Full feed
            <ArrowRightIcon data-icon="inline-end" />
          </Link>
        </CardAction>
      </CardHeader>

      <div className="flex-1 border-t">
        {loading && (
          <CardContent className="flex flex-col gap-3 py-4">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-4 w-2/3" />
            <Skeleton className="h-4 w-1/2" />
          </CardContent>
        )}

        {!loading && rows.length === 0 && (
          <CardContent className="py-6">
            <p className="text-sm leading-relaxed text-muted-foreground">
              {t.changes.empty}. A scan that finds nothing different writes
              nothing here, so this is a quiet week rather than a gap in the
              record.
            </p>
          </CardContent>
        )}

        {!loading && rows.length > 0 && (
          <ul className="py-3 pr-5 pl-3">
            {rows.map((event, index) => (
              <ChangeLine
                key={event.id}
                event={event}
                index={index}
                first={index === 0}
                last={index === rows.length - 1}
              />
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}

function ChangeLine({
  event,
  index,
  first,
  last,
}: {
  event: ChangeEvent;
  index: number;
  first: boolean;
  last: boolean;
}) {
  const t = useT();
  const attribute = event.change.endsWith("_CHANGED");
  const moved = attribute
    ? changeDirection(event.previous_value, event.current_value)
    : "neutral";

  const { Icon, tone, ring } = mark(event.change, moved);

  return (
    <li
      className="grid grid-cols-[4.5rem_auto_1fr] items-start gap-x-3 [animation:cg-rise_260ms_ease-out_both]"
      style={stagger(index)}
    >
      <span className="py-2 text-right text-xs whitespace-nowrap text-muted-foreground">
        {formatDate(event.observed_at)}
      </span>

      {/* The spine. It stops at the first and last mark rather than running off
          the ends of the list, which would imply rows that are not there. */}
      <span className="relative flex w-5 justify-center self-stretch">
        <span
          className={cn(
            "absolute w-px bg-border",
            first ? "top-4" : "top-0",
            last ? "bottom-[calc(100%-1rem)]" : "bottom-0",
          )}
          aria-hidden
        />
        <span
          className={cn(
            "relative mt-2 flex size-4 items-center justify-center rounded-full bg-card ring-1",
            ring,
          )}
          aria-hidden
        >
          <Icon className={cn("size-2.5", tone)} />
        </span>
      </span>

      <div className="min-w-0 py-2">
        <p className="truncate text-sm">
          <Link
            to={`/assets/${event.asset.id}`}
            className="font-medium hover:underline"
          >
            {event.asset.name}
          </Link>
          <span className="text-muted-foreground">
            {" — "}
            {t.changes.kind[event.change]}
            {attribute && event.previous_value && event.current_value && (
              <>
                {": "}
                {event.previous_value} → {event.current_value}
              </>
            )}
          </span>
        </p>
      </div>
    </li>
  );
}

/** The shape and colour of a movement, or the absence of one. */
function mark(change: ChangeEvent["change"], moved: "worse" | "better" | "neutral") {
  const neutral = {
    tone: "text-muted-foreground",
    ring: "ring-border",
  };
  if (change === "APPEARED") return { Icon: PlusIcon, ...neutral };
  if (change === "DISAPPEARED") return { Icon: MinusIcon, ...neutral };
  if (moved === "worse")
    return { Icon: TrendingUpIcon, tone: "text-critical", ring: "ring-critical-border" };
  if (moved === "better")
    return { Icon: TrendingDownIcon, tone: "text-ok", ring: "ring-ok-border" };
  // An attribute that moved into or out of UNKNOWN. Neither direction, and
  // saying otherwise would turn a gap in knowledge into good news.
  return { Icon: MinusIcon, ...neutral };
}
