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
import { Skeleton } from "@/components/ui/skeleton";
import { cn, formatDate } from "@/lib/format";

/**
 * What moved, in the week the rest of this page cannot see.
 *
 * Every other panel is a photograph of now. This is the only one that answers
 * the question somebody actually asks after a week of other people's
 * deployments, and it is deliberately short: five rows and a way through.
 *
 * A movement is coloured only when it *is* one. An attribute that changed into
 * UNKNOWN is a loss of knowledge, not an improvement — colouring it green would
 * be the one lie this product exists to refuse — so it renders neutral, as does
 * an asset simply appearing.
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
    <section
      aria-labelledby="recent-changes"
      className="flex flex-col overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <header className="flex items-start justify-between gap-4 px-5 py-4">
        <div>
          <h2 id="recent-changes" className="text-sm font-semibold">
            Recent changes
          </h2>
          <p className="mt-0.5 text-xs text-muted-foreground">
            What moved in the last seven days, newest first
          </p>
        </div>
        <Link
          to="/changes"
          className={cn(buttonVariants({ variant: "ghost", size: "sm" }), "shrink-0")}
        >
          Full feed
          <ArrowRightIcon data-icon="inline-end" />
        </Link>
      </header>

      <div className="flex-1 border-t">
        {loading && (
          <div className="flex flex-col gap-3 px-5 py-4">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-4 w-2/3" />
            <Skeleton className="h-4 w-1/2" />
          </div>
        )}

        {!loading && rows.length === 0 && (
          <p className="px-5 py-6 text-sm leading-relaxed text-muted-foreground">
            {t.changes.empty}. A scan that finds nothing different writes nothing
            here, so this is a quiet week rather than a gap in the record.
          </p>
        )}

        {!loading && rows.length > 0 && (
          <ul>
            {rows.map((event, index) => (
              <ChangeLine key={event.id} event={event} index={index} />
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function ChangeLine({ event, index }: { event: ChangeEvent; index: number }) {
  const t = useT();
  const attribute = event.change.endsWith("_CHANGED");
  const moved = attribute
    ? changeDirection(event.previous_value, event.current_value)
    : "neutral";

  const { Icon, tone } = mark(event.change, moved);

  return (
    <li
      className="flex items-center gap-3 border-b px-5 py-2.5 last:border-0 [animation:cg-rise_260ms_ease-out_both]"
      style={stagger(index)}
    >
      <Icon className={cn("size-4 shrink-0", tone)} aria-hidden />

      <div className="min-w-0 flex-1">
        <Link
          to={`/assets/${event.asset.id}`}
          className="block truncate text-sm hover:underline"
        >
          {event.asset.name}
        </Link>
        <p className="truncate text-xs text-muted-foreground">
          {t.changes.kind[event.change]}
          {attribute && event.previous_value && event.current_value && (
            <>
              {" · "}
              {event.previous_value} → {event.current_value}
            </>
          )}
        </p>
      </div>

      <span className="shrink-0 text-xs text-muted-foreground">
        {formatDate(event.observed_at)}
      </span>
    </li>
  );
}

/** The shape and colour of a movement, or the absence of one. */
function mark(change: ChangeEvent["change"], moved: "worse" | "better" | "neutral") {
  if (change === "APPEARED") return { Icon: PlusIcon, tone: "text-muted-foreground" };
  if (change === "DISAPPEARED")
    return { Icon: MinusIcon, tone: "text-muted-foreground" };
  if (moved === "worse") return { Icon: TrendingUpIcon, tone: "text-critical" };
  if (moved === "better") return { Icon: TrendingDownIcon, tone: "text-ok" };
  // An attribute that moved into or out of UNKNOWN. Neither direction, and
  // saying otherwise would turn a gap in knowledge into good news.
  return { Icon: MinusIcon, tone: "text-muted-foreground" };
}
