import { useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  ArrowRightIcon,
  GitCompareArrowsIcon,
  MinusIcon,
  PlusIcon,
  TrendingDownIcon,
  TrendingUpIcon,
} from "lucide-react";

import { api } from "@/lib/api";
import type { AssetChange, ChangeEvent } from "@/lib/types";
import { useT } from "@/i18n";
import { cn, formatDate, formatDateTime, resourceTypeLabel } from "@/lib/format";
import { changeDirection, type Direction } from "@/lib/changes";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { SelectField } from "@/components/common/SelectField";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";

const PAGE_SIZE = 50;
const WINDOWS = [1, 7, 30, 90] as const;

/**
 * What moved in the environment, rather than what is true in it now.
 *
 * Every other screen is a photograph: these are the findings, this is the
 * score, these are the assets. None of them answers the question a customer
 * actually asks after a week of somebody else's deployments -- *what changed
 * while I was away* -- and until this page existed the change events the
 * scanner has been writing all along were reachable only through the API.
 *
 * A feed of transitions, not a diff of two scans. The distinction shows up in
 * the empty state: a quiet week here is a genuinely quiet week, not a page
 * saying everything is still where it was.
 */
export function ChangesPage() {
  const t = useT();
  const [days, setDays] = useState<number>(7);
  const [kind, setKind] = useState<string>("all");
  const [page, setPage] = useState(0);

  const params = new URLSearchParams();
  params.set("days", String(days));
  if (kind !== "all") params.set("change", kind);
  params.set("limit", String(PAGE_SIZE));
  params.set("offset", String(page * PAGE_SIZE));

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["changes", days, kind, page],
    queryFn: () =>
      api
        .get<ChangeEvent[]>(`/api/v1/changes?${params.toString()}`)
        .then((r) => r.data),
    placeholderData: keepPreviousData,
  });

  const events = data ?? [];
  // The endpoint returns a window rather than a count, so there is no total to
  // page against. A full page is the only honest signal that more exists.
  const hasMore = events.length === PAGE_SIZE;

  function rewindow(apply: () => void) {
    apply();
    setPage(0);
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader title={t.changes.title} description={t.changes.intro} />

      <div className="flex flex-wrap items-center gap-2">
        <SelectField
          value={String(days)}
          onValueChange={(value) => rewindow(() => setDays(Number(value)))}
          ariaLabel={t.changes.windowLabel}
          className="w-[170px]"
          options={WINDOWS.map((window) => ({
            value: String(window),
            label: t.changes.windows[window],
          }))}
        />

        <SelectField
          value={kind}
          onValueChange={(value) => rewindow(() => setKind(value || "all"))}
          ariaLabel={t.changes.kindLabel}
          className="w-[210px]"
          options={[
            { value: "all", label: t.changes.allKinds },
            ...(Object.keys(t.changes.kind) as AssetChange[]).map((value) => ({
              value,
              label: t.changes.kind[value],
            })),
          ]}
        />
      </div>

      {isLoading && <CardsSkeleton count={2} />}

      {error && (
        <ErrorState
          title="Could not load the change feed"
          detail="CloudGuard could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {data && events.length === 0 && (
        <EmptyState
          icon={GitCompareArrowsIcon}
          title={kind === "all" ? t.changes.empty : t.changes.emptyFiltered}
          detail={
            kind === "all" ? t.changes.emptyDetail : t.changes.emptyFilteredDetail
          }
          action={
            kind !== "all" ? (
              <Button
                variant="outline"
                onClick={() => rewindow(() => setKind("all"))}
              >
                Show all changes
              </Button>
            ) : undefined
          }
        />
      )}

      {data && events.length > 0 && (
        <>
          {/* Grouped by the day it was observed, because that is the unit the
              question is asked in. An undifferentiated list of fifty rows makes
              "Tuesday's deployment" something the reader has to reconstruct
              from timestamps. */}
          {groupByDay(events).map(([day, rows]) => (
            <section key={day} className="flex flex-col gap-2">
              <h2 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                {formatDate(day)}
              </h2>
              <Card>
                <CardContent className="p-0">
                  <ul>
                    {rows.map((event) => (
                      <ChangeRow key={event.id} event={event} />
                    ))}
                  </ul>
                </CardContent>
              </Card>
            </section>
          ))}

          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-xs text-muted-foreground">
              {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + events.length}{" "}
              {events.length === 1 ? t.changes.count : t.changes.countPlural}
            </p>
            {(page > 0 || hasMore) && (
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page === 0}
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!hasMore}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </Button>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

/** Calendar days, newest first, preserving the order the API returned. */
function groupByDay(events: ChangeEvent[]): [string, ChangeEvent[]][] {
  const days = new Map<string, ChangeEvent[]>();
  for (const event of events) {
    const day = event.observed_at.slice(0, 10);
    const existing = days.get(day);
    if (existing) existing.push(event);
    else days.set(day, [event]);
  }
  return [...days.entries()];
}

function ChangeRow({ event }: { event: ChangeEvent }) {
  const t = useT();
  const attribute = event.change.endsWith("_CHANGED");
  const moved = attribute
    ? changeDirection(event.previous_value, event.current_value)
    : "neutral";

  return (
    <li className="flex flex-wrap items-start gap-x-3 gap-y-2 border-b px-4 py-3 last:border-0">
      <ChangeMark change={event.change} moved={moved} />

      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <Link
            to={`/assets/${event.asset.id}`}
            className="truncate text-sm font-medium text-foreground underline-offset-4 hover:underline"
          >
            {event.asset.name}
          </Link>
          <span className="text-xs text-muted-foreground">
            {resourceTypeLabel(event.asset.resource_type)}
          </span>
          {event.asset.environment && (
            <Badge variant="outline">{event.asset.environment}</Badge>
          )}
        </div>

        <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
          <span>{t.changes.kind[event.change]}</span>

          {attribute && (
            <span className="flex items-center gap-1.5">
              <SeverityBadge level={event.previous_value ?? "UNKNOWN"} size="sm" />
              <ArrowRightIcon className="size-3 shrink-0" aria-hidden />
              <SeverityBadge level={event.current_value ?? "UNKNOWN"} size="sm" />
              {moved !== "neutral" && (
                <span
                  className={cn(
                    "font-medium",
                    moved === "worse" ? "text-critical" : "text-ok",
                  )}
                >
                  {moved === "worse" ? t.changes.worse : t.changes.better}
                </span>
              )}
            </span>
          )}

          {event.change === "APPEARED" && <span>{t.changes.appeared}</span>}

          {/* The reading that decides whether this row is history or a job.
              The asset row is never deleted when a scan stops seeing it, so a
              DISAPPEARED event says nothing on its own about whether the thing
              is gone now. */}
          {event.change === "DISAPPEARED" &&
            (event.asset.absent_since ? (
              <span className="font-medium text-high">
                {t.changes.stillMissing}
              </span>
            ) : (
              <span className="font-medium text-ok">{t.changes.returned}</span>
            ))}
        </div>
      </div>

      <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
        {formatDateTime(event.observed_at)}
      </span>
    </li>
  );
}

/**
 * The one glyph that carries the row's meaning at a glance.
 *
 * Shape as well as colour: an arrow that only turned red would tell a reader
 * who cannot separate the hues nothing at all, on a feed whose entire value is
 * spotting the handful of rows that got worse.
 */
function ChangeMark({
  change,
  moved,
}: {
  change: AssetChange;
  moved: Direction;
}) {
  const Icon =
    change === "APPEARED"
      ? PlusIcon
      : change === "DISAPPEARED"
        ? MinusIcon
        : moved === "worse"
          ? TrendingUpIcon
          : moved === "better"
            ? TrendingDownIcon
            : GitCompareArrowsIcon;

  const tone =
    change === "APPEARED" || change === "DISAPPEARED"
      ? "border-border bg-muted text-muted-foreground"
      : moved === "worse"
        ? "border-critical-border bg-critical-bg text-critical"
        : moved === "better"
          ? "border-ok-border bg-ok-bg text-ok"
          : "border-border bg-muted text-muted-foreground";

  return (
    <span
      className={cn(
        "mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full border",
        tone,
      )}
    >
      <Icon className="size-3.5" aria-hidden />
    </span>
  );
}
