import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { CollectionOutcome, CollectionReading, CollectionStatus } from "@/lib/types";
import { useT } from "@/i18n";
import { Skeleton } from "@/components/ui/skeleton";
import { outcomeStyle } from "@/lib/format";

/**
 * What the scan could and could not read.
 *
 * Reported apart from rule coverage next door: that says what the checks
 * concluded, this says whether they were entitled to conclude it. Fetched only
 * when the panel is open, because it is one request per scan and the list
 * renders dozens of cards.
 */
export function CollectionPanel({ scanId }: { scanId: string }) {
  const t = useT();
  const status = useQuery({
    queryKey: ["scan-collection", scanId],
    queryFn: () =>
      api.get<CollectionStatus>(`/api/v1/scans/${scanId}/collection`).then((r) => r.data),
  });

  if (status.isLoading) return <Skeleton className="h-16 w-full" />;
  if (!status.data || status.data.total === 0) return null;

  const { tasks, total, complete, partial, failed, skipped } = status.data;
  const bySubscription = new Map<string, CollectionReading[]>();
  for (const task of tasks) {
    const key = task.subscription ?? task.cloud_account_id;
    bySubscription.set(key, [...(bySubscription.get(key) ?? []), task]);
  }

  return (
    <div>
      <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
        {t.scans.collectionTitle}
      </p>

      <p className="mt-1.5 text-xs text-muted-foreground">
        <span className="font-medium tabular-nums text-foreground">
          {complete}/{total}
        </span>{" "}
        {t.scans.collectionSummary}
        {partial > 0 && (
          <>
            {" "}
            · {partial} {t.scans.collectionPartial}
          </>
        )}
        {failed > 0 && (
          <>
            {" "}
            · {failed} {t.scans.collectionFailed}
          </>
        )}
        {skipped > 0 && (
          <>
            {" "}
            · {skipped} {t.scans.collectionSkipped}
          </>
        )}
      </p>

      {partial > 0 && (
        <p className="mt-1 text-xs leading-relaxed text-medium">{t.scans.partialHint}</p>
      )}

      <div className="mt-2 flex flex-col gap-3">
        {[...bySubscription.entries()].map(([subscription, readings]) => (
          <div key={subscription}>
            {bySubscription.size > 1 && (
              <p className="text-xs font-medium text-foreground">{subscription}</p>
            )}
            <ul className="mt-1 divide-y rounded-lg border bg-background">
              {readings.map((reading) => (
                <li
                  key={`${reading.cloud_account_id}-${reading.task}`}
                  className="flex flex-wrap items-start gap-x-3 gap-y-1 px-3 py-2"
                >
                  <span className="min-w-0 flex-1 font-mono text-[11px] text-foreground">
                    {reading.task}
                  </span>
                  {reading.outcome === "COMPLETE" && (
                    <span className="text-xs tabular-nums text-muted-foreground">
                      {reading.item_count}
                    </span>
                  )}
                  <OutcomeBadge outcome={reading.outcome} />
                  {reading.detail && (
                    <p className="w-full text-xs leading-relaxed text-muted-foreground">
                      {reading.detail}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Not shadcn's `Badge`, and not `SeverityBadge` either.
 *
 * PARTIAL and FAILED are facts about the reading, not about how bad anything
 * is, and `outcomeStyle` keeps their colours in one place so a partial
 * collection never renders as reassuringly as a complete one.
 */
function OutcomeBadge({ outcome }: { outcome: CollectionOutcome }) {
  const t = useT();
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${outcomeStyle(outcome)}`}
    >
      {outcomeLabel(t, outcome)}
    </span>
  );
}

function outcomeLabel(t: ReturnType<typeof useT>, outcome: CollectionOutcome): string {
  return {
    COMPLETE: t.scans.outcomeComplete,
    PARTIAL: t.scans.outcomePartial,
    FAILED: t.scans.outcomeFailed,
    SKIPPED: t.scans.outcomeSkipped,
  }[outcome];
}
