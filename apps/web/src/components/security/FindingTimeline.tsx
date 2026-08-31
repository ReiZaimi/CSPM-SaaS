import { BotIcon, UserIcon } from "lucide-react";

import type { FindingEvent } from "@/lib/types";
import { cn, formatDateTime, label } from "@/lib/format";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

/** The colour an event earns. Only an observed fix gets the success tone. */
const TONE: Record<FindingEvent["event"], string> = {
  DETECTED: "bg-critical",
  REOPENED: "bg-high",
  RESOLVED: "bg-ok",
  RISK_ACCEPTED: "bg-unknown",
  STATUS_CHANGED: "bg-muted-foreground",
};

/**
 * Everything that has happened to this finding.
 *
 * Two timestamps could say when it was first seen and when it was closed, and
 * nothing in between -- so a finding raised, fixed, regressed and fixed again
 * looked exactly like one raised and fixed once. That difference is the whole
 * question of whether a fix held.
 *
 * Each row says whether a *scan* or a *person* caused it, because the two mean
 * different things: a scan observing a check pass is verification, and a person
 * moving a status is a decision.
 */
export function FindingTimeline({ events }: { events: FindingEvent[] }) {
  if (events.length === 0) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle>History</CardTitle>
        <CardDescription>What has happened to this finding, newest first</CardDescription>
      </CardHeader>
      <CardContent>
        <ol className="flex flex-col gap-3">
          {events.map((event, index) => (
            <li key={`${event.observed_at}-${index}`} className="flex gap-3">
              <div className="flex flex-col items-center">
                <span className={cn("mt-1 size-2 shrink-0 rounded-full", TONE[event.event])} />
                {index < events.length - 1 && <span className="mt-1 w-px flex-1 bg-border" />}
              </div>
              <div className="min-w-0 pb-1">
                <div className="flex flex-wrap items-center gap-x-2 text-sm">
                  <span className="font-medium">{label(event.event)}</span>
                  {event.user_id ? (
                    <UserIcon className="size-3 text-muted-foreground" aria-label="By a person" />
                  ) : (
                    <BotIcon className="size-3 text-muted-foreground" aria-label="By a scan" />
                  )}
                  <span className="text-xs text-muted-foreground">
                    {formatDateTime(event.observed_at)}
                  </span>
                </div>
                {event.detail && (
                  <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
                    {event.detail}
                  </p>
                )}
              </div>
            </li>
          ))}
        </ol>
      </CardContent>
    </Card>
  );
}
