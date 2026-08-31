import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { CloudConnection } from "@/lib/types";
import { useT } from "@/i18n";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/format";

/**
 * How often this environment is re-read.
 *
 * The values are the ones a customer actually asks for, not the range the API
 * accepts. An hourly option is technically valid and would mostly produce a
 * scan that is still running when the next is due; a free-number input invites
 * exactly that, so the choice is a short list of intervals that make sense for
 * a posture report.
 *
 * Saving is immediate rather than behind a Save button. There is one value and
 * changing it is reversible in a click, so a staging step would be ceremony
 * around a dropdown.
 */
export function ScheduleControl({
  connection,
  onError,
}: {
  connection: CloudConnection;
  onError: (message: string) => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [saved, setSaved] = useState(false);

  const options: { value: string; label: string }[] = [
    { value: "", label: t.connection.scheduleManual },
    { value: "6", label: t.connection.scheduleEvery6Hours },
    { value: "24", label: t.connection.scheduleDaily },
    { value: "72", label: t.connection.scheduleEvery3Days },
    { value: "168", label: t.connection.scheduleWeekly },
  ];

  const save = useMutation({
    mutationFn: (hours: number | null) =>
      api.patch<CloudConnection>(
        `/api/v1/cloud-connections/${connection.id}/schedule`,
        { scan_interval_hours: hours },
      ),
    onSuccess: () => {
      // Confirmation for a control that has no Save button: without it, a
      // dropdown that writes silently gives no evidence it wrote at all.
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2000);
      queryClient.invalidateQueries({ queryKey: ["cloud-connection", connection.id] });
      queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
    },
    onError: (err) =>
      onError(
        err instanceof Error ? err.message : "Could not change the scan schedule",
      ),
  });

  const current = connection.scan_interval_hours;
  // An interval the list does not offer -- set through the API, or offered by
  // an older build. Shown rather than silently reset to "manual", which would
  // turn scheduled scanning off for somebody who never asked.
  const known = options.some((o) => o.value === String(current ?? ""));

  return (
    <div className="mt-4 rounded-lg border border-border bg-muted/40 px-4 py-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm font-medium text-foreground">
            {t.connection.scheduleTitle}
          </p>
          <p className="mt-1 max-w-prose text-xs leading-relaxed text-muted-foreground">
            {t.connection.scheduleHelp}
          </p>
        </div>
        {/* Not a `Badge`: that primitive maps a *severity* level through
            `levelStyle`, and scheduling being on is not a severity. Borrowing
            the scale would tint an ordinary setting with the colours the rest
            of the product reserves for how bad a finding is. */}
        <span
          className={cn(
            "inline-flex shrink-0 items-center rounded-full border px-2 py-0.5 text-xs font-medium",
            current === null
              ? "border-border bg-background text-muted-foreground"
              : "border-ok-border bg-ok-bg text-ok",
          )}
        >
          {current === null ? t.connection.scheduleOff : t.connection.scheduleOn}
        </span>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-3">
        <Select
          value={known ? String(current ?? "") : String(current)}
          disabled={save.isPending}
          onValueChange={(value) =>
            save.mutate(value === null || value === "" ? null : Number(value))
          }
        >
          <SelectTrigger size="sm" className="w-[190px]" aria-label={t.connection.scheduleLabel}>
            {/* Rendered from the value rather than left to the primitive: the
                options live in a portal that is not mounted while the control
                is closed, so the trigger would otherwise show the raw number
                of hours instead of what it means. */}
            <SelectValue>
              {(value) =>
                options.find((option) => option.value === value)?.label ??
                (value ? `${value} h` : t.connection.scheduleManual)
              }
            </SelectValue>
          </SelectTrigger>
          <SelectContent>
            {/* An interval the list does not offer stays selectable, so
                choosing something else is a decision rather than the only way
                out of a dropdown that cannot show the current value. */}
            {!known && current !== null && (
              <SelectItem value={String(current)}>{current} h</SelectItem>
            )}
            {options.map((option) => (
              <SelectItem key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {save.isPending && (
          <span className="text-xs text-muted-foreground">{t.connection.scheduleSaving}</span>
        )}
        {saved && !save.isPending && (
          <span className="text-xs text-ok">{t.connection.scheduleSaved}</span>
        )}
      </div>

      <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
        {t.connection.scheduleFloorNote}
      </p>
      {current !== null && (
        <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
          {t.connection.scheduleFirstRunNote}
        </p>
      )}
    </div>
  );
}
