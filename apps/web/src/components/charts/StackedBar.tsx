import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/format";

export type Segment = {
  key: string;
  label: string;
  value: number;
  tone: string;
};

/**
 * One bar, divided into the parts of a whole.
 *
 * The severity split is a composition, and a composition of five is the case a
 * ring handles worst and a single stacked bar handles best: the eye compares
 * lengths along one line instead of angles around a circle, and the whole thing
 * costs 8px of height rather than a panel.
 *
 * Plain elements rather than a charting runtime. This is five widths that add
 * up to 100% — a library would add a canvas, a resize observer and 100kB to
 * draw what flexbox draws exactly.
 *
 * Each segment carries a written label beneath, because severity is a status
 * and a status is never communicated by colour alone.
 */
export function StackedBar({
  segments,
  ariaLabel,
  className,
}: {
  segments: Segment[];
  ariaLabel: string;
  className?: string;
}) {
  const total = segments.reduce((sum, segment) => sum + segment.value, 0);

  if (total === 0) {
    return (
      <div className={cn("flex flex-col gap-2", className)}>
        <div className="h-2 w-full rounded-full bg-muted" aria-hidden />
        <p className="text-xs text-muted-foreground">
          Nothing open to break down.
        </p>
      </div>
    );
  }

  return (
    <div className={cn("flex flex-col gap-2.5", className)}>
      {/* `gap` rather than borders between segments: a 2px strip of the surface
          keeps two adjacent colours from reading as one. */}
      <div
        className="flex h-2 w-full gap-0.5 overflow-hidden rounded-full"
        role="img"
        aria-label={ariaLabel}
      >
        {segments
          .filter((segment) => segment.value > 0)
          .map((segment) => (
            <Tooltip key={segment.key}>
              <TooltipTrigger
                render={
                  <span
                    className="h-full rounded-full transition-[width] duration-700 ease-out"
                    style={{
                      width: `${(segment.value / total) * 100}%`,
                      background: segment.tone,
                    }}
                  />
                }
              />
              <TooltipContent>
                {segment.label}: {segment.value} of {total} (
                {Math.round((segment.value / total) * 100)}%)
              </TooltipContent>
            </Tooltip>
          ))}
      </div>

      <ul className="flex flex-wrap gap-x-4 gap-y-1">
        {segments.map((segment) => (
          <li key={segment.key} className="flex items-center gap-1.5 text-xs">
            <span
              className="size-2 shrink-0 rounded-[2px]"
              style={{ background: segment.tone }}
              aria-hidden
            />
            <span className="text-muted-foreground">{segment.label}</span>
            <span className="font-medium tabular-nums">{segment.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
