import { ScissorsIcon } from "lucide-react";

import type { AttackPathStep } from "@/lib/types";
import { cn } from "@/lib/format";

/**
 * A route, drawn as a route.
 *
 * The list this replaces was numbered sentences: correct, and it made the
 * reader assemble the shape in their head. A chain with a visible spine shows
 * the two things that decide what to do about it -- how many links there are,
 * and which one is worth cutting -- before any of the text is read.
 *
 * Not a force-directed graph. A canvas of draggable nodes photographs well and
 * makes "which link do I break" harder to answer than a straight line does, and
 * this component exists to answer exactly that.
 */
export function AttackPathRoute({
  steps,
  cutIndex,
  className,
}: {
  steps: AttackPathStep[];
  cutIndex?: number;
  className?: string;
}) {
  return (
    <ol className={cn("flex flex-col", className)}>
      {steps.map((step, index) => {
        const isCut = index === cutIndex;
        const last = index === steps.length - 1;

        return (
          <li key={`${step.source_id}-${step.relationship}-${step.target_id}`} className="flex gap-3">
            {/* The spine. The connector below a severed link is dashed, so the
                break reads as a break rather than as a highlighted row. */}
            <div className="flex flex-col items-center">
              <span
                className={cn(
                  "flex size-6 shrink-0 items-center justify-center rounded-full border text-[10px] font-medium",
                  isCut
                    ? "border-ok-border bg-ok-bg text-ok"
                    : "border-border bg-background text-muted-foreground",
                )}
                aria-hidden
              >
                {isCut ? <ScissorsIcon className="size-3" /> : index + 1}
              </span>
              {!last && (
                <span
                  className={cn(
                    "min-h-6 w-px flex-1",
                    isCut ? "border-l border-dashed border-ok-border" : "bg-border",
                  )}
                  aria-hidden
                />
              )}
            </div>

            <div className={cn("min-w-0 pb-4", last && "pb-0")}>
              <p className={cn("text-sm", isCut ? "font-medium text-foreground" : "text-muted-foreground")}>
                {step.description}
              </p>
              {isCut && (
                <p className="mt-0.5 text-xs text-ok">
                  Cutting this link severs the route
                </p>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
