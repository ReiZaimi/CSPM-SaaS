import {
  CheckIcon,
  CircleIcon,
  LoaderIcon,
  RotateCwIcon,
  SkipForwardIcon,
  XIcon,
} from "lucide-react";

import type { ScanStage } from "@/lib/types";
import { cn } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

/** What a scan is actually made of, in the order it runs. */
const STAGE_LABELS: Record<ScanStage["stage"], string> = {
  PLAN: "Plan",
  COLLECT: "Collect",
  ANALYZE: "Analyze",
};

const STAGE_BLURB: Record<ScanStage["stage"], string> = {
  PLAN: "Work out what this scan covers",
  COLLECT: "Read each scope and store what came back",
  ANALYZE: "Interpret every capture: normalize, evaluate, score",
};

const STATUS_ICON = {
  SUCCEEDED: CheckIcon,
  RUNNING: LoaderIcon,
  FAILED: XIcon,
  SKIPPED: SkipForwardIcon,
  PENDING: CircleIcon,
} as const;

const STATUS_TONE = {
  SUCCEEDED: "border-ok-border bg-ok-bg text-ok",
  RUNNING: "border-border bg-muted text-foreground",
  FAILED: "border-critical-border bg-critical-bg text-critical",
  // Its input never arrived, so it was never attempted. Not a failure: nothing
  // is known to be wrong with this step, and saying otherwise sends somebody
  // looking for a problem that is one hop away.
  SKIPPED: "border-unknown-border bg-unknown-bg text-unknown border-dashed",
  PENDING: "border-border bg-background text-muted-foreground",
} as const;

/**
 * What the scan is doing, from the steps it is actually made of.
 *
 * The bar this replaces had four fixed segments driven by the scan's *status*
 * string, which meant it described a pipeline the backend stopped running when
 * scans became durable steps. A tenant with twelve subscriptions ran fourteen
 * units of work and the bar showed four, none of which named a subscription --
 * so "which one is slow" and "how much is left" were both unanswerable while
 * the answer sat in the response.
 *
 * Collection is grouped and counted because that is where the time goes and
 * where partial failure happens. One unreadable subscription out of twelve is a
 * gap in a report, not a broken scan, and the count says which it is.
 */
export function ScanProgress({ stages }: { stages: ScanStage[] }) {
  if (stages.length === 0) return null;

  const collect = stages.filter((s) => s.stage === "COLLECT");
  const done = collect.filter((s) => s.status === "SUCCEEDED").length;
  const failed = collect.filter((s) => s.status === "FAILED").length;

  return (
    <div className="flex flex-col gap-3">
      {(["PLAN", "COLLECT", "ANALYZE"] as const).map((stage) => {
        const steps = stages.filter((s) => s.stage === stage);
        if (steps.length === 0) return null;

        return (
          <div key={stage} className="flex flex-col gap-1.5">
            <div className="flex flex-wrap items-baseline gap-x-2">
              <p className="text-xs font-medium">{STAGE_LABELS[stage]}</p>
              {stage === "COLLECT" && collect.length > 1 && (
                <p className="text-xs tabular-nums text-muted-foreground">
                  {done} of {collect.length} scopes read
                  {failed > 0 && (
                    <span className="text-critical"> · {failed} failed</span>
                  )}
                </p>
              )}
              <p className="text-xs text-muted-foreground">{STAGE_BLURB[stage]}</p>
            </div>

            <ul className="flex flex-wrap gap-1.5">
              {steps.map((step, index) => (
                <StepChip key={`${step.stage}-${step.scope ?? index}`} step={step} />
              ))}
            </ul>
          </div>
        );
      })}
    </div>
  );
}

function StepChip({ step }: { step: ScanStage }) {
  const Icon = STATUS_ICON[step.status] ?? CircleIcon;
  const name = step.scope ?? STAGE_LABELS[step.stage];

  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <li
            className={cn(
              "inline-flex max-w-full items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs",
              STATUS_TONE[step.status],
            )}
          />
        }
      >
        <Icon
          className={cn("size-3 shrink-0", step.status === "RUNNING" && "animate-spin")}
          aria-hidden
        />
        <span className="truncate">{name}</span>
        {step.duration_seconds !== null && step.status !== "PENDING" && (
          <span className="tabular-nums opacity-70">{formatSeconds(step.duration_seconds)}</span>
        )}
        {/* A retry is the single most useful thing to surface about a slow
            scan, and it is invisible in a duration. */}
        {step.attempt > 1 && (
          <Badge variant="secondary" className="gap-0.5 px-1 py-0 text-[10px]">
            <RotateCwIcon className="size-2.5" aria-hidden />
            {step.attempt}
          </Badge>
        )}
      </TooltipTrigger>
      <TooltipContent>
        {step.error ? (
          step.error
        ) : (
          <>
            {name} · {step.status.toLowerCase()}
            {step.attempt > 1 && ` · attempt ${step.attempt}`}
          </>
        )}
      </TooltipContent>
    </Tooltip>
  );
}

function formatSeconds(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${String(Math.round(seconds % 60)).padStart(2, "0")}s`;
}
