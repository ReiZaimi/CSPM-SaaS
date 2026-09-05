import { CheckIcon } from "lucide-react";

import { useT } from "@/i18n";
import { setupSteps, stepIndex, type SetupStage } from "@/lib/connectionStage";
import { setupCopy } from "@/lib/setupCopy";
import type { Provider } from "@/lib/types";
import { cn } from "@/lib/format";

/**
 * The steps, and where the customer is in them.
 *
 * The same rows as the empty state's preview, in the same words. Somebody who
 * read "what the three minutes look like" before starting should recognise the
 * list they are now standing inside, rather than meet a second, differently
 * worded account of the same flow.
 *
 * Four rows on Azure and three on AWS, because AWS has no consent step. A rail
 * with a permanently grey "Grant consent" row would read as a flow that is
 * stuck on something nobody is going to do.
 */
export function SetupRail({
  stage,
  provider,
}: {
  stage: SetupStage;
  provider: Provider;
}) {
  const t = useT();
  const copy = setupCopy(t, provider);
  const steps = setupSteps(provider);
  const current = stepIndex(stage, provider);

  return (
    <div className="rounded-xl border border-border bg-muted/30 p-5">
      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        {copy.railTitle}
      </p>
      <ol className="mt-4 space-y-4">
        {steps.map((step, index) => {
          const done = index < current || (index === current && stage === "done");
          const active = index === current && stage !== "done";
          return (
            <li key={step.stage} className="flex gap-3">
              <span
                className={cn(
                  "mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full text-xs font-medium",
                  // `text-background`, not `text-white`: in dark mode `--sev-ok`
                  // is a light green, and white on it measured 1.95:1.
                  done && "bg-ok text-background",
                  active && "bg-foreground text-background",
                  !done && !active && "border border-border text-muted-foreground",
                )}
              >
                {/* A tick rather than a number once a step is behind the
                    reader, so finished and pending differ by shape and not by
                    colour alone. */}
                {done ? <CheckIcon className="size-3.5" /> : index + 1}
              </span>
              <span className="min-w-0">
                <span
                  className={cn(
                    "block text-sm font-medium",
                    active || done ? "text-foreground" : "text-muted-foreground",
                  )}
                >
                  {copy[step.key]}
                </span>
                <span className="mt-0.5 block text-xs leading-relaxed text-muted-foreground">
                  {copy[`${step.key}Detail`]}
                </span>
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
