import { CheckIcon } from "lucide-react";

import { useT } from "@/i18n";
import { SETUP_STEPS, stepIndex, type SetupStage } from "@/lib/connectionStage";
import { cn } from "@/lib/format";

/**
 * The four steps, and where the customer is in them.
 *
 * The same four rows as the empty state's preview, in the same words. Somebody
 * who read "what the three minutes look like" before starting should recognise
 * the list they are now standing inside, rather than meet a second, differently
 * worded account of the same flow.
 */
export function SetupRail({ stage }: { stage: SetupStage }) {
  const t = useT();
  const current = stepIndex(stage);

  return (
    <div className="rounded-xl border border-border bg-muted/30 p-5">
      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        {t.setup.railTitle}
      </p>
      <ol className="mt-4 space-y-4">
        {SETUP_STEPS.map((step, index) => {
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
                  {t.setup[step.key]}
                </span>
                <span className="mt-0.5 block text-xs leading-relaxed text-muted-foreground">
                  {t.setup[`${step.key}Detail`]}
                </span>
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
