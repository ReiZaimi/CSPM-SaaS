import {
  CheckCircle2Icon,
  CircleDashedIcon,
  HelpCircleIcon,
  XCircleIcon,
} from "lucide-react";

import type { Verification } from "@/lib/types";
import { cn, formatDateTime } from "@/lib/format";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

/**
 * Whether the fix worked.
 *
 * The product's strongest claim is "verified fixed", and the interface has to
 * be as careful with it as the engine is. Four presentations, because there are
 * four genuinely different things to say:
 *
 * - VERIFIED — a scan observed the check passing. Green, and the only green.
 * - PENDING — CloudGuard is still looking. Neutral, with the next attempt named
 *   so waiting feels like progress rather than silence.
 * - STILL_FAILING — CloudGuard looked, repeatedly, and disagrees. Red.
 * - INSUFFICIENT_EVIDENCE — CloudGuard could not look. **Not red.** Telling
 *   somebody their fix failed when the truth is that the evidence never arrived
 *   is the same overclaim as a PASS nobody earned, pointed at the person
 *   instead of the environment.
 */
const PRESENTATION = {
  VERIFIED: {
    icon: CheckCircle2Icon,
    tone: "border-ok-border bg-ok-bg text-ok",
    heading: "Fix verified",
  },
  PENDING: {
    icon: CircleDashedIcon,
    tone: "border-border bg-muted text-muted-foreground",
    heading: "Checking",
  },
  STILL_FAILING: {
    icon: XCircleIcon,
    tone: "border-critical-border bg-critical-bg text-critical",
    heading: "Still failing",
  },
  INSUFFICIENT_EVIDENCE: {
    icon: HelpCircleIcon,
    tone: "border-unknown-border bg-unknown-bg text-unknown border-dashed",
    heading: "Could not verify",
  },
  ABANDONED: {
    icon: CircleDashedIcon,
    tone: "border-border bg-muted text-muted-foreground",
    heading: "No longer checking",
  },
} as const;

export function VerificationPanel({ verification }: { verification: Verification }) {
  const view = PRESENTATION[verification.status] ?? PRESENTATION.PENDING;
  const Icon = view.icon;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Verification</CardTitle>
        <CardDescription>
          Claimed fixed {formatDateTime(verification.claimed_at)}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className={cn("flex items-start gap-2.5 rounded-lg border px-3 py-2.5", view.tone)}>
          <Icon
            className={cn(
              "mt-0.5 size-4 shrink-0",
              verification.status === "PENDING" && "animate-pulse",
            )}
            aria-hidden
          />
          <div className="min-w-0 text-sm">
            <p className="font-medium">{view.heading}</p>
            {verification.detail && (
              <p className="mt-0.5 opacity-90">{verification.detail}</p>
            )}
          </div>
        </div>

        {verification.expected_state.length > 0 && (
          <div>
            <p className="text-xs font-medium text-muted-foreground">
              What CloudGuard is looking for
            </p>
            <ul className="mt-1.5 flex flex-col gap-1">
              {verification.expected_state.map((state) => (
                <li key={state.field} className="flex items-start gap-2 text-sm">
                  <span className="mt-1.5 size-1 shrink-0 rounded-full bg-muted-foreground" />
                  <span>{state.describes}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        <dl className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-muted-foreground">
          <div>
            <dt className="inline">Attempts: </dt>
            <dd className="inline font-medium text-foreground">{verification.attempts}</dd>
          </div>
          {verification.next_attempt_at && (
            <div>
              <dt className="inline">Next check: </dt>
              <dd className="inline font-medium text-foreground">
                {formatDateTime(verification.next_attempt_at)}
              </dd>
            </div>
          )}
          {verification.settled_at && (
            <div>
              <dt className="inline">Settled: </dt>
              <dd className="inline font-medium text-foreground">
                {formatDateTime(verification.settled_at)}
              </dd>
            </div>
          )}
        </dl>
      </CardContent>
    </Card>
  );
}
