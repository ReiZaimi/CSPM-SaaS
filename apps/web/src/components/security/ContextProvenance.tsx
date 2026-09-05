import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/format";

/** Where a context value came from, said the way a customer would say it. */
const SOURCE_LABEL: Record<string, string> = {
  customer: "You declared this",
  inherited: "You declared this for the whole environment",
  provider_tag: "Read from a tag on the resource",
  type_floor: "True of this kind of resource",
  inferred: "Worked out from the name",
  none: "Nothing said",
};

export interface ContextFact {
  value: string | null;
  source: string;
  confidence: number;
}

/**
 * A context value, with who said so.
 *
 * These three numbers are the multiplier the risk engine turns a finding into a
 * risk with, and a bare "CRITICAL" invites the obvious question. Until the
 * backend started recording provenance there was no answer to give; now there
 * is, and withholding it would leave the reader unable to tell a value they
 * chose from one CloudGuard guessed off a resource name.
 *
 * Confidence is shown as a strength bar rather than a number. "0.4" is not
 * something anyone can act on, and the useful distinction is coarse: is this
 * something somebody decided, or something we inferred.
 */
export function ContextRow({
  label,
  fact,
  fallback,
}: {
  label: string;
  fact?: ContextFact;
  fallback?: React.ReactNode;
}) {
  if (!fact) {
    return (
      <div className="flex items-baseline justify-between gap-3">
        <dt className="text-muted-foreground">{label}</dt>
        <dd>{fallback ?? "—"}</dd>
      </div>
    );
  }

  const source = SOURCE_LABEL[fact.source] ?? fact.source;
  const declared = fact.source === "customer" || fact.source === "inherited";

  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="flex items-center gap-2">
        <Tooltip>
          <TooltipTrigger render={<span className="flex items-center gap-1.5" />}>
            {typeof fact.value === "string" && /^[A-Z_]+$/.test(fact.value) ? (
              <SeverityBadge level={fact.value} size="sm" />
            ) : (
              <span className="text-sm">{fact.value ?? "—"}</span>
            )}
            <ConfidenceBar confidence={fact.confidence} declared={declared} />
          </TooltipTrigger>
          <TooltipContent>
            {source}
            {!declared && fact.source !== "none" && (
              <span className="block opacity-80">
                Declare it on the subscription to be certain
              </span>
            )}
          </TooltipContent>
        </Tooltip>
      </dd>
    </div>
  );
}

function ConfidenceBar({
  confidence,
  declared,
}: {
  confidence: number;
  declared: boolean;
}) {
  // Four steps, because the sources are ranked rather than measured and a
  // continuous bar would imply a precision the scale does not have.
  const filled = Math.max(1, Math.round(confidence * 4));
  return (
    <span className="flex items-center gap-0.5" aria-label={`Confidence ${confidence}`}>
      {[0, 1, 2, 3].map((step) => (
        <span
          key={step}
          className={cn(
            "h-2.5 w-1 rounded-sm",
            step < filled ? (declared ? "bg-ok" : "bg-muted-foreground") : "bg-muted",
          )}
        />
      ))}
    </span>
  );
}
