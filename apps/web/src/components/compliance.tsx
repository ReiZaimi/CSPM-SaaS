import { useT } from "@/i18n";
import type { ControlStatus } from "@/lib/types";
import { cn, controlStatusStyle, label } from "@/lib/format";

/**
 * Shared compliance chrome.
 *
 * The bar and the pill live together because they encode the same judgement:
 * which statuses count as *knowing something*. Splitting them across two files
 * is how a green segment and a green pill eventually come to disagree.
 */

/** Segment order, worst first — the same reading order as the findings list. */
const SEGMENTS: { status: ControlStatus; className: string }[] = [
  { status: "FAILING", className: "bg-critical" },
  { status: "INCONCLUSIVE", className: "bg-unknown" },
  { status: "PASSING", className: "bg-ok" },
  { status: "NOT_ASSESSED", className: "bg-stone-300" },
  { status: "NOT_COVERED", className: "bg-stone-200" },
];

export function CoverageBar({
  counts,
  total,
}: {
  counts: Record<ControlStatus, number>;
  total: number;
}) {
  const t = useT();
  if (total === 0) return null;

  return (
    <div>
      <div className="flex h-2 w-full overflow-hidden rounded-full bg-stone-100">
        {SEGMENTS.map(({ status, className }) => {
          const count = counts[status] ?? 0;
          if (count === 0) return null;
          return (
            <div
              key={status}
              className={className}
              style={{ width: `${(count / total) * 100}%` }}
              title={`${label(status)}: ${count}`}
            />
          );
        })}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
        {SEGMENTS.map(({ status, className }) => {
          const count = counts[status] ?? 0;
          if (count === 0) return null;
          return (
            <span
              key={status}
              className="flex items-center gap-1.5 text-[11px] text-stone-500"
              title={t.compliance.statusHelp[status]}
            >
              <span className={cn("h-2 w-2 rounded-full", className)} aria-hidden="true" />
              {count} {label(status).toLowerCase()}
            </span>
          );
        })}
      </div>
    </div>
  );
}

export function ControlStatusPill({ status }: { status: ControlStatus }) {
  const t = useT();
  return (
    <span
      title={t.compliance.statusHelp[status]}
      className={cn(
        "inline-flex shrink-0 items-center rounded-full border px-2 py-0.5 text-xs font-medium",
        controlStatusStyle(status),
      )}
    >
      {label(status)}
    </span>
  );
}

/**
 * The disclaimer. Shown on every compliance screen, never collapsed behind a
 * "learn more" — the whole page invites a reading this product cannot support,
 * and the correction has to travel with it.
 */
export function EvidenceNotice() {
  const t = useT();
  return (
    <p className="rounded-lg border border-stone-200 bg-stone-50 px-4 py-3 text-xs leading-relaxed text-stone-600">
      {t.compliance.notALegalClaim}
    </p>
  );
}
