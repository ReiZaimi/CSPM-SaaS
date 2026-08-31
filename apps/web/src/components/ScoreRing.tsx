import { scoreColor } from "@/lib/format";

/**
 * The security score as an arc.
 *
 * A number alone makes 100 and 40 look equally like "a number". The arc gives
 * the reader the proportion before they've finished reading the digits, which
 * is the whole job of this element.
 */
export function ScoreRing({ score }: { score: number }) {
  const radius = 58;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, score));
  // 270° sweep, leaving a gap at the bottom so the ends read as a gauge.
  const sweep = 0.75;
  const filled = circumference * sweep * (clamped / 100);

  return (
    <div className="relative h-[150px] w-[150px]">
      <svg viewBox="0 0 140 140" className="h-full w-full -rotate-[135deg]">
        <circle
          cx="70"
          cy="70"
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="10"
          strokeLinecap="round"
          className="text-stone-100"
          strokeDasharray={`${circumference * sweep} ${circumference}`}
        />
        <circle
          cx="70"
          cy="70"
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="10"
          strokeLinecap="round"
          className={`${scoreColor(clamped)} transition-[stroke-dasharray] duration-700 ease-out`}
          strokeDasharray={`${filled} ${circumference}`}
        />
      </svg>

      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span
          className={`text-4xl font-semibold tabular-nums leading-none ${scoreColor(clamped)}`}
        >
          {Math.round(clamped)}
        </span>
        <span className="mt-1 text-[11px] uppercase tracking-wide text-muted-foreground">
          out of 100
        </span>
      </div>
    </div>
  );
}
