import { cn } from "@/lib/format";

export type Slice = {
  key: string;
  label: string;
  value: number;
  /** A CSS colour, always from the status scale — never a generated hue. */
  tone: string;
};

/**
 * A ring's key, as words.
 *
 * Its own module, away from the ring itself, for a reason that is about weight
 * rather than tidiness: the ring pulls in the charting runtime, and a panel
 * that imported the legend from beside it would drag 200kB of Recharts into
 * the page's own chunk and undo the lazy loading entirely.
 *
 * Always rendered beside a ring rather than optionally: it is what keeps the
 * chart readable to somebody who cannot separate the hues, and it is where the
 * counts live so the ring never needs a number printed on every wedge.
 */
export function DonutLegend({
  slices,
  className,
}: {
  slices: Slice[];
  className?: string;
}) {
  return (
    <ul className={cn("flex flex-col gap-1.5", className)}>
      {slices.map((slice) => (
        <li key={slice.key} className="flex items-center gap-2 text-xs">
          <span
            className="size-2 shrink-0 rounded-[2px]"
            style={{ background: slice.tone }}
            aria-hidden
          />
          <span className="flex-1 text-muted-foreground">{slice.label}</span>
          <span className="font-medium tabular-nums">{slice.value}</span>
        </li>
      ))}
    </ul>
  );
}
