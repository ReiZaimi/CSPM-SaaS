import { cn, scoreColor } from "@/lib/format";

/**
 * A finding's risk score, sized so it can lead a row or sit inside a sentence.
 *
 * Coloured by band rather than always neutral: the number is the ranking, and a
 * list of identical grey numbers makes the reader do the comparison themselves.
 */
export function RiskScore({
  score,
  size = "default",
  className,
}: {
  score: number | null;
  size?: "default" | "lg";
  className?: string;
}) {
  if (score === null) {
    return <span className={cn("text-muted-foreground tabular-nums", className)}>—</span>;
  }
  const value = Math.round(score);
  return (
    <span
      className={cn(
        "font-semibold tabular-nums",
        size === "lg" ? "text-3xl" : "text-sm",
        scoreColor(100 - value),
        className,
      )}
    >
      {value}
    </span>
  );
}
