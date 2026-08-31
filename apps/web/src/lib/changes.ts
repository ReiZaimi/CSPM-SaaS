/**
 * Whether a change made the environment worse, better, or neither.
 *
 * UNKNOWN is deliberately outside the ordering rather than at the bottom of it.
 * A level that became UNKNOWN is a loss of knowledge, not an improvement, and
 * ranking it below LOW would render exactly that as a green arrow — the one
 * thing this product must never do.
 *
 * Its own module because two screens read it now: the changes feed, and the
 * dashboard's summary of it. A second copy is how the same movement ends up
 * green on one page and red on another.
 */
const RANK: Record<string, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

export type Direction = "worse" | "better" | "neutral";

export function changeDirection(
  previous: string | null,
  current: string | null,
): Direction {
  const from = RANK[previous ?? ""];
  const to = RANK[current ?? ""];
  if (from === undefined || to === undefined) return "neutral";
  if (to > from) return "worse";
  if (to < from) return "better";
  return "neutral";
}
