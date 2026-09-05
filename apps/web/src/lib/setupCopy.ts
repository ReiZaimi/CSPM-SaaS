import type { Strings } from "@/i18n/en";
import type { Provider } from "@/lib/types";

/**
 * Widened to `string`, because the two clouds say different things.
 *
 * `en.ts` is a const object, so every value has a literal type — and an
 * intersection of `"Connect Azure"` and `"Connect AWS"` is `never`. Widening is
 * what lets one component read a sentence whose wording depends on which cloud
 * it is looking at.
 */
type AsStrings<T> = { [K in keyof T]: T[K] extends string ? string : T[K] };

type Shared = AsStrings<Omit<Strings["setup"], "aws">>;
type AwsOnly = AsStrings<Strings["setup"]["aws"]>;

export type SetupCopy = Shared & Partial<AwsOnly>;

/**
 * The setup wizard's words, for one cloud.
 *
 * Most of setup reads identically in both: the rail, the waiting notes, the
 * discard confirmation. What differs is the handful of sentences that name a
 * consent screen, a template or a subscription — so AWS is held as an override
 * over the shared block rather than as a second copy of it. Two full sets would
 * drift, and the half that drifted would be the half nobody was looking at.
 */
export function setupCopy(t: Strings, provider: Provider): SetupCopy {
  const shared = t.setup as Shared;
  return provider === "aws" ? { ...shared, ...(t.setup.aws as AwsOnly) } : shared;
}
