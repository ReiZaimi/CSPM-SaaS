import type { Provider } from "@/lib/types";

/**
 * What each cloud calls the things a customer reads about.
 *
 * The API's field names keep Azure's vocabulary — `subscriptions`,
 * `subscription_id` — because the columns behind them do, and renaming those
 * would make every stored capture unreplayable (`DECISIONS.md` §70). What a
 * customer *reads* is a different question, and telling somebody with an AWS
 * connection that CloudGuard found "3 subscriptions" is a product that has not
 * noticed which cloud it is looking at.
 *
 * So identifiers stay Azure-flavoured and sentences do not. Nouns rather than
 * sentences, for the reason `setupCopy` holds overrides rather than a second
 * copy of the whole block: two sets of sentences drift, and the half that
 * drifts is the half nobody is looking at.
 */
export interface Words {
  /** The unit a scan reads. */
  account: string;
  accounts: string;
  /** Capitalised, for a column heading or the start of a sentence. */
  Account: string;
  Accounts: string;
  /** The trust boundary above it. */
  boundary: string;
  /** What the boundary's own reading is *of*. */
  directory: string;
  /** What the customer deploys, and where. */
  artifact: string;
  console: string;
}

const AZURE: Words = {
  account: "subscription",
  accounts: "subscriptions",
  Account: "Subscription",
  Accounts: "Subscriptions",
  boundary: "tenant",
  directory: "tenant directory",
  artifact: "scanner role",
  console: "Azure Portal",
};

const AWS: Words = {
  account: "account",
  accounts: "accounts",
  Account: "Account",
  Accounts: "Accounts",
  boundary: "organization",
  directory: "organization",
  artifact: "scanner stack",
  console: "the AWS console",
};

/**
 * The nouns for one cloud.
 *
 * An unknown provider gets Azure's words rather than throwing. This is a
 * sentence, not a security decision: a missing noun should read slightly wrong
 * rather than break the page somebody is trying to read.
 */
export function words(provider: Provider | string | undefined | null): Words {
  return provider === "aws" ? AWS : AZURE;
}
