/**
 * What each cloud calls the things a customer reads about.
 *
 * The API's field names keep Azure's vocabulary because the columns behind them
 * do, and renaming those would make every stored capture unreplayable
 * (`DECISIONS.md` §70). What a customer *reads* is a different question:
 * telling somebody with an AWS connection that CloudGuard found "3
 * subscriptions" is a product that has not noticed which cloud it is looking
 * at.
 */
import { describe, expect, it } from "vitest";

import { words } from "@/lib/vocabulary";

describe("cloud vocabulary", () => {
  it("gives each cloud its own nouns", () => {
    expect(words("aws").accounts).toBe("accounts");
    expect(words("azure").accounts).toBe("subscriptions");
    expect(words("aws").boundary).toBe("organization");
    expect(words("azure").boundary).toBe("tenant");
  });

  it("carries a capitalised form, because headings exist", () => {
    // Otherwise every caller writes its own capitalisation and two of them
    // disagree.
    expect(words("aws").Accounts).toBe("Accounts");
    expect(words("azure").Account).toBe("Subscription");
  });

  it("names the artefact and the console too", () => {
    // "Check that the deployment succeeded in Azure Portal" is the wrong pair
    // of nouns for somebody who ran a CloudFormation stack.
    expect(words("aws").artifact).toBe("scanner stack");
    expect(words("aws").console).toBe("the AWS console");
  });

  it("reads slightly wrong rather than breaking on an unknown cloud", () => {
    // A missing noun is a sentence problem, not a security decision. Throwing
    // would take down the page somebody is trying to read in order to avoid
    // saying "subscription" once.
    expect(words(undefined).account).toBe("subscription");
    expect(words(null).account).toBe("subscription");
    expect(words("gcp").account).toBe("subscription");
  });
});
