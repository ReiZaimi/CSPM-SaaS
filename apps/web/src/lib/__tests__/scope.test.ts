import { describe, expect, it } from "vitest";

import { parseScope, scopeLabel } from "../scope";

/**
 * Where an asset sits, read out of the id rather than fetched.
 *
 * The backend derives containment the same way when it builds the asset graph,
 * so these cases are really about the two agreeing: a group shown in the
 * inventory and an edge drawn in the graph should never disagree about which
 * resource group something is in.
 */
describe("parseScope", () => {
  it("reads the subscription and resource group out of an ARM id", () => {
    expect(
      parseScope(
        "/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/payroll",
      ),
    ).toEqual({ subscriptionId: "sub-1", resourceGroup: "prod" });
  });

  it("matches the segment names case-insensitively", () => {
    // ARM treats `/resourcegroups/` and `/resourceGroups/` as the same path,
    // and an estate whose ids arrive in the other casing would otherwise show
    // every asset as ungrouped.
    expect(
      parseScope("/SUBSCRIPTIONS/sub-1/resourcegroups/prod/providers/x/y/z").resourceGroup,
    ).toBe("prod");
  });

  it("reports a subscription-scoped asset as having no resource group", () => {
    expect(parseScope("/subscriptions/sub-1")).toEqual({
      subscriptionId: "sub-1",
      resourceGroup: null,
    });
  });

  it("claims nothing about an id it cannot read", () => {
    expect(parseScope("/users/abc")).toEqual({
      subscriptionId: null,
      resourceGroup: null,
    });
    expect(parseScope(undefined)).toEqual({
      subscriptionId: null,
      resourceGroup: null,
    });
  });
});

describe("scopeLabel", () => {
  it("names a directory asset rather than calling it ungrouped", () => {
    // A user belongs to the tenant and sits in no resource group at all.
    // "Ungrouped" would read as a tagging oversight rather than as a fact.
    expect(scopeLabel("/users/abc")).toBe("Directory");
  });

  it("uses the resource group when there is one", () => {
    expect(scopeLabel("/subscriptions/s/resourceGroups/prod/providers/x/y/z")).toBe("prod");
  });
});
