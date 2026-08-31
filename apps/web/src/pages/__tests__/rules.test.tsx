import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { RulesPage } from "@/pages/Rules";
import { api } from "@/lib/api";
import type { Rule } from "@/lib/types";

function rule(overrides: Partial<Rule> = {}): Rule {
  return {
    rule_id: "AZ-STO-001",
    name: "Storage account allows public blob access",
    description: "Anonymous readers can list and download blobs.",
    category: "storage",
    severity: "CRITICAL",
    version: "1.0",
    exploitability: 4,
    scope: "resource",
    applies_to: ["storage_account"],
    enabled: true,
    remediation: "",
    rationale: "",
    estimated_effort_minutes: 10,
    compliance_mappings: { ISO_27001: ["A.8.3"] },
    ...overrides,
  } as Rule;
}

function mount(rules: Rule[]) {
  vi.spyOn(api, "get").mockResolvedValue({ data: rules, meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <RulesPage />
    </QueryClientProvider>,
  );
}

describe("the rule catalogue", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("searches the whole catalogue, which arrives in one request", async () => {
    // Filtering in the browser is honest here and nowhere else in the product:
    // this list is the rulebook, not an estate, and it is all present.
    mount([
      rule(),
      rule({ rule_id: "AZ-NET-002", name: "Network security group permits inbound SSH" }),
    ]);

    fireEvent.change(await screen.findByLabelText("Search rules"), {
      target: { value: "ssh" },
    });

    expect(screen.getByText("Network security group permits inbound SSH")).toBeInTheDocument();
    expect(
      screen.queryByText("Storage account allows public blob access"),
    ).not.toBeInTheDocument();
  });

  it("matches on the rule id, which is how a finding names its rule", async () => {
    mount([rule(), rule({ rule_id: "AZ-NET-002", name: "Inbound SSH" })]);

    fireEvent.change(await screen.findByLabelText("Search rules"), {
      target: { value: "AZ-NET" },
    });

    expect(screen.getByText("Inbound SSH")).toBeInTheDocument();
  });

  it("says how much of the catalogue is showing", async () => {
    mount([rule(), rule({ rule_id: "AZ-NET-002", name: "Inbound SSH" })]);

    expect(await screen.findByText("2 of 2 rules")).toBeInTheDocument();
  });

  it("marks a tenant-wide rule, which belongs to no asset", async () => {
    mount([rule({ scope: "aggregate" })]);

    expect(await screen.findByText("Tenant-wide")).toBeInTheDocument();
  });

  it("offers a way back when a filter matches nothing", async () => {
    mount([rule()]);

    fireEvent.change(await screen.findByLabelText("Search rules"), {
      target: { value: "nothing at all" },
    });

    expect(screen.getByText("No rules match")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Clear filters" })).toBeInTheDocument();
  });
});
