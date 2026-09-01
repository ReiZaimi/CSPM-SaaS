import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CommandPalette } from "@/components/layout/CommandPalette";
import { NAV_GROUPS } from "@/components/layout/nav";

const RULES = [
  {
    rule_id: "AZ-STO-001",
    name: "Storage account allows public blob access",
    description: "",
    category: "storage",
    severity: "CRITICAL",
    version: "1",
    exploitability: 5,
    scope: "resource",
    applies_to: [],
    enabled: true,
    remediation: "",
    rationale: "",
    estimated_effort_minutes: 10,
    compliance_mappings: {},
  },
];

const ASSETS = [
  {
    id: "11111111-1111-1111-1111-111111111111",
    name: "payroll",
    resource_type: "storage_account",
    region: null,
    environment: "production",
    criticality: "HIGH",
    data_sensitivity: "HIGH",
    public_exposure: "CRITICAL",
    provider_resource_id: "/subscriptions/s/resourceGroups/prod/x/payroll",
    open_findings: 3,
    first_seen_at: "2026-01-01T00:00:00Z",
    last_seen_at: "2026-01-01T00:00:00Z",
  },
];

function envelope(data: unknown) {
  return {
    ok: true,
    status: 200,
    json: async () => ({ data, error: null, meta: {} }),
  } as Response;
}

/** Reports where the router ended up, so a jump can be asserted on. */
function Location() {
  const location = useLocation();
  return <span data-testid="location">{location.pathname + location.search}</span>;
}

function renderPalette() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/"]}>
        <CommandPalette />
        <Routes>
          <Route path="*" element={<Location />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function open() {
  fireEvent.click(screen.getByRole("button", { name: "Search CloudGuard" }));
}

async function type(value: string) {
  fireEvent.change(screen.getByPlaceholderText(/Search assets/), { target: { value } });
  // The asset search is debounced, so nothing is asked of the API until the
  // typing stops.
  await vi.advanceTimersByTimeAsync(250);
}

describe("the command palette", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/rules")) return envelope(RULES);
        if (url.includes("/assets")) {
          // Filters the way the endpoint does (`name ILIKE %search%`), so a
          // search for something absent comes back empty here too.
          const search = new URL(url, "https://example.test").searchParams.get("search") ?? "";
          return envelope(
            ASSETS.filter((a) => a.name.toLowerCase().includes(search.toLowerCase())),
          );
        }
        return envelope([]);
      }),
    );
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("opens on the keyboard shortcut, on either platform's modifier", () => {
    renderPalette();

    fireEvent.keyDown(document, { key: "k", metaKey: true });
    expect(screen.getByPlaceholderText(/Search assets/)).toBeInTheDocument();

    fireEvent.keyDown(document, { key: "k", metaKey: true });
    expect(screen.queryByPlaceholderText(/Search assets/)).not.toBeInTheDocument();

    fireEvent.keyDown(document, { key: "k", ctrlKey: true });
    expect(screen.getByPlaceholderText(/Search assets/)).toBeInTheDocument();
  });

  it("ignores a bare k, which is a character somebody is typing", () => {
    renderPalette();

    fireEvent.keyDown(document, { key: "k" });

    expect(screen.queryByPlaceholderText(/Search assets/)).not.toBeInTheDocument();
  });

  it("offers every navigable page, so it cannot drift from the sidebar", () => {
    renderPalette();
    open();

    for (const group of NAV_GROUPS) {
      for (const item of group.items) {
        expect(screen.getByText(item.label)).toBeInTheDocument();
      }
    }
  });

  it("jumps to an asset by name", async () => {
    renderPalette();
    open();
    await type("payroll");

    fireEvent.click(await screen.findByText("payroll"));

    await waitFor(() =>
      expect(screen.getByTestId("location")).toHaveTextContent(
        "/assets/11111111-1111-1111-1111-111111111111",
      ),
    );
  });

  it("opens a rule's findings rather than the rule catalogue", async () => {
    renderPalette();
    open();
    await type("public blob");

    fireEvent.click(await screen.findByText(RULES[0].name));

    // A rule on its own is a definition; what the reader wants is what it
    // found in their environment.
    await waitFor(() =>
      expect(screen.getByTestId("location")).toHaveTextContent(
        "/findings?rule_id=AZ-STO-001",
      ),
    );
  });

  it("does not ask the API about a one-letter search", async () => {
    renderPalette();
    open();
    await type("p");

    const calls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.map(String);
    expect(calls.some((url) => url.includes("search="))).toBe(false);
  });

  it("says what it searched when nothing matches", async () => {
    renderPalette();
    open();
    await type("zzzzz nothing");

    // A bare "no results" would read as a claim about the whole product, and
    // findings are not searched here at all.
    expect(await screen.findByText(/Findings are reached/)).toBeInTheDocument();
  });
});
