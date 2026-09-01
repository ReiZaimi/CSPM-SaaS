/**
 * The sidebar's second width.
 *
 * Sixty pixels of label per row is a good trade on a wide monitor and a bad one
 * on a thirteen-inch laptop, so the rail exists — and because it is a choice
 * about the shape of somebody's workspace rather than a transient state, it has
 * to survive a reload.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Shell } from "@/components/Shell";

function renderShell() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/"]}>
        <Shell />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the application shell", () => {
  beforeEach(() => {
    window.localStorage.clear();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        const data = url.includes("/organizations")
          ? [{ id: "org-1", name: "Acme", slug: "acme", role: "OWNER" }]
          : [];
        return {
          ok: true,
          status: 200,
          json: async () => ({ data, error: null, meta: {} }),
        } as Response;
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    window.localStorage.clear();
  });

  it("collapses to a rail and remembers that it did", async () => {
    const { unmount } = renderShell();

    fireEvent.click(
      await screen.findByRole("button", { name: "Collapse navigation" }),
    );

    // The labels go; the destinations do not. An icon rail that stopped being
    // navigable would be a worse trade than the width it saves.
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Expand navigation" }),
      ).toBeInTheDocument(),
    );
    expect(screen.getAllByRole("link", { name: "Findings" }).length).toBeGreaterThan(0);

    unmount();
    renderShell();

    expect(
      await screen.findByRole("button", { name: "Expand navigation" }),
    ).toBeInTheDocument();
  });
});
