/**
 * The bell, and the three answers it must keep apart.
 *
 * "Nothing new", "we could not ask", and "here is what happened" all render as
 * a quiet bell if the component is careless, and only the first is a statement
 * about the customer's estate.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { NotificationBell } from "@/components/layout/NotificationBell";

const ROWS = [
  {
    id: "n-1",
    kind: "REACHABLE_FINDING",
    title: "Storage account allows public blob access on prodstore",
    detail:
      "This asset stands on a route from somewhere an attacker could start to something worth taking.",
    link: "/findings/f-1",
    event_at: new Date(Date.now() - 3600 * 1000).toISOString(),
  },
  {
    id: "n-2",
    kind: "VERIFIED_FIX",
    title: "Fixed: Public RDP",
    detail: "A scan checked and the finding no longer holds.",
    link: "/findings/f-2",
    event_at: new Date(Date.now() - 7200 * 1000).toISOString(),
  },
];

let posted: string[] = [];

function mount(rows: object[], unread: number, ok = true) {
  posted = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (init?.method === "POST") {
        posted.push(url);
        return {
          ok: true,
          status: 200,
          json: async () => ({ data: {}, error: null, meta: {} }),
        } as Response;
      }
      if (!ok) return { ok: false, status: 500, json: async () => ({}) } as Response;
      return {
        ok: true,
        status: 200,
        json: async () => ({ data: rows, error: null, meta: { unread } }),
      } as Response;
    }),
  );

  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <NotificationBell />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the notification bell", () => {
  beforeEach(() => vi.restoreAllMocks());
  afterEach(() => vi.unstubAllGlobals());

  it("counts what has not been seen, and says so to a screen reader", async () => {
    mount(ROWS, 2);

    expect(
      await screen.findByRole("button", { name: "Notifications, 2 unread" }),
    ).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
  });

  it("shows no count when everything has been seen", async () => {
    mount(ROWS, 0);

    expect(
      await screen.findByRole("button", { name: "Notifications" }),
    ).toBeInTheDocument();
  });

  it("opens to what happened, newest first, each linking to its subject", async () => {
    mount(ROWS, 2);

    fireEvent.click(await screen.findByRole("button", { name: /Notifications/ }));

    expect(
      await screen.findByText(/Storage account allows public blob access/),
    ).toBeInTheDocument();
    const link = screen.getByRole("link", { name: /public blob access/ });
    expect(link).toHaveAttribute("href", "/findings/f-1");
  });

  it("marks read when the panel opens, not when it closes", async () => {
    // On close would leave the badge lit behind somebody who read everything
    // and navigated away from the page instead of dismissing the popover.
    //
    // Clicked on the bare label rather than after waiting for the count, which
    // is the race the effect exists for: opening the instant the page loads
    // used to mark read against an unread of zero and leave the badge lit
    // behind a panel somebody was looking at.
    mount(ROWS, 2);

    fireEvent.click(await screen.findByRole("button", { name: /Notifications/ }));

    await waitFor(() =>
      expect(posted.some((url) => url.includes("/notifications/read"))).toBe(true),
    );
  });

  it("does not mark read when there was nothing unread", async () => {
    mount(ROWS, 0);

    fireEvent.click(await screen.findByRole("button", { name: /Notifications/ }));

    await waitFor(() => expect(screen.getByText(/Fixed: Public RDP/)).toBeVisible());
    expect(posted).toEqual([]);
  });

  it("says what it would have told you about when there is nothing", async () => {
    // Not "no notifications" alone, which is ambiguous between all quiet and
    // CloudGuard having stopped checking.
    mount([], 0);

    fireEvent.click(await screen.findByRole("button", { name: /Notifications/ }));

    expect(await screen.findByText(/Nothing new/)).toBeInTheDocument();
    expect(screen.getByText(/verified fixes/)).toBeInTheDocument();
  });

  it("renders nothing at all when the request fails", async () => {
    // A network error is not an absence of news. A quiet bell here would say
    // "all clear" on the strength of a failed fetch.
    const { container } = mount([], 0, false);

    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });
});
