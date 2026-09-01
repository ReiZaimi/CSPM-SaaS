/**
 * The queue has to be reachable from the work.
 *
 * `POST /remediation` existed from the start and nothing called it: the queue's
 * empty state sent the reader to the finding's detail page, and that page had
 * no way to assign anything. The queue could therefore only ever be empty.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { TrackFix } from "@/components/security/TrackFix";

const TASK = {
  id: "task-1",
  finding_id: "finding-1",
  risk_id: null,
  status: "TODO",
  priority: "HIGH",
  due_date: null,
  estimated_effort_minutes: 15,
  notes: null,
  completed_at: null,
  created_at: "2026-08-20T00:00:00Z",
};

function mount(tasks: unknown[], status = "OPEN") {
  const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => ({
    ok: true,
    status: init?.method === "POST" ? 201 : 200,
    json: async () => ({
      data: init?.method === "POST" ? TASK : tasks,
      error: null,
      meta: {},
    }),
  })) as unknown as typeof fetch;
  vi.stubGlobal("fetch", fetchMock);

  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <TrackFix
          findingId="finding-1"
          status={status as "OPEN"}
          effortMinutes={15}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return fetchMock as unknown as ReturnType<typeof vi.fn>;
}

afterEach(() => vi.unstubAllGlobals());

describe("tracking a fix", () => {
  it("assigns the work through the API the queue reads", async () => {
    const fetchMock = mount([]);
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: /Track this fix/ }));

    await waitFor(() => {
      const post = fetchMock.mock.calls.find(
        ([, init]) => (init as RequestInit | undefined)?.method === "POST",
      );
      expect(post?.[0]).toContain("/api/v1/remediation");
      expect((post?.[1] as RequestInit).body).toBe(
        JSON.stringify({ finding_id: "finding-1" }),
      );
    });
  });

  it("does not promise the finding closes", async () => {
    mount([]);

    expect(
      await screen.findByText(/does not close the finding — a scan does/),
    ).toBeInTheDocument();
  });

  it("says the work is already tracked rather than offering it twice", async () => {
    // The API refuses a second open task for one finding, so a button that was
    // always offered would be a button that sometimes only produced an error.
    mount([TASK]);

    expect(
      await screen.findByText(/In the remediation queue since/),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Track this fix/ }),
    ).not.toBeInTheDocument();
  });

  it("offers nothing on a finding a scan has already closed", async () => {
    mount([], "RESOLVED");

    await waitFor(() =>
      expect(
        screen.queryByRole("button", { name: /Track this fix/ }),
      ).not.toBeInTheDocument(),
    );
  });
});
