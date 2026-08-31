/**
 * The reports page.
 *
 * Two things it must get right. A report is a document, so it cannot be
 * fetched as an envelope or linked to with a plain anchor — the bearer token
 * lives in memory, and a browser-initiated navigation would arrive
 * unauthenticated. And a server that simply cannot render PDFs is an operator
 * problem, not something a reader retries their way out of, so it is named.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ReportsPage } from "../Reports";
import { api, ApiError } from "@/lib/api";

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ReportsPage />
    </QueryClientProvider>,
  );
}

describe("ReportsPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    // jsdom implements none of these, and all three are incidental to what is
    // asserted. Without the anchor stub, the download's own click() makes
    // jsdom log a navigation error on every passing test — noise that would
    // hide a real one later.
    URL.createObjectURL = vi.fn(() => "blob:report");
    URL.revokeObjectURL = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  });

  it("offers both reports, and says what each is for", () => {
    mount();

    expect(screen.getByText("Executive report")).toBeInTheDocument();
    expect(screen.getByText("Technical report")).toBeInTheDocument();
    expect(screen.getByText(/does not touch Azure/)).toBeInTheDocument();
  });

  it("fetches the PDF through the authenticated path, not a bare link", async () => {
    const doc = vi.spyOn(api, "document").mockResolvedValue(new Blob(["%PDF-"]));
    mount();

    fireEvent.click(screen.getAllByRole("button", { name: /Download PDF/ })[0]);

    await waitFor(() =>
      expect(doc).toHaveBeenCalledWith("/api/v1/reports/executive?format=pdf"),
    );
    // No anchor a browser could follow without the token.
    expect(screen.queryByRole("link", { name: /Download/ })).not.toBeInTheDocument();
  });

  it("asks for the technical report when that is the one clicked", async () => {
    const doc = vi.spyOn(api, "document").mockResolvedValue(new Blob(["%PDF-"]));
    mount();

    fireEvent.click(screen.getAllByRole("button", { name: /Download PDF/ })[1]);

    await waitFor(() =>
      expect(doc).toHaveBeenCalledWith("/api/v1/reports/technical?format=pdf"),
    );
  });

  it("previews the same document as HTML rather than downloading it", async () => {
    const doc = vi.spyOn(api, "document").mockResolvedValue(new Blob(["<html>"]));
    const open = vi.spyOn(window, "open").mockReturnValue(null);
    mount();

    fireEvent.click(screen.getByRole("button", { name: "Preview: Executive report" }));

    await waitFor(() =>
      expect(doc).toHaveBeenCalledWith("/api/v1/reports/executive?format=html"),
    );
    expect(open).toHaveBeenCalled();
  });

  it("names a server that cannot render PDFs, rather than blaming the request", async () => {
    vi.spyOn(api, "document").mockRejectedValue(
      new ApiError("NOT_CONFIGURED", "WeasyPrint's native libraries are not installed.", 503),
    );
    mount();

    fireEvent.click(screen.getAllByRole("button", { name: /Download PDF/ })[0]);

    await waitFor(() =>
      expect(screen.getByText("This server cannot produce PDFs")).toBeInTheDocument(),
    );
    expect(
      screen.getByText("WeasyPrint's native libraries are not installed."),
    ).toBeInTheDocument();
  });

  it("reports an ordinary failure as an ordinary failure", async () => {
    vi.spyOn(api, "document").mockRejectedValue(
      new ApiError("NETWORK_ERROR", "Server returned 500", 500),
    );
    mount();

    fireEvent.click(screen.getAllByRole("button", { name: /Download PDF/ })[0]);

    await waitFor(() =>
      expect(screen.getByText("Could not generate the report")).toBeInTheDocument(),
    );
    expect(screen.queryByText("This server cannot produce PDFs")).not.toBeInTheDocument();
  });

  it("says reports are generated rather than kept", async () => {
    // A customer expecting a library of past reports should not have to
    // discover its absence.
    mount();

    expect(screen.getByText(/CloudGuard keeps no copies/)).toBeInTheDocument();
  });
});
