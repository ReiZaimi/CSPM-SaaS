import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ErrorBoundary } from "@/components/ErrorBoundary";
import { isStaleChunkError } from "@/lib/staleChunk";

function Boom({ error }: { error: Error }): never {
  throw error;
}

describe("the last thing between an error and a blank page", () => {
  beforeEach(() => {
    sessionStorage.clear();
    // React logs the caught error itself, and the boundary logs it again. Both
    // are wanted in production and neither is wanted in the test output.
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    sessionStorage.clear();
  });

  it("renders something a reader can act on instead of nothing at all", () => {
    render(
      <ErrorBoundary>
        <Boom error={new Error("cannot read properties of undefined")} />
      </ErrorBoundary>,
    );

    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /reload cloudguard/i }),
    ).toBeInTheDocument();
    // The one line worth quoting to support, and never a stack.
    expect(
      screen.getByText(/cannot read properties of undefined/i),
    ).toBeInTheDocument();
  });

  it("says nothing about the environment having changed", () => {
    // A security product's error screen is read as a security statement. The
    // reader has to be told that a broken page is not a changed posture.
    render(
      <ErrorBoundary>
        <Boom error={new Error("boom")} />
      </ErrorBoundary>,
    );

    expect(screen.getByText(/nothing about your environment has changed/i)).toBeInTheDocument();
  });

  it("reloads once when a deploy took the page's code away", () => {
    // The common case, and not a bug: every page is a dynamic import, and a
    // release replaces the hashed files an open tab was going to fetch.
    const reload = vi.fn();
    const original = window.location;
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...original, reload },
    });

    try {
      render(
        <ErrorBoundary>
          <Boom
            error={new Error("Failed to fetch dynamically imported module: /assets/Findings-abc.js")}
          />
        </ErrorBoundary>,
      );

      expect(reload).toHaveBeenCalledTimes(1);
    } finally {
      Object.defineProperty(window, "location", {
        configurable: true,
        value: original,
      });
    }
  });

  it("stops reloading if the new build fails the same way", () => {
    // A reload that hits the same error again -- offline, or a genuinely broken
    // chunk -- would loop for ever, which is a worse blank page than the one it
    // replaced. So the second time it is reported rather than retried.
    sessionStorage.setItem("cloudguard.chunk-reloaded", "1");
    const reload = vi.fn();
    const original = window.location;
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...original, reload },
    });

    try {
      render(
        <ErrorBoundary>
          <Boom error={new Error("Failed to fetch dynamically imported module")} />
        </ErrorBoundary>,
      );

      expect(reload).not.toHaveBeenCalled();
      expect(screen.getByText(/this page could not be loaded/i)).toBeInTheDocument();
    } finally {
      Object.defineProperty(window, "location", {
        configurable: true,
        value: original,
      });
    }
  });

  it("passes a working page straight through", () => {
    render(
      <ErrorBoundary>
        <p>the dashboard</p>
      </ErrorBoundary>,
    );

    expect(screen.getByText("the dashboard")).toBeInTheDocument();
  });

  it("offers a reload that clears the guard it set", async () => {
    sessionStorage.setItem("cloudguard.chunk-reloaded", "1");
    const reload = vi.fn();
    const original = window.location;
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...original, reload },
    });

    try {
      render(
        <ErrorBoundary>
          <Boom error={new Error("boom")} />
        </ErrorBoundary>,
      );
      await userEvent.click(screen.getByRole("button", { name: /reload cloudguard/i }));

      expect(reload).toHaveBeenCalled();
      expect(sessionStorage.getItem("cloudguard.chunk-reloaded")).toBeNull();
    } finally {
      Object.defineProperty(window, "location", {
        configurable: true,
        value: original,
      });
    }
  });
});

describe("telling a new release apart from a broken app", () => {
  it("recognises how each engine words a missing chunk", () => {
    for (const message of [
      "Failed to fetch dynamically imported module: /assets/Findings-abc.js",
      "error loading dynamically imported module",
      "Importing a module script failed.",
    ]) {
      expect(isStaleChunkError(new Error(message))).toBe(true);
    }
    expect(isStaleChunkError(Object.assign(new Error("x"), { name: "ChunkLoadError" }))).toBe(
      true,
    );
  });

  it("does not mistake an ordinary bug for one", () => {
    // A false positive costs one reload; treating every error as a stale build
    // would reload the tab on a genuine crash and hide it.
    expect(isStaleChunkError(new Error("Cannot read properties of undefined"))).toBe(false);
    expect(isStaleChunkError("not even an error")).toBe(false);
  });
});
