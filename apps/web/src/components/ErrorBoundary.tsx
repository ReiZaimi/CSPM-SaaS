import { Component, type ErrorInfo, type ReactNode } from "react";

import { isStaleChunkError } from "@/lib/staleChunk";

/**
 * The last thing between a thrown error and a blank white page.
 *
 * React unmounts the whole tree when a render throws and nothing catches it, so
 * before this existed every runtime error in any page produced an empty
 * document: no message, no way back, and nothing on screen to describe to
 * support. For a product whose users are being told whether their cloud is
 * secure, "the page went white" is the worst available answer.
 *
 * **The failure this catches most often is not a bug.** Every page is a dynamic
 * import, and a deploy replaces the hashed files a tab already open was going
 * to fetch. Somebody who leaves CloudGuard open, gets a release, and then
 * clicks Findings asks for a chunk that no longer exists -- the import rejects,
 * the Suspense boundary above has nothing to catch it, and the app disappears.
 * That is not an error to report; it is a page that needs the new build, so it
 * reloads itself once and lands where the reader was going.
 *
 * Once, and recorded in session storage, because the reload only helps if the
 * new build actually fixes it. A reload that hits the same error again -- an
 * offline browser, a genuinely broken chunk -- would otherwise loop forever,
 * which is a worse blank page than the one it replaced.
 */

const RELOAD_KEY = "cloudguard.chunk-reloaded";

type Props = {
  children: ReactNode;
  /**
   * ``page`` keeps the surrounding chrome. Used around the router's outlet, so
   * a page that throws leaves the reader with the navigation they arrived by --
   * one broken screen rather than a broken product. ``app`` takes the whole
   * viewport, because at the root there is nothing left to keep.
   */
  variant?: "app" | "page";
};
type State = { error: Error | null };

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    if (isStaleChunkError(error) && !sessionStorage.getItem(RELOAD_KEY)) {
      try {
        sessionStorage.setItem(RELOAD_KEY, "1");
      } catch {
        // Private browsing, or storage denied. The reload still happens; what
        // is lost is the guard against doing it twice, and a reader who ends up
        // in that loop can close the tab. Refusing to reload at all would leave
        // every open tab broken after every deploy.
      }
      window.location.reload();
      return;
    }

    // The console is where a browser's own error reporting looks, and it is
    // what a reader is asked for when they say the page broke. There is no
    // error-reporting service wired up, and inventing one here would send a
    // customer's screen contents somewhere nobody agreed to.
    console.error("CloudGuard failed to render", error, info.componentStack);
  }

  private reload = (): void => {
    try {
      sessionStorage.removeItem(RELOAD_KEY);
    } catch {
      /* Nothing to clear, and nothing depending on it having been cleared. */
    }
    window.location.reload();
  };

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;

    // A stale chunk that got here has already used its one reload, so it is
    // reported as what it now is: a page that could not be fetched.
    const stale = isStaleChunkError(error);

    // Deliberately plain markup. This renders because something else did not,
    // so it depends on nothing beyond the stylesheet -- no data, no icons, no
    // component that could be the thing that threw.
    const page = this.props.variant === "page";

    return (
      <div
        className={
          page
            ? "flex items-center justify-center py-12"
            : "flex min-h-screen items-center justify-center bg-muted/40 px-6 py-12"
        }
      >
        <div className="w-full max-w-lg rounded-xl border border-border bg-background p-6 shadow-sm">
          <h1 className="text-lg font-semibold text-foreground">
            {stale ? "This page could not be loaded" : "Something went wrong"}
          </h1>
          <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
            {stale
              ? "CloudGuard could not fetch part of the app. This usually means a " +
                "new version was released while this tab was open, or the " +
                "connection dropped mid-load."
              : "CloudGuard hit an error it could not recover from while drawing " +
                "this page. Nothing about your environment has changed, and no " +
                "scan or finding was affected."}
          </p>
          <div className="mt-5 flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={this.reload}
              className="rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:opacity-90"
            >
              Reload CloudGuard
            </button>
            <a
              href="/"
              className="rounded-md border border-border px-3 py-2 text-sm font-medium text-foreground hover:bg-muted"
            >
              Back to the dashboard
            </a>
          </div>
          {/* The one line worth quoting to support. Kept short and never a
              stack: a stack on screen is noise to a reader and a description of
              our own internals to everyone else. */}
          <p className="mt-5 border-t border-border pt-4 font-mono text-xs text-muted-foreground">
            {error.message.slice(0, 200)}
          </p>
        </div>
      </div>
    );
  }
}
