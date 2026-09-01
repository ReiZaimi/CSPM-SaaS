import { useSyncExternalStore } from "react";

/**
 * Which theme the user asked for -- which is not the same as which one they
 * get. "system" is a standing instruction to follow the operating system, so it
 * has to survive being stored: collapsing it to whatever the OS said at the
 * moment of choosing would freeze the answer and stop the app following a
 * machine that switches at sunset.
 */
export type ThemeChoice = "light" | "dark" | "system";

/** What is actually on screen once the choice has been resolved. */
export type ResolvedTheme = "light" | "dark";

/**
 * Also spelled out in `index.html`, and it has to stay spelled out there.
 *
 * That inline script runs before React exists, which is the only way to avoid
 * painting a white screen and then correcting it -- a flash that is worse in a
 * dark room than no dark mode at all. The duplication is deliberate and
 * `__tests__/theme.test.ts` fails if the two ever disagree.
 */
export const THEME_STORAGE_KEY = "cloudguard-theme";
export const DARK_CLASS = "dark";

const DEFAULT_CHOICE: ThemeChoice = "system";

export function isThemeChoice(value: unknown): value is ThemeChoice {
  return value === "light" || value === "dark" || value === "system";
}

/** A stored value that is missing, corrupt, or from an older scheme is not an error. */
export function parseStoredChoice(raw: string | null): ThemeChoice {
  return isThemeChoice(raw) ? raw : DEFAULT_CHOICE;
}

export function resolveTheme(choice: ThemeChoice, prefersDark: boolean): ResolvedTheme {
  if (choice === "system") return prefersDark ? "dark" : "light";
  return choice;
}

const DARK_QUERY = "(prefers-color-scheme: dark)";

function prefersDark(): boolean {
  return typeof window !== "undefined" && window.matchMedia(DARK_QUERY).matches;
}

/**
 * Puts a resolved theme on the document.
 *
 * `color-scheme` alongside the class, because the class only reaches things
 * this stylesheet paints. Scrollbars, native form controls and the canvas
 * behind an overscroll are drawn by the browser, and without this they stay
 * light while everything around them goes dark.
 */
export function applyTheme(resolved: ResolvedTheme, root: HTMLElement): void {
  root.classList.toggle(DARK_CLASS, resolved === "dark");
  root.style.colorScheme = resolved;
}

interface ThemeSnapshot {
  choice: ThemeChoice;
  resolved: ResolvedTheme;
}

const listeners = new Set<() => void>();

// Cached rather than rebuilt per read: useSyncExternalStore compares snapshots
// by identity, and a fresh object every call is an infinite render loop.
let snapshot: ThemeSnapshot = { choice: DEFAULT_CHOICE, resolved: "light" };

function publish(choice: ThemeChoice): void {
  const resolved = resolveTheme(choice, prefersDark());
  if (snapshot.choice === choice && snapshot.resolved === resolved) return;
  snapshot = { choice, resolved };
  if (typeof document !== "undefined") applyTheme(resolved, document.documentElement);
  for (const listener of listeners) listener();
}

/**
 * Reads the stored choice and starts following the OS.
 *
 * Called once from the entry point. The class is already on the document by
 * then (the inline script put it there); this re-derives the same answer so
 * React's view of it is not a guess, and subscribes so a machine that flips to
 * dark while the tab is open is followed rather than ignored until reload.
 */
export function initTheme(): void {
  if (typeof window === "undefined") return;

  let stored: string | null = null;
  try {
    stored = window.localStorage.getItem(THEME_STORAGE_KEY);
  } catch {
    // Storage can throw outright in a locked-down browser. A theme is not
    // worth failing a security product's boot over.
  }
  publish(parseStoredChoice(stored));

  window.matchMedia(DARK_QUERY).addEventListener("change", () => {
    // Only "system" is following the OS; an explicit choice is not a default
    // to be overruled by one.
    if (snapshot.choice === "system") publish("system");
  });
}

export function setThemeChoice(choice: ThemeChoice): void {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, choice);
  } catch {
    // Unstored, but still applied for this session.
  }
  publish(choice);
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useTheme(): ThemeSnapshot {
  return useSyncExternalStore(
    subscribe,
    () => snapshot,
    () => snapshot,
  );
}
