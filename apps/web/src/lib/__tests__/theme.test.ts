import { beforeEach, describe, expect, it } from "vitest";

// The real file, imported as text: reading it through the bundler rather than
// through node:fs keeps the test working wherever it is run from.
import html from "../../../index.html?raw";

import {
  DARK_CLASS,
  THEME_STORAGE_KEY,
  applyTheme,
  parseStoredChoice,
  resolveTheme,
  setThemeChoice,
  useTheme,
} from "@/lib/theme";

describe("the stored choice", () => {
  it("is taken at face value when it names a theme", () => {
    expect(parseStoredChoice("dark")).toBe("dark");
    expect(parseStoredChoice("light")).toBe("light");
    expect(parseStoredChoice("system")).toBe("system");
  });

  it("falls back to system when there is nothing stored", () => {
    expect(parseStoredChoice(null)).toBe("system");
  });

  it("falls back rather than throwing on a value from some older scheme", () => {
    // Somebody else's key, a half-written value, a hand-edited localStorage.
    // None of those are worth a blank screen.
    expect(parseStoredChoice("midnight")).toBe("system");
    expect(parseStoredChoice("")).toBe("system");
  });
});

describe("resolving a choice", () => {
  it("follows the machine only when asked to", () => {
    expect(resolveTheme("system", true)).toBe("dark");
    expect(resolveTheme("system", false)).toBe("light");
  });

  it("does not let the machine overrule an explicit choice", () => {
    // The point of picking light on a dark-mode laptop is that it stays light.
    expect(resolveTheme("light", true)).toBe("light");
    expect(resolveTheme("dark", false)).toBe("dark");
  });
});

describe("applying a theme", () => {
  beforeEach(() => {
    document.documentElement.className = "";
    document.documentElement.style.colorScheme = "";
  });

  it("sets colour-scheme as well as the class", () => {
    applyTheme("dark", document.documentElement);

    expect(document.documentElement.classList.contains(DARK_CLASS)).toBe(true);
    // Without this the scrollbar and any native control stay light while the
    // page around them goes dark.
    expect(document.documentElement.style.colorScheme).toBe("dark");
  });

  it("takes the class off again", () => {
    applyTheme("dark", document.documentElement);
    applyTheme("light", document.documentElement);

    expect(document.documentElement.classList.contains(DARK_CLASS)).toBe(false);
    expect(document.documentElement.style.colorScheme).toBe("light");
  });
});

describe("choosing a theme", () => {
  beforeEach(() => {
    window.localStorage.clear();
    document.documentElement.className = "";
  });

  it("remembers the choice and applies it at once", () => {
    setThemeChoice("dark");

    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
    expect(document.documentElement.classList.contains(DARK_CLASS)).toBe(true);
  });
});

/**
 * The one duplication in this feature, guarded.
 *
 * `index.html` repeats the key and the class in an inline script because that
 * script has to run before React exists -- otherwise the browser paints white
 * and corrects itself, which is the flash the whole arrangement is for. Two
 * copies of a constant drift, so the test asserts they have not.
 */
describe("the pre-paint script", () => {
  it("reads the same storage key the store writes", () => {
    expect(html).toContain(`"${THEME_STORAGE_KEY}"`);
  });

  it("sets the same class the stylesheet is written against", () => {
    expect(html).toContain(`classList.toggle("${DARK_CLASS}"`);
  });

  it("runs before the app script, or it is pointless", () => {
    expect(html.indexOf("prefers-color-scheme")).toBeLessThan(html.indexOf("/src/main.tsx"));
  });
});

// Exported for the toggle; asserted here so an accidental rename is caught by
// the type checker rather than at runtime in the header.
it("exposes a hook for components to read the current theme", () => {
  expect(typeof useTheme).toBe("function");
});
