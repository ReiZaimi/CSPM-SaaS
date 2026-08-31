import "@testing-library/jest-dom/vitest";

/**
 * jsdom implements no `ResizeObserver`, and Recharts' `ResponsiveContainer`
 * measures its parent through one. Without this any chart under test throws
 * during commit rather than rendering.
 *
 * A stub rather than a real implementation on purpose: jsdom gives every
 * element a zero-size box regardless, so a faithful observer would report
 * 0×0 and the chart would still render nothing measurable. What the tests can
 * check is what the component *decides* — whether it draws a line at all,
 * whether it carries a legend — and that needs the container to mount without
 * exploding, not to have real dimensions.
 */
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}

globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver;

/**
 * jsdom implements no `matchMedia`, and the theme store asks it what the
 * operating system prefers. Defaults to light so a test that says nothing
 * about the theme gets the same surface every run; tests that care replace it.
 */
globalThis.matchMedia ??= ((query: string) => ({
  matches: false,
  media: query,
  onchange: null,
  addEventListener: () => {},
  removeEventListener: () => {},
  addListener: () => {},
  removeListener: () => {},
  dispatchEvent: () => false,
})) as unknown as typeof window.matchMedia;

/**
 * jsdom implements no `scrollIntoView`, and cmdk calls it to keep the
 * highlighted row of the command palette visible as the arrow keys move
 * through it. Nothing scrolls in a zero-height jsdom list, so a stub is the
 * whole of what a faithful implementation would achieve here.
 */
Element.prototype.scrollIntoView ??= function scrollIntoView() {};
