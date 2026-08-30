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
