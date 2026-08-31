import { useEffect, useRef, useState } from "react";

/**
 * Whether this reader has asked the operating system for less motion.
 *
 * Consulted rather than assumed, and consulted live: somebody who turns it on
 * mid-session has said something about how they want to be treated, and a
 * dashboard that keeps animating until reload has not listened.
 *
 * Everything in this file degrades to *the final state, immediately* — never to
 * a slower version of the animation. Reduced motion means arriving, not
 * crawling.
 */
export function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() => {
    if (typeof window === "undefined" || !window.matchMedia) return false;
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  });

  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    const onChange = () => setReduced(query.matches);
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);

  return reduced;
}

/**
 * A number that counts up to its value.
 *
 * Two rules, and both are about not lying with motion:
 *
 * **It animates when the value changes, not when the component renders.** The
 * dashboard polls every twenty seconds; a count-up on every refetch would make
 * a page nobody touched twitch four times a minute, and a reader would learn to
 * distrust movement that means nothing.
 *
 * **It always ends on the exact value.** The easing is applied to the fraction
 * of the distance travelled, and the last frame is assigned rather than
 * interpolated, so a security score never settles on 71 because a float landed
 * short.
 */
export function useCountUp(value: number, durationMs = 650): number {
  const reduced = usePrefersReducedMotion();
  const [shown, setShown] = useState(value);
  const previous = useRef(value);

  useEffect(() => {
    const from = previous.current;
    previous.current = value;

    if (reduced || from === value) {
      setShown(value);
      return;
    }

    let frame = 0;
    const started = performance.now();

    const step = (now: number) => {
      const elapsed = now - started;
      if (elapsed >= durationMs) {
        setShown(value);
        return;
      }
      // Ease-out cubic: fast enough to feel immediate, slow enough at the end
      // that the reader's eye lands on the final digits rather than chasing.
      const progress = 1 - Math.pow(1 - elapsed / durationMs, 3);
      setShown(from + (value - from) * progress);
      frame = requestAnimationFrame(step);
    };

    frame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame);
  }, [value, durationMs, reduced]);

  return shown;
}

/**
 * A list that arrives a row at a time.
 *
 * Capped, deliberately: past about eight rows the stagger stops reading as
 * arrival and starts reading as a slow page, so later rows share the last
 * delay. Returns a style rather than a class so a caller can put it on whatever
 * element it already has.
 */
export function stagger(index: number, stepMs = 30): { animationDelay: string } {
  return { animationDelay: `${Math.min(index, 8) * stepMs}ms` };
}
