import { describe, expect, it } from "vitest";
import { formatEffort, levelStyle, label, scoreColor } from "../format";

describe("severity presentation", () => {
  it("gives UNKNOWN its own treatment rather than reusing LOW", () => {
    // Making a gap in knowledge look like a clean result is the most
    // misleading thing a security dashboard can do.
    expect(levelStyle("UNKNOWN")).not.toBe(levelStyle("LOW"));
    expect(levelStyle("UNKNOWN")).toContain("dashed");
  });

  it("falls back to UNKNOWN styling for an unrecognised level", () => {
    expect(levelStyle("NONSENSE")).toBe(levelStyle("UNKNOWN"));
  });

  it("gives every severity a distinct treatment", () => {
    const styles = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].map(levelStyle);
    expect(new Set(styles).size).toBe(5);
  });
});

describe("score colour", () => {
  it("turns critical only when the score is genuinely bad", () => {
    expect(scoreColor(92)).toBe("text-ok");
    expect(scoreColor(70)).toBe("text-medium");
    expect(scoreColor(45)).toBe("text-high");
    expect(scoreColor(10)).toBe("text-critical");
  });
});

describe("status labels", () => {
  it("says 'Verified fixed' rather than 'Resolved'", () => {
    // The wording carries the product claim: a scan proved it.
    expect(label("RESOLVED")).toBe("Verified fixed");
  });

  it("translates scan pipeline stages into plain language", () => {
    expect(label("EVALUATING")).toBe("Running security rules");
    expect(label("PARTIAL")).toBe("Completed with gaps");
  });

  it("humanises an unmapped value instead of showing raw enum text", () => {
    expect(label("SOME_NEW_STATE")).toBe("Some new state");
  });
});

describe("effort formatting", () => {
  it("scales units so a 15-minute fix reads differently from a 2-day one", () => {
    expect(formatEffort(15)).toBe("15 min");
    expect(formatEffort(120)).toBe("2 hr");
    expect(formatEffort(960)).toBe("2 days");
  });
});
