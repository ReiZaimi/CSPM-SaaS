import { describe, expect, it } from "vitest";
import { formatEffort, levelStyle, label, outcomeStyle, scoreColor } from "../format";

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

describe("outcomeStyle", () => {
  it("does not render a complete reading as a gap in knowledge", () => {
    // The bug this guards. `levelStyle` has no OK, so routing outcomes through
    // it made COMPLETE fall back to UNKNOWN — a full, trustworthy read wearing
    // the dashed border that means "we could not look".
    expect(outcomeStyle("COMPLETE")).not.toBe(levelStyle("UNKNOWN"));
    expect(outcomeStyle("COMPLETE")).toContain("ok");
  });

  it("does not render a partial reading as a complete one", () => {
    // The whole reason PARTIAL exists: data came back, and it still cannot
    // support a pass.
    expect(outcomeStyle("PARTIAL")).not.toBe(outcomeStyle("COMPLETE"));
  });

  it("gives every outcome its own treatment", () => {
    const styles = (["COMPLETE", "PARTIAL", "FAILED", "SKIPPED"] as const).map(
      outcomeStyle,
    );
    expect(new Set(styles).size).toBe(4);
  });

  it("treats a skipped reading as unknown rather than failed", () => {
    // Nothing is known to be wrong with it, and colouring it as a failure
    // would send someone hunting a second problem one hop from the real one.
    expect(outcomeStyle("SKIPPED")).toContain("unknown");
    expect(outcomeStyle("SKIPPED")).not.toContain("critical");
  });
});
