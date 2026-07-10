import { describe, it, expect } from "vitest";
import { KILL_CHAIN, baseTechnique, tacticFor } from "./mitre";

describe("tacticFor", () => {
  it("maps real ATT&CK techniques the live agent can cite, not just a small fixture sample", () => {
    expect(tacticFor("T1498")).toBe("Impact");
    expect(tacticFor("T1046")).toBe("Discovery");
  });

  it("strips sub-technique suffixes before lookup", () => {
    expect(baseTechnique("T1046.001")).toBe("T1046");
    expect(tacticFor("T1046.001")).toBe("Discovery");
  });

  it("falls back to Other for an unrecognized technique id", () => {
    expect(tacticFor("T0000")).toBe("Other");
  });

  it("only ever returns a kill-chain column or Other", () => {
    expect([...KILL_CHAIN, "Other"]).toContain(tacticFor("T1498"));
  });
});
