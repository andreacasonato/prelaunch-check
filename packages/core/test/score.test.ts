import { describe, expect, it } from "vitest";
import { computeCounts, computeScore, computeVerdict, WEIGHTS } from "../src/score.js";
import type { Confidence, Finding, FindingStatus, Severity } from "../src/types.js";

let n = 0;
function f(
  ruleId: string,
  severity: Severity,
  confidence: Confidence = "high",
  status: FindingStatus = "open",
): Finding {
  n++;
  return {
    fingerprint: `f1_TEST${n}`,
    ruleId,
    title: ruleId,
    category: "secrets",
    severity,
    confidence,
    owasp: "A04",
    location: { kind: "file", path: `f${n}.ts` },
    evidence: {},
    status,
    fixPrompt: "",
  };
}

/** Expected score computed independently from the TRD §8 formula, never hard-coded. */
function expectedScore(findings: Finding[]): number {
  const byRule = new Map<string, { sev: Severity; count: number }>();
  for (const x of findings) {
    if (x.status !== "open" || x.confidence === "low") continue;
    const key = `${x.ruleId}|${x.severity}`;
    const cur = byRule.get(key) ?? { sev: x.severity, count: 0 };
    cur.count++;
    byRule.set(key, cur);
  }
  let penalty = 0;
  for (const { sev, count } of byRule.values()) penalty += Math.min(WEIGHTS[sev] * count, 2 * WEIGHTS[sev]);
  return Math.max(0, 100 - penalty);
}

describe("score and verdict (TRD §8)", () => {
  it("uses the published weights", () => {
    expect(WEIGHTS).toEqual({ critical: 25, high: 10, medium: 4, low: 1, info: 0 });
  });

  it("reproduces the SCHEMA §3.1 example: 51 and blocked", () => {
    const findings = [
      f("SEC-003", "critical"),
      f("DB-001", "high"),
      f("DB-003", "high"),
      f("CFG-002", "medium"),
      f("SEC-INFO-001", "info"),
      f("CODE-INV-001", "info"),
      f("CODE-INV-001", "info"),
      f("CODE-003", "medium", "low"),
    ];
    expect(computeScore(findings)).toBe(expectedScore(findings));
    expect(computeScore(findings)).toBe(51);
    expect(computeVerdict(findings)).toBe("blocked");
    expect(computeCounts(findings)).toEqual({
      critical: 1,
      high: 2,
      medium: 1,
      low: 0,
      info: 3,
      worthChecking: 1,
      suppressed: 0,
    });
  });

  it("reproduces the APP-FLOW C-01 example: 30", () => {
    const findings = [
      f("SEC-003", "critical"),
      f("DB-004", "critical"),
      f("DB-003", "high"),
      f("WEB-003", "medium"),
      f("CFG-001", "medium"),
      f("WEB-006", "low"),
      f("WEB-007", "low"),
    ];
    expect(computeScore(findings)).toBe(expectedScore(findings));
    expect(computeScore(findings)).toBe(30);
  });

  it("caps repeat findings of one rule at 2× the weight", () => {
    const findings = [
      f("SEC-001", "critical"),
      f("SEC-001", "critical"),
      f("SEC-001", "critical"),
      f("SEC-001", "critical"),
    ];
    expect(computeScore(findings)).toBe(50);
    expect(computeScore(findings)).toBe(expectedScore(findings));
  });

  it("caps per rule and severity when one rule emits several severities", () => {
    const findings = [
      f("SEC-001", "critical"),
      f("SEC-001", "medium"),
      f("SEC-001", "medium"),
      f("SEC-001", "medium"),
    ];
    expect(computeScore(findings)).toBe(expectedScore(findings));
  });

  it("never goes below zero", () => {
    const findings = ["A", "B", "C", "D", "E"].map((r) => f(`R-${r}`, "critical"));
    expect(computeScore(findings)).toBe(0);
  });

  it("excludes low-confidence findings from score and verdict", () => {
    const findings = [f("CODE-003", "critical", "low"), f("WEB-012", "high", "low")];
    expect(computeScore(findings)).toBe(100);
    expect(computeVerdict(findings)).toBe("no_blocking");
    expect(computeCounts(findings).worthChecking).toBe(2);
  });

  it("excludes accepted-risk and false-positive findings", () => {
    const findings = [
      f("SEC-003", "critical", "high", "accepted_risk"),
      f("DB-001", "high", "high", "false_positive"),
    ];
    expect(computeScore(findings)).toBe(100);
    expect(computeVerdict(findings)).toBe("no_blocking");
    expect(computeCounts(findings).suppressed).toBe(2);
  });

  it("returns needs_attention when the worst open finding is high", () => {
    expect(computeVerdict([f("DB-001", "high"), f("CFG-001", "medium")])).toBe("needs_attention");
  });

  it("verdict never depends on score", () => {
    const manyMediums = Array.from({ length: 30 }, (_, i) => f(`M-${i}`, "medium"));
    expect(computeScore(manyMediums)).toBe(0);
    expect(computeVerdict(manyMediums)).toBe("no_blocking");
  });
});
