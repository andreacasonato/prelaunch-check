// Scoring and verdict (docs/02-TRD.md §8). The weights are a published Decision, not a standard.
import type { Finding, Severity, SeverityCounts, Verdict } from "./types.js";

export const WEIGHTS: Readonly<Record<Severity, number>> = Object.freeze({
  critical: 25,
  high: 10,
  medium: 4,
  low: 1,
  info: 0,
});
export const PER_RULE_CAP_MULTIPLIER = 2 as const;

/** Findings that count: open and not low confidence. */
export function countsTowardScore(f: Finding): boolean {
  return f.status === "open" && f.confidence !== "low";
}

export function computeScore(findings: readonly Finding[]): number {
  // Repeats of one rule cap at 2× the weight. A rule that emits several severities
  // (e.g. SEC-001 live vs test keys) is capped per severity.
  const groups = new Map<string, { sev: Severity; count: number }>();
  for (const f of findings) {
    if (!countsTowardScore(f)) continue;
    const key = `${f.ruleId}\0${f.severity}`;
    const g = groups.get(key) ?? { sev: f.severity, count: 0 };
    g.count++;
    groups.set(key, g);
  }
  let penalty = 0;
  for (const { sev, count } of groups.values()) {
    penalty += Math.min(WEIGHTS[sev] * count, PER_RULE_CAP_MULTIPLIER * WEIGHTS[sev]);
  }
  return Math.max(0, 100 - penalty);
}

export function computeVerdict(findings: readonly Finding[]): Verdict {
  const open = findings.filter(countsTowardScore);
  if (open.some((f) => f.severity === "critical")) return "blocked";
  if (open.some((f) => f.severity === "high")) return "needs_attention";
  return "no_blocking";
}

export function computeCounts(findings: readonly Finding[]): SeverityCounts {
  const counts: SeverityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    worthChecking: 0,
    suppressed: 0,
  };
  for (const f of findings) {
    if (f.status !== "open") counts.suppressed++;
    else if (f.confidence === "low") counts.worthChecking++;
    else counts[f.severity]++;
  }
  return counts;
}
