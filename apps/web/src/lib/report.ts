// Applies user decisions to a report and recomputes the summary with core's own scoring.
import {
  computeCounts,
  computeScore,
  computeVerdict,
  type Finding,
  type Report,
} from "@prelaunch-check/core";
import type { StoredDecision } from "./storage";

export function applyDecisions(report: Report, decisions: Record<string, StoredDecision>): Report {
  const findings: Finding[] = report.findings.map((f) => {
    const d = decisions[f.fingerprint];
    if (!d) return f;
    return { ...f, status: d.status, decision: { reason: d.reason, decidedAt: d.decidedAt, source: "ui" } };
  });
  return {
    ...report,
    findings,
    summary: {
      ...report.summary,
      verdict: computeVerdict(findings),
      score: computeScore(findings),
      counts: computeCounts(findings),
    },
  };
}

export interface Comparison {
  newFingerprints: Set<string>;
  fixedCount: number;
}

export function compare(report: Report, previous: string[] | null): Comparison | null {
  if (!previous) return null;
  const prev = new Set(previous);
  const now = new Set(report.findings.map((f) => f.fingerprint));
  return {
    newFingerprints: new Set([...now].filter((fp) => !prev.has(fp))),
    fixedCount: [...prev].filter((fp) => !now.has(fp)).length,
  };
}

export function projectName(report: Report): string {
  return report.target.folderName ?? report.profile.name ?? report.target.url ?? "project";
}
