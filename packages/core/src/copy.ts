// Fixed user-facing words (docs/04-DESIGN-BRIEF.md §3). Never call the user's app "safe" or "secure".
import type { Report, Severity, Verdict } from "./types.js";

export const VERDICT_LABEL: Record<Verdict, string> = {
  blocked: "Blocked",
  needs_attention: "Needs attention",
  no_blocking: "No blocking issues found",
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

export function verdictSentence(report: Report): string {
  const c = report.summary.counts;
  switch (report.summary.verdict) {
    case "blocked":
      return `${plural(c.critical, "critical issue")} could let a stranger take data or money right now.`;
    case "needs_attention":
      return `No critical issues, but ${plural(c.high, "high-severity problem")} should be fixed before launch.`;
    case "no_blocking":
      return "We didn't find critical or high issues. This doesn't mean the app is safe. Complete the checklist below.";
  }
}
