// Deterministic finding order (docs/05-SCHEMA.md §3):
// severity desc, confidence desc, category order, path, line, then rule and fingerprint as tie-breakers.
import type { Category, Confidence, Finding, Severity } from "../types.js";

export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
export const CONFIDENCE_ORDER: readonly Confidence[] = ["high", "medium", "low"];
export const CATEGORY_ORDER: readonly Category[] = ["secrets", "data", "web", "deps", "code", "config"];

function cmp(a: string | number, b: string | number): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function compareFindings(a: Finding, b: Finding): number {
  return (
    cmp(SEVERITY_ORDER.indexOf(a.severity), SEVERITY_ORDER.indexOf(b.severity)) ||
    cmp(CONFIDENCE_ORDER.indexOf(a.confidence), CONFIDENCE_ORDER.indexOf(b.confidence)) ||
    cmp(CATEGORY_ORDER.indexOf(a.category), CATEGORY_ORDER.indexOf(b.category)) ||
    cmp(a.location.path ?? a.location.url ?? "", b.location.path ?? b.location.url ?? "") ||
    cmp(a.location.line ?? 0, b.location.line ?? 0) ||
    cmp(a.location.column ?? 0, b.location.column ?? 0) ||
    cmp(a.ruleId, b.ruleId) ||
    cmp(a.fingerprint, b.fingerprint)
  );
}
