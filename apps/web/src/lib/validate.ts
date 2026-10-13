// Validation for report files opened in W-07. Files may come from anyone, so the shape is checked,
// strings are type-checked, and nothing is ever rendered as HTML.
import type { Finding, Report } from "@prelaunch-check/core";

export type OpenResult = { ok: true; report: Report; newerVersion: boolean } | { ok: false; message: string };

const NOT_A_REPORT = "This doesn't look like a Prelaunch Check report.";
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const CONFIDENCES = ["high", "medium", "low"];
const STATUSES = ["open", "accepted_risk", "false_positive"];
const CATEGORIES = ["secrets", "data", "web", "deps", "code", "config"];
export const MAX_REPORT_BYTES = 25 * 1024 * 1024;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string";

function validFinding(f: unknown): f is Finding {
  if (!isObj(f)) return false;
  const loc = f.location;
  const ev = f.evidence;
  return (
    isStr(f.fingerprint) &&
    isStr(f.ruleId) &&
    isStr(f.title) &&
    CATEGORIES.includes(f.category as string) &&
    SEVERITIES.includes(f.severity as string) &&
    CONFIDENCES.includes(f.confidence as string) &&
    STATUSES.includes(f.status as string) &&
    isStr(f.owasp) &&
    isStr(f.fixPrompt) &&
    isObj(loc) &&
    (loc.kind === "file" || loc.kind === "url") &&
    (loc.path === undefined || isStr(loc.path)) &&
    (loc.url === undefined || isStr(loc.url)) &&
    (loc.line === undefined || typeof loc.line === "number") &&
    isObj(ev) &&
    (ev.snippet === undefined || isStr(ev.snippet))
  );
}

export function validateReport(text: string): OpenResult {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return { ok: false, message: NOT_A_REPORT };
  }
  if (!isObj(data) || !isStr(data.schemaVersion) || !isObj(data.tool) || data.tool.name !== "prelaunch-check")
    return { ok: false, message: NOT_A_REPORT };
  const major = Number(data.schemaVersion.split(".")[0]);
  const newerVersion = !(major <= 1);
  const summary = data.summary;
  if (
    !isObj(summary) ||
    !isObj(summary.counts) ||
    typeof summary.score !== "number" ||
    !Array.isArray(data.findings) ||
    !isObj(data.coverage) ||
    !isObj(data.target) ||
    !isObj(data.profile)
  ) {
    return { ok: false, message: NOT_A_REPORT };
  }
  // Keep only well-formed findings; a newer version may add fields we ignore.
  const findings = (data.findings as unknown[]).filter(validFinding);
  if (findings.length !== data.findings.length && !newerVersion) return { ok: false, message: NOT_A_REPORT };
  const report = {
    ...data,
    findings,
    checklist: Array.isArray(data.checklist) ? data.checklist : [],
  } as unknown as Report;
  return { ok: true, report, newerVersion };
}
