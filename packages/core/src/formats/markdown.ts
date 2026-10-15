// Plain Markdown report: paste into PRs, issues or an AI agent (TRD §9).
import type { Finding, Report, Severity } from "../types.js";
import { VERDICT_LABEL, verdictSentence, SEVERITY_LABEL } from "../copy.js";
import { groupChecklist } from "../checklist/group.js";

function longestBacktickRun(text: string): number {
  return Math.max(0, ...Array.from(text.matchAll(/`+/g), (m) => m[0].length));
}

/** A code fence longer than any backtick run inside the content. */
function fence(content: string): string {
  return "`".repeat(Math.max(3, longestBacktickRun(content) + 1));
}

/** Inline code that survives backticks in the content. */
function code(text: string): string {
  const ticks = "`".repeat(longestBacktickRun(text) + 1);
  const pad = text.startsWith("`") || text.endsWith("`") ? " " : "";
  return `${ticks}${pad}${text}${pad}${ticks}`;
}

/** Escapes Markdown control characters in free text such as titles. */
function esc(text: string): string {
  return text.replace(/([\\`*_{}[\]<>()#+!|])/g, "\\$1").replace(/\r?\n/g, " ");
}

export function locationText(f: Finding): string {
  const l = f.location;
  if (l.kind === "url") return l.url ?? "";
  return l.line !== undefined ? `${l.path}:${l.line}` : (l.path ?? "");
}

function findingBlock(f: Finding): string {
  const lines: string[] = [];
  const conf = f.confidence !== "high" ? ` · ${f.confidence} confidence` : "";
  const status = f.status !== "open" ? ` · ${f.status.replace("_", " ")}` : "";
  const existing = f.existing ? " · existing" : "";
  lines.push(`### ${SEVERITY_LABEL[f.severity]}: ${esc(f.title)}`);
  lines.push("");
  lines.push(
    `${code(f.ruleId)} · OWASP ${f.owasp}:2025${conf}${status}${existing} · ${code(locationText(f))}`,
  );
  if (f.decision) lines.push("", `Decision (${f.decision.source}): ${esc(f.decision.reason)}`);
  if (f.evidence.snippet) {
    const fc = fence(f.evidence.snippet);
    lines.push("", fc, f.evidence.snippet, fc);
  }
  lines.push("", "**Fix prompt**", "", ...f.fixPrompt.split("\n").map((l) => `> ${l}`));
  return lines.join("\n");
}

const SKIP_REASON_TEXT: Record<string, string> = {
  no_url: "Live-site checks (run the CLI with --url)",
  offline: "Online dependency checks (online lookups were off)",
  not_applicable: "Not applicable to this project",
  missing_tool: "Needs an optional tool that wasn't found",
  disabled_by_config: "Disabled in config",
};

export function toMarkdown(report: Report): string {
  const s = report.summary;
  const out: string[] = [];
  const name = report.target.folderName ?? report.target.url ?? report.profile.name;
  out.push(`# Prelaunch Check report: ${esc(name)}`, "");
  out.push(
    `Generated ${report.generatedAt} by ${report.tool.name} ${report.tool.version} (rules ${report.tool.rulesetVersion}).`,
    "",
  );
  out.push(`**${VERDICT_LABEL[s.verdict]}**: ${verdictSentence(report)}`, "");
  out.push(`Score: ${s.score} / 100`, "");
  const c = s.counts;
  out.push(
    `${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low · ${c.worthChecking} worth checking · ${c.info} info · ${c.suppressed} suppressed`,
  );

  const sections: Array<[string, Finding[]]> = [];
  const open = report.findings.filter((f) => f.status === "open");
  const order: Severity[] = ["critical", "high", "medium", "low"];
  for (const sev of order) {
    const list = open.filter((f) => f.severity === sev && f.confidence !== "low");
    if (list.length) sections.push([SEVERITY_LABEL[sev], list]);
  }
  const worth = open.filter((f) => f.confidence === "low");
  if (worth.length) sections.push(["Worth checking", worth]);
  const info = open.filter((f) => f.severity === "info" && f.confidence !== "low");
  if (info.length) sections.push(["Info", info]);
  const suppressed = report.findings.filter((f) => f.status !== "open");
  if (suppressed.length) sections.push([`Suppressed (${suppressed.length})`, suppressed]);

  for (const [title, list] of sections) {
    out.push("", `## ${title}`, "");
    out.push(list.map(findingBlock).join("\n\n"));
  }
  if (report.findings.length === 0) out.push("", "No findings.");

  if (report.endpoints?.length) {
    out.push("", "## Endpoint inventory", "");
    out.push(
      "Decide for each route whether it should be reachable by an anonymous user, a regular user, or an admin.",
    );
    out.push("", "| Method | Route | File | Auth call seen |", "|---|---|---|---|");
    for (const e of report.endpoints)
      out.push(
        `| ${e.method} | ${code(e.route)} | ${code(`${e.file}:${e.line}`)} | ${e.authCallSeen ? "yes" : "no"} |`,
      );
  }

  const cov = report.coverage;
  out.push("", "## What we couldn't check", "");
  const covLines: string[] = [];
  for (const note of cov.notes) covLines.push(`- ${esc(note)}`);
  const skipped = new Map<string, string[]>();
  for (const sk of cov.rulesSkipped) skipped.set(sk.reason, [...(skipped.get(sk.reason) ?? []), sk.ruleId]);
  for (const [reason, ids] of skipped)
    covLines.push(`- ${SKIP_REASON_TEXT[reason] ?? reason}: ${ids.join(", ")}`);
  if (cov.filesSkippedTotal)
    covLines.push(`- ${cov.filesSkippedTotal} files skipped (ignored folders, binary, or too large).`);
  for (const e of cov.errors) covLines.push(`- ${e.ruleId} stopped with an error: ${esc(e.message)}`);
  out.push(covLines.length ? covLines.join("\n") : "- Everything applicable was checked.");

  out.push("", "## Pre-launch checklist", "");
  out.push("No scanner can verify these. Work through them before you launch.", "");
  for (const section of groupChecklist(report.checklist)) {
    out.push(`### ${esc(section.title)}`, "");
    if (section.intro) out.push(esc(section.intro), "");
    for (const item of section.items)
      out.push(`- [ ] **${item.id}** ${esc(item.title)}: ${esc(item.howToTest)}`);
    out.push("");
  }
  return out.join("\n");
}
