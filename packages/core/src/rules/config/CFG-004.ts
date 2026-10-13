import type { RawFinding, Rule } from "../../types.js";
import { GHA_SECURE_USE, lineEvidence, loadWorkflows } from "./workflows.js";

export const CFG_004: Rule = {
  meta: {
    id: "CFG-004",
    title: "Workflow token has broad permissions",
    category: "config",
    severity: "medium",
    confidence: "high",
    owasp: "A01",
    requires: ["files"],
    summary:
      "Finds workflows with `permissions: write-all`, or with no top-level `permissions:` key (unless every job sets its own).",
    why: "Every workflow run gets a GITHUB_TOKEN. Without explicit permissions it may be able to push code, create releases or change issues. If any step is compromised, a broad token turns a small problem into a repository takeover.",
    fix: [
      "Add a top-level block granting only what the workflow needs, usually:\n\n```yaml\npermissions:\n  contents: read\n```",
      "Grant extra scopes (for example `security-events: write`) only on the job that needs them.",
    ],
    fixPromptTemplate:
      "In `{{path}}`, {{detail.problem}}. Add a top-level `permissions:` block with only `contents: read`, and grant any additional scope only on the specific job that needs it.",
    sources: [{ title: "GitHub Actions: secure use reference", url: GHA_SECURE_USE }],
  },
  async check(ctx) {
    const out: RawFinding[] = [];
    for (const wf of await loadWorkflows(ctx.files!)) {
      for (const e of wf.entries) {
        if (e.key === "permissions" && e.value === "write-all") {
          out.push({
            ruleId: "CFG-004",
            title: "Workflow grants write-all permissions",
            location: { kind: "file", path: wf.path, line: e.line },
            evidence: {
              ...lineEvidence(wf, e.line, "write-all"),
              detail: { problem: `line ${e.line} grants write-all permissions` },
            },
          });
        }
      }
      const topLevel = wf.entries.some((e) => e.key === "permissions" && e.path.length === 0);
      if (topLevel) continue;
      const jobs = wf.entries.filter((e) => e.path.length === 1 && e.path[0] === "jobs");
      if (!jobs.length) continue;
      const allJobsScoped = jobs.every((job) =>
        wf.entries.some(
          (e) =>
            e.key === "permissions" && e.path.length === 2 && e.path[1] === job.key && e.path[0] === "jobs",
        ),
      );
      if (allJobsScoped) continue;
      out.push({
        ruleId: "CFG-004",
        title: "Workflow has no top-level permissions",
        location: { kind: "file", path: wf.path, line: 1 },
        evidence: {
          detail: { problem: "there is no top-level permissions block, so jobs get the default token scope" },
        },
      });
    }
    return out;
  },
};
