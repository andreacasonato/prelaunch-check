import type { RawFinding, Rule } from "../../types.js";
import { GHA_SECURE_USE, lineEvidence, loadWorkflows } from "./workflows.js";

const UNTRUSTED_REF = /github\.event\.pull_request\.head|github\.head_ref/;

export const CFG_005: Rule = {
  meta: {
    id: "CFG-005",
    title: "pull_request_target checks out PR code",
    category: "config",
    severity: "high",
    confidence: "high",
    owasp: "A03",
    requires: ["files"],
    summary:
      "Finds workflows triggered by pull_request_target that check out the pull request's head commit with actions/checkout.",
    why: "pull_request_target runs with your repository's secrets and a write token, even for pull requests from strangers' forks. Checking out their code and running it (installing dependencies, building, testing) hands those secrets to anyone who opens a pull request.",
    fix: [
      "Use the `pull_request` trigger for anything that builds or tests contributed code.",
      "If you need pull_request_target (for example to label PRs), don't check out the PR's code in that workflow.",
      "Split privileged follow-up work into a separate `workflow_run` workflow that never executes PR code.",
    ],
    fixPromptTemplate:
      "In `{{path}}` line {{line}}, a pull_request_target workflow checks out the pull request's head commit. Change the trigger to pull_request for build and test steps, or remove the checkout of PR code from this privileged workflow, following GitHub's guidance that such workflows must not check out untrusted code.",
    sources: [{ title: "GitHub Actions: secure use reference", url: GHA_SECURE_USE }],
  },
  async check(ctx) {
    const out: RawFinding[] = [];
    for (const wf of await loadWorkflows(ctx.files!)) {
      const prTarget = wf.entries.some(
        (e) =>
          (e.key === "on" && e.path.length === 0 && /\bpull_request_target\b/.test(e.value)) ||
          (e.key === "pull_request_target" && e.path.length === 1 && e.path[0] === "on"),
      );
      if (!prTarget) continue;
      const checkoutItems = new Set(
        wf.entries
          .filter((e) => e.key === "uses" && e.value.startsWith("actions/checkout"))
          .map((e) => e.itemId),
      );
      for (const e of wf.entries) {
        if (e.key !== "ref" || e.path[e.path.length - 1] !== "with" || !checkoutItems.has(e.itemId)) continue;
        if (!UNTRUSTED_REF.test(e.value)) continue;
        out.push({
          ruleId: "CFG-005",
          location: { kind: "file", path: wf.path, line: e.line },
          evidence: { ...lineEvidence(wf, e.line, e.value), detail: { ref: e.value } },
        });
      }
    }
    return out;
  },
};
