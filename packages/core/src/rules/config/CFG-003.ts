import type { RawFinding, Rule } from "../../types.js";
import { GHA_SECURE_USE, lineEvidence, loadWorkflows } from "./workflows.js";

export const CFG_003: Rule = {
  meta: {
    id: "CFG-003",
    title: "GitHub Action not pinned to a commit SHA",
    category: "config",
    severity: "low",
    confidence: "high",
    owasp: "A03",
    requires: ["files"],
    summary:
      "Finds `uses: owner/repo@ref` in workflows where ref is a tag or branch instead of a full 40-character commit SHA.",
    why: "Tags and branches can be moved. If an action's repository is compromised, a moved tag runs the attacker's code in your CI with access to your secrets. A commit SHA can't be changed.",
    fix: [
      "Replace the tag with the full commit SHA it points to, and keep the version as a comment: `uses: actions/checkout@<40-char-sha> # v4.2.2`.",
      "Use Dependabot or Renovate to keep pinned SHAs up to date.",
    ],
    fixPromptTemplate:
      "In `{{path}}` line {{line}}, the action `{{detail.action}}` is pinned to `{{detail.ref}}`, which can be moved. Replace it with the full 40-character commit SHA that this version points to, and add the version as a trailing comment (e.g. `# v4.2.2`).",
    falsePositiveNotes: "Local actions (./path) and docker:// images are not checked.",
    sources: [{ title: "GitHub Actions: secure use reference", url: GHA_SECURE_USE }],
  },
  async check(ctx) {
    const out: RawFinding[] = [];
    for (const wf of await loadWorkflows(ctx.files!)) {
      for (const e of wf.entries) {
        if (e.key !== "uses" || !e.value) continue;
        const v = e.value.trim();
        if (v.startsWith("./") || v.startsWith("docker://")) continue;
        const at = v.lastIndexOf("@");
        const action = at === -1 ? v : v.slice(0, at);
        const ref = at === -1 ? "" : v.slice(at + 1);
        if (/^[0-9a-f]{40}$/.test(ref)) continue;
        out.push({
          ruleId: "CFG-003",
          location: { kind: "file", path: wf.path, line: e.line },
          evidence: { ...lineEvidence(wf, e.line, v), detail: { action, ref: ref || "(no ref)" } },
        });
      }
    }
    return out;
  },
};
