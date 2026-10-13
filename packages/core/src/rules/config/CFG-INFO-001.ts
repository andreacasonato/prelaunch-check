import type { RawFinding, Rule } from "../../types.js";
import { parseInlineSuppressions } from "../../engine/suppress.js";

export const CFG_INFO_001: Rule = {
  meta: {
    id: "CFG-INFO-001",
    title: "Suppression without reason",
    category: "config",
    severity: "info",
    confidence: "high",
    owasp: "A09",
    requires: ["files"],
    summary:
      "Lists `prelaunch-check-ignore` comments that have no reason after the colon. They are ignored until a reason is added.",
    why: "A suppression is a decision that a reviewer should be able to understand later. Without a reason, nobody can tell whether the risk was really accepted or just hidden.",
    fix: [
      "Add a reason after a colon: `// prelaunch-check-ignore DB-003: credits is only written by a trigger`.",
    ],
    fixPromptTemplate:
      "In `{{path}}` line {{line}}, a prelaunch-check-ignore comment for {{detail.rules}} has no reason. Add a short reason after a colon explaining why the finding is acceptable, or remove the comment.",
    sources: [{ title: "Prelaunch Check suppression format (README: Config file)" }],
  },
  async check(ctx) {
    const files = ctx.files!;
    const out: RawFinding[] = [];
    for (const e of files.all()) {
      const text = await files.text(e.path);
      if (text === null) continue;
      for (const s of parseInlineSuppressions(text)) {
        if (s.reason !== null) continue;
        out.push({
          ruleId: "CFG-INFO-001",
          location: { kind: "file", path: e.path, line: s.line },
          evidence: { snippet: text.split("\n")[s.line - 1] ?? "", detail: { rules: s.ruleIds.join(", ") } },
        });
      }
    }
    return out;
  },
};
