// Test-only placeholder rule that exercises the pipeline. Not registered in the default rule set.
import type { RawFinding, Rule } from "../../types.js";
import { snippetAround } from "../../util/text.js";

const MARKER = "PLC_TEST_MARKER";

export const testRule000: Rule = {
  meta: {
    id: "TEST-000",
    title: "Test marker found",
    category: "code",
    severity: "low",
    confidence: "high",
    owasp: "A02",
    requires: ["files"],
    summary: "Finds the literal PLC_TEST_MARKER. Used only by the engine's own tests.",
    why: "This rule exists to test the scan pipeline. It never runs in real scans.",
    fix: ["Remove the marker."],
    fixPromptTemplate: "Remove PLC_TEST_MARKER from {{path}} line {{line}}.",
    sources: [{ title: "Prelaunch Check implementation plan, Phase 2" }],
  },
  async check(ctx) {
    const out: RawFinding[] = [];
    for (const entry of ctx.files?.all() ?? []) {
      const text = await ctx.files!.text(entry.path);
      if (text === null) continue;
      let from = 0;
      for (;;) {
        const idx = text.indexOf(MARKER, from);
        if (idx === -1) break;
        const s = snippetAround(text, idx, idx + MARKER.length);
        out.push({
          ruleId: "TEST-000",
          location: { kind: "file", path: entry.path, line: s.line, column: s.column },
          evidence: { snippet: s.snippet, matchStart: s.matchStart, matchEnd: s.matchEnd },
        });
        from = idx + MARKER.length;
      }
    }
    return out;
  },
};
