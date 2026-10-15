// HTML report (Phase 8): written test-first. Attacker-controlled strings must render inert.
import { describe, expect, it } from "vitest";
import { toHtml } from "../src/formats/html.js";
import { scan } from "./helpers.js";
import type { Rule } from "../src/types.js";
import { testRule000 } from "../src/rules/test/TEST-000.js";

const EVIL = [
  `<script>alert(1)</script>`,
  `"><img src=x onerror=alert(1)>`,
  `</style><script>alert(2)</script>`,
  `javascript:alert(3)`,
  `{{constructor}}`,
];

const evilRule: Rule = {
  meta: {
    ...testRule000.meta,
    id: "TEST-401",
    title: EVIL[0]!,
    fixPromptTemplate: `Fix ${EVIL[1]} in {{path}}`,
  },
  async check() {
    return EVIL.map((e, i) => ({
      ruleId: "TEST-401",
      title: `${e} title ${i}`,
      location: { kind: "file" as const, path: `src/${e}-${i}.ts`, line: i + 1 },
      evidence: {
        snippet: `const x = "${e}";`,
        matchStart: 0,
        matchEnd: 5,
        detail: { url: EVIL[3]!, note: e },
      },
    }));
  },
};

describe("toHtml", () => {
  it("escapes every attacker-controlled string and contains no script or event handlers", async () => {
    const report = await scan({ "src/a.ts": "x" }, { rules: [evilRule], folderName: EVIL[1]! });
    const html = await toHtml(report);
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/<img/i);
    // No real tag (an unescaped "<") carries an event-handler attribute. Escaped text like
    // "&lt;img onerror=…&gt;" is inert, because it's text, not markup.
    expect(html).not.toMatch(/<[a-z][^>]*\son[a-z]+\s*=/i);
    expect(html).not.toMatch(/href\s*=\s*["']?\s*javascript:/i);
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).toContain("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;");
    // Exactly one <style> element: an attacker can't close it early.
    expect(html.match(/<style/g)).toHaveLength(1);
    expect(html.match(/<\/style>/g)).toHaveLength(1);
  });

  it("groups the checklist under escaped headings, with the legal disclaimer", async () => {
    const report = await scan({ "src/a.ts": "x" }, { rules: [testRule000] });
    const html = await toHtml({
      ...report,
      checklist: [...report.checklist, { ...report.checklist[0]!, id: "MAN-999", group: EVIL[0]! }],
    });
    expect(html).toContain("<h3>Try to break in</h3>");
    expect(html).toContain("<h3>Legal &amp; trust</h3>");
    expect(html).toContain("This isn&#39;t legal advice");
    expect(html).toContain("<h3>&lt;script&gt;alert(1)&lt;/script&gt;</h3>");
    expect(html).not.toMatch(/<script/i);
  });

  it("is self-contained with a strict CSP that pins the inline style by hash", async () => {
    const report = await scan({ "src/a.ts": "// PLC_TEST_MARKER\n" }, { rules: [testRule000] });
    const html = await toHtml(report);
    const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html)?.[1];
    expect(csp).toBeDefined();
    expect(csp).toContain("default-src 'none'");
    expect(csp).not.toContain("unsafe-inline");
    const style = /<style>([\s\S]*?)<\/style>/.exec(html)![1]!;
    const digest = Buffer.from(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(style)),
    ).toString("base64");
    expect(csp).toContain(`style-src 'sha256-${digest}'`);
    // No external resources: no src= at all, and stylesheets are inline.
    expect(html).not.toMatch(/\ssrc\s*=/i);
    expect(html).not.toMatch(/<link[^>]+stylesheet/i);
    expect(html).toContain("TEST-000");
    expect(html).toContain("No blocking issues found");
  });
});
