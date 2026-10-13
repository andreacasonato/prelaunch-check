import { describe, expect, it } from "vitest";
import { scan } from "./helpers.js";
import { testRule000 } from "../src/rules/test/TEST-000.js";
import { toMarkdown } from "../src/formats/markdown.js";

describe("toMarkdown", () => {
  it("renders verdict, score, findings, coverage and checklist", async () => {
    const report = await scan(
      { "src/a.ts": "x\n// PLC_TEST_MARKER ```` tricky\n" },
      { rules: [testRule000] },
    );
    const md = toMarkdown(report);
    expect(md).toContain("# Prelaunch Check report: my-app");
    expect(md).toContain("**No blocking issues found**");
    expect(md).toContain("Score: 99 / 100");
    expect(md).toContain("TEST-000");
    expect(md).toContain("`src/a.ts:2`");
    expect(md).toContain("## Pre-launch checklist");
    expect(md).toContain("- [ ] **MAN-001**");
    // Fence must be longer than any backtick run inside the snippet.
    expect(md).toContain("`````");
  });
});
