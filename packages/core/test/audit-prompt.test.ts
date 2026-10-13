import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { auditPrompt } from "../src/formats/audit-prompt.js";
import { DEFAULT_RULES } from "../src/rules/index.js";
import { REPO_ROOT } from "./support/fixtures.js";

describe("AUDIT-PROMPT.md", () => {
  it("is up to date with the rules (regenerate with: node packages/cli/dist/index.js audit-prompt > AUDIT-PROMPT.md)", () => {
    expect(readFileSync(join(REPO_ROOT, "AUDIT-PROMPT.md"), "utf8")).toBe(auditPrompt());
  });

  it("covers every user-facing rule and the whole checklist", () => {
    const text = auditPrompt();
    for (const r of DEFAULT_RULES)
      if (!r.meta.id.startsWith("CFG-INFO")) expect(text, r.meta.id).toContain(`**${r.meta.id} ·`);
    expect(text).toContain("**SEC-006 ·");
    expect(text).toContain("**MAN-018**");
    expect(text).not.toMatch(/sk_live_[A-Za-z0-9]{8}/);
  });
});
