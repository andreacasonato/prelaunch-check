import { describe, expect, it } from "vitest";
import { createGitignoreMatcher } from "../src/files/gitignore.js";

describe("gitignore matcher", () => {
  const m = createGitignoreMatcher({
    ".gitignore": [
      "# comment",
      "node_modules",
      ".env*",
      "!.env.example",
      "/build/",
      "*.log",
      "docs/**/*.tmp",
      "secret[0-9].txt",
      "\\#literal",
    ].join("\n"),
    "apps/web/.gitignore": "local.json\n!keep.log\n",
  });

  it.each([
    ["node_modules/react/index.js", true],
    ["apps/web/node_modules/x.js", true],
    [".env", true],
    [".env.local", true],
    ["apps/web/.env.production", true],
    [".env.example", false],
    ["build/out.js", true],
    ["src/build/out.js", false],
    ["server.log", true],
    ["docs/a/b/c.tmp", true],
    ["docs/c.tmp", true],
    ["secret1.txt", true],
    ["secretX.txt", false],
    ["#literal", true],
    ["apps/web/local.json", true],
    ["local.json", false],
    ["apps/web/keep.log", false],
    ["src/index.ts", false],
  ])("%s → %s", (path, ignored) => {
    expect(m.isIgnored(path)).toBe(ignored);
  });

  it("can't re-include a file inside an ignored directory", () => {
    const n = createGitignoreMatcher({ ".gitignore": "secrets/\n!secrets/ok.txt\n" });
    expect(n.isIgnored("secrets/ok.txt")).toBe(true);
  });

  it("reports when there are no rules", () => {
    expect(createGitignoreMatcher({}).hasRules).toBe(false);
  });
});
