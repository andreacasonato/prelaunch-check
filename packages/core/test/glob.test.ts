import { describe, expect, it } from "vitest";
import { globToRegExp, matchGlob } from "../src/files/glob.js";

describe("glob", () => {
  it.each([
    ["**/*.sql", "supabase/migrations/0001.sql", true],
    ["**/*.sql", "init.sql", true],
    ["*.sql", "a/init.sql", false],
    ["src/**", "src/a/b.ts", true],
    ["src/**", "srcx/a.ts", false],
    [".github/workflows/*.{yml,yaml}", ".github/workflows/ci.yaml", true],
    ["app/**/route.{ts,js}", "app/api/users/route.ts", true],
    ["app/**/route.{ts,js}", "app/route.ts", true],
    ["file?.txt", "file1.txt", true],
    ["a.b", "aXb", false],
  ])("%s vs %s → %s", (pattern, path, expected) => {
    expect(matchGlob(pattern, path)).toBe(expected);
  });

  it("produces linear-safe regexes without nested quantifiers", () => {
    const src = globToRegExp("**/a/**/b/**/*.ts").source;
    expect(src).not.toMatch(/\([^)]*[*+]\)[*+]/);
  });
});
