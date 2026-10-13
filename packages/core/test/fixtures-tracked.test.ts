// Guard: every fixture file must be committable. A broad .gitignore rule (like "dist/")
// once hid fixture build folders, so tests passed locally and failed in CI.
import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { REPO_ROOT } from "./support/fixtures.js";

describe("fixtures", () => {
  it("contain no git-ignored files", () => {
    let ignored: string;
    try {
      ignored = execFileSync("git", ["ls-files", "--others", "--ignored", "--exclude-standard", "fixtures"], {
        cwd: REPO_ROOT,
        encoding: "utf8",
      });
    } catch {
      return; // git unavailable: nothing to check
    }
    expect(ignored.trim().split("\n").filter(Boolean)).toEqual([]);
  });
});
