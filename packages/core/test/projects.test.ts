// Full-project fixtures (TRD §13). Expected findings are listed explicitly per project.
import { describe, expect, it } from "vitest";
import { join } from "node:path";
import { MemoryFileSource } from "../src/sources/memory.js";
import { runScan } from "../src/engine/runScan.js";
import { resolveConfig } from "../src/config.js";
import { FIXTURES, allFakeValues, loadFixtureDir } from "./support/fixtures.js";

async function scanProject(name: string) {
  return runScan({
    files: new MemoryFileSource(loadFixtureDir(join(FIXTURES, "projects", name))),
    folderName: name,
    config: resolveConfig({}).config,
    toolVersion: "0.0.0-test",
    now: new Date("2026-10-13T00:00:00Z"),
  });
}

const summary = (r: Awaited<ReturnType<typeof scanProject>>) =>
  r.findings.map(
    (f) => `${f.ruleId} ${f.severity} ${f.location.path}${f.location.line ? `:${f.location.line}` : ""}`,
  );

describe("vuln-vite-firebase", () => {
  it("shows the expected secret and config findings (DB rules arrive in Phase 4)", async () => {
    const r = await scanProject("vuln-vite-firebase");
    expect(r.profile.frameworks).toEqual(["vite", "react"]);
    expect(r.profile.backends).toEqual(["firebase"]);
    const s = summary(r);
    expect(s).toContain("SEC-001 critical src/checkout.ts:4");
    expect(s).toContain("SEC-003 critical .env:2");
    expect(s).toContain("SEC-004 high .env");
    expect(s).toContain("CFG-002 medium .gitignore");
    expect(s).toContain("SEC-INFO-001 info src/firebase.ts:4");
    expect(r.summary.verdict).toBe("blocked");
    const json = JSON.stringify(r);
    for (const v of allFakeValues()) expect(json).not.toContain(v);
  });
});
