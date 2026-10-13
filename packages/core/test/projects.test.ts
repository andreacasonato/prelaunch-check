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

describe("vuln-next-supabase", () => {
  it("is blocked, with the TRD §13 issues: NEXT_PUBLIC_ secret, table without RLS, credits editable, admin route without auth", async () => {
    const r = await scanProject("vuln-next-supabase");
    expect(r.profile.frameworks).toEqual(["next", "react"]);
    expect(r.profile.backends).toEqual(["supabase"]);
    expect(r.profile.services).toEqual(["stripe"]);
    const s = summary(r);
    expect(s).toContain("SEC-003 critical .env.local:3");
    expect(s).toContain("DB-001 high supabase/migrations/20260101000000_init.sql:2");
    expect(s).toContain("DB-003 high supabase/migrations/20260102000000_profiles.sql:4");
    expect(s).toContain("DB-003 high supabase/migrations/20260102000000_profiles.sql:5");
    expect(s).toContain("CODE-006 critical app/checkout/CheckoutButton.tsx:3");
    expect(s).toContain("CODE-INV-001 medium app/api/admin/users/route.ts:5");
    expect(r.summary.verdict).toBe("blocked");
    expect(r.endpoints?.map((e) => `${e.method} ${e.route} ${e.authCallSeen}`)).toEqual([
      "GET /api/admin/users false",
      "POST /api/notes true",
    ]);
    const json = JSON.stringify(r);
    for (const v of allFakeValues()) expect(json).not.toContain(v);
  });
});

describe("clean-next-supabase", () => {
  it("has zero critical or high findings, and DB-003 stays quiet once credits live in a read-only table", async () => {
    const r = await scanProject("clean-next-supabase");
    const bad = r.findings.filter((f) => f.severity === "critical" || f.severity === "high");
    expect(bad.map((f) => `${f.ruleId} ${f.location.path}:${f.location.line}`)).toEqual([]);
    expect(r.findings.filter((f) => f.ruleId === "DB-003")).toEqual([]);
    expect(r.summary.verdict).toBe("no_blocking");
    expect(r.coverage.errors).toEqual([]);
  });
});

describe("determinism on a real project fixture", () => {
  it("gives identical reports across runs", async () => {
    const a = await scanProject("vuln-next-supabase");
    const b = await scanProject("vuln-next-supabase");
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});
