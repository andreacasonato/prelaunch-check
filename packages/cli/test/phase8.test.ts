import { describe, expect, it } from "vitest";
import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { main } from "../src/main.js";
import { allFakeValues, makeIo, project, tempDir } from "./helpers.js";

const scan = (io: ReturnType<typeof makeIo>, ...args: string[]) =>
  main(["scan", ...args, "--no-gitleaks", "--offline"], io);

describe("baseline (APP-FLOW C-06)", () => {
  it("existing findings don't fail CI; one new finding does", async () => {
    const dir = project("vuln-next-supabase");
    expect(await scan(makeIo({ cwd: dir }), ".")).toBe(1);
    const baseline = join(tempDir(), "old-report.json");
    copyFileSync(join(dir, "prelaunch-check-report/prelaunch-check-report.json"), baseline);

    expect(await scan(makeIo({ cwd: dir }), ".", "--baseline", baseline, "--fail-on", "high")).toBe(0);

    writeFileSync(
      join(dir, "lib/danger.ts"),
      "export const run = (code: string) => eval(code);\nexport const q = (id: string) => db.query(`select * from users where id = ${id}`);\n",
    );
    const io = makeIo({ cwd: dir });
    expect(await scan(io, ".", "--baseline", baseline, "--fail-on", "high")).toBe(1);
    const report = JSON.parse(
      readFileSync(join(dir, "prelaunch-check-report/prelaunch-check-report.json"), "utf8"),
    );
    const fresh = report.findings.filter(
      (f: { existing?: boolean; severity: string }) => !f.existing && f.severity === "high",
    );
    expect(fresh.map((f: { ruleId: string }) => f.ruleId)).toEqual(["CODE-001"]);
  });

  it("rejects a baseline that isn't a report", async () => {
    const dir = project("clean-next-supabase");
    const bad = join(tempDir(), "x.json");
    writeFileSync(bad, '{"hello":1}');
    expect(await scan(makeIo({ cwd: dir }), ".", "--baseline", bad)).toBe(2);
  });
});

describe("SARIF and HTML output", () => {
  it("writes both, with no raw secrets or absolute paths", async () => {
    const dir = project("vuln-next-supabase");
    const io = makeIo({ cwd: dir });
    await scan(io, ".", "--format", "json,md,sarif,html");
    const sarif = readFileSync(join(dir, "prelaunch-check-report/prelaunch-check.sarif"), "utf8");
    const html = readFileSync(join(dir, "prelaunch-check-report/prelaunch-check-report.html"), "utf8");
    expect(JSON.parse(sarif).version).toBe("2.1.0");
    expect(html).toMatch(/^<!doctype html>/);
    for (const text of [sarif, html]) {
      expect(text).not.toContain(dir);
      for (const v of allFakeValues()) expect(text).not.toContain(v);
    }
    expect(io.out).toContain("prelaunch-check.sarif");
  });
});

describe("suppressions through the CLI", () => {
  it("inline suppressions with a reason stop a finding from failing the run", async () => {
    const dir = project("clean-next-supabase");
    writeFileSync(
      join(dir, "lib/run.ts"),
      "// prelaunch-check-ignore CODE-001: id comes from our own enum, never from users\nexport const q = (id: string) => db.query(`select * from t where id = ${id}`);\n",
    );
    expect(await scan(makeIo({ cwd: dir }), ".", "--fail-on", "high")).toBe(0);
    const report = JSON.parse(
      readFileSync(join(dir, "prelaunch-check-report/prelaunch-check-report.json"), "utf8"),
    );
    const f = report.findings.find((x: { ruleId: string }) => x.ruleId === "CODE-001");
    expect(f.status).toBe("accepted_risk");
    expect(f.decision.source).toBe("inline");
  });
});
