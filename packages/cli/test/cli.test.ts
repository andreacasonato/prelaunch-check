import { describe, expect, it } from "vitest";
import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { main } from "../src/main.js";
import { NodeFileSource } from "../src/sources/node-files.js";
import { allFakeValues, json, makeIo, project, tempDir } from "./helpers.js";

const scan = (io: ReturnType<typeof makeIo>, ...args: string[]) =>
  main(["scan", ...args, "--no-gitleaks"], io);

describe("scan", () => {
  it("blocks the vulnerable fixture with exit code 1 and writes reports", async () => {
    const dir = project("vuln-next-supabase");
    const io = makeIo({ cwd: dir });
    expect(await scan(io, ".", "--offline", "--format", "json,md")).toBe(1);
    expect(io.out).toMatch(/^ BLOCKED +2 critical · 3 high/m);
    expect(io.out).toMatch(/CRITICAL +SEC-003 +Stripe live secret key/);
    expect(io.out).toContain("Report written: ./prelaunch-check-report/prelaunch-check-report.json");
    const reportText = readFileSync(join(dir, "prelaunch-check-report/prelaunch-check-report.json"), "utf8");
    const report = JSON.parse(reportText);
    expect(report.summary.verdict).toBe("blocked");
    expect(report.target.folderName).toBe("vuln-next-supabase");
    // Privacy: no absolute paths, no raw secrets, in any output.
    for (const text of [
      reportText,
      readFileSync(join(dir, "prelaunch-check-report/prelaunch-check-report.md"), "utf8"),
      io.out,
      io.err,
    ]) {
      expect(text).not.toContain(dir);
      for (const v of allFakeValues()) expect(text).not.toContain(v);
    }
  });

  it("passes the clean fixture with exit code 0", async () => {
    const io = makeIo({ cwd: project("clean-next-supabase") });
    expect(await scan(io, ".", "--offline")).toBe(0);
    expect(io.out).toMatch(/^ NO BLOCKING ISSUES FOUND/m);
  });

  it("--offline makes zero network requests", async () => {
    const io = makeIo({ cwd: project("vuln-next-supabase") });
    await scan(io, ".", "--offline");
    expect(io.fetchCalls).toEqual([]);
    const report = JSON.parse(
      readFileSync(join(io.cwd, "prelaunch-check-report/prelaunch-check-report.json"), "utf8"),
    );
    expect(report.coverage.online).toEqual({ osv: "off", npmRegistry: "off" });
    expect(report.coverage.rulesSkipped).toContainEqual({ ruleId: "DEP-001", reason: "offline" });
  });

  it("looks up dependencies online and reports OSV advisories", async () => {
    const dir = tempDir();
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({ name: "app", dependencies: { lodash: "^4.17.20" } }),
    );
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify(
        { lockfileVersion: 3, packages: { "": {}, "node_modules/lodash": { version: "4.17.20" } } },
        null,
        2,
      ),
    );
    const bodies: unknown[] = [];
    const io = makeIo({
      cwd: dir,
      fetch: async (input, init) => {
        const url = String(input);
        if (url.endsWith("/v1/querybatch")) {
          bodies.push(JSON.parse(String(init?.body)));
          return json({
            results: [{ vulns: [{ id: "GHSA-35jh-r3h4-6jhm", modified: "2024-01-01T00:00:00Z" }] }],
          });
        }
        if (url.includes("/v1/vulns/"))
          return json({
            id: "GHSA-35jh-r3h4-6jhm",
            summary: "Command Injection in lodash",
            aliases: ["CVE-2021-23337"],
            database_specific: { severity: "HIGH" },
            affected: [
              {
                package: { ecosystem: "npm", name: "lodash" },
                ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
              },
            ],
          });
        if (url.startsWith("https://registry.npmjs.org/"))
          return json({
            name: "lodash",
            versions: Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`4.0.${i}`, {}])),
          });
        return new Response("not found", { status: 404 });
      },
    });
    expect(await scan(io, ".")).toBe(1);
    // Only package names and versions leave the machine.
    expect(bodies).toEqual([
      { queries: [{ package: { ecosystem: "npm", name: "lodash" }, version: "4.17.20" }] },
    ]);
    expect(
      io.fetchCalls.every(
        (u) => u.startsWith("https://api.osv.dev/") || u.startsWith("https://registry.npmjs.org/"),
      ),
    ).toBe(true);
    const report = JSON.parse(
      readFileSync(join(dir, "prelaunch-check-report/prelaunch-check-report.json"), "utf8"),
    );
    const dep = report.findings.find((f: { ruleId: string }) => f.ruleId === "DEP-001");
    expect(dep).toMatchObject({ severity: "high", title: "lodash@4.17.20: Command Injection in lodash" });
    expect(dep.evidence.detail.fixedIn).toBe("4.17.21");
    expect(report.coverage.online).toEqual({ osv: "used", npmRegistry: "used" });
  });

  it("keeps going when the network fails, and says so", async () => {
    const io = makeIo({
      cwd: project("vuln-next-supabase"),
      fetch: async () => {
        throw new TypeError("fetch failed");
      },
    });
    expect(await scan(io, ".")).toBe(1);
    expect(io.err).toContain("Dependency check skipped");
    const report = JSON.parse(
      readFileSync(join(io.cwd, "prelaunch-check-report/prelaunch-check-report.json"), "utf8"),
    );
    // This fixture's lockfile is empty, so only the npm registry lookup ran (and failed).
    expect(report.coverage.online).toEqual({ osv: "used", npmRegistry: "failed" });
  });

  it("respects --fail-on", async () => {
    const dir = project("vuln-next-supabase");
    expect(await scan(makeIo({ cwd: dir }), ".", "--offline", "--fail-on", "none")).toBe(0);
    expect(await scan(makeIo({ cwd: dir }), ".", "--offline", "--fail-on", "critical")).toBe(1);
    expect(
      await scan(makeIo({ cwd: project("clean-next-supabase") }), ".", "--offline", "--fail-on", "low"),
    ).toBe(0);
  });

  it("uses exit code 2 for usage and config errors", async () => {
    const dir = project("clean-next-supabase");
    expect(await scan(makeIo({ cwd: dir }), ".", "--fail-on", "sometimes")).toBe(2);
    expect(await main(["scan", "--bogus"], makeIo({ cwd: dir }))).toBe(2);
    expect(await scan(makeIo({ cwd: dir }), ".", "--format", "pdf")).toBe(2);
    writeFileSync(
      join(dir, "prelaunch-check.config.json"),
      JSON.stringify({ suppressions: [{ ruleId: "DB-003" }] }),
    );
    const io = makeIo({ cwd: dir });
    expect(await scan(io, ".", "--offline")).toBe(2);
    expect(io.err).toContain('needs a non-empty "reason"');
  });

  it("uses exit code 3 when the folder can't be read", async () => {
    const io = makeIo({ cwd: tempDir() });
    expect(await scan(io, "does-not-exist")).toBe(3);
    expect(io.err).toContain("does the folder exist?");
  });

  it("applies config: disabled rules and ignorePaths", async () => {
    const dir = project("vuln-next-supabase");
    writeFileSync(
      join(dir, "prelaunch-check.config.json"),
      JSON.stringify({ rules: { "SEC-003": "off" }, ignorePaths: ["app/checkout/**"], online: false }),
    );
    const io = makeIo({ cwd: dir });
    await scan(io, ".");
    const report = JSON.parse(
      readFileSync(join(dir, "prelaunch-check-report/prelaunch-check-report.json"), "utf8"),
    );
    expect(
      report.findings.some((f: { ruleId: string }) => f.ruleId === "SEC-003" || f.ruleId === "CODE-006"),
    ).toBe(false);
    expect(io.fetchCalls).toEqual([]);
  });

  it("never scans its own report folder", async () => {
    const dir = project("vuln-next-supabase");
    await scan(makeIo({ cwd: dir }), ".", "--offline");
    const io = makeIo({ cwd: dir });
    await scan(io, ".", "--offline");
    const report = JSON.parse(
      readFileSync(join(dir, "prelaunch-check-report/prelaunch-check-report.json"), "utf8"),
    );
    expect(
      report.findings.every(
        (f: { location: { path?: string } }) => !f.location.path?.startsWith("prelaunch-check-report/"),
      ),
    ).toBe(true);
  });

  it("prints no colour codes when not a TTY or when NO_COLOR is set", async () => {
    const io = makeIo({ cwd: project("vuln-next-supabase"), env: { NO_COLOR: "1" } });
    io.isTTY = true;
    await scan(io, ".", "--offline", "--quiet");
    expect(io.out).not.toContain("\x1b[");
    expect(io.out.trim().split("\n")).toHaveLength(1);
  });
});

describe("other commands", () => {
  it("--version and --help", async () => {
    const io = makeIo({ cwd: tempDir() });
    expect(await main(["--version"], io)).toBe(0);
    expect(io.out.trim()).toMatch(/^\d+\.\d+\.\d+/);
    expect(await main(["--help"], io)).toBe(0);
    expect(io.out).toContain("prelaunch-check scan [path]");
  });

  it("explain prints rule docs, and suggests close IDs for unknown ones", async () => {
    const io = makeIo({ cwd: tempDir() });
    expect(await main(["explain", "db-003"], io)).toBe(0);
    expect(io.out).toContain("How to fix");
    expect(io.out).toContain("Sources");
    const bad = makeIo({ cwd: tempDir() });
    expect(await main(["explain", "DB-03"], bad)).toBe(2);
    expect(bad.err).toMatch(/Did you mean: DB-003/);
  });

  it("rules lists every rule, including SEC-006, as text and JSON", async () => {
    const io = makeIo({ cwd: tempDir() });
    expect(await main(["rules", "--json"], io)).toBe(0);
    const rules = JSON.parse(io.out) as Array<{ id: string; sources: unknown[] }>;
    expect(rules.map((r) => r.id)).toContain("SEC-006");
    expect(rules.map((r) => r.id)).toContain("DEP-001");
    expect(rules.every((r) => r.sources.length > 0)).toBe(true);
  });

  it("init writes a config once and offers the .gitignore entry", async () => {
    const dir = tempDir();
    const io = makeIo({ cwd: dir, confirm: true });
    expect(await main(["init"], io)).toBe(0);
    const config = JSON.parse(readFileSync(join(dir, "prelaunch-check.config.json"), "utf8"));
    expect(config.failOn).toBe("high");
    expect(readFileSync(join(dir, ".gitignore"), "utf8")).toContain("prelaunch-check-report/");
    expect(await main(["init"], makeIo({ cwd: dir }))).toBe(2);
    // The generated config is accepted by the scanner.
    writeFileSync(join(dir, "index.js"), "console.log(1);\n");
    expect(await scan(makeIo({ cwd: dir }), ".", "--offline")).toBe(0);
  });
});

describe("NodeFileSource", () => {
  it("doesn't follow symlinks, counts ignored folders, and refuses paths outside the root", async () => {
    const outside = tempDir();
    writeFileSync(join(outside, "secret.txt"), "outside");
    const dir = tempDir();
    writeFileSync(join(dir, "a.txt"), "a");
    mkdirSync(join(dir, "node_modules/x"), { recursive: true });
    writeFileSync(join(dir, "node_modules/x/index.js"), "x");
    symlinkSync(outside, join(dir, "linked"));
    symlinkSync(join(outside, "secret.txt"), join(dir, "link.txt"));
    const src = new NodeFileSource(dir);
    const listed: string[] = [];
    for await (const e of src.list()) listed.push(e.path);
    expect(listed.sort()).toEqual(["a.txt", "node_modules/x/index.js"]);
    expect(await src.readText("../" + outside.split("/").pop() + "/secret.txt")).toBeNull();
    expect(await src.isGitTracked("a.txt")).toBeNull();
    expect(existsSync(join(dir, "linked"))).toBe(true);
  });
});
