import { describe, expect, it } from "vitest";
import { scan, FIXED_NOW } from "./helpers.js";
import { testRule000 } from "../src/rules/test/TEST-000.js";
import { resolveConfig } from "../src/config.js";
import type { Rule } from "../src/types.js";
import { SK_LIVE } from "./fake-secrets.js";

const files = {
  "package.json": JSON.stringify({ name: "my-app", dependencies: { next: "15.0.0" } }),
  "src/a.ts": "line1\n// PLC_TEST_MARKER here\nline3\n",
  "src/b.ts": "// PLC_TEST_MARKER\n// PLC_TEST_MARKER\n",
  "node_modules/lib/index.js": "// PLC_TEST_MARKER in a dependency",
};

describe("runScan", () => {
  it("produces a schema-shaped report", async () => {
    const report = await scan(files, { rules: [testRule000] });
    expect(report.schemaVersion).toBe("1.0");
    expect(report.tool.name).toBe("prelaunch-check");
    expect(report.tool.version).toBe("0.0.0-test");
    expect(report.generatedAt).toBe("2026-10-13T14:02:11Z");
    expect(report.target).toEqual({ kind: "folder", folderName: "my-app" });
    expect(report.summary.scoring).toEqual({
      formula: "v1",
      weights: { critical: 25, high: 10, medium: 4, low: 1, info: 0 },
      perRuleCapMultiplier: 2,
    });
    expect(report.checklist).toHaveLength(31);
    expect(report.coverage.rulesRun).toEqual(["TEST-000"]);
  });

  it("skips always-ignored directories before reading them", async () => {
    const report = await scan(files, { rules: [testRule000] });
    expect(report.findings.map((x) => x.location.path)).not.toContain("node_modules/lib/index.js");
    expect(report.coverage.filesSkipped).toContainEqual({ path: "node_modules/", reason: "ignored_dir" });
    expect(report.coverage.filesSkippedTotal).toBe(1);
    expect(report.coverage.filesScanned).toBe(3);
  });

  it("disambiguates identical matches in one file with #2, #3", async () => {
    const report = await scan(files, { rules: [testRule000] });
    const b = report.findings.filter((x) => x.location.path === "src/b.ts").map((x) => x.fingerprint);
    expect(b).toHaveLength(2);
    expect(b[1]).toBe(`${b[0]}#2`);
  });

  it("is deterministic: two runs give identical JSON apart from generatedAt", async () => {
    const a = await scan(files, { rules: [testRule000], now: FIXED_NOW });
    const b = await scan(files, { rules: [testRule000], now: new Date("2027-01-01T00:00:00Z") });
    const strip = (r: typeof a) => JSON.stringify({ ...r, generatedAt: "" });
    expect(strip(a)).toBe(strip(b));
  });

  it("is deterministic regardless of the order files are listed", async () => {
    const reversed = Object.fromEntries(Object.entries(files).reverse());
    const a = await scan(files, { rules: [testRule000] });
    const b = await scan(reversed, { rules: [testRule000] });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });

  it("never puts an absolute path in the report (privacy)", async () => {
    const report = await scan(files, { rules: [testRule000], folderName: "/Users/alice/projects/my-app" });
    const json = JSON.stringify(report);
    expect(report.target.folderName).toBe("my-app");
    expect(json).not.toContain("/Users/");
    expect(json).not.toContain("alice");
    expect(json).not.toMatch(/"path":"\//);
  });

  it("drops absolute or traversal paths a FileSource might return", async () => {
    const report = await scan(
      {
        "/etc/passwd": "PLC_TEST_MARKER",
        "../outside.ts": "PLC_TEST_MARKER",
        "./src/ok.ts": "PLC_TEST_MARKER",
      },
      { rules: [testRule000] },
    );
    expect(report.findings.map((x) => x.location.path)).toEqual(["src/ok.ts"]);
  });

  it("catches a crashing rule into coverage.errors and keeps going", async () => {
    const boom: Rule = {
      meta: { ...testRule000.meta, id: "TEST-999" },
      async check() {
        throw new Error("kaboom");
      },
    };
    const report = await scan(files, { rules: [boom, testRule000] });
    expect(report.coverage.errors).toEqual([{ ruleId: "TEST-999", message: "kaboom" }]);
    expect(report.findings.length).toBeGreaterThan(0);
  });

  it("skips rules disabled in config and applies severity overrides", async () => {
    const off = await scan(files, {
      rules: [testRule000],
      config: resolveConfig({ rules: { "TEST-000": "off" } }).config,
    });
    expect(off.findings).toHaveLength(0);
    expect(off.coverage.rulesSkipped).toEqual([{ ruleId: "TEST-000", reason: "disabled_by_config" }]);

    const regraded = await scan(files, {
      rules: [testRule000],
      config: resolveConfig({ rules: { "TEST-000": { severity: "critical" } } }).config,
    });
    expect(regraded.findings.every((x) => x.severity === "critical")).toBe(true);
    expect(regraded.summary.verdict).toBe("blocked");
  });

  it("skips site rules without a URL and online rules when offline", async () => {
    const siteRule: Rule = {
      meta: { ...testRule000.meta, id: "TEST-101", requires: ["site"] },
      check: async () => [],
    };
    const onlineRule: Rule = {
      meta: { ...testRule000.meta, id: "TEST-102", requires: ["files", "online"] },
      check: async () => [],
    };
    const report = await scan(files, { rules: [siteRule, onlineRule] });
    expect(report.coverage.rulesSkipped).toEqual([
      { ruleId: "TEST-101", reason: "no_url" },
      { ruleId: "TEST-102", reason: "offline" },
    ]);
    expect(report.coverage.online).toEqual({ osv: "off", npmRegistry: "off" });
  });

  it("skips rules whose appliesWhen is false", async () => {
    const supa: Rule = {
      meta: { ...testRule000.meta, id: "TEST-103", appliesWhen: (p) => p.backends.includes("supabase") },
      check: async () => [],
    };
    const report = await scan(files, { rules: [supa] });
    expect(report.coverage.rulesSkipped).toEqual([{ ruleId: "TEST-103", reason: "not_applicable" }]);
  });

  it("skips files over the size cap and binary files", async () => {
    const big = "PLC_TEST_MARKER" + "x".repeat(200);
    const report = await scan(
      { "big.txt": big, "bin.dat": "PLC_TEST_MARKER\u0000\u0001", "ok.txt": "PLC_TEST_MARKER" },
      { rules: [testRule000], config: resolveConfig({ maxFileSizeBytes: 100 }).config },
    );
    expect(report.findings.map((x) => x.location.path)).toEqual(["ok.txt"]);
    expect(report.coverage.filesSkipped).toEqual([
      { path: "big.txt", reason: "too_large" },
      { path: "bin.dat", reason: "binary" },
    ]);
  });

  it("caps coverage.filesSkipped at 200 entries but keeps the total", async () => {
    const many: Record<string, string> = {};
    for (let i = 0; i < 250; i++) many[`blob${String(i).padStart(3, "0")}.bin`] = "\u0000";
    const report = await scan(many, { rules: [testRule000] });
    expect(report.coverage.filesSkipped).toHaveLength(200);
    expect(report.coverage.filesSkippedTotal).toBe(250);
  });

  it("honours config ignorePaths globs", async () => {
    const report = await scan(files, {
      rules: [testRule000],
      config: resolveConfig({ ignorePaths: ["src/b.ts"] }).config,
    });
    expect(report.findings.map((x) => x.location.path)).toEqual(["src/a.ts"]);
  });

  it("sorts findings by severity, confidence, category, path, line", async () => {
    const multi: Rule = {
      meta: { ...testRule000.meta, id: "TEST-200" },
      async check() {
        return [
          {
            ruleId: "TEST-200",
            severity: "low",
            location: { kind: "file", path: "a.ts", line: 1 },
            evidence: { snippet: "1" },
          },
          {
            ruleId: "TEST-200",
            severity: "critical",
            confidence: "medium",
            location: { kind: "file", path: "z.ts", line: 9 },
            evidence: { snippet: "2" },
          },
          {
            ruleId: "TEST-200",
            severity: "critical",
            location: { kind: "file", path: "z.ts", line: 2 },
            evidence: { snippet: "3" },
          },
          {
            ruleId: "TEST-200",
            severity: "critical",
            location: { kind: "file", path: "b.ts", line: 5 },
            evidence: { snippet: "4" },
          },
        ];
      },
    };
    const report = await scan(files, { rules: [multi] });
    expect(
      report.findings.map((x) => `${x.severity}/${x.confidence}/${x.location.path}:${x.location.line}`),
    ).toEqual(["critical/high/b.ts:5", "critical/high/z.ts:2", "critical/medium/z.ts:9", "low/high/a.ts:1"]);
  });

  it("redacts secrets everywhere and removes secretValue before output", async () => {
    const secret = `${SK_LIVE}FAKEFAKEFAKEFAKEFAKE1234`;
    const leaky: Rule = {
      meta: { ...testRule000.meta, id: "TEST-300", fixPromptTemplate: "Rotate {{detail.value}} in {{path}}" },
      async check() {
        return [
          {
            ruleId: "TEST-300",
            title: `Found ${secret}`,
            location: { kind: "file", path: "x.ts", line: 1 },
            evidence: {
              snippet: `const k = "${secret}";`,
              matchStart: 11,
              matchEnd: 11 + secret.length,
              detail: { value: secret },
            },
            secretValue: secret,
          },
        ];
      },
    };
    const report = await scan(files, { rules: [leaky] });
    const json = JSON.stringify(report);
    expect(json).not.toContain(secret);
    expect(json).not.toContain("secretValue");
    const finding = report.findings[0]!;
    expect(finding.evidence.snippet).toBe('const k = "sk_l…1234";');
    expect(finding.evidence.snippet!.slice(finding.evidence.matchStart, finding.evidence.matchEnd)).toBe(
      "sk_l…1234",
    );
    expect(finding.fixPrompt).toBe("Rotate sk_l…1234 in x.ts");
  });

  it("adds the Supabase-without-migrations coverage note", async () => {
    const report = await scan(
      { "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "2.0.0" } }) },
      { rules: [testRule000] },
    );
    expect(report.coverage.notes.join(" ")).toMatch(/Supabase detected but no migration files/);
  });

  it("reports progress stages", async () => {
    const stages: string[] = [];
    await scan(files, { rules: [testRule000], onProgress: (p) => stages.push(p.stage) });
    expect(stages[0]).toBe("reading");
    expect(stages).toContain("detecting");
    expect(stages.at(-1)).toBe("building");
  });

  it("stops when aborted", async () => {
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(scan(files, { rules: [testRule000], signal: ctrl.signal })).rejects.toThrow(/abort/i);
  });
});
