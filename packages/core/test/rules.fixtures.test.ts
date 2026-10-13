// Fixture runner: every rule folder in fixtures/rules/<ID>/ has positive* and negative* cases.
// Positives must produce exactly the findings in expected.json; negatives must produce none.
import { describe, expect, it } from "vitest";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DEFAULT_RULES } from "../src/rules/index.js";
import { MemoryFileSource } from "../src/sources/memory.js";
import { runScan } from "../src/engine/runScan.js";
import { resolveConfig } from "../src/config.js";
import {
  FIXTURES,
  allFakeValues,
  fixtureGitTracked,
  fixtureSite,
  loadFixtureDir,
} from "./support/fixtures.js";
import type { OnlineServices, OsvVulnSummary, SiteSnapshot } from "../src/types.js";

/** Recorded online answers (online.json in a fixture case): no network in tests. */
function recordedOnline(dir: string): OnlineServices | undefined {
  const file = join(dir, "online.json");
  if (!existsSync(file)) return undefined;
  const data = JSON.parse(readFileSync(file, "utf8")) as {
    osv?: Record<string, string[]>;
    vulns?: Record<string, OsvVulnSummary>;
    npm?: Record<string, { exists: boolean; createdAt?: string }>;
  };
  return {
    osvQueryBatch: async (pkgs) =>
      pkgs.map((pkg) => ({ pkg, vulnIds: data.osv?.[`${pkg.name}@${pkg.version}`] ?? [] })),
    osvGetVuln: async (id) => {
      const v = data.vulns?.[id];
      if (!v) throw new Error(`no recorded vuln ${id}`);
      return v;
    },
    npmPackageInfo: async (name) => {
      const v = data.npm?.[name];
      if (!v) throw new Error(`no recorded npm answer for ${name}`);
      return v;
    },
  };
}

const RULES_DIR = join(FIXTURES, "rules");
const RECORD = process.env.PLC_RECORD === "1";

interface Expected {
  path: string;
  line: number | null;
  severity: string;
  confidence: string;
}

async function scanCase(ruleId: string, dir: string) {
  const rule = DEFAULT_RULES.find((r) => r.meta.id === ruleId);
  if (!rule) throw new Error(`No registered rule ${ruleId}`);
  const tracked = fixtureGitTracked(dir);
  const fileMap = loadFixtureDir(dir);
  const files = new MemoryFileSource(fileMap, tracked ? { gitTracked: tracked } : {});
  const online = recordedOnline(dir);
  const site = fixtureSite<SiteSnapshot>(dir);
  return runScan({
    ...(online ? { online } : {}),
    ...(site ? { site } : {}),
    ...(Object.keys(fileMap).length || !site ? { files } : {}),
    folderName: "fixture",
    config: resolveConfig({}).config,
    toolVersion: "0.0.0-test",
    now: new Date("2026-10-13T00:00:00Z"),
    rules: [rule],
  });
}

const ruleIds = readdirSync(RULES_DIR).sort();

describe("every registered rule has positive and negative fixtures", () => {
  it.each(DEFAULT_RULES.map((r) => r.meta.id))("%s", (id) => {
    const cases = existsSync(join(RULES_DIR, id)) ? readdirSync(join(RULES_DIR, id)) : [];
    expect(cases.some((c) => c.startsWith("positive"))).toBe(true);
    expect(cases.some((c) => c.startsWith("negative"))).toBe(true);
  });
});

for (const ruleId of ruleIds) {
  describe(ruleId, () => {
    const cases = readdirSync(join(RULES_DIR, ruleId)).sort();
    for (const c of cases) {
      const dir = join(RULES_DIR, ruleId, c);
      it(c, async () => {
        const report = await scanCase(ruleId, dir);
        expect(report.coverage.errors).toEqual([]);
        const json = JSON.stringify(report);
        for (const v of allFakeValues())
          expect(json, "raw fake value leaked into the report").not.toContain(v);
        const got: Expected[] = report.findings
          .filter((f) => f.ruleId === ruleId)
          .map((f) => ({
            path: f.location.path ?? f.location.url ?? "",
            line: f.location.line ?? null,
            severity: f.severity,
            confidence: f.confidence,
          }))
          .sort((a, b) => (a.path === b.path ? (a.line ?? 0) - (b.line ?? 0) : a.path < b.path ? -1 : 1));
        if (c.startsWith("negative")) {
          expect(got).toEqual([]);
          return;
        }
        const expectedFile = join(dir, "expected.json");
        if (RECORD) {
          writeFileSync(expectedFile, JSON.stringify(got, null, 2) + "\n");
          console.log(
            `${ruleId}/${c}:`,
            report.findings.map(
              (f) =>
                `${f.location.path}:${f.location.line} ${f.severity}/${f.confidence} ${f.title} | ${f.evidence.snippet?.split("\n").find((l) => l.includes("…") || l.includes("••••")) ?? ""}`,
            ),
          );
        }
        expect(got.length).toBeGreaterThan(0);
        expect(got).toEqual(JSON.parse(readFileSync(expectedFile, "utf8")));
      });
    }
  });
}
