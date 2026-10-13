// SARIF 2.1.0 output, validated against the official OASIS schema.
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import Ajv from "ajv-draft-04";
import { toSarif, SECURITY_SEVERITY } from "../src/formats/sarif.js";
import { MemoryFileSource } from "../src/sources/memory.js";
import { runScan } from "../src/engine/runScan.js";
import { resolveConfig } from "../src/config.js";
import { FIXTURES, loadFixtureDir } from "./support/fixtures.js";
import type { SiteSnapshot } from "../src/types.js";

const schema = JSON.parse(
  readFileSync(new URL("./schemas/sarif-schema-2.1.0.json", import.meta.url), "utf8"),
);
const validate = new Ajv({ strict: false, allErrors: true }).compile(schema);

async function sampleReport() {
  const site = JSON.parse(readFileSync(join(FIXTURES, "sites/bad.json"), "utf8")) as SiteSnapshot;
  return runScan({
    files: new MemoryFileSource(loadFixtureDir(join(FIXTURES, "projects/vuln-next-supabase"))),
    site,
    folderName: "vuln-next-supabase",
    config: resolveConfig({ suppressions: [{ ruleId: "DB-006", reason: "accepted for the demo" }] }).config,
    toolVersion: "0.3.0-test",
    now: new Date("2026-10-13T00:00:00Z"),
  });
}

describe("toSarif", () => {
  it("validates against the SARIF 2.1.0 schema", async () => {
    const sarif = toSarif(await sampleReport());
    const ok = validate(sarif);
    expect(validate.errors ?? []).toEqual([]);
    expect(ok).toBe(true);
  });

  it("maps rules, levels, security-severity, fingerprints and locations", async () => {
    const report = await sampleReport();
    const sarif = toSarif(report);
    const run = sarif.runs[0]!;
    expect(sarif.version).toBe("2.1.0");
    expect(run.tool.driver.name).toBe("prelaunch-check");
    const ids = run.tool.driver.rules.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    const sec003 = run.tool.driver.rules.find((r) => r.id === "SEC-003")!;
    expect(sec003.properties["security-severity"]).toBe(SECURITY_SEVERITY.critical);
    expect(sec003.defaultConfiguration.level).toBe("error");
    const result = run.results.find((r) => r.ruleId === "SEC-003")!;
    expect(result.level).toBe("error");
    expect(run.tool.driver.rules[result.ruleIndex]!.id).toBe("SEC-003");
    expect(result.partialFingerprints["prelaunchCheck/v1"]).toBe(
      report.findings.find((f) => f.ruleId === "SEC-003")!.fingerprint,
    );
    expect(result.locations[0]!.physicalLocation.artifactLocation.uri).toBe(".env.local");
    expect(result.locations[0]!.physicalLocation.region?.startLine).toBe(3);
    // WEB findings use the URL as the artifact location.
    const web = run.results.find((r) => r.ruleId.startsWith("WEB-"))!;
    expect(web.locations[0]!.physicalLocation.artifactLocation.uri).toMatch(/^https?:\/\//);
    // Accepted risks are reported as suppressed, with the reason.
    const sup = run.results.find((r) => r.ruleId === "DB-006")!;
    expect(sup.suppressions?.[0]).toEqual({ kind: "external", justification: "accepted for the demo" });
    // Info findings are notes without security-severity.
    const info = run.tool.driver.rules.find((r) => r.id === "SEC-INFO-001")!;
    expect(info.properties["security-severity"]).toBeUndefined();
    // No raw secrets.
    expect(JSON.stringify(sarif)).not.toMatch(/sk_live_[A-Za-z0-9]{10}/);
  });
});
