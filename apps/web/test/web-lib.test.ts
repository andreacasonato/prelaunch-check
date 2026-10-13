import { beforeEach, describe, expect, it } from "vitest";
import { validateReport } from "../src/lib/validate.js";
import { safeHref } from "../src/lib/rules.js";
import { applyDecisions, compare } from "../src/lib/report.js";
import type { Report } from "@prelaunch-check/core";

function report(): Report {
  return {
    schemaVersion: "1.0",
    tool: { name: "prelaunch-check", version: "0.2.0", rulesetVersion: "2026.10" },
    generatedAt: "2026-10-13T00:00:00Z",
    target: { kind: "folder", folderName: '<img src=x onerror="alert(1)">' },
    profile: {
      name: "x",
      frameworks: [],
      backends: [],
      services: [],
      packageManagers: [],
      lockfiles: [],
      buildDirs: [],
      publicEnvPrefixes: [],
      hasGit: false,
      supabaseMigrationsFound: false,
    },
    summary: {
      verdict: "blocked",
      score: 75,
      counts: { critical: 1, high: 0, medium: 0, low: 0, info: 0, worthChecking: 0, suppressed: 0 },
      scoring: {
        formula: "v1",
        weights: { critical: 25, high: 10, medium: 4, low: 1, info: 0 },
        perRuleCapMultiplier: 2,
      },
    },
    findings: [
      {
        fingerprint: "f1_AAAAAAAAAAAAAAAAAAAA",
        ruleId: "SEC-001",
        title: "<script>alert(1)</script>",
        category: "secrets",
        severity: "critical",
        confidence: "high",
        owasp: "A04",
        location: { kind: "file", path: '"><img onerror=alert(1)>.ts', line: 1 },
        evidence: { snippet: "<script>x</script>", detail: { url: "javascript:alert(1)" } },
        status: "open",
        fixPrompt: "fix",
      },
    ],
    coverage: {
      rulesRun: [],
      rulesSkipped: [],
      filesScanned: 1,
      filesSkipped: [],
      filesSkippedTotal: 0,
      notes: [],
      errors: [],
      online: { osv: "off", npmRegistry: "off" },
    },
    checklist: [],
  };
}

describe("validateReport", () => {
  it("accepts a well-formed report and keeps hostile strings as plain data", () => {
    const r = validateReport(JSON.stringify(report()));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.report.findings[0]!.title).toBe("<script>alert(1)</script>");
  });
  it("rejects invalid JSON, other tools' files and malformed findings", () => {
    expect(validateReport("{nope").ok).toBe(false);
    expect(validateReport(JSON.stringify({ hello: "world" })).ok).toBe(false);
    const bad = report() as unknown as { findings: Array<Record<string, unknown>> };
    bad.findings[0]!.severity = "apocalyptic";
    expect(validateReport(JSON.stringify(bad)).ok).toBe(false);
  });
  it("flags reports from a newer major version but still opens them", () => {
    const r = validateReport(JSON.stringify({ ...report(), schemaVersion: "2.0" }));
    expect(r.ok && r.newerVersion).toBe(true);
  });
});

describe("safeHref", () => {
  it("only allows http(s) links", () => {
    expect(safeHref("javascript:alert(1)")).toBeUndefined();
    expect(safeHref("data:text/html,<script>")).toBeUndefined();
    expect(safeHref("https://osv.dev/vulnerability/X")).toBe("https://osv.dev/vulnerability/X");
  });
});

describe("decisions and comparison", () => {
  it("excludes accepted risks from the verdict and score", () => {
    const r = applyDecisions(report(), {
      f1_AAAAAAAAAAAAAAAAAAAA: {
        status: "accepted_risk",
        reason: "test key",
        decidedAt: "2026-10-13T00:00:00Z",
      },
    });
    expect(r.summary.verdict).toBe("no_blocking");
    expect(r.summary.score).toBe(100);
    expect(r.findings[0]!.decision).toEqual({
      reason: "test key",
      decidedAt: "2026-10-13T00:00:00Z",
      source: "ui",
    });
  });
  it("computes new and fixed findings against the previous scan", () => {
    const c = compare(report(), ["f1_GONE"]);
    expect(c?.newFingerprints.has("f1_AAAAAAAAAAAAAAAAAAAA")).toBe(true);
    expect(c?.fixedCount).toBe(1);
  });
});

describe("storage when localStorage is unavailable", () => {
  beforeEach(() => {
    const throwing = {
      getItem: () => {
        throw new Error("SecurityError");
      },
      setItem: () => {
        throw new Error("QuotaExceededError");
      },
      removeItem: () => {
        throw new Error("SecurityError");
      },
    };
    Object.defineProperty(globalThis, "localStorage", { value: throwing, configurable: true });
  });
  it("never throws and falls back to defaults", async () => {
    const s = await import("../src/lib/storage.js");
    expect(s.storageAvailable()).toBe(false);
    expect(s.getTheme()).toBe("system");
    expect(() =>
      s.setDecision("p", "f1_X", {
        status: "false_positive",
        reason: "r",
        decidedAt: "2026-10-13T00:00:00Z",
      }),
    ).not.toThrow();
    expect(s.getDecisions("p")).toEqual({});
    expect(s.getLastScan("p")).toBeNull();
    expect(s.projectKey("My App!!/../x")).toBe("my-app-..-x");
  });
});
