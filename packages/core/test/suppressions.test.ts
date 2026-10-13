import { describe, expect, it } from "vitest";
import { scan } from "./helpers.js";
import { testRule000 } from "../src/rules/test/TEST-000.js";
import { resolveConfig } from "../src/config.js";
import { CFG_INFO_001 } from "../src/rules/config/CFG-INFO-001.js";
import { CFG_INFO_002 } from "../src/rules/config/CFG-INFO-002.js";

const rules = [testRule000, CFG_INFO_001, CFG_INFO_002];

describe("inline suppressions", () => {
  it("apply to the same line or the next non-blank line, and need a reason", async () => {
    const r = await scan(
      {
        "src/a.ts": [
          'call("PLC_TEST_MARKER"); // prelaunch-check-ignore TEST-000: same-line reason', // 1: suppressed (same line)
          "// prelaunch-check-ignore TEST-000,CODE-001: next-line reason", //       2
          "", //                                                                   3
          "// PLC_TEST_MARKER", //                                                 4: suppressed (next non-blank)
          "# prelaunch-check-ignore TEST-000", //                                  5: no reason → CFG-INFO-001
          "PLC_TEST_MARKER", //                                                    6: open
          "-- prelaunch-check-ignore OTHER-001: wrong rule", //                    7
          "PLC_TEST_MARKER", //                                                    8: open
        ].join("\n"),
      },
      { rules },
    );
    const markers = r.findings
      .filter((f) => f.ruleId === "TEST-000")
      .map((f) => `${f.location.line}:${f.status}`);
    expect(markers).toEqual(["1:accepted_risk", "4:accepted_risk", "6:open", "8:open"]);
    const s = r.findings.find((f) => f.location.line === 4 && f.ruleId === "TEST-000")!;
    expect(s.decision).toEqual({
      reason: "next-line reason",
      decidedAt: "2026-10-13T14:02:11Z",
      source: "inline",
    });
    expect(r.findings.filter((f) => f.ruleId === "CFG-INFO-001").map((f) => f.location.line)).toEqual([5]);
    // Suppressed findings stay listed but don't count.
    expect(r.summary.counts.suppressed).toBe(2);
  });
});

describe("config suppressions", () => {
  it("match by rule + path glob or by fingerprint, and stop applying after they expire", async () => {
    const files = {
      "src/a.ts": "PLC_TEST_MARKER\n",
      "lib/b.ts": "PLC_TEST_MARKER\n",
      "lib/c.ts": "PLC_TEST_MARKER\n",
    };
    const first = await scan(files, { rules });
    const cFp = first.findings.find((f) => f.location.path === "lib/c.ts")!.fingerprint;
    const r = await scan(files, {
      rules,
      config: resolveConfig({
        suppressions: [
          { ruleId: "TEST-000", path: "src/**", reason: "src is generated" },
          { ruleId: "TEST-000", fingerprint: cFp, reason: "known", expires: "2026-01-01" },
        ],
      }).config,
    });
    const by = (p: string) => r.findings.find((f) => f.location.path === p && f.ruleId === "TEST-000")!;
    expect(by("src/a.ts").status).toBe("accepted_risk");
    expect(by("src/a.ts").decision?.source).toBe("config");
    expect(by("lib/b.ts").status).toBe("open");
    expect(by("lib/c.ts").status).toBe("open"); // expired
    const expired = r.findings.filter((f) => f.ruleId === "CFG-INFO-002");
    expect(expired).toHaveLength(1);
    expect(expired[0]!.title).toMatch(/expired/i);
  });
});

describe("baseline", () => {
  it("marks findings present in the baseline as existing", async () => {
    const files = { "src/a.ts": "PLC_TEST_MARKER\n" };
    const first = await scan(files, { rules: [testRule000] });
    const second = await scan(
      { ...files, "src/new.ts": "PLC_TEST_MARKER\n" },
      { rules: [testRule000], baseline: first.findings.map((f) => f.fingerprint) },
    );
    expect(second.findings.map((f) => `${f.location.path}:${f.existing ?? false}`)).toEqual([
      "src/a.ts:true",
      "src/new.ts:false",
    ]);
  });
});
