import { describe, expect, it } from "vitest";
import {
  findDbUrls,
  findPrivateKeys,
  findPublishable,
  findSecrets,
  OVERLAP,
  WINDOW,
} from "../src/rules/secrets/scan.js";
import { PUBLISHABLE_PATTERNS, SECRET_PATTERNS, JWT_REGEX } from "../src/rules/secrets/patterns.js";
import { FAKE } from "./support/fixtures.js";
import { scan } from "./helpers.js";
import { testRule000 } from "../src/rules/test/TEST-000.js";
import { DEFAULT_RULES } from "../src/rules/index.js";

/** Hostile inputs: long runs of near-matches for each pattern's prefix. */
function adversarial(prefix: string): string[] {
  const mb = 1024 * 1024;
  const near = (prefix + "a").repeat(Math.ceil(mb / (prefix.length + 1))).slice(0, mb);
  return [near, prefix + "A".repeat(mb), (prefix + "0-").repeat(mb / (prefix.length + 2)), "x".repeat(mb)];
}

describe("regex safety (TRD §12)", () => {
  const all = [...SECRET_PATTERNS, ...PUBLISHABLE_PATTERNS];
  it.each(all.map((p) => [p.id, p] as const))("%s runs on 1 MB adversarial input in < 100 ms", (_id, p) => {
    for (const input of adversarial(p.keywords[0]!)) {
      const re = new RegExp(p.regex.source, p.regex.flags);
      // Best of three, so scheduler noise from parallel test files doesn't cause false failures.
      // A catastrophic pattern is slower by orders of magnitude and still fails.
      let best = Infinity;
      for (let attempt = 0; attempt < 3; attempt++) {
        const t0 = performance.now();
        // Scan the way the engine does: 64 KB windows.
        for (let off = 0; off < input.length; off += WINDOW - OVERLAP) {
          re.lastIndex = 0;
          const chunk = input.slice(off, off + WINDOW);
          while (re.exec(chunk) !== null) {
            /* drain */
          }
        }
        best = Math.min(best, performance.now() - t0);
      }
      expect(best).toBeLessThan(100);
    }
  });

  it("JWT, private-key and DB-URL scanners stay fast on hostile input", () => {
    const inputs = [
      "eyJ" + "a".repeat(1024 * 1024),
      ("eyJabcdefghijklmnopqrs.eyJ" + "b".repeat(30) + ".").repeat(20000),
      "-----BEGIN PRIVATE KEY-----".repeat(40000),
      "postgres://u:".repeat(80000),
      ("mongodb://" + "a".repeat(100) + ":" + "b".repeat(200)).repeat(3000),
    ];
    for (const input of inputs) {
      const t0 = performance.now();
      findSecrets(input);
      findPublishable(input);
      findPrivateKeys(input);
      findDbUrls(input);
      expect(performance.now() - t0).toBeLessThan(500);
    }
    expect(JWT_REGEX.flags).toContain("g");
  });
});

describe("secret scanning", () => {
  it("finds a key that straddles a 64 KB window boundary, exactly once", () => {
    const key = FAKE.STRIPE_SK_LIVE!;
    const text = "x".repeat(WINDOW - 10) + ` "${key}" ` + "y".repeat(1000);
    const found = findSecrets(text);
    expect(found).toHaveLength(1);
    expect(found[0]!.value).toBe(key);
    expect(found[0]!.start).toBe(WINDOW - 10 + 2);
  });

  it("finds keys in minified bundles larger than one window", () => {
    const text = Array.from({ length: 5 }, (_, i) => "a".repeat(30_000) + `k${i}="${FAKE.GITHUB_PAT}";`).join(
      "",
    );
    expect(findSecrets(text)).toHaveLength(5);
  });

  it("classifies legacy Supabase JWTs by role", () => {
    expect(findSecrets(`k="${FAKE.SUPABASE_SERVICE_JWT}"`).map((m) => m.pattern.id)).toEqual([
      "supabase-service-role-jwt",
    ]);
    expect(findSecrets(`k="${FAKE.SUPABASE_ANON_JWT}"`)).toEqual([]);
    expect(findPublishable(`k="${FAKE.SUPABASE_ANON_JWT}"`).map((m) => m.pattern.id)).toEqual([
      "supabase-anon-jwt",
    ]);
  });

  it("never reports publishable keys or placeholders as secrets", () => {
    const text = [
      FAKE.STRIPE_PK_LIVE,
      FAKE.STRIPE_PK_TEST,
      FAKE.SUPABASE_PUBLISHABLE,
      FAKE.FIREBASE_API_KEY,
      FAKE.STRIPE_SK_PLACEHOLDER,
      FAKE.AWS_EXAMPLE_KEY,
    ]
      .map((v) => `"${v}"`)
      .join("\n");
    expect(findSecrets(text)).toEqual([]);
  });

  it("redacts secrets that appear in context lines of an unrelated finding", async () => {
    const neighbour = FAKE.OPENAI_KEY!;
    const report = await scan(
      { "src/a.ts": `const k = "${neighbour}";\n// PLC_TEST_MARKER\n` },
      { rules: [testRule000] },
    );
    const f = report.findings[0]!;
    expect(f.evidence.snippet).not.toContain(neighbour);
    expect(f.evidence.snippet).toContain("sk-");
    expect(f.evidence.snippet!.slice(f.evidence.matchStart, f.evidence.matchEnd)).toBe("PLC_TEST_MARKER");
  });

  it("every rule cites at least one source and has fix steps", () => {
    for (const r of DEFAULT_RULES) {
      expect(r.meta.sources.length, r.meta.id).toBeGreaterThan(0);
      expect(r.meta.fix.length, r.meta.id).toBeGreaterThan(0);
      expect(r.meta.id).toMatch(/^[A-Z]{2,4}(-INV|-INFO)?-\d{3}$/);
    }
  });

  it("every ported pattern names its source", () => {
    for (const p of [...SECRET_PATTERNS, ...PUBLISHABLE_PATTERNS]) {
      expect(p.source.length).toBeGreaterThan(0);
      expect(p.sourceUrl).toMatch(/^https:\/\//);
    }
  });
});
