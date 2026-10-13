import { describe, expect, it } from "vitest";
import { base32, computeFingerprintKey, sha256Hex } from "../src/fingerprint.js";
import type { RawFinding } from "../src/types.js";
import { SK_LIVE } from "./fake-secrets.js";

function raw(over: Partial<RawFinding> = {}): RawFinding {
  return {
    ruleId: "TEST-000",
    location: { kind: "file", path: "src/a.ts", line: 3 },
    evidence: { snippet: "const x = danger();", matchStart: 10, matchEnd: 16 },
    ...over,
  };
}

describe("fingerprint", () => {
  it("hashes with SHA-256 via Web Crypto", async () => {
    expect(await sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("encodes RFC 4648 base32", () => {
    expect(base32(new TextEncoder().encode("foobar"))).toBe("MZXW6YTBOI");
  });

  it("has the f1_ prefix and 20 base32 characters", async () => {
    const fp = await computeFingerprintKey(raw());
    expect(fp).toMatch(/^f1_[A-Z2-7]{20}$/);
  });

  it("is stable when the finding moves to another line", async () => {
    const a = await computeFingerprintKey(raw());
    const b = await computeFingerprintKey(
      raw({ location: { kind: "file", path: "src/a.ts", line: 99, column: 4 } }),
    );
    expect(a).toBe(b);
  });

  it("ignores whitespace differences in the match", async () => {
    const a = await computeFingerprintKey(
      raw({ evidence: { snippet: "danger(  1 )", matchStart: 0, matchEnd: 12 } }),
    );
    const b = await computeFingerprintKey(
      raw({ evidence: { snippet: "danger( 1 )", matchStart: 0, matchEnd: 11 } }),
    );
    expect(a).toBe(b);
  });

  it("differs for different paths, rules and matches", async () => {
    const base = await computeFingerprintKey(raw());
    expect(
      await computeFingerprintKey(raw({ location: { kind: "file", path: "src/b.ts", line: 3 } })),
    ).not.toBe(base);
    expect(await computeFingerprintKey(raw({ ruleId: "TEST-001" }))).not.toBe(base);
    expect(
      await computeFingerprintKey(
        raw({ evidence: { snippet: "const x = other();", matchStart: 10, matchEnd: 15 } }),
      ),
    ).not.toBe(base);
  });

  it("uses the secret value (not the redacted snippet) so the same key gives the same fingerprint", async () => {
    const a = await computeFingerprintKey(
      raw({
        secretValue: `${SK_LIVE}FAKEFAKEFAKEFAKEAAAA`,
        evidence: { snippet: `KEY=${SK_LIVE}FAKEFAKEFAKEFAKEAAAA` },
      }),
    );
    const b = await computeFingerprintKey(
      raw({
        secretValue: `${SK_LIVE}FAKEFAKEFAKEFAKEAAAA`,
        evidence: { snippet: `OTHER_NAME=${SK_LIVE}FAKEFAKEFAKEFAKEAAAA` },
      }),
    );
    const c = await computeFingerprintKey(
      raw({
        secretValue: `${SK_LIVE}FAKEFAKEFAKEFAKEBBBB`,
        evidence: { snippet: `KEY=${SK_LIVE}FAKEFAKEFAKEFAKEBBBB` },
      }),
    );
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });

  it("normalises URLs for url locations", async () => {
    const a = await computeFingerprintKey(
      raw({ location: { kind: "url", url: "https://Example.com:443/a#x" } }),
    );
    const b = await computeFingerprintKey(raw({ location: { kind: "url", url: "https://example.com/a" } }));
    expect(a).toBe(b);
  });
});
