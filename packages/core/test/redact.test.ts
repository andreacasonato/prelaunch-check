import { describe, expect, it } from "vitest";
import { redact, redactAll } from "../src/redact.js";
import { SK_LIVE } from "./fake-secrets.js";

describe("redact", () => {
  it("fully hides values of 12 characters or fewer", () => {
    expect(redact("")).toBe("••••");
    expect(redact("abc")).toBe("••••");
    expect(redact("123456789012")).toBe("••••");
  });

  it("keeps the first 4 and last 4 characters of longer values", () => {
    expect(redact("1234567890123")).toBe("1234…0123");
    expect(redact(`${SK_LIVE}FAKEFAKEFAKEFAKE9xQz`)).toBe("sk_l…9xQz");
  });

  it("counts code points, not UTF-16 units, so multi-byte characters are never split", () => {
    const value = "🔑🔑🔑🔑-secret-value-🗝️🗝";
    const out = redact(value);
    expect(out.startsWith("🔑🔑🔑🔑")).toBe(true);
    expect(out).not.toMatch(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/); // no lone high surrogate
    expect(out).not.toMatch(/(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/); // no lone low surrogate
    expect(redact("ééééééééééééé")).toBe("éééé…éééé");
  });

  it("never returns the input for any length", () => {
    for (let n = 0; n < 40; n++) {
      const value = "x".repeat(n) + "SECRET";
      expect(redact(value)).not.toBe(value);
      expect(redact(value).length).toBeLessThan(Math.max(value.length, 5));
    }
  });

  it("replaces every occurrence of a secret inside a larger string", () => {
    const secret = `${SK_LIVE}FAKEFAKEFAKEFAKE9xQz`;
    const text = `A=${secret}\nB=${secret}`;
    expect(redactAll(text, secret)).toBe("A=sk_l…9xQz\nB=sk_l…9xQz");
  });
});
