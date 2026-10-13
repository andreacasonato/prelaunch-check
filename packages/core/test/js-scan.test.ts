import { describe, expect, it } from "vitest";
import { stripJs } from "../src/util/js-scan.js";

describe("stripJs", () => {
  it("blanks comments but keeps offsets and newlines", () => {
    const src = "a = 1; // eval(x)\n/* new Function(y)\n */ b = 2;";
    const out = stripJs(src);
    expect(out.length).toBe(src.length);
    expect(out).not.toContain("eval");
    expect(out).not.toContain("Function");
    expect(out.split("\n").length).toBe(3);
    expect(out).toContain("b = 2;");
  });

  it("does not treat // inside strings as comments", () => {
    const src = 'const u = "https://x.com"; eval(u);';
    expect(stripJs(src)).toContain("eval(u)");
  });

  it("optionally blanks string contents, including template literals with nested expressions", () => {
    const src = "const q = `select * from t where id = ${id + `x`}`; f('eval(x)')";
    const out = stripJs(src, { blankStrings: true });
    expect(out.length).toBe(src.length);
    expect(out).not.toContain("select");
    expect(out).toContain("${id + ` `}");
    expect(out).not.toContain("eval(x)");
  });

  it("handles regex literals containing quotes and slashes", () => {
    const src = 'const r = /["\\/]/g; eval(code); const d = a / b / c;';
    const out = stripJs(src, { blankStrings: true });
    expect(out).toContain("eval(code)");
    expect(out).toContain("a / b / c");
  });
});
