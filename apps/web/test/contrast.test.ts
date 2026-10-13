// Contrast (Phase 7 acceptance): WCAG ratios for every text/background token pair in tokens.css,
// including the tinted severity backgrounds. Every text pair must be ≥ 4.5:1.
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("../src/styles/tokens.css", import.meta.url), "utf8");

function block(selector: string): Record<string, string> {
  const start = css.indexOf(selector);
  const body = css.slice(css.indexOf("{", start) + 1, css.indexOf("}", start));
  const out: Record<string, string> = {};
  for (const m of body.matchAll(/--([\w-]+):\s*([^;]+);/g)) out[m[1]!] = m[2]!.trim();
  return out;
}

const light = block(":root {");
const dark = { ...light, ...block(':root[data-theme="dark"]') };
const tint = Number(light.tint!.replace("%", "")) / 100;

function rgb(hex: string): [number, number, number] {
  const h = hex.replace("#", "");
  return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16)) as [number, number, number];
}
function lum([r, g, b]: [number, number, number]): number {
  const f = (c: number) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
}
function ratio(a: [number, number, number], b: [number, number, number]): number {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x! + 0.05) / (y! + 0.05);
}
function mix(
  fg: [number, number, number],
  bg: [number, number, number],
  p: number,
): [number, number, number] {
  return fg.map((c, i) => Math.round(c * p + bg[i]! * (1 - p))) as [number, number, number];
}

function resolve(theme: Record<string, string>, name: string): [number, number, number] {
  let v = theme[name]!;
  while (v.startsWith("var(--")) v = theme[v.slice(6, -1)]!;
  return rgb(v);
}

const TEXT = [
  "text",
  "text-muted",
  "accent",
  "sev-critical",
  "sev-high",
  "sev-medium",
  "sev-low",
  "sev-info",
];
const SEV = ["critical", "high", "medium", "low", "info"];

describe.each([
  ["light", light],
  ["dark", dark],
])("%s theme", (_name, theme) => {
  it.each(TEXT)("%s is ≥ 4.5:1 on --bg and --surface", (t) => {
    expect(ratio(resolve(theme, t), resolve(theme, "bg"))).toBeGreaterThanOrEqual(4.5);
    expect(ratio(resolve(theme, t), resolve(theme, "surface"))).toBeGreaterThanOrEqual(4.5);
  });
  it.each(SEV)("severity %s text is ≥ 4.5:1 on its tinted background", (s) => {
    const fg = resolve(theme, `sev-${s}`);
    const bg = mix(fg, resolve(theme, "surface"), tint);
    expect(ratio(fg, bg)).toBeGreaterThanOrEqual(4.5);
    // Body text inside a tinted verdict banner too.
    expect(ratio(resolve(theme, "text"), bg)).toBeGreaterThanOrEqual(4.5);
  });
  it("primary button text is ≥ 4.5:1 on the accent", () => {
    expect(ratio(resolve(theme, "on-accent"), resolve(theme, "accent"))).toBeGreaterThanOrEqual(4.5);
  });
  it("matches the Design Brief §4.1 values", () => {
    expect(light.bg).toBe("#fafaf7");
    expect(dark.accent).toBe("#6fc2a2");
  });
});
