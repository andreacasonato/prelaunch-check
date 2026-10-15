import { describe, expect, it } from "vitest";
import { CHECKLIST, CHECKLIST_GROUPS } from "../src/checklist/items.js";

describe("CHECKLIST", () => {
  it("has unique, sequential MAN ids", () => {
    expect(CHECKLIST.map((c) => c.id)).toEqual(
      CHECKLIST.map((_, i) => `MAN-${String(i + 1).padStart(3, "0")}`),
    );
  });

  it("puts every item in a declared group", () => {
    const titles = CHECKLIST_GROUPS.map((g) => g.title);
    for (const c of CHECKLIST) expect(titles, c.id).toContain(c.group);
    for (const t of titles)
      expect(
        CHECKLIST.some((c) => c.group === t),
        t,
      ).toBe(true);
  });

  it("links every legal item to at least one https source", () => {
    const legal = CHECKLIST.filter((c) => c.group === "Legal & trust");
    expect(legal.length).toBeGreaterThan(0);
    for (const c of legal) {
      expect(c.links?.length, c.id).toBeGreaterThan(0);
      for (const l of c.links!) expect(l.url, c.id).toMatch(/^https:\/\/[^\s"<>]+$/);
    }
  });

  it("never calls an app safe or secure", () => {
    for (const c of CHECKLIST)
      expect(`${c.title} ${c.howToTest} ${c.why}`, c.id).not.toMatch(/\b(safe|secure)\b/i);
    for (const g of CHECKLIST_GROUPS) expect(g.intro ?? "", g.title).not.toMatch(/\b(safe|secure)\b/i);
  });
});
