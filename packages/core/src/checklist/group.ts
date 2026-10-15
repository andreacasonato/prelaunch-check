import type { ChecklistItem } from "../types.js";
import { CHECKLIST_GROUPS } from "./items.js";

export interface ChecklistSection {
  title: string;
  intro?: string;
  items: ChecklistItem[];
}

/** Groups items in the declared group order. Unknown groups (e.g. from a newer report) follow, in order of appearance. */
export function groupChecklist(items: readonly ChecklistItem[]): ChecklistSection[] {
  const sections = new Map<string, ChecklistSection>();
  for (const g of CHECKLIST_GROUPS) sections.set(g.title, { ...g, items: [] });
  for (const item of items) {
    let s = sections.get(item.group);
    if (!s) sections.set(item.group, (s = { title: item.group, items: [] }));
    s.items.push(item);
  }
  return [...sections.values()].filter((s) => s.items.length > 0);
}
