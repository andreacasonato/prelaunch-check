// Renders fixPromptTemplate placeholders: {{path}}, {{line}}, {{url}}, {{title}}, {{detail.<key>}}.
import type { Evidence, Location } from "../types.js";

export function renderTemplate(
  template: string,
  ctx: { location: Location; evidence: Evidence; title: string },
): string {
  return template.replace(/\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}/g, (_, key: string) => {
    if (key === "path") return ctx.location.path ?? ctx.location.url ?? "";
    if (key === "line") return ctx.location.line !== undefined ? String(ctx.location.line) : "";
    if (key === "url") return ctx.location.url ?? "";
    if (key === "title") return ctx.title;
    if (key === "location") {
      const l = ctx.location;
      if (l.path) return l.line !== undefined ? `${l.path} line ${l.line}` : l.path;
      return l.url ?? "";
    }
    if (key.startsWith("detail.")) {
      const v = ctx.evidence.detail?.[key.slice(7)];
      return v === undefined ? "" : String(v);
    }
    return "";
  });
}
