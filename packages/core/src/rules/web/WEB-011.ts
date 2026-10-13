import type { RawFinding, Rule } from "../../types.js";
import { probeHits } from "./http.js";
import { DB_BOOK, webMeta } from "./meta.js";

export const WEB_011: Rule = {
  meta: webMeta({
    id: "WEB-011",
    title: "API documentation publicly accessible",
    severity: "medium",
    confidence: "medium",
    owasp: "A02",
    summary: "Requests common Swagger/OpenAPI/Redoc paths and reports any that serve API documentation.",
    why: "Public API docs hand attackers a map of every endpoint and parameter, including ones you forgot about. That makes finding unprotected endpoints much faster.",
    fix: [
      "Remove the docs route from production, or put it behind authentication.",
      "Serve docs from a separate, private environment.",
    ],
    fixPromptTemplate:
      "My production site exposes {{detail.label}} at {{url}}. Disable this route in production or protect it with authentication.",
    falsePositiveNotes: "Deliberately public API docs (for a public developer API) are reported too.",
    sources: [{ title: "Locking Down the Database (don't publish API docs or admin panels)", book: DB_BOOK }],
  }),
  async check(ctx) {
    return probeHits(ctx.site!, "api-docs").map(({ probe, url }): RawFinding => ({
      ruleId: "WEB-011",
      title: `${probe.label} is publicly accessible`,
      location: { kind: "url", url },
      evidence: { detail: { label: probe.label } },
    }));
  },
};
