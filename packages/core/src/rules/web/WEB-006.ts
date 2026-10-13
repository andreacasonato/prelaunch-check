import type { Rule } from "../../types.js";
import { header, OWASP_HEADERS, rootResponse } from "./http.js";
import { webMeta } from "./meta.js";

export const WEB_006: Rule = {
  meta: webMeta({
    id: "WEB-006",
    title: "X-Content-Type-Options: nosniff missing",
    severity: "low",
    confidence: "high",
    owasp: "A02",
    summary: "Checks for the header `X-Content-Type-Options: nosniff`.",
    why: "Without it, browsers may guess a file's type. An uploaded file that looks like a script can then be run as one.",
    fix: ["Send `X-Content-Type-Options: nosniff` on every response."],
    fixPromptTemplate:
      "Add the response header `X-Content-Type-Options: nosniff` to every route of {{url}} using my host or framework header configuration.",
    sources: [
      { title: "OWASP Secure Headers Project", url: OWASP_HEADERS },
      {
        title: "MDN: X-Content-Type-Options",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options",
      },
    ],
  }),
  async check(ctx) {
    const site = ctx.site!;
    const r = rootResponse(site);
    if (!r || (header(r, "x-content-type-options") ?? "").trim().toLowerCase() === "nosniff") return [];
    return [{ ruleId: "WEB-006", location: { kind: "url", url: site.target }, evidence: {} }];
  },
};
