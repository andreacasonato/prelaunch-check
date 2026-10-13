import type { Rule } from "../../types.js";
import { header, htmlOf, metaContent, OWASP_HEADERS, rootResponse } from "./http.js";
import { webMeta } from "./meta.js";

export const WEB_007: Rule = {
  meta: webMeta({
    id: "WEB-007",
    title: "Referrer-Policy missing",
    severity: "low",
    confidence: "high",
    owasp: "A02",
    summary: 'Checks for a Referrer-Policy header or <meta name="referrer">.',
    why: "Without a policy, full URLs (which can contain IDs, search terms or tokens) may be sent to other sites your pages link to or load resources from.",
    fix: ["Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter)."],
    fixPromptTemplate:
      "Add the response header `Referrer-Policy: strict-origin-when-cross-origin` to every route of {{url}}.",
    sources: [
      { title: "OWASP Secure Headers Project", url: OWASP_HEADERS },
      {
        title: "MDN: Referrer-Policy",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy",
      },
    ],
  }),
  async check(ctx) {
    const site = ctx.site!;
    const r = rootResponse(site);
    if (!r || header(r, "referrer-policy") || metaContent(htmlOf(r), "name", "referrer") !== null) return [];
    return [{ ruleId: "WEB-007", location: { kind: "url", url: site.target }, evidence: {} }];
  },
};
