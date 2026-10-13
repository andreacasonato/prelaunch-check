import type { Rule } from "../../types.js";
import { header, OWASP_HEADERS, rootResponse } from "./http.js";
import { webMeta } from "./meta.js";

const ONE_YEAR = 31_536_000;

export const WEB_002: Rule = {
  meta: webMeta({
    id: "WEB-002",
    title: "HSTS missing or too short",
    severity: "medium",
    confidence: "high",
    owasp: "A02",
    summary:
      "Checks for a Strict-Transport-Security header with max-age of at least one year (31536000 seconds).",
    why: "HSTS tells browsers to always use HTTPS for your site, even if someone clicks an http:// link. Without it, the very first visit can be intercepted and downgraded.",
    fix: [
      "Send this header on HTTPS responses: `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
      "Most hosts let you set headers in a config file (for example `vercel.json`, `netlify.toml` / `_headers`, or Next.js `headers()` in next.config).",
    ],
    fixPromptTemplate:
      "My site {{url}} {{detail.problem}}. Add the response header `Strict-Transport-Security: max-age=31536000; includeSubDomains` for all routes using my host's header configuration.",
    sources: [
      { title: "OWASP Secure Headers Project", url: OWASP_HEADERS },
      {
        title: "MDN: Strict-Transport-Security",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security",
      },
    ],
  }),
  async check(ctx) {
    const site = ctx.site!;
    const r = rootResponse(site);
    if (!r) return [];
    const hsts = header(r, "strict-transport-security");
    const age = hsts ? Number(/max-age\s*=\s*"?(\d+)/i.exec(hsts)?.[1] ?? NaN) : NaN;
    if (hsts && age >= ONE_YEAR) return [];
    const problem = hsts
      ? `sends HSTS with max-age=${Number.isNaN(age) ? "?" : age}, less than one year`
      : "doesn't send a Strict-Transport-Security header";
    return [
      {
        ruleId: "WEB-002",
        title: hsts ? "HSTS max-age is shorter than one year" : "Strict-Transport-Security header missing",
        location: { kind: "url", url: site.target },
        evidence: { detail: { problem, ...(hsts ? { header: hsts } : {}) } },
      },
    ];
  },
};
