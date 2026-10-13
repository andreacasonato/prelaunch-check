import type { Rule } from "../../types.js";
import { header, OWASP_HEADERS, rootResponse } from "./http.js";
import { parseCsp } from "./csp.js";
import { webMeta } from "./meta.js";

export const WEB_005: Rule = {
  meta: webMeta({
    id: "WEB-005",
    title: "Clickjacking protection missing",
    severity: "medium",
    confidence: "high",
    owasp: "A02",
    summary:
      "Checks for X-Frame-Options: DENY or SAMEORIGIN, or a CSP header with frame-ancestors. A <meta> CSP can't set frame-ancestors.",
    why: "Without it, another site can load yours in an invisible frame and trick users into clicking buttons they can't see, such as 'delete account' or 'confirm payment'.",
    fix: [
      "Send `Content-Security-Policy: frame-ancestors 'none'` (or `'self'`) as a response header, and `X-Frame-Options: DENY` for older browsers.",
    ],
    fixPromptTemplate:
      "My site {{url}} can be embedded in frames on other sites. Add the response headers `Content-Security-Policy: frame-ancestors 'none'` and `X-Frame-Options: DENY` (use 'self'/SAMEORIGIN if I embed my own pages).",
    sources: [
      { title: "OWASP Secure Headers Project", url: OWASP_HEADERS },
      {
        title: "HTMHell: frame-ancestors can't be set via <meta>",
        url: "https://htmhell.dev/adventcalendar/2023/7/",
      },
    ],
  }),
  async check(ctx) {
    const site = ctx.site!;
    const r = rootResponse(site);
    if (!r) return [];
    const xfo = (header(r, "x-frame-options") ?? "").trim().toUpperCase();
    const csp = header(r, "content-security-policy");
    if (xfo === "DENY" || xfo === "SAMEORIGIN") return [];
    if (csp && parseCsp(csp).has("frame-ancestors")) return [];
    return [{ ruleId: "WEB-005", location: { kind: "url", url: site.target }, evidence: {} }];
  },
};
