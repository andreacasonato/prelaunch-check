import type { Rule } from "../../types.js";
import { rootResponse, OWASP_HEADERS } from "./http.js";
import { cspSources } from "./csp.js";
import { INPUTS_BOOK, webMeta } from "./meta.js";

export const WEB_003: Rule = {
  meta: webMeta({
    id: "WEB-003",
    title: "Content-Security-Policy missing",
    severity: "medium",
    confidence: "high",
    owasp: "A02",
    summary: "Checks for a Content-Security-Policy header or <meta http-equiv> policy on the page.",
    why: "A Content-Security-Policy tells the browser which scripts may run. If an attacker manages to inject HTML (cross-site scripting), a good policy stops their script from loading or running.",
    fix: [
      "Start with a strict policy and loosen only what you need, for example: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`.",
      "Test in report-only mode first (`Content-Security-Policy-Report-Only`) to see what would break.",
    ],
    fixPromptTemplate:
      "My site {{url}} has no Content-Security-Policy. Propose a strict CSP for my stack (default-src 'self'; script-src 'self' with nonces or hashes if needed; object-src 'none'; base-uri 'self'; frame-ancestors 'none'), add it as a response header via my host or framework config, and list anything it would block.",
    sources: [
      { title: "OWASP Secure Headers Project", url: OWASP_HEADERS },
      {
        title: "MDN: Content-Security-Policy",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy",
      },
      { title: "Inputs, Outputs & Web Hardening", book: INPUTS_BOOK },
    ],
  }),
  async check(ctx) {
    const site = ctx.site!;
    if (!rootResponse(site)) return [];
    const { header, meta } = cspSources(site);
    if (header || meta) return [];
    return [{ ruleId: "WEB-003", location: { kind: "url", url: site.target }, evidence: {} }];
  },
};
