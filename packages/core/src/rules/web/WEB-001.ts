import type { RawFinding, Rule } from "../../types.js";
import { header, res } from "./http.js";
import { INPUTS_BOOK, webMeta } from "./meta.js";

export const WEB_001: Rule = {
  meta: webMeta({
    id: "WEB-001",
    title: "Site not served over HTTPS / no redirect",
    severity: "high",
    confidence: "high",
    owasp: "A04",
    summary: "Checks that the site answers over HTTPS and that plain http:// redirects to https://.",
    why: "Without HTTPS, anyone on the same Wi-Fi or network path can read and change what your users send and receive, including passwords and session cookies. If http:// doesn't redirect, people who type your address without https stay unprotected.",
    fix: [
      "Turn on HTTPS at your host (Vercel, Netlify, Cloudflare and most hosts do this automatically with a free certificate).",
      "Redirect every http:// request to https:// with a 301 or 308 redirect.",
    ],
    fixPromptTemplate:
      "My site {{url}} {{detail.problem}}. Configure HTTPS with a valid certificate on my host and add a permanent (301/308) redirect from http:// to https:// for every path.",
    sources: [
      {
        title: "MDN: Strict-Transport-Security",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security",
      },
      { title: "Inputs, Outputs & Web Hardening", book: INPUTS_BOOK },
    ],
  }),
  async check(ctx) {
    const site = ctx.site!;
    const out: RawFinding[] = [];
    const target = new URL(site.target);
    const root = res(site.root);
    if (target.protocol !== "https:" || !root) {
      out.push({
        ruleId: "WEB-001",
        title: "Site isn't served over HTTPS",
        location: { kind: "url", url: site.target },
        evidence: { detail: { problem: "isn't reachable over HTTPS" } },
      });
      return out;
    }
    const http = res(site.httpRoot);
    if (http) {
      const location = header(http, "location") ?? http.redirectedTo ?? "";
      const redirects = [301, 302, 307, 308].includes(http.status) && location.startsWith("https://");
      if (!redirects) {
        out.push({
          ruleId: "WEB-001",
          title: "http:// doesn't redirect to https://",
          location: { kind: "url", url: site.httpRoot!.request.url },
          evidence: {
            detail: {
              problem: `answers plain http:// with status ${http.status} instead of redirecting to https://`,
              status: http.status,
            },
          },
        });
      }
    }
    return out;
  },
};
