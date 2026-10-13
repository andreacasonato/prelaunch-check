import type { Rule } from "../../types.js";
import { cspSources, parseCsp } from "./csp.js";
import { INPUTS_BOOK, webMeta } from "./meta.js";

export const WEB_004: Rule = {
  meta: webMeta({
    id: "WEB-004",
    title: "CSP allows inline/eval scripts",
    severity: "low",
    confidence: "high",
    owasp: "A05",
    summary:
      "Checks that script-src (or default-src) doesn't allow 'unsafe-inline' without a nonce or hash, or 'unsafe-eval'.",
    why: "'unsafe-inline' lets any injected <script> run, which removes most of the protection a CSP gives against cross-site scripting. 'unsafe-eval' lets strings run as code.",
    fix: [
      "Remove 'unsafe-inline' and use nonces or hashes for the inline scripts you need (most frameworks support nonces).",
      "Remove 'unsafe-eval' and replace any code that relies on eval or new Function.",
    ],
    fixPromptTemplate:
      "The Content-Security-Policy on {{url}} allows {{detail.unsafe}} in {{detail.directive}}. Change my setup to use nonces or hashes for required inline scripts and remove 'unsafe-inline' and 'unsafe-eval' from script-src.",
    sources: [
      {
        title: "MDN: CSP script-src",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src",
      },
      { title: "Inputs, Outputs & Web Hardening", book: INPUTS_BOOK },
    ],
  }),
  async check(ctx) {
    const site = ctx.site!;
    const { header, meta } = cspSources(site);
    const policy = header ?? meta;
    if (!policy) return [];
    const csp = parseCsp(policy);
    const directive = csp.has("script-src") ? "script-src" : csp.has("default-src") ? "default-src" : null;
    if (!directive) return [];
    const values = csp.get(directive)!.map((v) => v.toLowerCase());
    // With a nonce or hash, browsers ignore 'unsafe-inline' (CSP Level 2+).
    const hasNonceOrHash = values.some((v) => /^'(?:nonce-|sha256-|sha384-|sha512-)/.test(v));
    const unsafe = [
      ...(values.includes("'unsafe-inline'") && !hasNonceOrHash ? ["'unsafe-inline'"] : []),
      ...(values.includes("'unsafe-eval'") ? ["'unsafe-eval'"] : []),
    ];
    if (!unsafe.length) return [];
    return [
      {
        ruleId: "WEB-004",
        title: `CSP ${directive} allows ${unsafe.join(" and ")}`,
        location: { kind: "url", url: site.target },
        evidence: { detail: { directive, unsafe: unsafe.join(" and ") } },
      },
    ];
  },
};
