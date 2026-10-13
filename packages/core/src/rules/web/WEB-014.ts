import type { RawFinding, Rule } from "../../types.js";
import { findSecrets } from "../secrets/scan.js";
import { snippetAround } from "../../util/text.js";
import { htmlOf, res } from "./http.js";
import { webMeta } from "./meta.js";

export const WEB_014: Rule = {
  meta: webMeta({
    id: "WEB-014",
    title: "Secret key in served JavaScript",
    severity: "critical",
    confidence: "high",
    owasp: "A04",
    summary:
      "Runs the secret-key patterns over the JavaScript files your page loads and over inline <script> blocks.",
    why: "Anything in the JavaScript you serve is public. A secret key there can be copied by any visitor and used to act as your server.",
    fix: [
      "Find where the key enters the bundle (often an env var with NEXT_PUBLIC_ or VITE_) and move the call that needs it to the server.",
      "Rotate the key in the provider's dashboard, then redeploy.",
    ],
    fixPromptTemplate:
      "The JavaScript served at {{url}} contains a {{detail.keyType}}. Find where it enters client code, move the call to a server-side function with a server-only env var, redeploy, and remind me to rotate the key with {{detail.vendor}}.",
    sources: [
      { title: "Secrets & API Keys", book: "Creating a Secure App — Secrets & API Keys" },
      { title: "gitleaks default rules (patterns ported, MIT)", url: "https://github.com/gitleaks/gitleaks" },
    ],
  }),
  async check(ctx) {
    const site = ctx.site!;
    const out: RawFinding[] = [];
    const scan = (url: string, text: string) => {
      for (const m of findSecrets(text)) {
        const s = snippetAround(text, m.start, m.end, 0);
        out.push({
          ruleId: "WEB-014",
          title: `${m.pattern.label} in served JavaScript`,
          ...(m.pattern.isTest ? { severity: "medium" as const } : {}),
          location: { kind: "url", url },
          evidence: {
            snippet: s.snippet,
            matchStart: s.matchStart,
            matchEnd: s.matchEnd,
            detail: { keyType: m.pattern.label, vendor: m.pattern.vendor },
          },
          secretValue: m.value,
        });
      }
    };
    for (const s of site.scripts) {
      const r = res(s.exchange);
      if (r?.status === 200 && r.bodyText) scan(s.url, r.bodyText);
    }
    const html = htmlOf(res(site.root));
    const inline = /<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
    for (let m = inline.exec(html); m !== null; m = inline.exec(html)) scan(site.target, m[1]!);
    return out;
  },
};
