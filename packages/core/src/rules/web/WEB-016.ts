import type { Rule } from "../../types.js";
import { probeHits } from "./http.js";
import { webMeta } from "./meta.js";

export const WEB_016: Rule = {
  meta: webMeta({
    id: "WEB-016",
    title: "security.txt missing or expired",
    severity: "low",
    confidence: "high",
    owasp: "A09",
    summary:
      "Checks for /.well-known/security.txt with a Contact line and an Expires date in the future, as RFC 9116 requires.",
    why: "security.txt tells people who find a vulnerability how to reach you. Without it, they may not bother, or may post it publicly.",
    fix: [
      "Create `/.well-known/security.txt` with at least:\n\n```\nContact: mailto:security@your-domain.com\nExpires: 2027-12-31T23:59:59Z\n```",
      "Put a reminder in your calendar to update Expires before it passes.",
    ],
    fixPromptTemplate:
      "{{detail.problem}}. Add a static file at /.well-known/security.txt with a Contact line (an email or URL I monitor) and an Expires date about a year ahead, following RFC 9116.",
    sources: [{ title: "RFC 9116: security.txt", url: "https://www.rfc-editor.org/rfc/rfc9116" }],
  }),
  async check(ctx) {
    const site = ctx.site!;
    const origin = new URL(site.target).origin;
    const hits = probeHits(site, "security-txt");
    const wellKnown = hits.find((h) => h.probe.id === "security-txt");
    const url = `${origin}/.well-known/security.txt`;
    if (!wellKnown) {
      const legacy = hits.find((h) => h.probe.id === "security-txt-legacy");
      const problem = legacy
        ? "security.txt is only at /security.txt, not the required /.well-known/ location"
        : "My site has no security.txt";
      return [
        {
          ruleId: "WEB-016",
          title: legacy ? "security.txt isn't at /.well-known/" : "No security.txt",
          location: { kind: "url", url },
          evidence: { detail: { problem } },
        },
      ];
    }
    const body = wellKnown.response.bodyText ?? "";
    const expires = /^\s*expires\s*:\s*(\S+)/im.exec(body)?.[1];
    const t = expires ? Date.parse(expires) : NaN;
    if (Number.isNaN(t) || t <= ctx.now.getTime()) {
      const problem = expires ? `security.txt expired on ${expires}` : "security.txt has no Expires line";
      return [
        {
          ruleId: "WEB-016",
          title: expires ? "security.txt has expired" : "security.txt has no Expires date",
          location: { kind: "url", url },
          evidence: { detail: { problem } },
        },
      ];
    }
    return [];
  },
};
