import type { RawFinding, Rule } from "../../types.js";
import { htmlOf, res } from "./http.js";
import { webMeta } from "./meta.js";

const TAG =
  /<(script|iframe|img)\b[^>]*?\bsrc\s*=\s*["']?(http:\/\/[^"'\s>]+)|<link\b(?=[^>]*\brel\s*=\s*["']?stylesheet)[^>]*?\bhref\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi;

export const WEB_018: Rule = {
  meta: webMeta({
    id: "WEB-018",
    title: "Mixed content",
    severity: "medium",
    confidence: "high",
    owasp: "A04",
    summary: "Finds http:// URLs in script, stylesheet, iframe and image tags on an HTTPS page.",
    why: "Resources loaded over plain HTTP can be read or replaced by anyone on the network path. A replaced script runs with full access to your page.",
    fix: [
      "Change the URLs to https:// (or protocol-relative paths you host yourself).",
      "Add `upgrade-insecure-requests` to your Content-Security-Policy as a safety net.",
    ],
    fixPromptTemplate:
      "The HTTPS page {{url}} loads {{detail.resource}} over plain HTTP. Switch these resources to https:// and add upgrade-insecure-requests to my CSP.",
    sources: [
      {
        title: "MDN: Mixed content",
        url: "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
      },
    ],
  }),
  async check(ctx) {
    const site = ctx.site!;
    if (new URL(site.target).protocol !== "https:") return [];
    const html = htmlOf(res(site.root));
    const out: RawFinding[] = [];
    const seen = new Set<string>();
    const re = new RegExp(TAG.source, "gi");
    for (let m = re.exec(html); m !== null; m = re.exec(html)) {
      const resource = m[2] ?? m[3]!;
      if (seen.has(resource)) continue;
      seen.add(resource);
      out.push({
        ruleId: "WEB-018",
        title: `${m[1] ? `<${m[1].toLowerCase()}>` : "Stylesheet"} loaded over HTTP: ${resource.slice(0, 80)}`,
        location: { kind: "url", url: site.target },
        evidence: { detail: { resource: resource.slice(0, 200) } },
      });
    }
    return out;
  },
};
