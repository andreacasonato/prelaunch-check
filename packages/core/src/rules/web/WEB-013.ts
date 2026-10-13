import type { RawFinding, Rule } from "../../types.js";
import { matchesBaseline, res } from "./http.js";
import { webMeta } from "./meta.js";

export const WEB_013: Rule = {
  meta: webMeta({
    id: "WEB-013",
    title: "Source maps publicly accessible",
    severity: "medium",
    confidence: "high",
    owasp: "A02",
    summary:
      "Follows the sourceMappingURL comment in your page's scripts and reports .map files that return real source-map JSON.",
    why: "Public source maps let anyone read your original source code, comments and file layout, which makes finding weaknesses much easier.",
    fix: [
      "Turn off production browser source maps in your build config, or delete .map files before deploying.",
      "If your error tracker needs them, upload them privately during the build.",
    ],
    fixPromptTemplate:
      "The source map {{url}} is publicly downloadable. Disable production browser source maps (or delete .map files from the deploy output) and upload them privately to my error tracker if I need them.",
    sources: [
      { title: "MDN: Source maps", url: "https://developer.mozilla.org/en-US/docs/Glossary/Source_map" },
    ],
  }),
  async check(ctx) {
    const site = ctx.site!;
    const out: RawFinding[] = [];
    for (const s of site.scripts) {
      const r = res(s.sourceMap);
      if (!r || r.status !== 200 || matchesBaseline(r, site)) continue;
      try {
        const map = JSON.parse(r.bodyText ?? "") as { sources?: unknown; sourcesContent?: unknown };
        if (!Array.isArray(map.sources) && !Array.isArray(map.sourcesContent)) continue;
      } catch {
        continue;
      }
      out.push({
        ruleId: "WEB-013",
        location: { kind: "url", url: s.sourceMap!.request.url },
        evidence: { detail: { script: s.url } },
      });
    }
    return out;
  },
};
