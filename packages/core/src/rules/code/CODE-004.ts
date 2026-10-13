import type { RawFinding, Rule } from "../../types.js";
import { finding, loadSources, matchBracket } from "./common.js";

const CREDENTIALS = /\bcredentials\s*:\s*true\b/g;
const WILDCARD_ORIGIN = /\borigin\s*:\s*(?:["'`]\*["'`]|true\b)/;
const HEADER_ORIGIN_STAR = /["'`]Access-Control-Allow-Origin["'`]\s*[,:]\s*["'`]\*["'`]/i;
const HEADER_CREDS_TRUE = /["'`]Access-Control-Allow-Credentials["'`]\s*[,:]\s*(?:["'`]true["'`]|true\b)/i;

export const CODE_004: Rule = {
  meta: {
    id: "CODE-004",
    title: "Wildcard CORS with credentials",
    category: "code",
    severity: "high",
    confidence: "high",
    owasp: "A01",
    requires: ["files"],
    summary:
      "Finds CORS configuration that allows every origin (`origin: '*'` or `origin: true`) together with `credentials: true`, or the equivalent response headers.",
    why: "`origin: true` reflects whatever site is asking, and credentials: true lets that site send your users' cookies. Any website your users visit could then call your API as them and read the responses.",
    fix: [
      "List the exact origins that may call your API: `cors({ origin: ['https://app.example.com'], credentials: true })`.",
      "If you don't need cookies cross-origin, remove `credentials: true`.",
    ],
    fixPromptTemplate:
      "In `{{path}}` line {{line}}, CORS allows any origin together with credentials. Replace the wildcard/reflected origin with an explicit allow-list of my front-end origins (read from config), or drop credentials: true if cross-origin cookies aren't needed.",
    sources: [
      {
        title: "MDN: CORS and credentials",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS#requests_with_credentials",
      },
      {
        title: "OWASP: Testing Cross Origin Resource Sharing",
        url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
      },
    ],
  },
  async check(ctx) {
    const out: RawFinding[] = [];
    for (const f of await loadSources(ctx.files!, ctx.profile.buildDirs)) {
      const re = new RegExp(CREDENTIALS.source, "g");
      for (let m = re.exec(f.bare); m !== null; m = re.exec(f.bare)) {
        // The enclosing object literal: nearest unmatched "{" before the match.
        let depth = 0;
        let open = -1;
        for (let i = m.index; i >= 0; i--) {
          const c = f.bare[i];
          if (c === "}") depth++;
          else if (c === "{") {
            if (depth === 0) {
              open = i;
              break;
            }
            depth--;
          }
        }
        if (open === -1) continue;
        const close = matchBracket(f.bare, open);
        if (close === -1 || !WILDCARD_ORIGIN.test(f.code.slice(open, close))) continue;
        out.push(finding("CODE-004", f, m.index, m.index + m[0].length));
      }
      // Header writes: both headers within 10 lines of each other.
      const lines = f.code.split("\n");
      lines.forEach((l, i) => {
        if (!HEADER_ORIGIN_STAR.test(l)) return;
        const near = lines.slice(Math.max(0, i - 10), i + 11).join("\n");
        if (!HEADER_CREDS_TRUE.test(near)) return;
        const offset = lines.slice(0, i).join("\n").length + (i > 0 ? 1 : 0);
        const at = l.search(HEADER_ORIGIN_STAR);
        out.push(finding("CODE-004", f, offset + at, offset + l.length));
      });
    }
    return out;
  },
};
