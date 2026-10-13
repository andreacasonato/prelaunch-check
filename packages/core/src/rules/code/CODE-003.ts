import type { RawFinding, Rule } from "../../types.js";
import { finding, INPUTS_BOOK, isStringLiteral, loadSources } from "./common.js";

const SANITIZED = /\b(?:DOMPurify\.sanitize|sanitize(?:Html)?|purify)\s*\(/;
const SINK =
  /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:|\.(?:innerHTML|outerHTML)\s*=(?!=)|\bv-html\s*=/g;

export const CODE_003: Rule = {
  meta: {
    id: "CODE-003",
    title: "Unsafe HTML sink",
    category: "code",
    severity: "medium",
    confidence: "low",
    owasp: "A05",
    requires: ["files"],
    summary:
      "Finds dangerouslySetInnerHTML, .innerHTML = and v-html with a non-literal value that isn't wrapped in a sanitizer such as DOMPurify.sanitize.",
    why: "Writing HTML from a variable lets any markup in it run. If the value ever contains user content (a comment, a profile bio, a URL parameter), an attacker can run script in other users' browsers and steal their sessions.",
    fix: [
      "Render text instead of HTML where you can (plain JSX `{value}` or `textContent`).",
      "If you must render HTML, sanitize it first: `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}`.",
    ],
    fixPromptTemplate:
      "In `{{path}}` line {{line}}, HTML is inserted from a variable without sanitizing it. If the value can contain user content, render it as text instead, or sanitize it with DOMPurify.sanitize before inserting.",
    falsePositiveNotes:
      "Shown as Worth checking: many sinks only receive trusted, static HTML. The rule can't follow where a value comes from.",
    sources: [
      {
        title: "OWASP: Cross Site Scripting Prevention Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
      },
      { title: "Inputs, Outputs & Web Hardening", book: INPUTS_BOOK },
    ],
  },
  async check(ctx) {
    const out: RawFinding[] = [];
    for (const f of await loadSources(ctx.files!, ctx.profile.buildDirs)) {
      const re = new RegExp(SINK.source, "g");
      for (let m = re.exec(f.bare); m !== null; m = re.exec(f.bare)) {
        // Value: up to the end of the statement / attribute on this line.
        const valueStart = m.index + m[0].length;
        const lineEnd = f.code.indexOf("\n", valueStart);
        const raw = f.code.slice(valueStart, lineEnd === -1 ? undefined : lineEnd);
        const value = raw.replace(/\}\s*\}.*$|;.*$/, "").trim();
        if (m[0].startsWith("v-html")) {
          if (SANITIZED.test(value)) continue;
        } else if (value === "" || isStringLiteral(value) || SANITIZED.test(value)) continue;
        out.push(finding("CODE-003", f, m.index, valueStart + value.length));
      }
    }
    return out;
  },
};
