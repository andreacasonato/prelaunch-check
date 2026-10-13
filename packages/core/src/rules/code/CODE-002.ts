import type { RawFinding, Rule } from "../../types.js";
import { finding, firstArg, INPUTS_BOOK, isStringLiteral, loadSources, matchBracket } from "./common.js";

const CALL = /(?<![.\w$])eval\s*\(|\bnew\s+Function\s*\(/g;

export const CODE_002: Rule = {
  meta: {
    id: "CODE-002",
    title: "Dynamic code execution",
    category: "code",
    severity: "medium",
    confidence: "medium",
    owasp: "A05",
    requires: ["files"],
    summary: "Finds eval() and new Function() called with something other than a fixed string.",
    why: "eval and new Function run text as code. If any part of that text comes from a user, a URL or a database, an attacker can run their own code in your server or in your users' browsers.",
    fix: [
      "Replace eval with a safe alternative: `JSON.parse` for data, a lookup table for choosing functions, or a proper expression parser.",
      "Never build code from user input.",
    ],
    fixPromptTemplate:
      "In `{{path}}` line {{line}}, code is executed dynamically with eval or new Function using a non-constant argument. Replace it with a safe alternative (JSON.parse for data, a map of allowed functions, or a dedicated parser) so no runtime text is ever executed as code.",
    falsePositiveNotes:
      "Method calls like redis.eval() are ignored. Build tooling that evaluates trusted config is reported too.",
    sources: [
      {
        title: "MDN: Never use eval()!",
        url: "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_direct_eval!",
      },
      { title: "Inputs, Outputs & Web Hardening", book: INPUTS_BOOK },
    ],
  },
  async check(ctx) {
    const out: RawFinding[] = [];
    for (const f of await loadSources(ctx.files!, ctx.profile.buildDirs)) {
      const re = new RegExp(CALL.source, "g");
      for (let m = re.exec(f.bare); m !== null; m = re.exec(f.bare)) {
        const argsStart = m.index + m[0].length;
        const close = matchBracket(f.bare, argsStart - 1);
        const end = close === -1 ? argsStart : close - 1;
        // eval runs its first argument; new Function runs its last (earlier ones are parameter names).
        const args: string[] = [];
        for (let s = argsStart; s < end;) {
          const [a, b] = firstArg(f.bare, s);
          args.push(f.code.slice(a, b).trim());
          s = b + 1;
        }
        const body = m[0].startsWith("eval") ? args[0] : args[args.length - 1];
        if (body === undefined || body === "" || isStringLiteral(body)) continue;
        out.push(finding("CODE-002", f, m.index, end + 1));
      }
    }
    return out;
  },
};
