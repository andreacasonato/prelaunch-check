import type { RawFinding, Rule } from "../../types.js";
import { finding, firstArg, loadSources } from "./common.js";

const CONSOLE = /\bconsole\s*\.\s*(?:log|info|debug|warn|error|trace|dir)\s*\(/g;
const SENSITIVE_IDENT =
  /(?<![\w$])[\w$]*(?:secret|password|passwd|token|api_?key|private_?key)[\w$]*(?![\w$])/i;

export const CODE_005: Rule = {
  meta: {
    id: "CODE-005",
    title: "Environment or secrets logged",
    category: "code",
    severity: "medium",
    confidence: "medium",
    owasp: "A09",
    requires: ["files"],
    summary:
      "Finds console calls that print process.env, import.meta.env, or variables named like secrets, passwords or tokens.",
    why: "Logs are copied to hosting dashboards, error trackers and support tickets, and are often readable by more people than your secrets should be. A logged key or password is a leaked key or password.",
    fix: [
      "Remove the log line, or log only non-sensitive facts (for example `console.log('Stripe key set:', Boolean(process.env.STRIPE_SECRET_KEY))`).",
      "Rotate any secret that has already reached your logs.",
    ],
    fixPromptTemplate:
      "In `{{path}}` line {{line}}, a console call prints environment variables or a secret-like value. Remove it or replace it with a log that reveals nothing sensitive (e.g. whether the value is set), and check the rest of the codebase for similar logs.",
    falsePositiveNotes:
      "Names are matched, not values: variables like tokenCount or passwordStrength are reported too. Strings such as 'Enter your password' are ignored.",
    sources: [
      {
        title: "OWASP: Logging Cheat Sheet (data to exclude)",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude",
      },
    ],
  },
  async check(ctx) {
    const out: RawFinding[] = [];
    for (const f of await loadSources(ctx.files!, ctx.profile.buildDirs)) {
      const re = new RegExp(CONSOLE.source, "g");
      for (let m = re.exec(f.bare); m !== null; m = re.exec(f.bare)) {
        const argsStart = m.index + m[0].length;
        let depth = 1;
        let end = argsStart;
        for (; end < f.bare.length && depth > 0; end++) {
          if (f.bare[end] === "(") depth++;
          else if (f.bare[end] === ")") depth--;
        }
        // Checking whether a secret is set reveals nothing: drop Boolean(x), !!x, typeof x, x.length, x ? …
        const args = f.bare
          .slice(argsStart, end - 1)
          .replace(
            /\bBoolean\s*\([^()]*\)|!!\s*[\w$.]+|\btypeof\s+[\w$.]+|[\w$.]+\.length\b|[\w$.]+\s*\?(?!\.)/g,
            " ",
          );
        const [s, e] = firstArg(f.bare, argsStart);
        const first = f.bare.slice(s, e).trim();
        const envDump =
          /^(?:process\.env|import\.meta\.env)$/.test(first) ||
          /(?:process\.env|import\.meta\.env)\s*(?:[,)]|$)/.test(args);
        if (!envDump && !SENSITIVE_IDENT.test(args)) continue;
        out.push(finding("CODE-005", f, m.index, end));
      }
    }
    return out;
  },
};
