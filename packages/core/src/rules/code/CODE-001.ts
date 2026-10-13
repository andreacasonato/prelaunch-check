import type { RawFinding, Rule } from "../../types.js";
import { finding, firstArg, INPUTS_BOOK, loadSources } from "./common.js";

const CALL = /(?:\.(?:query|execute|raw)|\$queryRawUnsafe|\$executeRawUnsafe|\bsql\.unsafe)\s*\(/g;
const SQL_WORD = /\b(?:select|insert|update|delete)\b/i;

export const CODE_001: Rule = {
  meta: {
    id: "CODE-001",
    title: "Raw SQL built from strings",
    category: "code",
    severity: "high",
    confidence: "medium",
    owasp: "A05",
    requires: ["files"],
    summary:
      "Finds query(), execute(), raw(), $queryRawUnsafe(), $executeRawUnsafe() and sql.unsafe() calls whose SQL is built with ${…} or + concatenation.",
    why: "When user input is pasted into SQL text, an attacker can change the query itself: read other users' data, bypass login or delete tables. Parameterized queries keep data and SQL separate, so input can never become code.",
    fix: [
      "Pass values as parameters instead of building the string: `db.query('select * from users where id = $1', [id])`.",
      "With Prisma, use the tagged template `prisma.$queryRaw`…`` (it parameterizes automatically) instead of the Unsafe variants.",
      "Prefer your ORM's query builder for anything that includes user input.",
    ],
    fixPromptTemplate:
      "In `{{path}}` line {{line}}, an SQL query is built by inserting values into the SQL string. Rewrite it as a parameterized query (placeholders like $1 with a values array, or the ORM's safe tagged-template/query-builder API) so no input is ever concatenated into SQL. Check the rest of the file for the same pattern.",
    falsePositiveNotes:
      "Interpolating only constants (for example a table name from a fixed list) is reported too; confirm no user input can reach the string.",
    sources: [
      {
        title: "OWASP: SQL Injection Prevention Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
      },
      { title: "Inputs, Outputs & Web Hardening", book: INPUTS_BOOK },
    ],
  },
  async check(ctx) {
    const out: RawFinding[] = [];
    for (const f of await loadSources(ctx.files!, ctx.profile.buildDirs)) {
      const re = new RegExp(CALL.source, "g");
      for (let m = re.exec(f.bare); m !== null; m = re.exec(f.bare)) {
        const [s, e] = firstArg(f.bare, m.index + m[0].length);
        const arg = f.code.slice(s, e).trim();
        const bareArg = f.bare.slice(s, e);
        const template = arg.startsWith("`") && arg.includes("${");
        const concat = /["'`]/.test(arg) && /\+/.test(bareArg.replace(/["'`][^"'`]*["'`]/g, ""));
        if (!(template || concat) || !SQL_WORD.test(arg)) continue;
        out.push(finding("CODE-001", f, m.index, e));
      }
    }
    return out;
  },
};
