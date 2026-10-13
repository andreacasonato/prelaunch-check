import type { RawFinding, Rule } from "../../types.js";
import { snippetAround } from "../../util/text.js";
import { findDbUrls, isEnvFile, isLockfile } from "./scan.js";
import { ROTATE_STEP, SECRETS_BOOK } from "./common.js";

export const SEC_007: Rule = {
  meta: {
    id: "SEC-007",
    title: "Hard-coded database connection string with password",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    owasp: "A04",
    requires: ["files"],
    summary: "Finds postgres://, mysql:// and mongodb:// URLs with an inline password in project files.",
    why: "A connection string with a password gives direct access to your database, bypassing your app and any access rules it enforces. Anyone who reads the code can read, change or delete all your data.",
    fix: [
      "Move the connection string into a server-only environment variable (for example DATABASE_URL in a git-ignored .env file).",
      "Read it with `process.env.DATABASE_URL` in server code only.",
      "Change the database password, since the old one has been exposed.",
      ROTATE_STEP,
    ],
    fixPromptTemplate:
      "In `{{path}}` line {{line}}, a {{detail.scheme}} connection string contains a hard-coded password. Replace it with process.env.DATABASE_URL read in server-only code, add DATABASE_URL to the git-ignored .env file and to .env.example (without the password), and remind me to change the database password.",
    falsePositiveNotes:
      "Local development URLs (localhost, 127.0.0.1, docker service names without a dot) and placeholder passwords like ${PASSWORD}, <password> or 'postgres' are ignored. .env files are not checked here (that's where the URL belongs).",
    sources: [{ title: "Secrets & API Keys", book: SECRETS_BOOK }],
  },
  async check(ctx) {
    const files = ctx.files!;
    const out: RawFinding[] = [];
    for (const entry of files.all()) {
      if (isEnvFile(entry.path) || isLockfile(entry.path)) continue;
      const text = await files.text(entry.path);
      if (text === null) continue;
      for (const m of findDbUrls(text)) {
        const s = snippetAround(text, m.passwordStart, m.passwordStart + m.password.length);
        out.push({
          ruleId: "SEC-007",
          location: { kind: "file", path: entry.path, line: s.line, column: s.column },
          evidence: {
            snippet: s.snippet,
            matchStart: s.matchStart,
            matchEnd: s.matchEnd,
            detail: { scheme: m.scheme, host: m.host },
          },
          secretValue: m.password,
        });
      }
    }
    return out;
  },
};
