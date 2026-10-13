import type { RawFinding, Rule } from "../../types.js";
import { createGitignoreMatcher } from "../../files/gitignore.js";
import { findSecrets, isEnvExample, isEnvFile } from "./scan.js";
import { ROTATE_STEP, SECRETS_BOOK, secretFinding } from "./common.js";

export const SEC_004: Rule = {
  meta: {
    id: "SEC-004",
    title: ".env file committed or not git-ignored",
    category: "secrets",
    severity: "high",
    confidence: "high",
    owasp: "A02",
    requires: ["files"],
    summary:
      ".env files that are tracked by git, or that no .gitignore rule covers. Example files are included only when they contain real-looking secrets.",
    why: ".env files hold your real keys. Once committed, they live in git history forever and are copied to every clone, fork and CI runner. If the repository is public, bots find them within minutes.",
    fix: [
      "Add `.env*` and `!.env.example` to your `.gitignore`.",
      "If the file is already committed, stop tracking it with `git rm --cached <file>` and commit that change.",
      ROTATE_STEP,
      "Keep a `.env.example` with variable names and empty or fake values for collaborators.",
    ],
    fixPromptTemplate:
      "The file `{{path}}` {{detail.problem}}. Add `.env*` and `!.env.example` to .gitignore, run `git rm --cached {{path}}` if it is tracked, and create a .env.example with the same variable names but no real values. Remind me to rotate every key that was in the file, because removing it from git doesn't remove it from history.",
    falsePositiveNotes:
      "Without git (for example in the web app) the rule uses .gitignore rules only, so a file that is ignored but was committed earlier is not detected. Nested repositories with their own .git are treated as part of the project.",
    sources: [
      { title: "gitignore documentation", url: "https://git-scm.com/docs/gitignore" },
      { title: "Secrets & API Keys", book: SECRETS_BOOK },
    ],
  },
  async check(ctx) {
    const files = ctx.files!;
    const gitignores: Record<string, string> = {};
    for (const e of files.all()) {
      if (/(?:^|\/)\.gitignore$/.test(e.path)) gitignores[e.path] = (await files.text(e.path)) ?? "";
    }
    const matcher = createGitignoreMatcher(gitignores);
    const out: RawFinding[] = [];
    for (const entry of files.all()) {
      const p = entry.path;
      if (!isEnvFile(p)) continue;
      const tracked = await files.isGitTracked(p);
      // Tracked files are already exposed; untracked files that no rule ignores are one `git add .` away.
      const exposed = tracked === true || !matcher.isIgnored(p);
      if (!exposed) continue;
      const problem = tracked === true ? "is committed to git" : "isn't covered by any .gitignore rule";
      if (isEnvExample(p)) {
        const text = await files.text(p);
        const m = text === null ? undefined : findSecrets(text)[0];
        if (!m || text === null) continue;
        const f = secretFinding(
          "SEC-004",
          p,
          text,
          m,
          `Example env file ${problem} and contains a ${m.pattern.label}`,
        );
        // Never show neighbouring .env lines: they may hold other values.
        const lineStart = text.lastIndexOf("\n", m.start - 1) + 1;
        const lineEndIdx = text.indexOf("\n", m.end);
        f.evidence.snippet = text.slice(lineStart, lineEndIdx === -1 ? text.length : lineEndIdx);
        f.evidence.matchStart = m.start - lineStart;
        f.evidence.matchEnd = m.end - lineStart;
        f.evidence.detail = { ...f.evidence.detail, problem };
        delete f.severity;
        out.push(f);
        continue;
      }
      out.push({
        ruleId: "SEC-004",
        title: tracked === true ? `${p} is committed to git` : `${p} isn't git-ignored`,
        location: { kind: "file", path: p },
        evidence: { detail: { problem, tracked: tracked === true } },
      });
    }
    return out;
  },
};
