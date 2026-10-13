import type { RawFinding, Rule } from "../../types.js";
import { createGitignoreMatcher } from "../../files/gitignore.js";

export const CFG_002: Rule = {
  meta: {
    id: "CFG-002",
    title: ".gitignore missing key entries",
    category: "config",
    severity: "medium",
    confidence: "high",
    owasp: "A02",
    requires: ["files"],
    summary:
      "Checks that .gitignore covers .env files (.env, .env.local) and, for JavaScript projects, node_modules.",
    why: "Without these rules, one `git add .` commits your real keys or thousands of dependency files. Leaked .env files are one of the most common ways secrets end up public.",
    fix: [
      "Add these lines to the `.gitignore` at the root of your project:\n\n```\n.env*\n!.env.example\nnode_modules/\n```",
      "Run `git status` to check that .env files no longer show up.",
    ],
    fixPromptTemplate:
      "My .gitignore {{detail.problem}}. Add `.env*`, `!.env.example` and `node_modules/` to the root .gitignore (create it if missing), then check with `git status` that no .env file is tracked. If one is, run `git rm --cached` on it.",
    falsePositiveNotes:
      "Next.js's default .gitignore ignores only `.env*.local`, on the basis that `.env` holds non-secret defaults. If that's how you use `.env`, record this as an accepted risk.",
    sources: [
      { title: "gitignore documentation", url: "https://git-scm.com/docs/gitignore" },
      { title: "Secrets & API Keys", book: "Creating a Secure App — Secrets & API Keys" },
    ],
  },
  async check(ctx) {
    const files = ctx.files!;
    const all = files.all();
    const gitignores: Record<string, string> = {};
    for (const e of all)
      if (/(?:^|\/)\.gitignore$/.test(e.path)) gitignores[e.path] = (await files.text(e.path)) ?? "";
    const matcher = createGitignoreMatcher(gitignores);
    const hasRoot = ".gitignore" in gitignores;
    const out: RawFinding[] = [];
    const location = { kind: "file" as const, path: ".gitignore" };

    if (!matcher.isIgnored(".env") || !matcher.isIgnored(".env.local")) {
      const problem = hasRoot ? "doesn't ignore .env files" : "is missing, so .env files aren't ignored";
      out.push({
        ruleId: "CFG-002",
        title: hasRoot ? ".gitignore doesn't ignore .env files" : "No .gitignore: .env files aren't ignored",
        location,
        evidence: { detail: { missing: ".env*", problem } },
      });
    }
    if (all.some((e) => e.path === "package.json") && !matcher.isIgnored("node_modules/x")) {
      const problem = hasRoot ? "doesn't ignore node_modules" : "is missing, so node_modules isn't ignored";
      out.push({
        ruleId: "CFG-002",
        title: hasRoot
          ? ".gitignore doesn't ignore node_modules"
          : "No .gitignore: node_modules isn't ignored",
        location,
        evidence: { detail: { missing: "node_modules", problem } },
      });
    }
    return out;
  },
};
