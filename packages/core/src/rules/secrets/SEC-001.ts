import type { RawFinding, Rule } from "../../types.js";
import { findSecrets, isEnvFile, isLockfile } from "./scan.js";
import { ROTATE_STEP, SECRETS_BOOK, secretFinding } from "./common.js";

export const SEC_001: Rule = {
  meta: {
    id: "SEC-001",
    title: "Secret API key in source code",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    owasp: "A04",
    requires: ["files"],
    summary:
      "Finds secret API keys (Stripe, Supabase, AWS, OpenAI, GitHub and more) written directly in project files.",
    why: "A secret key in the code ends up in git history, in screenshots and in every copy of the repository. Anyone who gets it can act as your app: charge cards, read every database row or run up your AI bill. Test-mode keys are less dangerous but still let people tamper with your test data.",
    fix: [
      "Move the key into a server-only environment variable (for example in `.env.local`, which must be git-ignored) and read it with `process.env` on the server.",
      "Make every call that needs the key from server code (an API route, server action or edge function), never from the browser.",
      ROTATE_STEP,
      "Search the whole project, including built files, to confirm the old value is gone.",
    ],
    fixPromptTemplate:
      "In `{{path}}` line {{line}}, there is a hard-coded {{detail.keyType}}. Move it to a server-only environment variable (no NEXT_PUBLIC_ or VITE_ prefix), read it with process.env in server code only, and make every call that needs it from the server. Then remind me to rotate the key in the {{detail.vendor}} dashboard, and search the project and its build output to confirm the old value is gone.",
    falsePositiveNotes:
      "Fake keys in tests or documentation that happen to have high entropy still match. Test-mode Stripe keys are reported as medium. .env files are handled by SEC-003/SEC-004 instead.",
    sources: [
      { title: "Stripe API keys", url: "https://docs.stripe.com/keys" },
      { title: "Supabase API keys", url: "https://supabase.com/docs/guides/api/api-keys" },
      { title: "gitleaks default rules (patterns ported, MIT)", url: "https://github.com/gitleaks/gitleaks" },
      { title: "Secrets & API Keys", book: SECRETS_BOOK },
    ],
  },
  async check(ctx) {
    const files = ctx.files!;
    const out: RawFinding[] = [];
    for (const entry of files.all()) {
      const p = entry.path;
      if (isEnvFile(p) || isLockfile(p)) continue;
      if (ctx.profile.buildDirs.some((d) => p.startsWith(d))) continue; // SEC-002
      const text = await files.text(p);
      if (text === null) continue;
      for (const m of findSecrets(text))
        out.push(secretFinding("SEC-001", p, text, m, `${m.pattern.label} in source code`));
    }
    return out;
  },
};
