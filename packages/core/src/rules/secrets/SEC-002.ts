import type { RawFinding, Rule } from "../../types.js";
import { findSecrets } from "./scan.js";
import { ROTATE_STEP, SECRETS_BOOK, secretFinding } from "./common.js";

export const SEC_002: Rule = {
  meta: {
    id: "SEC-002",
    title: "Secret API key in built client bundle",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    owasp: "A04",
    requires: ["files"],
    appliesWhen: (p) => p.buildDirs.length > 0,
    summary:
      "Finds secret API keys inside build output (dist/, build/, out/, .next/static/) that is shipped to browsers.",
    why: "Files in your build output are downloaded by every visitor. A secret key there is public: anyone can open the browser's developer tools, copy it, and use it as if they were your server.",
    fix: [
      "Find where the key enters the bundle: usually an environment variable with a public prefix (NEXT_PUBLIC_, VITE_) or a hard-coded value in client code.",
      "Move the call that needs the key to server code and read the key from a server-only environment variable.",
      ROTATE_STEP,
      "Rebuild and search the build folder again to confirm the key is gone.",
    ],
    fixPromptTemplate:
      "The built file `{{path}}` contains a {{detail.keyType}}, which means it is shipped to every visitor's browser. Find where this key enters client code (likely an env var with a NEXT_PUBLIC_ or VITE_ prefix, or a hard-coded value), move the call that needs it to a server-side function that reads a server-only environment variable, rebuild, and confirm the key no longer appears in the build output. Remind me to rotate the key in the {{detail.vendor}} dashboard.",
    falsePositiveNotes: "Build output of server-only code placed inside a build directory is also scanned.",
    sources: [
      { title: "Vite env variables and modes", url: "https://vite.dev/guide/env-and-mode" },
      {
        title: "Next.js environment variables",
        url: "https://nextjs.org/docs/app/guides/environment-variables",
      },
      { title: "Secrets & API Keys", book: SECRETS_BOOK },
    ],
  },
  async check(ctx) {
    const files = ctx.files!;
    const out: RawFinding[] = [];
    for (const entry of files.all()) {
      const p = entry.path;
      if (!ctx.profile.buildDirs.some((d) => p.startsWith(d))) continue;
      const text = await files.text(p);
      if (text === null) continue;
      for (const m of findSecrets(text))
        out.push(secretFinding("SEC-002", p, text, m, `${m.pattern.label} in shipped build output`));
    }
    return out;
  },
};
