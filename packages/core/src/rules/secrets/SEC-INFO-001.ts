import type { RawFinding, Rule } from "../../types.js";
import { findPublishable, isLockfile } from "./scan.js";
import { SECRETS_BOOK, secretFinding } from "./common.js";

export const SEC_INFO_001: Rule = {
  meta: {
    id: "SEC-INFO-001",
    title: "Publishable key detected (fine to expose)",
    category: "secrets",
    severity: "info",
    confidence: "high",
    owasp: "A04",
    requires: ["files"],
    summary:
      "Lists keys that are designed to be public (Stripe pk_, Supabase sb_publishable_ and legacy anon keys, Firebase web API keys) so you know they're not a problem.",
    why: "Some keys are meant to live in the browser. What protects your data is not hiding these keys but your access rules: Supabase Row Level Security, Firebase security rules, and server-side checks.",
    fix: [
      "No change is needed for the key itself.",
      "Make sure your access rules are in place: see DB-001 to DB-006 for Supabase and Firebase.",
      "For Google/Firebase API keys, restrict the key to the APIs and domains you use in the Google Cloud console.",
    ],
    fixPromptTemplate:
      "`{{path}}` line {{line}} contains a {{detail.keyType}}. This key is designed to be public. Please review my database access rules (Supabase RLS policies or Firebase security rules) to confirm they, not the key, protect user data.",
    sources: [
      { title: "Stripe API keys", url: "https://docs.stripe.com/keys" },
      { title: "Supabase API keys", url: "https://supabase.com/docs/guides/api/api-keys" },
      { title: "Firebase API keys", url: "https://firebase.google.com/docs/projects/api-keys" },
      { title: "Secrets & API Keys", book: SECRETS_BOOK },
    ],
  },
  async check(ctx) {
    const files = ctx.files!;
    const out: RawFinding[] = [];
    const seen = new Set<string>(); // one finding per key value
    for (const entry of files.all()) {
      if (isLockfile(entry.path)) continue;
      const text = await files.text(entry.path);
      if (text === null) continue;
      for (const m of findPublishable(text)) {
        if (seen.has(m.value)) continue;
        seen.add(m.value);
        const note = m.pattern.vendor === "Firebase" ? " (your security rules protect the data)" : "";
        const f = secretFinding(
          "SEC-INFO-001",
          entry.path,
          text,
          m,
          `${m.pattern.label} detected: fine to expose${note}`,
        );
        delete f.severity;
        out.push(f);
      }
    }
    return out;
  },
};
