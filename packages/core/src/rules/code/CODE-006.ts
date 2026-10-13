import type { RawFinding, Rule } from "../../types.js";
import { finding, loadSources, matchBracket } from "./common.js";

const STRIPE_IMPORT =
  /\bimport\s+(?:[\w$*{}\s,]+\s+from\s+)?["']stripe["']|\brequire\s*\(\s*["']stripe["']\s*\)/g;
const CREATE_CLIENT = /\bcreateClient\s*\(/g;
const SECRET_ENV =
  /(?:process\.env|import\.meta\.env)\s*(?:\.\s*|\[\s*["'`])[\w$]*(?:SERVICE_ROLE|SECRET)[\w$]*/;

export const CODE_006: Rule = {
  meta: {
    id: "CODE-006",
    title: "Secret-key SDK in client code",
    category: "code",
    severity: "critical",
    confidence: "medium",
    owasp: "A04",
    requires: ["files"],
    summary:
      "In code that ships to the browser (Vite src/, Next.js 'use client' files, build output): the server-side Stripe SDK, or a Supabase client created with a SERVICE_ROLE/SECRET key.",
    why: "The `stripe` package and a Supabase service-role client need secret keys. In browser code, those keys must be bundled for the code to work, which makes them public. Anyone could then charge cards or read your whole database.",
    fix: [
      "Use the browser SDKs in client code: `@stripe/stripe-js` and a Supabase client with the publishable (anon) key.",
      "Move secret operations to server code (API routes, server actions, edge functions) and call them from the client.",
    ],
    fixPromptTemplate:
      "`{{path}}` line {{line}} is client-side code but uses {{detail.what}}, which requires a secret key. Move this logic to a server-side route or function that reads the key from a server-only environment variable, and call that endpoint from the client instead. Use @stripe/stripe-js or the Supabase publishable key on the client.",
    falsePositiveNotes:
      "Client detection is path-based for Vite (everything under src/), so server code kept in a Vite src/ folder is reported too.",
    sources: [
      { title: "Stripe API keys", url: "https://docs.stripe.com/keys" },
      { title: "Supabase API keys", url: "https://supabase.com/docs/guides/api/api-keys" },
      { title: "Secrets & API Keys", book: "Creating a Secure App — Secrets & API Keys" },
    ],
  },
  async check(ctx) {
    const files = ctx.files!;
    const out: RawFinding[] = [];
    // Build output is client code too, so include it here.
    for (const f of await loadSources(files, [])) {
      if (!files.isClientShipped(f.path)) continue;
      const imp = new RegExp(STRIPE_IMPORT.source, "g");
      for (let m = imp.exec(f.code); m !== null; m = imp.exec(f.code)) {
        if (f.bare.slice(m.index, m.index + 6) !== f.code.slice(m.index, m.index + 6)) continue; // inside a string
        const x = finding("CODE-006", f, m.index, m.index + m[0].length);
        x.title = "Server-side Stripe SDK imported in client code";
        x.evidence.detail = { what: "the server-side `stripe` SDK" };
        out.push(x);
      }
      const cc = new RegExp(CREATE_CLIENT.source, "g");
      for (let m = cc.exec(f.bare); m !== null; m = cc.exec(f.bare)) {
        const close = matchBracket(f.bare, m.index + m[0].length - 1);
        const args = f.code.slice(m.index, close === -1 ? undefined : close);
        if (!SECRET_ENV.test(args)) continue;
        const x = finding("CODE-006", f, m.index, m.index + m[0].length);
        x.title = "Supabase client with a secret key in client code";
        x.evidence.detail = { what: "a Supabase client created with a service-role or secret key" };
        out.push(x);
      }
    }
    return out;
  },
};
