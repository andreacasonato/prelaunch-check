// Env var prefixes that frameworks inline into client-side code (TRD §4.2).
// Add an entry only after checking that framework's own docs, and cite the page.
import type { Framework } from "../types.js";

export interface PublicEnvPrefix {
  framework: Framework;
  prefix: string;
  sourceUrl: string;
  quote: string;
}

export const PUBLIC_ENV_PREFIXES: readonly PublicEnvPrefix[] = [
  {
    framework: "next",
    prefix: "NEXT_PUBLIC_",
    sourceUrl: "https://nextjs.org/docs/app/guides/environment-variables",
    quote: "inlined into any JavaScript sent to the browser",
  },
  {
    framework: "vite",
    prefix: "VITE_",
    sourceUrl: "https://vite.dev/guide/env-and-mode",
    quote: "Variables prefixed with VITE_ will be exposed in client-side source code",
  },
];
