import type { RawFinding, Rule } from "../../types.js";
import { PUBLIC_ENV_PREFIXES } from "../../detect/public-env-prefixes.js";
import { findDbUrls, findSecrets, isEnvExample, isEnvFile } from "./scan.js";
import { parseEnv } from "./env.js";
import { ROTATE_STEP, SECRETS_BOOK } from "./common.js";

const SENSITIVE_NAME = /SECRET|SERVICE_ROLE|PRIVATE|PASSWORD/;

export const SEC_003: Rule = {
  meta: {
    id: "SEC-003",
    title: "Secret placed in a client-exposed env var",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    owasp: "A04",
    requires: ["files"],
    summary:
      "Finds .env variables whose name starts with a browser-exposed prefix (NEXT_PUBLIC_, VITE_) but whose value is a secret key or whose name says it's secret.",
    why: "Frameworks copy every variable with a public prefix into the JavaScript sent to the browser. A secret stored under such a name is readable by every visitor, even though it lives in a .env file.",
    fix: [
      "Rename the variable without the public prefix so it stays on the server.",
      "Move the code that uses it into a server-side function (API route, server action, edge function).",
      ROTATE_STEP,
      "Rebuild and search the build output to confirm the key is gone.",
    ],
    fixPromptTemplate:
      "In `{{path}}` line {{line}}, the variable {{detail.variable}} holds {{detail.what}}. Variables starting with {{detail.prefix}} are bundled into the browser. Move the code that uses it to a server-side function, read the value from a server-only environment variable without the {{detail.prefix}} prefix, and then search the build output to confirm the value no longer appears. Remind me to rotate the key in the provider's dashboard.",
    falsePositiveNotes:
      "Matches by name only (e.g. NEXT_PUBLIC_PASSWORD_MIN_LENGTH) are reported with medium confidence; numeric and boolean values are ignored.",
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
    // Every known public prefix applies: a NEXT_PUBLIC_ variable only exists to reach the browser.
    const prefixes = [
      ...new Set([...ctx.profile.publicEnvPrefixes, ...PUBLIC_ENV_PREFIXES.map((p) => p.prefix)]),
    ];
    const out: RawFinding[] = [];
    for (const entry of files.all()) {
      if (!isEnvFile(entry.path)) continue;
      const text = await files.text(entry.path);
      if (text === null) continue;
      for (const e of parseEnv(text)) {
        const prefix = prefixes.find((p) => e.name.startsWith(p));
        if (!prefix || e.value === "") continue;
        const lineText = text.slice(e.lineStart, e.lineEnd);
        const base = {
          ruleId: "SEC-003",
          location: { kind: "file" as const, path: entry.path, line: e.line },
        };
        const secret = findSecrets(e.value)[0];
        const db = secret ? undefined : findDbUrls(e.value)[0];
        if (secret || db) {
          const value = secret ? secret.value : db!.password;
          const what = secret ? `a ${secret.pattern.label}` : "a database password";
          const start = e.valueStart - e.lineStart + (secret ? secret.start : db!.passwordStart);
          out.push({
            ...base,
            title: `${secret ? secret.pattern.label : "Database password"} in a client-exposed environment variable`,
            evidence: {
              snippet: lineText,
              matchStart: start,
              matchEnd: start + value.length,
              detail: { variable: e.name, prefix, vendor: secret?.pattern.vendor ?? "Database", what },
            },
            secretValue: value,
          });
          continue;
        }
        if (isEnvExample(entry.path)) continue;
        if (!SENSITIVE_NAME.test(e.name) || /^(?:\d+|true|false)$/i.test(e.value)) continue;
        out.push({
          ...base,
          confidence: "medium",
          title: `Secret-named variable ${e.name} is exposed to the browser`,
          evidence: {
            snippet: lineText,
            matchStart: e.valueStart - e.lineStart,
            matchEnd: e.valueEnd - e.lineStart,
            detail: {
              variable: e.name,
              prefix,
              vendor: "the provider",
              what: "a value its name marks as secret",
            },
          },
          secretValue: e.value,
        });
      }
    }
    return out;
  },
};
