import type { RawFinding, Rule } from "../../types.js";
import { lineCol, snippetAround } from "../../util/text.js";
import { findPrivateKeys, isLockfile } from "./scan.js";
import { SECRETS_BOOK } from "./common.js";

export const SEC_005: Rule = {
  meta: {
    id: "SEC-005",
    title: "Private key file or block",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    owasp: "A04",
    requires: ["files"],
    summary:
      "Finds PEM private keys (RSA, EC, OpenSSH, PKCS#8) in any scanned text file, including *.pem and id_rsa files.",
    why: "A private key proves identity: it can sign tokens, decrypt traffic or log in to servers as you. Anyone with a copy of the repository has a copy of the key.",
    fix: [
      "Delete the key from the project and store it in your host's secret manager or a server-only environment variable.",
      "Generate a new key pair and revoke the old one wherever it was trusted (server authorized_keys, JWT verifiers, certificate authority).",
      "Add `*.pem`, `id_rsa*` and `*.key` to .gitignore.",
    ],
    fixPromptTemplate:
      "The file `{{path}}` line {{line}} contains a {{detail.label}}. Remove it from the project, load it at runtime from a secret manager or a server-only environment variable, and add *.pem, *.key and id_rsa* to .gitignore. Remind me to generate a new key pair and revoke the old one wherever it was trusted.",
    falsePositiveNotes:
      "Sample keys in tests or documentation match when they have a full-length body. Short placeholders are ignored. Encrypted keys are reported as high instead of critical.",
    sources: [
      { title: "gitleaks private-key rule (ported, MIT)", url: "https://github.com/gitleaks/gitleaks" },
      { title: "Secrets & API Keys", book: SECRETS_BOOK },
    ],
  },
  async check(ctx) {
    const files = ctx.files!;
    const out: RawFinding[] = [];
    for (const entry of files.all()) {
      if (isLockfile(entry.path)) continue;
      const text = await files.text(entry.path);
      if (text === null) continue;
      for (const k of findPrivateKeys(text)) {
        const s = snippetAround(text, k.bodyStart, k.bodyStart + k.body.length, 1);
        const f: RawFinding = {
          ruleId: "SEC-005",
          title: k.encrypted ? `Encrypted ${k.label} in project files` : `${k.label} in project files`,
          location: { kind: "file", path: entry.path, line: lineCol(text, k.start).line },
          evidence: {
            snippet: s.snippet,
            matchStart: s.matchStart,
            matchEnd: s.matchEnd,
            detail: { label: k.label },
          },
          secretValue: k.body,
        };
        if (k.encrypted) f.severity = "high";
        out.push(f);
      }
    }
    return out;
  },
};
