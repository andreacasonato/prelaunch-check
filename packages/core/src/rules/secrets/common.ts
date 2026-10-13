// Shared helpers for secret rules.
import type { RawFinding } from "../../types.js";
import { snippetAround } from "../../util/text.js";
import type { SecretMatch } from "./scan.js";

export function secretFinding(
  ruleId: string,
  path: string,
  text: string,
  m: SecretMatch,
  title: string,
): RawFinding {
  const s = snippetAround(text, m.start, m.end);
  const f: RawFinding = {
    ruleId,
    title,
    location: { kind: "file", path, line: s.line, column: s.column },
    evidence: {
      snippet: s.snippet,
      matchStart: s.matchStart,
      matchEnd: s.matchEnd,
      detail: { vendor: m.pattern.vendor, keyType: m.pattern.label, patternId: m.pattern.id },
    },
    secretValue: m.value,
  };
  if (m.pattern.isTest) f.severity = "medium";
  else if (m.pattern.severity !== "critical") f.severity = m.pattern.severity;
  return f;
}

export const SECRETS_BOOK = "Creating a Secure App — Secrets & API Keys";

export const ROTATE_STEP =
  "Rotate the key in the provider's dashboard. Removing it from the code doesn't un-leak it: anyone who saw it can still use it until it's revoked.";
