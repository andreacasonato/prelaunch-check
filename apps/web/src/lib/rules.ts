import { DEFAULT_RULES, SEC_006_META, type RuleMeta } from "@prelaunch-check/core";

export const ALL_RULE_META: RuleMeta[] = [...DEFAULT_RULES.map((r) => r.meta), SEC_006_META].sort((a, b) =>
  a.id < b.id ? -1 : 1,
);

export function ruleMeta(id: string): RuleMeta | undefined {
  return ALL_RULE_META.find((m) => m.id === id);
}

/** Only http(s) links are rendered as links; anything else (javascript:, data:) is shown as text. */
export function safeHref(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const u = new URL(url);
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : undefined;
  } catch {
    return undefined;
  }
}

/** Names of the OWASP Top 10:2025 categories used by the rules (TRD §6). */
export const OWASP_2025: Record<string, string> = {
  A01: "Broken Access Control",
  A02: "Security Misconfiguration",
  A03: "Software Supply Chain Failures",
  A04: "Cryptographic Failures",
  A05: "Injection",
  A07: "Authentication Failures",
  A09: "Security Logging and Alerting Failures",
};

export const REPO_URL = "https://github.com/andreacasonato/prelaunch-check";
