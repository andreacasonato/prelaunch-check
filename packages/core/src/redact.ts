// Redaction (docs/05-SCHEMA.md §2.9). Applied in core before any output; it cannot be disabled.

const HIDDEN = "••••";

/** ≤ 12 code points → fully hidden; otherwise first 4 + "…" + last 4 (e.g. "sk_l…9xQz"). */
export function redact(value: string): string {
  const chars = Array.from(value);
  if (chars.length <= 12) return HIDDEN;
  return `${chars.slice(0, 4).join("")}…${chars.slice(-4).join("")}`;
}

/** Replaces every occurrence of `secret` in `text` with its redacted form. */
export function redactAll(text: string, secret: string): string {
  if (secret === "") return text;
  return text.split(secret).join(redact(secret));
}
