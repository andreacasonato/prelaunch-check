// Fingerprints (docs/05-SCHEMA.md §2.8): stable identity across scans, independent of line numbers.
import type { RawFinding } from "./types.js";

const encoder = new TextEncoder();
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

async function sha256(input: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(input)));
}

export async function sha256Hex(input: string): Promise<string> {
  return Array.from(await sha256(input), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** RFC 4648 base32, no padding. */
export function base32(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(buffer << (5 - bits)) & 31];
  return out;
}

export function normaliseUrl(url: string): string {
  try {
    const u = new URL(url);
    u.hash = "";
    u.username = "";
    u.password = "";
    return u.toString();
  } catch {
    return url.trim();
  }
}

function collapse(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}

function stableStringify(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "";
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${stableStringify(o[k])}`)
    .join(",")}}`;
}

/** The matched text a fingerprint is based on. Secrets use the raw value, which is hashed and never stored. */
function matchText(f: RawFinding): string {
  const { snippet, matchStart, matchEnd, detail } = f.evidence;
  if (snippet !== undefined) {
    if (matchStart !== undefined && matchEnd !== undefined && matchEnd > matchStart)
      return snippet.slice(matchStart, matchEnd);
    return snippet;
  }
  return detail ? stableStringify(detail) : "";
}

/**
 * Computes the fingerprint before disambiguation (the engine appends #2, #3 for identical
 * matches in one file). Must be called on the RAW finding, before redaction.
 */
export async function computeFingerprintKey(f: RawFinding): Promise<string> {
  const where = f.location.path ?? (f.location.url ? normaliseUrl(f.location.url) : "");
  const matchHash =
    f.secretValue !== undefined ? await sha256Hex(f.secretValue) : await sha256Hex(collapse(matchText(f)));
  const digest = await sha256(`${f.ruleId}\0${where}\0${await sha256Hex(matchHash)}`);
  return `f1_${base32(digest).slice(0, 20)}`;
}
