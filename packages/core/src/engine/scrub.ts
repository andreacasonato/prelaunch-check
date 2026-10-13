// Defence in depth: after rule-level redaction, every snippet is re-scanned with all secret
// detectors and anything that still looks like a credential is redacted. This catches secrets
// in context lines around a finding, whichever rule produced it.
import type { Evidence } from "../types.js";
import { redact, redactAll } from "../redact.js";
import { findDbUrls, findPrivateKeys, findPublishable, findSecrets } from "../rules/secrets/scan.js";

interface Span {
  start: number;
  end: number;
  value: string;
}

function credentialSpans(text: string): Span[] {
  const spans: Span[] = [
    ...findSecrets(text).map((m) => ({ start: m.start, end: m.end, value: m.value })),
    ...findPublishable(text).map((m) => ({ start: m.start, end: m.end, value: m.value })),
    ...findDbUrls(text).map((m) => ({
      start: m.passwordStart,
      end: m.passwordStart + m.password.length,
      value: m.password,
    })),
    ...findPrivateKeys(text).map((k) => ({
      start: k.bodyStart,
      end: k.bodyStart + k.body.length,
      value: k.body,
    })),
  ].sort((a, b) => a.start - b.start || b.end - a.end);
  const out: Span[] = [];
  for (const s of spans) if (!out.length || s.start >= out[out.length - 1]!.end) out.push(s);
  return out;
}

export function scrubEvidence(evidence: Evidence): Evidence {
  if (evidence.snippet === undefined) return evidence;
  const spans = credentialSpans(evidence.snippet);
  if (!spans.length) return evidence;
  let snippet = evidence.snippet;
  let { matchStart, matchEnd } = evidence;
  for (const s of [...spans].reverse()) {
    const replacement = redact(s.value);
    const delta = replacement.length - (s.end - s.start);
    snippet = snippet.slice(0, s.start) + replacement + snippet.slice(s.end);
    if (matchStart !== undefined && matchEnd !== undefined) {
      if (s.end <= matchStart) {
        matchStart += delta;
        matchEnd += delta;
      } else if (s.start < matchEnd) {
        matchStart = Math.min(matchStart, s.start);
        matchEnd = Math.max(s.start + replacement.length, matchEnd + delta);
      }
    }
  }
  const out: Evidence = { ...evidence, snippet };
  if (matchStart !== undefined) out.matchStart = matchStart;
  if (matchEnd !== undefined) out.matchEnd = matchEnd;
  if (evidence.detail) {
    const detail: Record<string, string | number | boolean> = {};
    for (const [k, v] of Object.entries(evidence.detail)) {
      detail[k] = typeof v === "string" ? spans.reduce((acc, s) => redactAll(acc, s.value), v) : v;
    }
    out.detail = detail;
  }
  return out;
}
