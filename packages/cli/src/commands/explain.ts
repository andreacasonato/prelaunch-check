import type { Rule } from "@prelaunch-check/core";

function levenshtein(a: string, b: string): number {
  const dp = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0]!;
    dp[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = dp[j]!;
      dp[j] = Math.min(dp[j]! + 1, dp[j - 1]! + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[b.length]!;
}

export function closestIds(input: string, rules: readonly Rule[], n = 3): string[] {
  const q = input.toUpperCase();
  return rules
    .map((r) => ({
      id: r.meta.id,
      d: levenshtein(q, r.meta.id) - (r.meta.id.startsWith(q.split("-")[0] ?? "") ? 1 : 0),
    }))
    .sort((a, b) => a.d - b.d || (a.id < b.id ? -1 : 1))
    .slice(0, n)
    .map((x) => x.id);
}

export function explainText(rule: Rule): string {
  const m = rule.meta;
  const out: string[] = [];
  out.push(`${m.id}  ${m.title}`);
  out.push(
    `Severity: ${m.severity} · Confidence: ${m.confidence} · Category: ${m.category} · OWASP ${m.owasp}:2025`,
  );
  out.push("");
  out.push("What it detects");
  out.push(`  ${m.summary}`);
  out.push("");
  out.push("Why it matters");
  out.push(`  ${m.why}`);
  out.push("");
  out.push("How to fix");
  m.fix.forEach((step, i) => out.push(`  ${i + 1}. ${step.replace(/\n/g, "\n     ")}`));
  if (m.falsePositiveNotes) {
    out.push("");
    out.push("Known false positives");
    out.push(`  ${m.falsePositiveNotes}`);
  }
  out.push("");
  out.push("Sources");
  for (const s of m.sources)
    out.push(`  - ${s.title}${s.url ? `: ${s.url}` : ""}${s.book ? ` (book: ${s.book})` : ""}`);
  return out.join("\n") + "\n";
}
