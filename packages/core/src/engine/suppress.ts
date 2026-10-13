// Inline suppressions (docs/05-SCHEMA.md §4):
//   // prelaunch-check-ignore <RULE-ID>[,<RULE-ID>]: <reason>
//   #  prelaunch-check-ignore <RULE-ID>: <reason>      (YAML, shell, .env, Python)
//   -- prelaunch-check-ignore <RULE-ID>: <reason>      (SQL)
// A comment alone on its line applies to the next non-blank line; otherwise to its own line.
// A reason is required; without one the suppression is ignored (CFG-INFO-001 reports it).

export interface InlineSuppression {
  /** 1-based line the comment is on. */
  line: number;
  /** 1-based line it applies to. */
  target: number;
  ruleIds: string[];
  reason: string | null;
}

const MARKER =
  /(\/\/|#|--|\/\*|<!--)\s*prelaunch-check-ignore\s+([A-Z0-9][A-Z0-9,\s-]*?)\s*(?::\s*(.*?))?\s*(?:\*\/|-->)?\s*$/;

export function parseInlineSuppressions(text: string): InlineSuppression[] {
  if (!text.includes("prelaunch-check-ignore")) return [];
  const lines = text.split("\n");
  const out: InlineSuppression[] = [];
  lines.forEach((raw, i) => {
    const m = MARKER.exec(raw);
    if (!m) return;
    const before = raw.slice(0, m.index);
    const ownLine = before.trim() === "";
    let target = i + 1;
    if (ownLine) {
      let j = i + 1;
      while (j < lines.length && lines[j]!.trim() === "") j++;
      target = j + 1;
    }
    const reason = m[3]?.trim() ?? "";
    out.push({
      line: i + 1,
      target,
      ruleIds: m[2]!
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      reason: reason === "" ? null : reason,
    });
  });
  return out;
}
