// Minimal .env line reader for SEC-003/SEC-004.

export interface EnvEntry {
  name: string;
  value: string;
  line: number;
  /** Offsets of the value within the full file text. */
  valueStart: number;
  valueEnd: number;
  lineStart: number;
  lineEnd: number;
}

const LINE = /^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.]*)[ \t]*=[ \t]*(.*)$/;

export function parseEnv(text: string): EnvEntry[] {
  const out: EnvEntry[] = [];
  let offset = 0;
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!.replace(/\r$/, "");
    const lineStart = offset;
    offset += lines[i]!.length + 1;
    const m = LINE.exec(raw);
    if (!m) continue;
    const name = m[1]!;
    let rawValue = m[2]!;
    let rel = raw.length - rawValue.length;
    let value: string;
    const q = rawValue[0];
    if ((q === '"' || q === "'" || q === "`") && rawValue.indexOf(q, 1) !== -1) {
      value = rawValue.slice(1, rawValue.indexOf(q, 1));
      rel += 1;
    } else {
      const hash = rawValue.search(/\s#/);
      if (hash !== -1) rawValue = rawValue.slice(0, hash);
      value = rawValue.trim();
    }
    out.push({
      name,
      value,
      line: i + 1,
      valueStart: lineStart + rel,
      valueEnd: lineStart + rel + value.length,
      lineStart,
      lineEnd: lineStart + raw.length,
    });
  }
  return out;
}
