// A tiny, dependency-free YAML outline reader for GitHub workflow files.
// It does not build a full YAML tree; it records every "key: value" with its
// indentation, line number and parent chain, which is all the CFG rules need.

export interface YamlEntry {
  key: string;
  /** Inline value (comments stripped, quotes removed); "" when the value is a block. */
  value: string;
  /** For block scalars (| or >), the joined block text. */
  block?: string;
  line: number;
  indent: number;
  /** Keys of ancestors, outermost first. Sequence items appear as "-". */
  path: string[];
  /** Index of the sequence item this entry belongs to, per ancestor sequence. */
  itemId: number;
}

function stripComment(s: string): string {
  let inS = false;
  let inD = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "'" && !inD) inS = !inS;
    else if (c === '"' && !inS) inD = !inD;
    else if (c === "#" && !inS && !inD && (i === 0 || /\s/.test(s[i - 1]!))) return s.slice(0, i).trimEnd();
  }
  return s.trimEnd();
}

function unquote(v: string): string {
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) return v.slice(1, -1);
  return v;
}

const KEY_RE = /^([^\s:#'"][^:#]*?|"[^"]*"|'[^']*'):(?:\s+(.*))?$/;

export function readYamlOutline(text: string): YamlEntry[] {
  const lines = text.split(/\r?\n/);
  const out: YamlEntry[] = [];
  const stack: Array<{ indent: number; key: string }> = [];
  let itemCounter = 0;
  let currentItem = 0;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i]!;
    if (/^\s*(#|$)/.test(rawLine)) continue;
    let indent = rawLine.length - rawLine.trimStart().length;
    let content = stripComment(rawLine.trim());

    // Sequence item: "- key: value" or "- value"
    while (content.startsWith("- ") || content === "-") {
      while (stack.length && stack[stack.length - 1]!.indent >= indent) stack.pop();
      stack.push({ indent, key: "-" });
      currentItem = ++itemCounter;
      const rest = content === "-" ? "" : content.slice(2).trimStart();
      indent += content.length - rest.length;
      content = rest;
    }
    if (content === "") continue;

    const m = KEY_RE.exec(content);
    if (!m) continue;
    while (stack.length && stack[stack.length - 1]!.indent >= indent) stack.pop();
    const key = unquote(m[1]!.trim());
    const value = (m[2] ?? "").trim();
    const entry: YamlEntry = {
      key,
      value: unquote(value),
      line: i + 1,
      indent,
      path: stack.map((s) => s.key),
      itemId: currentItem,
    };

    if (/^[|>][-+0-9]*$/.test(value)) {
      const block: string[] = [];
      let j = i + 1;
      let blockIndent = -1;
      for (; j < lines.length; j++) {
        const l = lines[j]!;
        if (l.trim() === "") {
          block.push("");
          continue;
        }
        const ind = l.length - l.trimStart().length;
        if (ind <= indent) break;
        if (blockIndent === -1) blockIndent = ind;
        block.push(l.slice(Math.min(ind, blockIndent)));
      }
      entry.block = block.join("\n").trimEnd();
      entry.value = "";
      out.push(entry);
      i = j - 1;
      continue;
    }
    out.push(entry);
    stack.push({ indent, key });
  }
  return out;
}
