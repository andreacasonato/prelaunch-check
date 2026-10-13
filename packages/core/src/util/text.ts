// Text helpers shared by rules.

export interface Snippet {
  snippet: string;
  matchStart: number;
  matchEnd: number;
  line: number;
  column: number;
}

const MAX_LINE = 240;

/** 1-based line and column of an offset. */
export function lineCol(text: string, offset: number): { line: number; column: number } {
  let line = 1;
  let lastNl = -1;
  for (let i = text.indexOf("\n"); i !== -1 && i < offset; i = text.indexOf("\n", i + 1)) {
    line++;
    lastNl = i;
  }
  return { line, column: offset - lastNl };
}

/**
 * Up to `context` lines before and after the match (≤ 7 lines total for context = 3).
 * Very long lines (minified bundles) are clipped around the match so snippets stay small.
 */
export function snippetAround(text: string, start: number, end: number, context = 3): Snippet {
  const { line, column } = lineCol(text, start);
  const lineStart = text.lastIndexOf("\n", start - 1) + 1;
  let lineEnd = text.indexOf("\n", end);
  if (lineEnd === -1) lineEnd = text.length;

  const matchLine = text.slice(lineStart, lineEnd);
  if (matchLine.length > MAX_LINE) {
    const relStart = start - lineStart;
    const relEnd = end - lineStart;
    const pad = Math.max(0, Math.floor((MAX_LINE - (relEnd - relStart)) / 2));
    const from = Math.max(0, relStart - pad);
    const to = Math.min(matchLine.length, relEnd + pad);
    const prefix = from > 0 ? "…" : "";
    const clipped = prefix + matchLine.slice(from, to) + (to < matchLine.length ? "…" : "");
    return {
      snippet: clipped,
      matchStart: prefix.length + relStart - from,
      matchEnd: prefix.length + relEnd - from,
      line,
      column,
    };
  }

  const before: string[] = [];
  let cursor = lineStart;
  for (let i = 0; i < context && cursor > 0; i++) {
    const prevEnd = cursor - 1;
    const prevStart = text.lastIndexOf("\n", prevEnd - 1) + 1;
    const l = text.slice(prevStart, prevEnd);
    before.unshift(l.length > MAX_LINE ? l.slice(0, MAX_LINE) + "…" : l);
    cursor = prevStart;
  }
  const after: string[] = [];
  cursor = lineEnd;
  for (let i = 0; i < context && cursor < text.length; i++) {
    const nextStart = cursor + 1;
    let nextEnd = text.indexOf("\n", nextStart);
    if (nextEnd === -1) nextEnd = text.length;
    if (nextStart > text.length) break;
    const l = text.slice(nextStart, nextEnd);
    after.push(l.length > MAX_LINE ? l.slice(0, MAX_LINE) + "…" : l);
    cursor = nextEnd;
  }
  while (after.length && after[after.length - 1] === "") after.pop();

  const head = before.length ? before.join("\n") + "\n" : "";
  return {
    snippet: head + matchLine + (after.length ? "\n" + after.join("\n") : ""),
    matchStart: head.length + (start - lineStart),
    matchEnd: head.length + (end - lineStart),
    line,
    column,
  };
}

/** Line number (1-based) for every offset lookup in one pass-friendly helper. */
export function lineOf(text: string, offset: number): number {
  return lineCol(text, offset).line;
}
