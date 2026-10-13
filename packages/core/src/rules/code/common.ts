// Shared helpers for CODE-* rules (JS/TS, regex + light tokenization, TRD §6.5).
import type { FileIndex, RawFinding } from "../../types.js";
import { stripJs } from "../../util/js-scan.js";
import { lineCol } from "../../util/text.js";

export const INPUTS_BOOK = "Creating a Secure App — Inputs, Outputs & Web Hardening";

const SOURCE_EXT = /\.(?:[cm]?[jt]sx?|vue|svelte)$/;

export interface SourceFile {
  path: string;
  text: string;
  /** Comments blanked; strings kept. */
  code: string;
  /** Comments and string contents blanked. */
  bare: string;
}

const cache = new WeakMap<FileIndex, Promise<SourceFile[]>>();

/** JS/TS sources, excluding build output, minified and declaration files. */
export function loadSources(files: FileIndex, buildDirs: string[]): Promise<SourceFile[]> {
  let hit = cache.get(files);
  if (!hit) {
    hit = (async () => {
      const out: SourceFile[] = [];
      for (const e of files.all()) {
        if (!SOURCE_EXT.test(e.path) || /\.d\.ts$|\.min\.js$/.test(e.path)) continue;
        if (buildDirs.some((d) => e.path.startsWith(d))) continue;
        const text = await files.text(e.path);
        if (text === null) continue;
        out.push({ path: e.path, text, code: stripJs(text), bare: stripJs(text, { blankStrings: true }) });
      }
      return out;
    })();
    cache.set(files, hit);
  }
  return hit;
}

/** Index just past the bracket matching the one at `open` in comment/string-blanked code. */
export function matchBracket(bare: string, open: number): number {
  const pairs: Record<string, string> = { "(": ")", "{": "}", "[": "]" };
  const stack: string[] = [];
  for (let i = open; i < bare.length; i++) {
    const c = bare[i]!;
    if (c in pairs) stack.push(pairs[c]!);
    else if (c === ")" || c === "}" || c === "]") {
      if (stack.pop() !== c) return -1;
      if (stack.length === 0) return i + 1;
    }
  }
  return -1;
}

/** First call argument starting at `start` (just after "("), as [start, end) offsets. */
export function firstArg(bare: string, start: number): [number, number] {
  let depth = 0;
  for (let i = start; i < bare.length; i++) {
    const c = bare[i]!;
    if (c === "(" || c === "{" || c === "[") depth++;
    else if (c === ")" || c === "}" || c === "]") {
      if (depth === 0) return [start, i];
      depth--;
    } else if (c === "," && depth === 0) return [start, i];
  }
  return [start, bare.length];
}

/** True if the expression is a single plain string literal (no interpolation). */
export function isStringLiteral(code: string): boolean {
  const t = code.trim();
  return /^(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\$]|\\.|\$(?!\{))*`)$/.test(t);
}

export function finding(ruleId: string, f: SourceFile, start: number, end: number): RawFinding {
  const { line, column } = lineCol(f.text, start);
  const lineStart = f.text.lastIndexOf("\n", start - 1) + 1;
  let lineEnd = f.text.indexOf("\n", start);
  if (lineEnd === -1) lineEnd = f.text.length;
  const snippet = f.text.slice(lineStart, lineEnd);
  return {
    ruleId,
    location: { kind: "file", path: f.path, line, column },
    evidence: { snippet, matchStart: start - lineStart, matchEnd: Math.min(end, lineEnd) - lineStart },
  };
}
