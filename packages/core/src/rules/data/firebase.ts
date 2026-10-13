// Firebase security rules reader (Firestore and Storage rules, Realtime Database JSON rules).
import type { FileIndex } from "../../types.js";
import { stripJs } from "../../util/js-scan.js";

export interface AllowStatement {
  file: string;
  ops: string[];
  /** Condition after `if`, or null for a bare `allow read, write;`. */
  condition: string | null;
  /** Enclosing match path, e.g. "/databases/{database}/documents/{document=**}". */
  path: string;
  offset: number;
  length: number;
}

const WRITE_OPS = new Set(["write", "create", "update", "delete"]);

export function hasWrite(ops: string[]): boolean {
  return ops.some((o) => WRITE_OPS.has(o));
}

/** Reads `allow` statements with their match path. Comments are ignored. */
export function readFirebaseRules(file: string, text: string): AllowStatement[] {
  const code = stripJs(text);
  const out: AllowStatement[] = [];
  const stack: Array<{ path: string; depth: number }> = [];
  let depth = 0;
  const token =
    /\bmatch\s+(\/[^\s{]*)\s*\{|\ballow\s+([a-z]+(?:\s*,\s*[a-z]+)*)\s*(?::\s*if\s+([^;]*))?;|[{}]/g;
  for (let m = token.exec(code); m !== null; m = token.exec(code)) {
    if (m[1] !== undefined) {
      depth++;
      stack.push({ path: m[1], depth });
    } else if (m[2] !== undefined) {
      out.push({
        file,
        ops: m[2].split(",").map((s) => s.trim()),
        condition: m[3] !== undefined ? m[3].replace(/\s+/g, " ").trim() : null,
        path: stack.map((s) => s.path).join(""),
        offset: m.index,
        length: m[0].length,
      });
    } else if (m[0] === "{") depth++;
    else {
      if (stack.length && stack[stack.length - 1]!.depth === depth) stack.pop();
      depth--;
    }
  }
  return out;
}

export interface RtdbRule {
  file: string;
  kind: ".read" | ".write";
  value: string;
  offset: number;
  length: number;
}

/** Finds ".read"/".write" entries in database.rules.json (comments tolerated). */
export function readRtdbRules(file: string, text: string): RtdbRule[] {
  const code = stripJs(text);
  const out: RtdbRule[] = [];
  const re = /"(\.read|\.write)"\s*:\s*(true|false|"(?:[^"\\]|\\.)*")/g;
  for (let m = re.exec(code); m !== null; m = re.exec(code)) {
    const raw = m[2]!;
    out.push({
      file,
      kind: m[1] as ".read" | ".write",
      value: raw.startsWith('"') ? raw.slice(1, -1).replace(/\s+/g, " ").trim() : raw,
      offset: m.index,
      length: m[0].length,
    });
  }
  return out;
}

export async function loadFirebase(files: FileIndex) {
  const rules: AllowStatement[] = [];
  const rtdb: RtdbRule[] = [];
  const texts = new Map<string, string>();
  for (const e of files.glob("**/{firestore,storage}.rules")) {
    const t = await files.text(e.path);
    if (t === null) continue;
    texts.set(e.path, t);
    rules.push(...readFirebaseRules(e.path, t));
  }
  for (const e of files.glob("**/database.rules.json")) {
    const t = await files.text(e.path);
    if (t === null) continue;
    texts.set(e.path, t);
    rtdb.push(...readRtdbRules(e.path, t));
  }
  return { rules, rtdb, texts };
}
