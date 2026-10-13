import type { FileIndex, RawFinding } from "../../types.js";
import { snippetAround } from "../../util/text.js";
import { buildSqlModel, type SqlModel } from "./sql.js";

export const DB_BOOK = "Creating a Secure App — Locking Down the Database";
export const SUPABASE_RLS = "https://supabase.com/docs/guides/database/postgres/row-level-security";
export const FIREBASE_INSECURE = "https://firebase.google.com/docs/rules/insecure-rules";

const cache = new WeakMap<FileIndex, Promise<{ model: SqlModel; texts: Map<string, string> }>>();

/** SQL files: Supabase migrations first, plus any other *.sql in the project (TRD §6.2). */
export function loadSqlModel(files: FileIndex): Promise<{ model: SqlModel; texts: Map<string, string> }> {
  let hit = cache.get(files);
  if (!hit) {
    hit = (async () => {
      const texts = new Map<string, string>();
      for (const e of files.glob("**/*.sql")) {
        const t = await files.text(e.path);
        if (t !== null) texts.set(e.path, t);
      }
      return { model: buildSqlModel([...texts].map(([path, text]) => ({ path, text }))), texts };
    })();
    cache.set(files, hit);
  }
  return hit;
}

/** A finding pointing at `offset` in a file, with a short snippet. */
export function at(ruleId: string, path: string, text: string, offset: number, length: number): RawFinding {
  const s = snippetAround(text, offset, offset + length, 2);
  return {
    ruleId,
    location: { kind: "file", path, line: s.line },
    evidence: { snippet: s.snippet, matchStart: s.matchStart, matchEnd: s.matchEnd },
  };
}

export function shortTable(name: string): string {
  return name.startsWith("public.") ? name.slice(7) : name;
}
