import type { RawFinding, Rule } from "../../types.js";
import { at, loadSqlModel, shortTable, SUPABASE_RLS } from "./common.js";

const UID_EQ =
  /(?:\(\s*select\s+auth\.uid\s*\(\s*\)\s*\)|auth\.uid\s*\(\s*\))\s*=\s*[\w."]+|[\w."]+\s*=\s*(?:\(\s*select\s+auth\.uid\s*\(\s*\)\s*\)|auth\.uid\s*\(\s*\))/i;
const NOT_NULL = /(?:\(\s*select\s+auth\.uid\s*\(\s*\)\s*\)|auth\.uid\s*\(\s*\))\s+is\s+not\s+null/i;

export const DB_006: Rule = {
  meta: {
    id: "DB-006",
    title: "Ownership policy without explicit null check",
    category: "data",
    severity: "low",
    confidence: "medium",
    owasp: "A01",
    requires: ["files"],
    appliesWhen: (p) => p.backends.includes("supabase") || p.supabaseMigrationsFound,
    summary:
      "Finds policies comparing auth.uid() to a column without also checking `auth.uid() is not null`.",
    why: "For logged-out requests auth.uid() is null. Comparisons with null are never true, so the policy usually fails closed, but an explicit check documents intent and protects you if a column can also be null. Supabase recommends it.",
    fix: [
      "Add the explicit check: `using ((select auth.uid()) is not null and (select auth.uid()) = user_id)`.",
    ],
    fixPromptTemplate:
      'In `{{path}}` line {{line}}, the policy "{{detail.policy}}" on `{{detail.table}}` compares auth.uid() to a column without `auth.uid() is not null`. Update it in a new migration to `(select auth.uid()) is not null and (select auth.uid()) = <owner column>`.',
    sources: [{ title: "Supabase: Row Level Security", url: SUPABASE_RLS }],
  },
  async check(ctx) {
    const { model, texts } = await loadSqlModel(ctx.files!);
    const out: RawFinding[] = [];
    for (const p of model.policies) {
      const exprs = [p.using ?? "", p.withCheck ?? ""].join(" ");
      if (!UID_EQ.test(exprs) || NOT_NULL.test(exprs)) continue;
      const text = texts.get(p.file)!;
      const f = at("DB-006", p.file, text, p.offset, p.text.split("\n")[0]!.length);
      f.title = `Policy "${p.name}" on ${shortTable(p.table)} has no explicit auth.uid() null check`;
      f.evidence.detail = { policy: p.name, table: shortTable(p.table) };
      out.push(f);
    }
    return out;
  },
};
