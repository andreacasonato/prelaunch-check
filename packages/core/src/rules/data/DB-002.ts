import type { RawFinding, Rule } from "../../types.js";
import { at, DB_BOOK, loadSqlModel, shortTable, SUPABASE_RLS } from "./common.js";
import { normaliseExpr, reachableByClients } from "./sql.js";

export const DB_002: Rule = {
  meta: {
    id: "DB-002",
    title: "Policy allows anyone to write",
    category: "data",
    severity: "high",
    confidence: "high",
    owasp: "A01",
    requires: ["files"],
    appliesWhen: (p) => p.backends.includes("supabase") || p.supabaseMigrationsFound,
    summary:
      "Finds insert, update, delete or all policies whose using or with check expression is just `true`, without being limited to service_role.",
    why: "A policy of `true` means the check always passes. For writes, that lets anyone holding your public key insert, change or delete rows, including other users' data.",
    fix: [
      "Replace `true` with a real condition, usually ownership: `using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id)`.",
      "If only your server should write, drop the policy and write from server code with the secret key instead.",
    ],
    fixPromptTemplate:
      'In `{{path}}` line {{line}}, the policy "{{detail.policy}}" on `{{detail.table}}` allows {{detail.command}} with `true`, so anyone can write. Replace it in a new migration with a policy that only allows the row\'s owner (using (select auth.uid()) = user_id, plus a matching with check), or remove it if only the server should write.',
    falsePositiveNotes:
      "Policies scoped `to service_role` are not reported. A table intended as a public write-only inbox still needs rate limits.",
    sources: [
      { title: "Supabase: Row Level Security", url: SUPABASE_RLS },
      { title: "Locking Down the Database", book: DB_BOOK },
    ],
  },
  async check(ctx) {
    const { model, texts } = await loadSqlModel(ctx.files!);
    const out: RawFinding[] = [];
    for (const p of model.policies) {
      if (p.command === "select" || !reachableByClients(p.roles)) continue;
      // For "all" and "update" without WITH CHECK, Postgres reuses USING as the check.
      const exprs = [normaliseExpr(p.using), normaliseExpr(p.withCheck)];
      if (!exprs.includes("true")) continue;
      const text = texts.get(p.file)!;
      const f = at("DB-002", p.file, text, p.offset, p.text.split("\n")[0]!.length);
      f.title = `Policy "${p.name}" lets anyone ${p.command === "all" ? "write to" : p.command} ${shortTable(p.table)}`;
      f.evidence.detail = { policy: p.name, table: shortTable(p.table), command: p.command };
      out.push(f);
    }
    return out;
  },
};
