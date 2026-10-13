import type { RawFinding, Rule } from "../../types.js";
import { at, DB_BOOK, loadSqlModel, shortTable, SUPABASE_RLS } from "./common.js";

export const DB_001: Rule = {
  meta: {
    id: "DB-001",
    title: "Supabase table without Row Level Security",
    category: "data",
    severity: "high",
    confidence: "medium",
    owasp: "A01",
    requires: ["files"],
    appliesWhen: (p) => p.backends.includes("supabase") || p.supabaseMigrationsFound,
    summary:
      "Finds tables in the public schema that are created in SQL files but never get `enable row level security`.",
    why: "Supabase exposes every table in the public schema through its API. Without Row Level Security, anyone with your public (anon or publishable) key, which ships in your front end, can read and change every row.",
    fix: [
      "Enable RLS in a new migration: `alter table <table> enable row level security;`",
      'Add policies for exactly what each user may do, for example `create policy "Users read own rows" on <table> for select to authenticated using ((select auth.uid()) = user_id);`',
      "Test as a logged-out visitor and as a second user that you can't read or change other people's rows.",
    ],
    fixPromptTemplate:
      "The table `{{detail.table}}` created in `{{path}}` line {{line}} has no Row Level Security. Write a new Supabase migration that runs `alter table {{detail.table}} enable row level security;` and adds the minimum policies the app needs (owner-only access using (select auth.uid())). Then show me how to test that a logged-out user and a different user can't read or modify these rows.",
    falsePositiveNotes:
      "RLS enabled outside SQL files (in the dashboard) is invisible to a folder scan. Tables in schemas other than public are ignored. Tables that are dropped later in the migrations are ignored.",
    sources: [
      { title: "Supabase: Row Level Security", url: SUPABASE_RLS },
      { title: "Locking Down the Database", book: DB_BOOK },
    ],
  },
  async check(ctx) {
    const { model, texts } = await loadSqlModel(ctx.files!);
    const out: RawFinding[] = [];
    for (const t of model.tables.values()) {
      if (t.schema !== "public" || t.rls) continue;
      const text = texts.get(t.file)!;
      const f = at("DB-001", t.file, text, t.offset, text.slice(t.offset).search(/\(/) + 1 || 12);
      f.title = `Table "${shortTable(t.name)}" has no Row Level Security`;
      f.evidence.detail = { table: shortTable(t.name) };
      out.push(f);
    }
    return out;
  },
};
