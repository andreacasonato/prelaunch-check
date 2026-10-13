import type { RawFinding, Rule } from "../../types.js";
import { at, DB_BOOK, loadSqlModel, shortTable, SUPABASE_RLS } from "./common.js";
import { AUTH_UID, reachableByClients, type SqlModel } from "./sql.js";
import { sensitiveMatcher } from "./sensitive-columns.js";

/** True if column-level grants stop clients from updating `column`. */
function columnProtected(model: SqlModel, table: string, column: string): boolean {
  let tableRevoked = false;
  let granted: Set<string> | null = null;
  for (const g of model.updateGrants) {
    if (g.table !== table || !reachableByClients(g.roles)) continue;
    if (g.kind === "revoke") {
      if (g.columns === null) tableRevoked = true;
      else if (g.columns.includes(column)) return true;
    } else if (g.columns !== null) {
      granted ??= new Set();
      for (const c of g.columns) granted.add(c);
    } else tableRevoked = false;
  }
  // `revoke update on t` then `grant update (a, b) on t`: other columns stay protected.
  return tableRevoked && (granted === null || !granted.has(column));
}

export const DB_003: Rule = {
  meta: {
    id: "DB-003",
    title: '"Money or power" column on a user-editable table',
    category: "data",
    severity: "high",
    confidence: "medium",
    owasp: "A01",
    requires: ["files"],
    appliesWhen: (p) => p.backends.includes("supabase") || p.supabaseMigrationsFound,
    summary:
      "Finds tables where users may update their own row (an update policy using auth.uid()) and that also hold columns like credits, plan, role or is_admin.",
    why: "Row Level Security decides which rows a user may change, not which columns. If users can update their own profile and the profile has a credits or plan column, they can give themselves unlimited credits or a paid plan from the browser console. Ask: if a user could edit this field freely, would it cost me money or give them power they shouldn't have?",
    fix: [
      "Move money and power fields to a separate table (for example `billing`) that users can only read; update it only from server code or a webhook using the secret key.",
      "Or block the column for clients: `revoke update (credits) on profiles from authenticated, anon;`",
      "Test it: sign in as a normal user and try `supabase.from('profiles').update({ credits: 999999 }).eq('id', myId)`; it must fail.",
    ],
    fixPromptTemplate:
      'In `{{path}}` line {{line}}, the column `{{detail.column}}` on table `{{detail.table}}` can be changed by the row\'s owner because policy "{{detail.policy}}" allows updates with auth.uid(). Users could change their own {{detail.column}}. Move {{detail.column}} to a separate table that users can only select from (and update it only from server code with the secret key), or add a migration with `revoke update ({{detail.column}}) on {{detail.table}} from authenticated, anon;`. Then write a test that signs in as a normal user, tries to update {{detail.column}}, and expects it to fail.',
    falsePositiveNotes:
      "Columns protected by a trigger, or by a with check expression that pins the column's value, are only recognised when the with check mentions the column. Column names are matched by name only; extend or narrow the list with config `sensitiveColumnNames`.",
    sources: [
      { title: "Locking Down the Database (the sneaky RLS failure)", book: DB_BOOK },
      { title: "Supabase: Row Level Security", url: SUPABASE_RLS },
      {
        title: "PostgreSQL: GRANT (column privileges)",
        url: "https://www.postgresql.org/docs/current/sql-grant.html",
      },
    ],
  },
  async check(ctx) {
    const { model, texts } = await loadSqlModel(ctx.files!);
    const isSensitive = sensitiveMatcher(ctx.config.sensitiveColumnNames);
    const out: RawFinding[] = [];
    for (const t of model.tables.values()) {
      if (t.schema !== "public") continue;
      const ownerUpdate = model.policies.find(
        (p) =>
          p.table === t.name &&
          (p.command === "update" || p.command === "all") &&
          reachableByClients(p.roles) &&
          (AUTH_UID.test(p.using ?? "") || AUTH_UID.test(p.withCheck ?? "")),
      );
      if (!ownerUpdate) continue;
      for (const col of t.columns) {
        if (!isSensitive(col.name)) continue;
        if (columnProtected(model, t.name, col.name)) continue;
        if (ownerUpdate.withCheck && new RegExp(`\\b${col.name}\\b`, "i").test(ownerUpdate.withCheck))
          continue;
        const text = texts.get(col.file)!;
        const f = at("DB-003", col.file, text, col.offset, col.name.length);
        f.title = `"${col.name}" on ${shortTable(t.name)} can be changed by its owner`;
        f.evidence.detail = { table: shortTable(t.name), column: col.name, policy: ownerUpdate.name };
        out.push(f);
      }
    }
    return out;
  },
};
