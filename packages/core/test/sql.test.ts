import { describe, expect, it } from "vitest";
import { buildSqlModel, normaliseExpr, normaliseTableName, splitStatements } from "../src/rules/data/sql.js";

describe("splitStatements", () => {
  it("splits on top-level semicolons only", () => {
    const sql = `create table a (x int); -- comment; not a split
/* block; /* nested; */ still comment; */ insert into a values ('it''s; fine');
create function f() returns void as $body$ begin perform 1; perform 2; end $body$ language plpgsql; select "weird;name" from a; select 1`;
    const parts = splitStatements(sql).map((s) => s.code.replace(/\s+/g, " ").trim());
    expect(parts).toHaveLength(5);
    expect(parts[0]).toBe("create table a (x int)");
    expect(parts[1]).toMatch(/^insert into a values \('it''s; fine'\)$/);
    expect(parts[2]).toMatch(/perform 1; perform 2;/);
    expect(parts[3]).toBe('select "weird;name" from a');
    expect(parts[4]).toBe("select 1");
  });

  it("handles multiple statements per line and reports start lines", () => {
    const parts = splitStatements("\n\nselect 1; select 2;\nselect 3;");
    expect(parts.map((p) => p.line)).toEqual([3, 3, 4]);
  });

  it("supports anonymous $$ bodies", () => {
    expect(splitStatements("do $$ begin raise notice ';'; end $$; select 1;")).toHaveLength(2);
  });
});

describe("buildSqlModel", () => {
  const model = buildSqlModel([
    {
      path: "supabase/migrations/0001.sql",
      text: `create table if not exists public."Profiles" (
  id uuid primary key references auth.users,
  "display name" text,
  credits int default 10 check (credits >= 0),
  constraint fk foreign key (id) references auth.users(id)
);
alter table only "Profiles" enable row level security;
create policy "Owners can update" on public."Profiles" as permissive for update to authenticated
  using ((select auth.uid()) = id) with check (auth.uid() = id);
create table private.secrets (v text);
alter table public."Profiles" add column plan text, add column if not exists tier text;
revoke update (credits) on public."Profiles" from authenticated;
create policy temp on public."Profiles" for select using (true);
drop policy temp on public."Profiles";`,
    },
  ]);

  it("reads tables, columns, schemas and RLS", () => {
    const t = model.tables.get("public.Profiles")!;
    expect(t.rls).toBe(true);
    expect(t.columns.map((c) => c.name)).toEqual(["id", "display name", "credits", "plan", "tier"]);
    expect(model.tables.get("private.secrets")!.schema).toBe("private");
  });

  it("reads policies with nested parentheses and drops", () => {
    expect(model.policies).toHaveLength(1);
    const p = model.policies[0]!;
    expect(p).toMatchObject({
      name: "Owners can update",
      table: "public.Profiles",
      command: "update",
      roles: ["authenticated"],
    });
    expect(p.using).toBe("(select auth.uid()) = id");
    expect(p.withCheck).toBe("auth.uid() = id");
  });

  it("reads column-level grants", () => {
    expect(model.updateGrants).toEqual([
      { table: "public.Profiles", kind: "revoke", columns: ["credits"], roles: ["authenticated"] },
    ]);
  });

  it("normalises names and expressions", () => {
    expect(normaliseTableName("profiles")).toBe("public.profiles");
    expect(normaliseTableName('"public"."Profiles"')).toBe("public.Profiles");
    expect(normaliseExpr(" ( (TRUE) ) ")).toBe("true");
    expect(normaliseExpr("(a) = (b)")).toBe("(a) = (b)");
  });
});
