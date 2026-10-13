// Lightweight Postgres reader for Supabase migrations (docs/02-TRD.md §6.2, Phase 4).
// Not a full SQL parser: it splits statements safely and extracts the handful of
// statement shapes the DB rules need. Every loop is linear in the input.

export interface SqlStatement {
  /** Original text (for snippets). */
  text: string;
  /** Same length as `text`, with comments blanked; string/identifier contents kept. */
  code: string;
  start: number;
  line: number;
}

/** Splits on top-level semicolons, aware of comments, quotes and $tag$ bodies. */
export function splitStatements(src: string): SqlStatement[] {
  const out: SqlStatement[] = [];
  const code: string[] = [];
  let stmtStart = 0;
  let i = 0;
  const blank = (c: string) => (c === "\n" ? "\n" : " ");

  const push = (end: number) => {
    const text = src.slice(stmtStart, end);
    const c = code.slice(stmtStart, end).join("");
    const lead = c.length - c.trimStart().length;
    if (c.trim() !== "") {
      const start = stmtStart + lead;
      let line = 1;
      for (let k = src.indexOf("\n"); k !== -1 && k < start; k = src.indexOf("\n", k + 1)) line++;
      out.push({ text: text.slice(lead).trimEnd(), code: c.slice(lead).trimEnd(), start, line });
    }
    stmtStart = end + 1;
  };

  while (i < src.length) {
    const ch = src[i]!;
    const nx = src[i + 1];
    if (ch === "-" && nx === "-") {
      while (i < src.length && src[i] !== "\n") code[i++] = " ";
      continue;
    }
    if (ch === "/" && nx === "*") {
      let depth = 0;
      while (i < src.length) {
        if (src[i] === "/" && src[i + 1] === "*") {
          depth++;
          code[i] = " ";
          code[i + 1] = " ";
          i += 2;
        } else if (src[i] === "*" && src[i + 1] === "/") {
          depth--;
          code[i] = " ";
          code[i + 1] = " ";
          i += 2;
          if (depth === 0) break;
        } else code[i] = blank(src[i++]!);
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      code[i++] = ch;
      while (i < src.length) {
        if (src[i] === ch && src[i + 1] === ch) {
          code[i] = ch;
          code[i + 1] = ch;
          i += 2;
          continue;
        }
        if (ch === "'" && src[i] === "\\" && /[eE]/.test(src[stmtStart > 0 ? i : 0] ?? "")) {
          code[i++] = "\\";
          continue;
        }
        const c = src[i]!;
        code[i++] = c;
        if (c === ch) break;
      }
      continue;
    }
    if (ch === "$") {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(src.slice(i, i + 64));
      if (m) {
        const tag = m[0];
        const close = src.indexOf(tag, i + tag.length);
        const end = close === -1 ? src.length : close + tag.length;
        for (; i < end; i++) code[i] = src[i]!;
        continue;
      }
    }
    if (ch === ";") {
      code[i] = ";";
      push(i);
      i++;
      continue;
    }
    code[i] = ch;
    i++;
  }
  push(src.length);
  return out;
}

// --- Identifiers

/** Normalises `"Public"."Profiles"` / public.profiles / profiles → "public.profiles". */
export function normaliseTableName(raw: string): string {
  const parts: string[] = [];
  const re = /"((?:[^"]|"")*)"|([A-Za-z_][A-Za-z0-9_$]*)/g;
  for (let m = re.exec(raw); m !== null; m = re.exec(raw)) {
    parts.push(m[1] !== undefined ? m[1].replace(/""/g, '"') : m[2]!.toLowerCase());
  }
  if (parts.length === 1) return `public.${parts[0]}`;
  return parts.slice(-2).join(".");
}

const IDENT = String.raw`(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)`;
const QNAME = String.raw`${IDENT}(?:\s*\.\s*${IDENT})?`;

/** Returns the index just after the parenthesis that closes the one at `open`, or -1. */
export function matchParen(code: string, open: number): number {
  let depth = 0;
  for (let i = open; i < code.length; i++) {
    const c = code[i];
    if (c === "'" || c === '"') {
      const close = code.indexOf(c, i + 1);
      if (close === -1) return -1;
      i = close;
      continue;
    }
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

/** Splits on commas that are not nested in parentheses or quotes. */
export function splitTopLevel(s: string): Array<{ text: string; offset: number }> {
  const out: Array<{ text: string; offset: number }> = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "'" || c === '"') {
      const close = s.indexOf(c, i + 1);
      i = close === -1 ? s.length : close;
    } else if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (c === "," && depth === 0) {
      out.push({ text: s.slice(start, i), offset: start });
      start = i + 1;
    }
  }
  out.push({ text: s.slice(start), offset: start });
  return out;
}

// --- Extracted model

export interface Column {
  name: string;
  /** File and offset of the column definition (ALTER TABLE … ADD COLUMN may be in a later migration). */
  file: string;
  offset: number;
}

export interface Table {
  name: string;
  schema: string;
  columns: Column[];
  offset: number;
  file: string;
  rls: boolean;
}

export interface Policy {
  name: string;
  table: string;
  command: "all" | "select" | "insert" | "update" | "delete";
  roles: string[];
  using: string | null;
  withCheck: string | null;
  offset: number;
  file: string;
  /** Statement text for snippets. */
  text: string;
}

export interface ColumnGrant {
  table: string;
  kind: "grant" | "revoke";
  /** null = whole-table privilege. */
  columns: string[] | null;
  roles: string[];
}

export interface SqlModel {
  tables: Map<string, Table>;
  policies: Policy[];
  updateGrants: ColumnGrant[];
}

const CONSTRAINT_START = /^\s*(?:constraint|primary\s+key|foreign\s+key|unique|check|exclude|like)\b/i;

function unquoteIdent(s: string): string {
  const t = s.trim();
  return t.startsWith('"') ? t.slice(1, -1).replace(/""/g, '"') : t.toLowerCase();
}

function roleList(s: string | undefined): string[] {
  if (!s) return ["public"];
  return s
    .split(",")
    .map((r) => unquoteIdent(r))
    .filter(Boolean);
}

const RE_CREATE_TABLE = new RegExp(
  String.raw`^create\s+(?:(?:global|local)\s+)?(?:(?:temp|temporary|unlogged)\s+)?table\s+(?:if\s+not\s+exists\s+)?(${QNAME})\s*\(`,
  "i",
);
const RE_RLS = new RegExp(
  String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(${QNAME})\s+(enable|disable)\s+row\s+level\s+security`,
  "i",
);
const RE_ADD_COLUMN = new RegExp(
  String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(${QNAME})\s+(add\s+.*)$`,
  "is",
);
const RE_POLICY_HEAD = new RegExp(String.raw`^create\s+policy\s+(${IDENT})\s+on\s+(${QNAME})`, "i");
const RE_DROP_POLICY = new RegExp(
  String.raw`^drop\s+policy\s+(?:if\s+exists\s+)?(${IDENT})\s+on\s+(${QNAME})`,
  "i",
);
const RE_DROP_TABLE = new RegExp(String.raw`^drop\s+table\s+(?:if\s+exists\s+)?(${QNAME})`, "i");
const RE_GRANT = new RegExp(
  String.raw`^(grant|revoke)\s+(?:grant\s+option\s+for\s+)?(.*?)\s+on\s+(?:table\s+)?(${QNAME}(?:\s*,\s*${QNAME})*)\s+(?:to|from)\s+(.*?)(?:\s+(?:cascade|restrict|with\s+grant\s+option))?$`,
  "is",
);

function parsePolicy(st: SqlStatement, file: string): Policy | null {
  const head = RE_POLICY_HEAD.exec(st.code);
  if (!head) return null;
  const policy: Policy = {
    name: unquoteIdent(head[1]!),
    table: normaliseTableName(head[2]!),
    command: "all",
    roles: ["public"],
    using: null,
    withCheck: null,
    offset: st.start,
    file,
    text: st.text,
  };
  let rest = st.code.slice(head[0].length);
  let restOffset = head[0].length;
  for (;;) {
    const lead = rest.length - rest.trimStart().length;
    rest = rest.slice(lead);
    restOffset += lead;
    if (!rest) break;
    let m: RegExpExecArray | null;
    if ((m = /^as\s+(permissive|restrictive)\b/i.exec(rest))) {
      rest = rest.slice(m[0].length);
      restOffset += m[0].length;
    } else if ((m = /^for\s+(all|select|insert|update|delete)\b/i.exec(rest))) {
      policy.command = m[1]!.toLowerCase() as Policy["command"];
      rest = rest.slice(m[0].length);
      restOffset += m[0].length;
    } else if ((m = /^to\s+((?:[A-Za-z_"][\w"]*\s*,\s*)*[A-Za-z_"][\w"]*)/i.exec(rest))) {
      policy.roles = roleList(m[1]);
      rest = rest.slice(m[0].length);
      restOffset += m[0].length;
    } else if ((m = /^(using|with\s+check)\s*\(/i.exec(rest))) {
      const open = restOffset + m[0].length - 1;
      const close = matchParen(st.code, open);
      if (close === -1) break;
      const expr = st.code.slice(open + 1, close - 1).trim();
      if (/^using/i.test(m[1]!)) policy.using = expr;
      else policy.withCheck = expr;
      restOffset = close;
      rest = st.code.slice(close);
    } else break;
  }
  return policy;
}

function parseColumns(body: string, bodyOffset: number, file: string): Column[] {
  const cols: Column[] = [];
  for (const part of splitTopLevel(body)) {
    if (CONSTRAINT_START.test(part.text) || part.text.trim() === "") continue;
    const m = new RegExp(`^\\s*(${IDENT})`).exec(part.text);
    if (!m) continue;
    const lead = part.text.length - part.text.trimStart().length;
    cols.push({ name: unquoteIdent(m[1]!), file, offset: bodyOffset + part.offset + lead });
  }
  return cols;
}

/** Builds a model from migration files, applied in path order (Supabase migrations are timestamp-prefixed). */
export function buildSqlModel(files: Array<{ path: string; text: string }>): SqlModel {
  const model: SqlModel = { tables: new Map(), policies: [], updateGrants: [] };
  for (const f of [...files].sort((a, b) => (a.path < b.path ? -1 : 1))) {
    for (const st of splitStatements(f.text)) {
      let m: RegExpExecArray | null;
      if ((m = RE_CREATE_TABLE.exec(st.code))) {
        const name = normaliseTableName(m[1]!);
        const open = m[0].length - 1;
        const close = matchParen(st.code, open);
        const body = close === -1 ? "" : st.code.slice(open + 1, close - 1);
        model.tables.set(name, {
          name,
          schema: name.split(".")[0]!,
          columns: parseColumns(body, st.start + open + 1, f.path),
          offset: st.start,
          file: f.path,
          rls: false,
        });
      } else if ((m = RE_RLS.exec(st.code))) {
        const t = model.tables.get(normaliseTableName(m[1]!));
        if (t) t.rls = m[2]!.toLowerCase() === "enable";
      } else if (RE_POLICY_HEAD.test(st.code)) {
        const p = parsePolicy(st, f.path);
        if (p) model.policies.push(p);
      } else if ((m = RE_DROP_POLICY.exec(st.code))) {
        const name = unquoteIdent(m[1]!);
        const table = normaliseTableName(m[2]!);
        model.policies = model.policies.filter((p) => !(p.name === name && p.table === table));
      } else if ((m = RE_DROP_TABLE.exec(st.code))) {
        const name = normaliseTableName(m[1]!);
        model.tables.delete(name);
        model.policies = model.policies.filter((p) => p.table !== name);
      } else if ((m = RE_ADD_COLUMN.exec(st.code))) {
        const t = model.tables.get(normaliseTableName(m[1]!));
        if (!t) continue;
        const actionsOffset = st.start + st.code.indexOf(m[2]!);
        for (const part of splitTopLevel(m[2]!)) {
          const am = new RegExp(
            `^\\s*add\\s+(?:column\\s+)?(?:if\\s+not\\s+exists\\s+)?(${IDENT})`,
            "i",
          ).exec(part.text);
          if (!am || /^(?:constraint|primary|foreign|unique|check)$/i.test(am[1]!)) continue;
          t.columns.push({
            name: unquoteIdent(am[1]!),
            file: f.path,
            offset: actionsOffset + part.offset + am.index + am[0].length - am[1]!.length,
          });
        }
      } else if ((m = RE_GRANT.exec(st.code))) {
        const privs = m[2]!;
        const um = /\b(?:update|all(?:\s+privileges)?)\b(?:\s*\(([^)]*)\))?/i.exec(privs);
        if (!um) continue;
        const columns = um[1] ? um[1].split(",").map(unquoteIdent) : null;
        for (const tbl of splitTopLevel(m[3]!)) {
          model.updateGrants.push({
            table: normaliseTableName(tbl.text),
            kind: m[1]!.toLowerCase() as "grant" | "revoke",
            columns,
            roles: roleList(m[4]),
          });
        }
      }
    }
  }
  return model;
}

/** Normalises a policy expression for comparisons: lower-case, no outer parens, collapsed spaces. */
export function normaliseExpr(expr: string | null): string {
  if (expr === null) return "";
  let e = expr.replace(/\s+/g, " ").trim().toLowerCase();
  while (e.startsWith("(") && matchParen(e, 0) === e.length) e = e.slice(1, -1).trim();
  return e;
}

/** Matches auth.uid() and the recommended (select auth.uid()) form. */
export const AUTH_UID = /\(\s*select\s+auth\.uid\s*\(\s*\)\s*\)|auth\.uid\s*\(\s*\)/i;

/** Roles that clients can act as; a policy limited to service_role is not reachable from the browser. */
export function reachableByClients(roles: string[]): boolean {
  return roles.some((r) => r !== "service_role" && r !== "postgres" && r !== "supabase_admin");
}
