import type { RawFinding, Rule } from "../../types.js";
import { loadSources, type SourceFile } from "./common.js";
import { lineCol } from "../../util/text.js";

// Heuristic from TRD §6.5: the file references a common auth call.
const AUTH_CALL =
  /\b(?:getUser|getSession|getServerSession|verifyIdToken|requireAuth|currentUser)\b|(?<![\w$.])auth\s*\(/;
const NEXT_EXPORT =
  /\bexport\s+(?:async\s+)?(?:function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g;
const EXPRESS = /\b(?:app|router)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*(["'`])([^"'`\n]+)\2/g;

interface Endpoint {
  method: string;
  route: string;
  offset: number;
}

function nextAppRoute(path: string): string | null {
  const m = /^(?:.*\/)?app\/((?:.*\/)?)route\.(?:[cm]?[jt]sx?)$/.exec(path);
  if (!m || path.includes("/pages/")) return null;
  const segs = m[1]!.split("/").filter((s) => s && !/^\(.*\)$/.test(s) && !s.startsWith("@"));
  return "/" + segs.join("/");
}

function pagesApiRoute(path: string): string | null {
  const m = /^(?:.*\/)?pages\/(api\/.*)\.(?:[cm]?[jt]sx?)$/.exec(path);
  if (!m) return null;
  return "/" + m[1]!.replace(/\/index$/, "");
}

function supabaseFunction(path: string): string | null {
  const m = /^(?:.*\/)?supabase\/functions\/([^/_][^/]*)\/index\.[jt]s$/.exec(path);
  return m ? `/functions/v1/${m[1]}` : null;
}

function endpointsIn(f: SourceFile): Endpoint[] {
  const out: Endpoint[] = [];
  const appRoute = nextAppRoute(f.path);
  if (appRoute !== null) {
    const re = new RegExp(NEXT_EXPORT.source, "g");
    for (let m = re.exec(f.bare); m !== null; m = re.exec(f.bare))
      out.push({ method: m[1]!, route: appRoute, offset: m.index });
    return out;
  }
  const pagesRoute = pagesApiRoute(f.path);
  if (pagesRoute !== null) {
    const def = f.bare.search(/\bexport\s+default\b/);
    return [{ method: "ANY", route: pagesRoute, offset: Math.max(0, def) }];
  }
  const fn = supabaseFunction(f.path);
  if (fn !== null) {
    const serve = f.bare.search(/\b(?:Deno\.serve|serve)\s*\(/);
    return [{ method: "ANY", route: fn, offset: Math.max(0, serve) }];
  }
  const re = new RegExp(EXPRESS.source, "g");
  for (let m = re.exec(f.code); m !== null; m = re.exec(f.code)) {
    if (f.bare[m.index] !== f.code[m.index]) continue; // inside a comment or string
    const route = m[3]!;
    if (!route.startsWith("/")) continue;
    out.push({ method: m[1]!.toUpperCase(), route, offset: m.index });
  }
  return out;
}

export const CODE_INV_001: Rule = {
  meta: {
    id: "CODE-INV-001",
    title: "API endpoint inventory",
    category: "code",
    severity: "info",
    confidence: "high",
    owasp: "A01",
    requires: ["files"],
    summary:
      "Lists Next.js route handlers, pages/api routes, Express routes and Supabase Edge Functions, noting whether each file seems to check who is calling. Admin routes with no auth call are raised as Worth checking.",
    why: "Every endpoint is a door into your app. Each one should be deliberately open to anonymous visitors, to signed-in users, or only to admins. Unprotected admin endpoints are a common way apps get taken over.",
    fix: [
      "Go through the list and write down who should reach each endpoint: anonymous, user, or admin.",
      "For user and admin endpoints, check the session on the server at the start of the handler, and check the role for admin routes.",
      "Test admin routes as a normal user and as a logged-out visitor.",
    ],
    fixPromptTemplate:
      "The endpoint {{detail.method}} {{detail.route}} in `{{path}}` line {{line}} {{detail.authNote}}. Check whether this endpoint should be reachable by anonymous visitors, signed-in users, or admins only, and if it's not public add a server-side session check (and a role check for admin routes) at the start of the handler. Then add a test that calls it without a session and as a non-admin.",
    falsePositiveNotes:
      "'Auth call seen' only means the file mentions a common auth function (getUser, getSession, auth(), verifyIdToken, requireAuth, currentUser). Middleware-based protection isn't detected, so admin routes protected by middleware are still flagged as Worth checking.",
    sources: [
      {
        title: "Locking Down the Database (classify every endpoint)",
        book: "Creating a Secure App — Locking Down the Database",
      },
      { title: "OWASP Top 10:2025 A01 Broken Access Control", url: "https://owasp.org/Top10/2025/" },
    ],
  },
  async check(ctx) {
    const out: RawFinding[] = [];
    for (const f of await loadSources(ctx.files!, ctx.profile.buildDirs)) {
      const eps = endpointsIn(f);
      if (!eps.length) continue;
      const authCallSeen = AUTH_CALL.test(f.bare);
      for (const ep of eps) {
        const { line } = lineCol(f.text, ep.offset);
        const lineText = f.text.split("\n")[line - 1] ?? "";
        const base = {
          ruleId: "CODE-INV-001",
          location: { kind: "file" as const, path: f.path, line },
        };
        const authNote = authCallSeen
          ? "references an auth call"
          : "has no auth call that the scanner could see";
        out.push({
          ...base,
          title: `${ep.method} ${ep.route}`,
          evidence: {
            snippet: lineText,
            detail: { kind: "endpoint", method: ep.method, route: ep.route, authCallSeen, authNote },
          },
        });
        if (!authCallSeen && /admin/i.test(ep.route)) {
          out.push({
            ...base,
            severity: "medium",
            confidence: "low",
            title: `Admin endpoint may be unprotected: ${ep.method} ${ep.route}`,
            evidence: {
              snippet: lineText,
              detail: {
                kind: "admin_unprotected",
                method: ep.method,
                route: ep.route,
                authCallSeen,
                authNote,
              },
            },
          });
        }
      }
    }
    return out;
  },
};
