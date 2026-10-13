// Secret scanning primitives shared by SEC-*, CODE-* and WEB-014.
import {
  GLOBAL_ALLOW,
  JWT_REGEX,
  PUBLISHABLE_PATTERNS,
  SECRET_PATTERNS,
  type SecretPattern,
} from "./patterns.js";

export interface SecretMatch {
  pattern: SecretPattern;
  value: string;
  start: number;
  end: number;
}

/** TRD §12: large or minified text is scanned in 64 KB windows with 256-byte overlap. */
export const WINDOW = 64 * 1024;
export const OVERLAP = 256;

export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  const n = s.length;
  for (const c of counts.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

function allowed(p: SecretPattern, value: string): boolean {
  if (p.entropy !== undefined && shannonEntropy(value) <= p.entropy) return true;
  if (p.allow?.some((r) => r.test(value))) return true;
  return GLOBAL_ALLOW.some((r) => r.test(value));
}

function* windows(text: string): Generator<{ offset: number; chunk: string }> {
  if (text.length <= WINDOW) {
    yield { offset: 0, chunk: text };
    return;
  }
  for (let offset = 0; offset < text.length; offset += WINDOW - OVERLAP) {
    yield { offset, chunk: text.slice(offset, offset + WINDOW) };
    if (offset + WINDOW >= text.length) break;
  }
}

function scanWith(text: string, lower: string, patterns: readonly SecretPattern[]): SecretMatch[] {
  const found = new Map<number, SecretMatch>();
  for (const p of patterns) {
    if (!p.keywords.some((k) => lower.includes(k))) continue;
    for (const { offset, chunk } of windows(text)) {
      const re = new RegExp(p.regex.source, p.regex.flags);
      for (let m = re.exec(chunk); m !== null; m = re.exec(chunk)) {
        const value = m[1] ?? m[0];
        const local = m.index + m[0].indexOf(value);
        // Resume right after the secret so a terminator char can't swallow an adjacent key.
        re.lastIndex = Math.max(local + value.length, m.index + 1);
        const start = offset + local;
        if (found.has(start) || allowed(p, value)) continue;
        found.set(start, { pattern: p, value, start, end: start + value.length });
      }
    }
  }
  return [...found.values()].sort((a, b) => a.start - b.start);
}

export function findSecrets(text: string): SecretMatch[] {
  const lower = text.toLowerCase();
  return [...scanWith(text, lower, SECRET_PATTERNS), ...findSupabaseJwts(text, "service_role")].sort(
    (a, b) => a.start - b.start,
  );
}

export function findPublishable(text: string): SecretMatch[] {
  const lower = text.toLowerCase();
  return [...scanWith(text, lower, PUBLISHABLE_PATTERNS), ...findSupabaseJwts(text, "anon")].sort(
    (a, b) => a.start - b.start,
  );
}

function base64UrlDecode(s: string): string | null {
  try {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const bin = atob(padded);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

/** Reads a JWT payload without verifying it. Returns null if it isn't a JSON object. */
export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const part = token.split(".")[1];
  if (!part) return null;
  const json = base64UrlDecode(part);
  if (json === null) return null;
  try {
    const v: unknown = JSON.parse(json);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

const SUPABASE_SERVICE_JWT: SecretPattern = {
  id: "supabase-service-role-jwt",
  vendor: "Supabase",
  label: "Supabase service_role key (legacy JWT)",
  kind: "secret",
  regex: JWT_REGEX,
  keywords: ["ey"],
  severity: "critical",
  isTest: false,
  source: "Supabase API keys docs (service_role bypasses RLS); gitleaks default config (MIT) jwt",
  sourceUrl: "https://supabase.com/docs/guides/api/api-keys",
};

const SUPABASE_ANON_JWT: SecretPattern = {
  ...SUPABASE_SERVICE_JWT,
  id: "supabase-anon-jwt",
  label: "Supabase anon key (legacy JWT)",
  kind: "publishable",
  severity: "info",
};

/**
 * Legacy Supabase keys are JWTs. Only role "service_role" is secret; an "anon" key is public
 * (TRD §6.1). Anon keys are only labelled when the issuer is Supabase, to avoid naming random JWTs.
 */
function findSupabaseJwts(text: string, role: "service_role" | "anon"): SecretMatch[] {
  if (!text.includes("eyJ")) return [];
  const out: SecretMatch[] = [];
  const seen = new Set<number>();
  for (const { offset, chunk } of windows(text)) {
    const re = new RegExp(JWT_REGEX.source, JWT_REGEX.flags);
    for (let m = re.exec(chunk); m !== null; m = re.exec(chunk)) {
      const value = m[1]!;
      const start = offset + m.index;
      if (seen.has(start)) continue;
      seen.add(start);
      const payload = decodeJwtPayload(value);
      if (!payload || payload.role !== role) continue;
      if (role === "anon" && payload.iss !== "supabase") continue;
      out.push({
        pattern: role === "service_role" ? SUPABASE_SERVICE_JWT : SUPABASE_ANON_JWT,
        value,
        start,
        end: start + value.length,
      });
    }
  }
  return out;
}

// --- Private keys (SEC-005). Header per TRD §6.1, widened like gitleaks' private-key rule.
// Implemented with indexOf rather than a lazy [\s\S]*? regex so it stays linear on hostile input.
const PK_HEADER = /-----BEGIN ((?:[A-Z0-9]+ ){0,4})PRIVATE KEY(?: BLOCK)?-----/g;
const MIN_KEY_BODY = 64;

export interface PrivateKeyMatch {
  label: string;
  start: number;
  end: number;
  body: string;
  bodyStart: number;
  encrypted: boolean;
}

export function findPrivateKeys(text: string): PrivateKeyMatch[] {
  if (!text.includes("PRIVATE KEY")) return [];
  const out: PrivateKeyMatch[] = [];
  const re = new RegExp(PK_HEADER.source, "g");
  // The next footer is found once and reused, so many headers without a footer stay linear.
  let footer = -1;
  for (let m = re.exec(text); m !== null; m = re.exec(text)) {
    const headerEnd = m.index + m[0].length;
    if (footer < headerEnd) {
      footer = text.indexOf("-----END", headerEnd);
      if (footer === -1) break;
    }
    if (footer - headerEnd > 64 * 1024) continue;
    const rawBody = text.slice(headerEnd, footer);
    const body = rawBody.trim();
    // Skip documentation placeholders like "..." or "<your key here>".
    if (body.replace(/[^A-Za-z0-9+/=]/g, "").length < MIN_KEY_BODY) continue;
    const label = `${m[1] ?? ""}PRIVATE KEY`.trim();
    out.push({
      label,
      start: m.index,
      end: footer,
      body,
      bodyStart: headerEnd + rawBody.indexOf(body),
      encrypted: /ENCRYPTED/.test(label) || /Proc-Type: 4,ENCRYPTED/.test(body),
    });
    re.lastIndex = footer;
  }
  return out;
}

// --- Database connection strings with an inline password (SEC-007, TRD §6.1).
const DB_URL =
  /\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/([^:@/\s'"`]{1,128}):([^@/\s'"`]{1,256})@([^/\s'"`:?#]{1,253})/g;
const LOCAL_HOSTS = /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|::1|host\.docker\.internal)$/i;
const PLACEHOLDER_PASSWORD =
  /^(?:\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_]+%|<[^>]*>|\[[^\]]*\]|\{\{[^}]*\}\}|\*+|x+|\.{3}|password|passwd|pass|pwd|secret|changeme|your[-_]?password|<password>|postgres|root|example)$/i;

export interface DbUrlMatch {
  scheme: string;
  user: string;
  password: string;
  host: string;
  start: number;
  end: number;
  passwordStart: number;
}

export function findDbUrls(text: string): DbUrlMatch[] {
  if (!/(?:postgres|mysql|mongodb)/i.test(text)) return [];
  const out: DbUrlMatch[] = [];
  const re = new RegExp(DB_URL.source, "g");
  for (let m = re.exec(text); m !== null; m = re.exec(text)) {
    const [, scheme, user, password, host] = m as unknown as [string, string, string, string, string];
    if (PLACEHOLDER_PASSWORD.test(password)) continue;
    if (LOCAL_HOSTS.test(host)) continue;
    // Single-label hosts (e.g. "db" in docker-compose) are local service names.
    if (!host.includes(".")) continue;
    const passwordStart = m.index + scheme.length + 3 + user.length + 1;
    out.push({ scheme, user, password, host, start: m.index, end: m.index + m[0].length, passwordStart });
  }
  return out;
}

/** True for .env files (any depth): .env, .env.local, .env.production, … */
export function isEnvFile(path: string): boolean {
  return /(?:^|\/)\.env(?:\.[^/]*)?$/.test(path);
}

/** Templates such as .env.example, .env.local.example or .env.production.sample. */
export function isEnvExample(path: string): boolean {
  return /(?:^|\/)\.env(?:\.[^/]*)?\.(?:example|sample|template|dist|defaults)$/i.test(path);
}

/** Lockfiles are skipped by secret scanning: integrity hashes are noise and they're large. */
export function isLockfile(path: string): boolean {
  return /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$/.test(
    path,
  );
}
