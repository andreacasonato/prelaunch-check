// Fixture helpers. Fixture files never contain secret-shaped strings: they hold
// placeholders like __PLC_FAKE_STRIPE_SK_LIVE__ that are replaced at test time with
// deterministic fake values. Path segments starting with "_dot_" become "." so that
// fixture .gitignore and .git files don't affect this repository's own git.
import { readdirSync, readFileSync, statSync, mkdirSync, writeFileSync } from "node:fs";
import { join, dirname, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "../../../..");
export const FIXTURES = join(REPO_ROOT, "fixtures");

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function seedOf(s: string): number {
  let h = 2166136261;
  for (const ch of s) h = Math.imul(h ^ ch.charCodeAt(0), 16777619);
  return h >>> 0;
}

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const B64URL = ALNUM + "_-";
const UPPER32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const DIGITS = "0123456789";
const HEX = "0123456789abcdef";

function rand(kind: string, n: number, chars: string, salt = ""): string {
  const r = mulberry32(seedOf(kind + salt));
  let out = "";
  for (let i = 0; i < n; i++) out += chars[Math.floor(r() * chars.length)];
  return out;
}

const j = (...parts: string[]) => parts.join("_");

function b64url(s: string): string {
  return Buffer.from(s).toString("base64url");
}

function jwt(payload: object, kind: string): string {
  return `${b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${b64url(JSON.stringify(payload))}.${rand(kind, 43, B64URL)}`;
}

function pem(kind: string, label: string): string {
  const body = rand(kind, 256, ALNUM + "+/");
  const lines = body.match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

/** Deterministic fake values by placeholder kind. Vendor prefixes are assembled at runtime. */
export const FAKE: Record<string, string> = {
  STRIPE_SK_LIVE: j("sk", "live", rand("sk_live", 24, ALNUM)),
  STRIPE_SK_LIVE_2: j("sk", "live", rand("sk_live2", 24, ALNUM)),
  STRIPE_SK_TEST: j("sk", "test", rand("sk_test", 24, ALNUM)),
  STRIPE_RK_LIVE: j("rk", "live", rand("rk_live", 24, ALNUM)),
  STRIPE_PK_LIVE: j("pk", "live", rand("pk_live", 24, ALNUM)),
  STRIPE_PK_TEST: j("pk", "test", rand("pk_test", 24, ALNUM)),
  SUPABASE_SECRET: j("sb", "secret", rand("sb_secret", 32, B64URL)),
  SUPABASE_PUBLISHABLE: j("sb", "publishable", rand("sb_pub", 32, B64URL)),
  SUPABASE_SERVICE_JWT: jwt(
    {
      iss: "supabase",
      ref: "abcdefghijklmnopqrst",
      role: ["service", "role"].join("_"),
      iat: 1700000000,
      exp: 2000000000,
    },
    "jwt_service",
  ),
  SUPABASE_ANON_JWT: jwt(
    { iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon", iat: 1700000000, exp: 2000000000 },
    "jwt_anon",
  ),
  FIREBASE_API_KEY: "AI" + "za" + rand("firebase", 35, B64URL),
  AWS_ACCESS_KEY_ID: "AK" + "IA" + rand("aws", 16, UPPER32),
  OPENAI_KEY: "sk-" + rand("openai1", 20, ALNUM) + "T3Blbk" + "FJ" + rand("openai2", 20, ALNUM),
  ANTHROPIC_KEY: "sk-ant-" + "api03-" + rand("anthropic", 93, B64URL) + "AA",
  GITHUB_PAT: "gh" + "p_" + rand("ghp", 36, ALNUM),
  SLACK_BOT:
    "xo" +
    "xb-" +
    rand("slack1", 12, DIGITS) +
    "-" +
    rand("slack2", 12, DIGITS) +
    "-" +
    rand("slack3", 24, ALNUM),
  SENDGRID_KEY: "SG." + rand("sg1", 22, ALNUM + "_-") + "." + rand("sg2", 43, ALNUM + "_-"),
  TWILIO_KEY: "S" + "K" + rand("twilio", 32, HEX),
  PRIVATE_KEY: pem("pk1", ["RSA", "PRIVATE", "KEY"].join(" ")),
  OPENSSH_PRIVATE_KEY: pem("pk2", ["OPENSSH", "PRIVATE", "KEY"].join(" ")),
  DB_PASSWORD: rand("dbpw", 18, ALNUM),
  // Whole connection URLs are placeholders too, so no credential-shaped URI is ever committed.
  POSTGRES_PROD_URL: ["postgres", "://admin:", rand("dbpw", 18, ALNUM), "@db.prod.example.com:5432/app"].join(
    "",
  ),
  POSTGRES_APP_URL: ["postgres", "://app:", rand("dbpw", 18, ALNUM), "@db.example.com:5432/app"].join(""),
  MONGO_ATLAS_URL: [
    "mongodb+srv",
    "://svc:",
    rand("dbpw", 18, ALNUM),
    "@cluster0.abcde.mongodb",
    ".net/app",
  ].join(""),
  // Placeholder-looking values that must NOT be reported.
  STRIPE_SK_PLACEHOLDER: j("sk", "live", "x".repeat(24)),
  AWS_EXAMPLE_KEY: "AK" + "IAIOSFODNN7" + "EXAMPLE",
  PRIVATE_KEY_PLACEHOLDER:
    ["-----BEGIN PRIVATE", "KEY-----"].join(" ") + "\n...\n" + ["-----END PRIVATE", "KEY-----"].join(" "),
};

const PLACEHOLDER = /__PLC_FAKE_([A-Z0-9_]+?)__/g;

export function materialize(text: string): string {
  return text.replace(PLACEHOLDER, (m, kind: string) => {
    const v = FAKE[kind];
    if (v === undefined) throw new Error(`Unknown fixture placeholder ${m}`);
    return v;
  });
}

export function mapFixturePath(rel: string): string {
  return rel
    .split("/")
    .map((seg) => (seg.startsWith("_dot_") ? "." + seg.slice(5) : seg))
    .join("/");
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir).sort()) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

/** Loads a fixture directory into memory: mapped paths → materialized contents. */
export function loadFixtureDir(dir: string): Record<string, string> {
  const files: Record<string, string> = {};
  for (const full of walk(dir)) {
    const rel = relative(dir, full).split(sep).join("/");
    if (rel === "expected.json" || rel === ".plc-git-tracked" || rel === "online.json" || rel === "site.json")
      continue;
    files[mapFixturePath(rel)] = materialize(readFileSync(full, "utf8"));
  }
  return files;
}

/** Paths listed in a fixture's .plc-git-tracked file, if present (simulates `git ls-files`). */
export function fixtureGitTracked(dir: string): string[] | undefined {
  try {
    return readFileSync(join(dir, ".plc-git-tracked"), "utf8")
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
  } catch {
    return undefined;
  }
}

/** Writes a materialized copy of a fixture directory to `dest` (for CLI and browser tests). */
export function writeFixtureDir(src: string, dest: string): void {
  for (const [rel, content] of Object.entries(loadFixtureDir(src))) {
    const out = join(dest, ...rel.split("/"));
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, content);
  }
}

/** Every fake value (publishable keys are redacted too), for "never appears in output" assertions. */
export function allFakeValues(): string[] {
  return Object.values(FAKE);
}

/** A fixture case's recorded SiteSnapshot (site.json), with placeholders materialized. */
export function fixtureSite<T>(dir: string): T | undefined {
  try {
    return JSON.parse(materialize(readFileSync(join(dir, "site.json"), "utf8"))) as T;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw e;
  }
}
