// Scan pipeline (docs/02-TRD.md §4): enumerate → detect → select → run → post-process → score → report.
import type { ResolvedConfig } from "../config.js";
import type {
  Category,
  Coverage,
  Endpoint,
  Finding,
  OnlineServices,
  RawFinding,
  Report,
  Rule,
  RuleContext,
  SiteSnapshot,
  SkipReason,
  FileSource,
} from "../types.js";
import { buildFileIndex, throwIfAborted, type BuiltFileIndex } from "../files/index.js";
import { detectProfile } from "../detect/profile.js";
import { computeFingerprintKey } from "../fingerprint.js";
import { redact, redactAll } from "../redact.js";
import { computeCounts, computeScore, computeVerdict, PER_RULE_CAP_MULTIPLIER, WEIGHTS } from "../score.js";
import { CHECKLIST } from "../checklist/items.js";
import { compareFindings } from "./sort.js";
import { renderTemplate } from "./template.js";
import { RULESET_VERSION, SCHEMA_VERSION, TOOL_NAME } from "../version.js";
import { DEFAULT_RULES } from "../rules/index.js";

export type ScanStage =
  "reading" | "detecting" | "secrets" | "data" | "deps" | "code" | "config" | "web" | "building";

export interface ScanProgress {
  stage: ScanStage;
  done?: number;
  total?: number;
}

export interface ScanInput {
  files?: FileSource;
  /** Folder name only; any directories are stripped (reports never contain absolute paths). */
  folderName?: string;
  site?: SiteSnapshot;
  online?: OnlineServices;
  config: ResolvedConfig;
  toolVersion: string;
  now?: Date;
  /** Rules to run. Defaults to the built-in registry. Front ends may append their own (e.g. SEC-006 in the CLI). */
  rules?: Rule[];
  /** Optional tools available to the front end (e.g. gitleaks on PATH). */
  capabilities?: { git?: boolean; gitleaks?: boolean };
  /** Extra coverage notes from the front end (e.g. online lookups that failed). */
  onlineStatus?: Partial<Coverage["online"]>;
  /** Wall-clock time the front end spent collecting the site snapshot. */
  siteDurationMs?: number;
  onProgress?: (p: ScanProgress) => void;
  signal?: AbortSignal;
}

const STAGE_ORDER: Category[] = ["secrets", "data", "deps", "code", "config", "web"];
const MAX_SKIPPED_ENTRIES = 200;
const MAX_ERROR_LENGTH = 300;
const ENDPOINT_RULE = "CODE-INV-001";

function folderBaseName(name: string | undefined): string | undefined {
  if (name === undefined) return undefined;
  const parts = name.replace(/\\/g, "/").split("/").filter(Boolean);
  return parts.at(-1);
}

function isoSeconds(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function skipReason(rule: Rule, input: ScanInput, files: BuiltFileIndex | undefined): SkipReason | null {
  const setting = input.config.rules[rule.meta.id];
  if (setting === "off") return "disabled_by_config";
  for (const req of rule.meta.requires) {
    if (req === "site" && !input.site) return "no_url";
    if (req === "files" && !files) return "not_applicable";
    if (req === "online" && !input.online) return "offline";
    if (req === "git" && !input.capabilities?.git) return "missing_tool";
    if (req === "gitleaks" && !input.capabilities?.gitleaks) return "missing_tool";
  }
  return null;
}

/** Deep-replaces a secret in every string of a value. */
function scrub<T>(value: T, secret: string): T {
  if (typeof value === "string") return redactAll(value, secret) as T;
  if (Array.isArray(value)) return value.map((v) => scrub(v, secret)) as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = scrub(v, secret);
    return out as T;
  }
  return value;
}

export async function runScan(input: ScanInput): Promise<Report> {
  const { config, signal } = input;
  const now = input.now ?? new Date();
  const progress = input.onProgress ?? (() => {});
  const rules = [...(input.rules ?? DEFAULT_RULES)].sort((a, b) => (a.meta.id < b.meta.id ? -1 : 1));

  // 2. Enumerate files
  let files: BuiltFileIndex | undefined;
  if (input.files) {
    progress({ stage: "reading", done: 0, total: 0 });
    files = await buildFileIndex(input.files, {
      maxFileSizeBytes: config.maxFileSizeBytes,
      ignorePaths: config.ignorePaths,
      signal,
      onRead: (done, total) => progress({ stage: "reading", done, total }),
    });
  }
  throwIfAborted(signal);

  // 3. Detect stack
  progress({ stage: "detecting" });
  const folderName = folderBaseName(input.folderName);
  const siteHost = input.site ? safeHost(input.site.target) : undefined;
  const profile = await detectProfile(files, folderName ?? siteHost ?? "project", config.publicEnvPrefixes);
  files?.setProfile(profile);

  const ctx: RuleContext = { profile, config, now };
  if (files) ctx.files = files;
  if (input.site) ctx.site = input.site;
  if (input.online) ctx.online = input.online;

  // 4–5. Select and run rules, grouped by category so progress reads like the UI stages.
  const rulesRun: string[] = [];
  const rulesSkipped: Coverage["rulesSkipped"] = [];
  const errors: Coverage["errors"] = [];
  const raw: Array<{ rule: Rule; finding: RawFinding }> = [];

  for (const stage of STAGE_ORDER) {
    const stageRules = rules.filter((r) => r.meta.category === stage);
    if (stageRules.length === 0) continue;
    progress({ stage });
    for (const rule of stageRules) {
      throwIfAborted(signal);
      const skip = skipReason(rule, input, files);
      if (skip) {
        rulesSkipped.push({ ruleId: rule.meta.id, reason: skip });
        continue;
      }
      if (rule.meta.appliesWhen && !rule.meta.appliesWhen(profile)) {
        rulesSkipped.push({ ruleId: rule.meta.id, reason: "not_applicable" });
        continue;
      }
      rulesRun.push(rule.meta.id);
      try {
        for (const finding of await rule.check(ctx)) raw.push({ rule, finding });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        errors.push({ ruleId: rule.meta.id, message: message.slice(0, MAX_ERROR_LENGTH) });
      }
    }
  }
  throwIfAborted(signal);

  // 6. Post-process: fingerprint (on raw values) → redact → build findings.
  progress({ stage: "building" });
  const findings: Finding[] = [];
  for (const { rule, finding: rf } of raw) {
    const fingerprint = await computeFingerprintKey(rf);
    const { secretValue, ...rest } = rf;
    let f: Omit<RawFinding, "secretValue"> = rest;
    if (secretValue !== undefined && secretValue !== "") {
      const rawSnippet = rf.evidence.snippet;
      f = scrub(f, secretValue);
      // Re-point the highlight at the redacted token.
      if (
        rawSnippet !== undefined &&
        f.evidence.snippet !== undefined &&
        rf.evidence.matchStart !== undefined
      ) {
        const token = redact(secretValue);
        const before = redactAll(rawSnippet.slice(0, rf.evidence.matchStart), secretValue);
        const at = f.evidence.snippet.indexOf(token, before.length);
        if (at !== -1) {
          f.evidence.matchStart = at;
          f.evidence.matchEnd = at + token.length;
        }
      }
    }
    const setting = config.rules[rule.meta.id];
    const severity = (typeof setting === "object" && setting.severity) || f.severity || rule.meta.severity;
    const title = f.title ?? rule.meta.title;
    findings.push({
      fingerprint,
      ruleId: rule.meta.id,
      title,
      category: rule.meta.category,
      severity,
      confidence: f.confidence ?? rule.meta.confidence,
      owasp: rule.meta.owasp,
      location: f.location,
      evidence: f.evidence,
      status: "open",
      fixPrompt: renderTemplate(rule.meta.fixPromptTemplate, {
        location: f.location,
        evidence: f.evidence,
        title,
      }),
    });
  }

  // Disambiguate identical fingerprints by order of appearance (#2, #3…).
  findings.sort(compareByLocation);
  const seen = new Map<string, number>();
  for (const f of findings) {
    const n = (seen.get(f.fingerprint) ?? 0) + 1;
    seen.set(f.fingerprint, n);
    if (n > 1) f.fingerprint = `${f.fingerprint}#${n}`;
  }
  findings.sort(compareFindings);

  // 7. Score + verdict
  const summary = {
    verdict: computeVerdict(findings),
    score: computeScore(findings),
    counts: computeCounts(findings),
    scoring: {
      formula: "v1" as const,
      weights: { ...WEIGHTS },
      perRuleCapMultiplier: PER_RULE_CAP_MULTIPLIER,
    },
  };

  // 8. Coverage + checklist
  const notes: string[] = [];
  if (profile.backends.includes("supabase") && !profile.supabaseMigrationsFound) {
    notes.push(
      "Supabase detected but no migration files found, so we couldn't check your database rules. Tables created in the dashboard aren't visible to a folder scan.",
    );
  }
  const anyOnlineRule = rules.some((r) => r.meta.requires.includes("online"));
  const coverage: Coverage = {
    rulesRun,
    rulesSkipped,
    filesScanned: files?.scannedCount ?? 0,
    filesSkipped: files ? files.skipped.slice(0, MAX_SKIPPED_ENTRIES) : [],
    filesSkippedTotal: files?.skippedTotal ?? 0,
    notes,
    errors,
    online: {
      osv: input.online && anyOnlineRule ? "used" : "off",
      npmRegistry: input.online && anyOnlineRule ? "used" : "off",
      ...input.onlineStatus,
    },
  };
  if (input.site)
    coverage.site = { requestCount: input.site.requestCount, durationMs: input.siteDurationMs ?? 0 };

  const report: Report = {
    schemaVersion: SCHEMA_VERSION,
    tool: { name: TOOL_NAME, version: input.toolVersion, rulesetVersion: RULESET_VERSION },
    generatedAt: isoSeconds(now),
    target: input.files
      ? input.site
        ? { kind: "folder+url", ...(folderName ? { folderName } : {}), url: input.site.target }
        : { kind: "folder", ...(folderName ? { folderName } : {}) }
      : { kind: "url", ...(input.site ? { url: input.site.target } : {}) },
    profile,
    summary,
    findings,
    coverage,
    checklist: CHECKLIST.map((c) => ({ ...c })),
  };
  const endpoints = collectEndpoints(findings);
  if (endpoints.length) report.endpoints = endpoints;
  return report;
}

function compareByLocation(a: Finding, b: Finding): number {
  const pa = a.location.path ?? a.location.url ?? "";
  const pb = b.location.path ?? b.location.url ?? "";
  if (pa !== pb) return pa < pb ? -1 : 1;
  const la = a.location.line ?? 0;
  const lb = b.location.line ?? 0;
  if (la !== lb) return la - lb;
  const ca = a.location.column ?? 0;
  const cb = b.location.column ?? 0;
  if (ca !== cb) return ca - cb;
  return a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0;
}

/** CODE-INV-001 findings carry endpoint details; they also feed the report's endpoint table. */
function collectEndpoints(findings: Finding[]): Endpoint[] {
  const out: Endpoint[] = [];
  for (const f of findings) {
    if (f.ruleId !== ENDPOINT_RULE) continue;
    const d = f.evidence.detail ?? {};
    if (typeof d.route !== "string" || typeof d.method !== "string") continue;
    out.push({
      method: d.method,
      route: d.route,
      file: f.location.path ?? "",
      line: f.location.line ?? 0,
      authCallSeen: d.authCallSeen === true,
    });
  }
  return out.sort((a, b) =>
    a.route !== b.route
      ? a.route < b.route
        ? -1
        : 1
      : a.method < b.method
        ? -1
        : a.method > b.method
          ? 1
          : 0,
  );
}

function safeHost(target: string): string | undefined {
  try {
    return new URL(target).host;
  } catch {
    return undefined;
  }
}
