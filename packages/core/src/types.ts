// Types from docs/05-SCHEMA.md §2–§3. Keep in sync with the schema doc.
import type { ResolvedConfig } from "./config.js";

// §2.1 Enumerations
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";
export type Category = "secrets" | "data" | "web" | "deps" | "code" | "config";
export type Verdict = "blocked" | "needs_attention" | "no_blocking";
export type FindingStatus = "open" | "accepted_risk" | "false_positive";
export type Owasp2025 = "A01" | "A02" | "A03" | "A04" | "A05" | "A06" | "A07" | "A08" | "A09" | "A10";

export type RuleRequirement = "files" | "site" | "online" | "git" | "gitleaks";

// §2.2 Rule metadata
export interface RuleMeta {
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  owasp: Owasp2025;
  requires: RuleRequirement[];
  appliesWhen?: (p: ProjectProfile) => boolean;
  summary: string;
  why: string;
  fix: string[];
  fixPromptTemplate: string;
  falsePositiveNotes?: string;
  sources: Array<{ title: string; url?: string; book?: string }>;
}

export interface Rule {
  meta: RuleMeta;
  check(ctx: RuleContext): Promise<RawFinding[]>;
}

// §2.3 Inputs
export interface FileEntry {
  path: string;
  size: number;
}

export interface FileSource {
  list(): AsyncIterable<FileEntry>;
  readText(path: string): Promise<string | null>;
  isGitTracked?(path: string): Promise<boolean | null>;
}

export interface PackageRef {
  ecosystem: "npm";
  name: string;
  version: string;
  direct: boolean;
}

export interface OnlineServices {
  osvQueryBatch?(pkgs: PackageRef[]): Promise<Array<{ pkg: PackageRef; vulnIds: string[] }>>;
  osvGetVuln?(id: string): Promise<OsvVulnSummary>;
  npmPackageInfo?(name: string): Promise<{ exists: boolean; createdAt?: string }>;
}

export interface OsvVulnSummary {
  id: string;
  summary?: string;
  aliases: string[];
  severity: Severity | null;
  fixedIn?: string[];
  url: string;
}

// §2.4 ProjectProfile
export type Framework = "next" | "vite" | "react" | "vue" | "svelte" | "express";
export type Backend = "supabase" | "firebase";
export type Service = "stripe";
export type PackageManager = "npm" | "pnpm" | "yarn" | "bun";

export interface ProjectProfile {
  name: string;
  frameworks: Framework[];
  backends: Backend[];
  services: Service[];
  packageManagers: PackageManager[];
  lockfiles: string[];
  buildDirs: string[];
  publicEnvPrefixes: string[];
  hasGit: boolean | null;
  supabaseMigrationsFound: boolean;
}

// §2.5 RuleContext
export interface RuleContext {
  profile: ProjectProfile;
  files?: FileIndex;
  site?: SiteSnapshot;
  online?: OnlineServices;
  config: ResolvedConfig;
  now: Date;
}

export interface FileIndex {
  all(): FileEntry[];
  glob(pattern: string): FileEntry[];
  text(path: string): Promise<string | null>;
  isClientShipped(path: string): boolean;
  isGitTracked(path: string): Promise<boolean | null>;
}

// §2.6 SiteSnapshot
export interface HttpResponse {
  status: number;
  headers: Array<[string, string]>;
  bodyText?: string;
  bodyBytesPrefix?: string;
  redirectedTo?: string;
  elapsedMs: number;
}

export interface HttpExchange {
  request: { method: "GET" | "HEAD"; url: string; headers: Record<string, string> };
  response: HttpResponse | { error: string };
}

export type TlsInfo = { validTo: string; issuer: string; protocol: string } | { error: string };

export interface SiteSnapshot {
  target: string;
  collectedAt: string;
  toolVersion: string;
  httpRoot?: HttpExchange;
  root: HttpExchange;
  redirectChain: string[];
  tls?: TlsInfo;
  baseline404: HttpExchange;
  probes: Array<{ id: string; path: string; exchange: HttpExchange }>;
  scripts: Array<{ url: string; exchange: HttpExchange; sourceMap?: HttpExchange }>;
  corsChecks: Array<{ url: string; exchange: HttpExchange }>;
  requestCount: number;
}

// §2.7 Finding
export interface Location {
  kind: "file" | "url";
  path?: string;
  line?: number;
  column?: number;
  endLine?: number;
  url?: string;
}

export interface Evidence {
  snippet?: string;
  matchStart?: number;
  matchEnd?: number;
  detail?: Record<string, string | number | boolean>;
}

export interface RawFinding {
  ruleId: string;
  severity?: Severity;
  confidence?: Confidence;
  title?: string;
  location: Location;
  evidence: Evidence;
  secretValue?: string;
}

export interface Decision {
  reason: string;
  decidedAt: string;
  source: "inline" | "config" | "ui";
}

export interface Finding {
  fingerprint: string;
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  owasp: Owasp2025;
  location: Location;
  evidence: Evidence;
  status: FindingStatus;
  decision?: Decision;
  existing?: boolean;
  fixPrompt: string;
}

// §3 Report
export type SkipReason = "no_url" | "offline" | "not_applicable" | "missing_tool" | "disabled_by_config";
export type FileSkipReason = "too_large" | "binary" | "ignored_dir" | "unreadable";
export type OnlineStatus = "used" | "off" | "failed";

export type SeverityCounts = Record<Severity, number> & { worthChecking: number; suppressed: number };

export interface ChecklistItem {
  id: string;
  group: string;
  title: string;
  howToTest: string;
  why: string;
  source: string;
}

export interface Endpoint {
  method: string;
  route: string;
  file: string;
  line: number;
  authCallSeen: boolean;
}

export interface Coverage {
  rulesRun: string[];
  rulesSkipped: Array<{ ruleId: string; reason: SkipReason }>;
  filesScanned: number;
  filesSkipped: Array<{ path: string; reason: FileSkipReason }>;
  filesSkippedTotal: number;
  notes: string[];
  errors: Array<{ ruleId: string; message: string }>;
  online: { osv: OnlineStatus; npmRegistry: OnlineStatus };
  site?: { requestCount: number; durationMs: number };
}

export interface Report {
  schemaVersion: "1.0";
  tool: { name: "prelaunch-check"; version: string; rulesetVersion: string };
  generatedAt: string;
  target: {
    kind: "folder" | "url" | "folder+url";
    folderName?: string;
    url?: string;
  };
  profile: ProjectProfile;
  summary: {
    verdict: Verdict;
    score: number;
    counts: SeverityCounts;
    scoring: { formula: "v1"; weights: Record<Severity, number>; perRuleCapMultiplier: 2 };
  };
  findings: Finding[];
  coverage: Coverage;
  checklist: ChecklistItem[];
  endpoints?: Endpoint[];
}
