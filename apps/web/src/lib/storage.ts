// localStorage per docs/05-SCHEMA.md §5. Every access is wrapped in try/catch: in private mode or with
// storage blocked, the app keeps working without persistence. No file contents, snippets or paths are stored.
import type { FindingStatus, SeverityCounts, Verdict } from "@prelaunch-check/core";

const PREFIX = "plc:v1:";
const MAX_DECISIONS = 500;
const MAX_FINGERPRINTS = 2000;

let available: boolean | null = null;

export function storageAvailable(): boolean {
  if (available !== null) return available;
  try {
    const k = `${PREFIX}probe`;
    localStorage.setItem(k, "1");
    localStorage.removeItem(k);
    available = true;
  } catch {
    available = false;
  }
  return available;
}

function read<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(PREFIX + key);
    return raw === null ? fallback : (JSON.parse(raw) as T);
  } catch {
    return fallback;
  }
}

function write(key: string, value: unknown): void {
  try {
    localStorage.setItem(PREFIX + key, JSON.stringify(value));
  } catch {
    /* storage unavailable or full: keep working without persistence */
  }
}

function remove(key: string): void {
  try {
    localStorage.removeItem(PREFIX + key);
  } catch {
    /* ignore */
  }
}

/** Sanitised to [a-z0-9._-], max 64 chars (SCHEMA §5). */
export function projectKey(name: string | undefined | null): string {
  const s = (name ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
  return s || "project";
}

export type Theme = "light" | "dark" | "system";
export const getTheme = (): Theme => {
  const t = read<string>("theme", "system");
  return t === "light" || t === "dark" ? t : "system";
};
export const setTheme = (t: Theme) => write("theme", t);

export const getOnlineDeps = (): boolean => read<boolean>("onlineDeps", false) === true;
export const setOnlineDeps = (v: boolean) => write("onlineDeps", v);

export interface StoredDecision {
  status: Exclude<FindingStatus, "open">;
  reason: string;
  decidedAt: string;
}

export function getDecisions(project: string): Record<string, StoredDecision> {
  const v = read<Record<string, StoredDecision>>(`decisions:${projectKey(project)}`, {});
  return v && typeof v === "object" ? v : {};
}

export function setDecision(project: string, fingerprint: string, d: StoredDecision | null): void {
  const all = getDecisions(project);
  if (d) all[fingerprint] = d;
  else delete all[fingerprint];
  // Keep the newest 500 (oldest dropped).
  const entries = Object.entries(all)
    .sort((a, b) => (a[1].decidedAt < b[1].decidedAt ? 1 : -1))
    .slice(0, MAX_DECISIONS);
  write(`decisions:${projectKey(project)}`, Object.fromEntries(entries));
}

export function getChecklist(project: string | null): Record<string, boolean> {
  return read<Record<string, boolean>>(`checklist:${project ? projectKey(project) : "general"}`, {});
}

export function setChecklist(project: string | null, value: Record<string, boolean> | null): void {
  const key = `checklist:${project ? projectKey(project) : "general"}`;
  if (value) write(key, value);
  else remove(key);
}

export interface LastScan {
  project: string;
  generatedAt: string;
  verdict: Verdict;
  score: number;
  counts: SeverityCounts;
  fingerprints: string[];
}

export function getLastScan(project: string): LastScan | null {
  return read<LastScan | null>(`lastScan:${projectKey(project)}`, null);
}

export function setLastScan(scan: LastScan): void {
  write(`lastScan:${projectKey(scan.project)}`, {
    ...scan,
    fingerprints: scan.fingerprints.slice(0, MAX_FINGERPRINTS),
  });
  write("lastProject", projectKey(scan.project));
}

export function getMostRecentScan(): LastScan | null {
  const p = read<string | null>("lastProject", null);
  return p ? getLastScan(p) : null;
}
