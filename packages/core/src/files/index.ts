// FileIndex: enumerates a FileSource once, applies ignore rules and caps, reads text
// with bounded concurrency, and offers cached helpers to rules (docs/05-SCHEMA.md §2.5).
import type { FileEntry, FileIndex, FileSkipReason, FileSource, ProjectProfile } from "../types.js";
import { globToRegExp } from "./glob.js";
import { ignoredDirOf, normalisePath } from "./paths.js";

export interface FileIndexOptions {
  maxFileSizeBytes: number;
  ignorePaths: string[];
  signal?: AbortSignal;
  onRead?: (done: number, total: number) => void;
}

export interface BuiltFileIndex extends FileIndex {
  setProfile(p: ProjectProfile): void;
  skipped: Array<{ path: string; reason: FileSkipReason }>;
  skippedTotal: number;
  scannedCount: number;
}

const BINARY_SNIFF = 8192;
const READ_CONCURRENCY = 16;

export function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new Error("Scan aborted");
}

export async function buildFileIndex(source: FileSource, opts: FileIndexOptions): Promise<BuiltFileIndex> {
  const ignoreRes = opts.ignorePaths.map((g) => globToRegExp(g));
  const entries: FileEntry[] = [];
  const skipped: Array<{ path: string; reason: FileSkipReason }> = [];
  const ignoredDirs = new Set<string>();
  const seen = new Set<string>();
  const rawPaths = new Map<string, string>();

  for await (const raw of source.list()) {
    throwIfAborted(opts.signal);
    const path = normalisePath(raw.path);
    if (path === null || seen.has(path)) continue;
    seen.add(path);
    const dir = ignoredDirOf(path);
    if (dir !== null) {
      ignoredDirs.add(dir);
      skipped.push({ path, reason: "ignored_dir" });
      continue;
    }
    if (ignoreRes.some((re) => re.test(path))) continue;
    rawPaths.set(path, raw.path);
    entries.push({ path, size: raw.size });
  }
  entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  const texts = new Map<string, string>();
  const readable = entries.filter((e) => {
    if (e.size > opts.maxFileSizeBytes) {
      skipped.push({ path: e.path, reason: "too_large" });
      return false;
    }
    return true;
  });

  let done = 0;
  let next = 0;
  const worker = async () => {
    while (next < readable.length) {
      throwIfAborted(opts.signal);
      const entry = readable[next++]!;
      let text: string | null;
      try {
        text = await source.readText(rawPaths.get(entry.path) ?? entry.path);
      } catch {
        text = null;
      }
      if (text === null) skipped.push({ path: entry.path, reason: "unreadable" });
      else if (text.slice(0, BINARY_SNIFF).includes("\u0000"))
        skipped.push({ path: entry.path, reason: "binary" });
      else texts.set(entry.path, text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
      done++;
      opts.onRead?.(done, readable.length);
    }
  };
  await Promise.all(Array.from({ length: Math.min(READ_CONCURRENCY, readable.length) }, worker));

  let profile: ProjectProfile | null = null;
  const globCache = new Map<string, FileEntry[]>();

  // Collapse per-file "ignored_dir" entries into one entry per ignored directory.
  const collapsed: Array<{ path: string; reason: FileSkipReason }> = [
    ...[...ignoredDirs].map((path) => ({ path, reason: "ignored_dir" as const })),
    ...skipped.filter((s) => s.reason !== "ignored_dir"),
  ].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  const index: BuiltFileIndex = {
    skipped: collapsed,
    // The total counts every skipped file, not every collapsed directory entry.
    skippedTotal: skipped.length,
    scannedCount: texts.size,
    all: () => entries,
    glob(pattern) {
      let hit = globCache.get(pattern);
      if (!hit) {
        const re = globToRegExp(pattern);
        hit = entries.filter((e) => re.test(e.path));
        globCache.set(pattern, hit);
      }
      return hit;
    },
    text: async (path) => texts.get(path) ?? null,
    isClientShipped(path) {
      if (!profile) return false;
      if (profile.buildDirs.some((d) => path.startsWith(d))) return true;
      if (profile.frameworks.includes("vite") && /^(?:[^/]+\/){0,2}src\//.test(path)) return true;
      if (profile.frameworks.includes("next")) {
        const t = texts.get(path);
        if (t && /^\s*(?:\/\/[^\n]*\n\s*|\/\*[\s\S]*?\*\/\s*)*["']use client["']/.test(t)) return true;
      }
      return false;
    },
    async isGitTracked(path) {
      if (!source.isGitTracked) return null;
      try {
        return await source.isGitTracked(path);
      } catch {
        return null;
      }
    },
    setProfile(p) {
      profile = p;
    },
  };
  return index;
}
