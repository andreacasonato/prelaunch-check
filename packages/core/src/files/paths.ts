// Path rules shared by every FileSource (TRD §4.1).

/** Directories never scanned. `.git/` is skipped except for the two files used for detection. */
export const ALWAYS_IGNORED_DIRS = [
  "node_modules/",
  ".git/",
  ".next/cache/",
  "coverage/",
  ".turbo/",
  ".vercel/output/",
] as const;

const GIT_KEEP = new Set([".git/HEAD", ".git/config"]);

/** Build output is scanned on purpose: shipped bundles are where client-exposed secrets end up. */
export const BUILD_DIR_NAMES = ["dist/", "build/", "out/", ".next/static/"] as const;

/** Returns a clean POSIX relative path, or null for absolute/traversal/empty paths. */
export function normalisePath(raw: string): string | null {
  let p = raw.replace(/\\/g, "/");
  while (p.startsWith("./")) p = p.slice(2);
  if (p === "" || p.startsWith("/") || /^[a-zA-Z]:\//.test(p)) return null;
  const parts = p.split("/");
  if (parts.some((s) => s === ".." || s === "")) return null;
  return p;
}

/**
 * If `path` is inside an always-ignored directory (at any depth), returns that directory's
 * prefix, e.g. "node_modules/" or "apps/web/node_modules/"; otherwise null.
 */
export function ignoredDirOf(path: string): string | null {
  if (GIT_KEEP.has(path)) return null;
  const segments = path.split("/");
  for (let i = 0; i < segments.length - 1; i++) {
    const rest = segments.slice(i).join("/");
    for (const dir of ALWAYS_IGNORED_DIRS) {
      if (rest.startsWith(dir)) return (i > 0 ? segments.slice(0, i).join("/") + "/" : "") + dir;
    }
  }
  return null;
}

/** True if a directory path (ending with "/") should not be descended into. Used by CLI walkers. */
export function isIgnoredDir(dirPath: string): boolean {
  const withSlash = dirPath.endsWith("/") ? dirPath : `${dirPath}/`;
  return ignoredDirOf(`${withSlash}x`) !== null;
}
