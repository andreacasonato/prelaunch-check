// Lockfile readers (npm v1–v3, pnpm, yarn v1 and Berry, bun.lock text). Dependency-free and line-aware.
import type { PackageRef } from "../../types.js";

export interface LockedPackage {
  name: string;
  version: string;
  /** 1-based line of the entry in the lockfile. */
  line: number;
}

export interface LockfileResult {
  packages: LockedPackage[];
  /** Set when the format isn't supported (e.g. binary bun.lockb). */
  unsupported?: string;
}

function lineAt(text: string, offset: number): number {
  let line = 1;
  for (let i = text.indexOf("\n"); i !== -1 && i < offset; i = text.indexOf("\n", i + 1)) line++;
  return line;
}

function stripJsonc(text: string): string {
  // bun.lock is JSONC: drop trailing commas outside strings.
  let out = "";
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (inStr) {
      out += c;
      if (c === "\\") out += text[++i] ?? "";
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    if (c === ",") {
      const rest = text.slice(i + 1).match(/^\s*([}\]])/);
      if (rest) continue;
    }
    out += c;
  }
  return out;
}

/** Finds the line of `"key"` in JSON text, starting the search at `from`. */
function keyLine(text: string, key: string, cache: Map<string, number>): number {
  const hit = cache.get(key);
  if (hit !== undefined) return hit;
  const idx = text.indexOf(JSON.stringify(key) + ":");
  const line = idx === -1 ? 1 : lineAt(text, idx);
  cache.set(key, line);
  return line;
}

export function parsePackageLock(text: string): LockfileResult {
  let data: {
    packages?: Record<string, { version?: string; link?: boolean; name?: string }>;
    dependencies?: Record<string, unknown>;
  };
  try {
    data = JSON.parse(text);
  } catch {
    return { packages: [], unsupported: "package-lock.json could not be parsed" };
  }
  const lines = new Map<string, number>();
  const out: LockedPackage[] = [];
  if (data.packages) {
    for (const [key, v] of Object.entries(data.packages)) {
      if (!key || v.link || !v.version) continue;
      const idx = key.lastIndexOf("node_modules/");
      if (idx === -1) continue;
      const name = v.name ?? key.slice(idx + "node_modules/".length);
      out.push({ name, version: v.version, line: keyLine(text, key, lines) });
    }
    return { packages: out };
  }
  // lockfileVersion 1: nested "dependencies".
  const walk = (deps: Record<string, unknown> | undefined) => {
    for (const [name, raw] of Object.entries(deps ?? {})) {
      const v = raw as { version?: string; dependencies?: Record<string, unknown> };
      if (v.version && !/^(?:file|link|git|github):/.test(v.version))
        out.push({ name, version: v.version, line: keyLine(text, name, lines) });
      walk(v.dependencies);
    }
  };
  walk(data.dependencies);
  return { packages: out };
}

export function parsePnpmLock(text: string): LockfileResult {
  const out: LockedPackage[] = [];
  const lines = text.split("\n");
  let inPackages = false;
  lines.forEach((l, i) => {
    if (/^packages:\s*$/.test(l)) {
      inPackages = true;
      return;
    }
    if (/^\S/.test(l)) inPackages = false;
    if (!inPackages) return;
    // v6+: "  /name@1.2.3:" or "  name@1.2.3:" or "  '@scope/name@1.2.3(peer@x)':"; v5: "  /name/1.2.3:"
    const m = /^ {2}['"]?\/?((?:@[^/@\s]+\/)?[^@/\s'"]+)(?:@|\/)(\d[^(:'"\s]*)/.exec(l);
    if (m) out.push({ name: m[1]!, version: m[2]!, line: i + 1 });
  });
  return { packages: out };
}

export function parseYarnLock(text: string): LockfileResult {
  const out: LockedPackage[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const header = lines[i]!;
    if (!header || /^\s|^#/.test(header) || !header.trimEnd().endsWith(":")) continue;
    if (header.startsWith("__metadata")) continue;
    const first = header.replace(/:$/, "").split(",")[0]!.trim().replace(/^"|"$/g, "");
    const at = first.lastIndexOf("@");
    if (at <= 0) continue;
    const name = first.slice(0, at);
    const range = first.slice(at + 1);
    if (/^(?:workspace|file|link|portal|patch):/.test(range)) continue;
    for (let j = i + 1; j < lines.length && /^\s/.test(lines[j]!); j++) {
      const v = /^\s+version:?\s+"?([^"\s]+)"?/.exec(lines[j]!);
      if (v) {
        out.push({ name, version: v[1]!, line: i + 1 });
        break;
      }
    }
  }
  return { packages: out };
}

export function parseBunLock(text: string): LockfileResult {
  let data: { packages?: Record<string, unknown[]> };
  try {
    data = JSON.parse(stripJsonc(text));
  } catch {
    return { packages: [], unsupported: "bun.lock could not be parsed" };
  }
  const lines = new Map<string, number>();
  const out: LockedPackage[] = [];
  for (const [key, v] of Object.entries(data.packages ?? {})) {
    const spec = Array.isArray(v) ? v[0] : undefined;
    if (typeof spec !== "string") continue;
    const at = spec.lastIndexOf("@");
    if (at <= 0) continue;
    const version = spec.slice(at + 1);
    if (!/^\d/.test(version)) continue;
    out.push({ name: spec.slice(0, at), version, line: keyLine(text, key, lines) });
  }
  return { packages: out };
}

export function parseLockfile(path: string, text: string | null): LockfileResult {
  if (/bun\.lockb$/.test(path) || text === null)
    return {
      packages: [],
      unsupported: `${path} is binary and not supported; run \`bun install --save-text-lockfile\``,
    };
  if (path.endsWith("package-lock.json") || path.endsWith("npm-shrinkwrap.json"))
    return parsePackageLock(text);
  if (path.endsWith("pnpm-lock.yaml")) return parsePnpmLock(text);
  if (path.endsWith("yarn.lock")) return parseYarnLock(text);
  if (path.endsWith("bun.lock")) return parseBunLock(text);
  return { packages: [], unsupported: `${path}: unknown lockfile format` };
}

export function toPackageRefs(pkgs: LockedPackage[], direct: Set<string>): PackageRef[] {
  const seen = new Set<string>();
  const out: PackageRef[] = [];
  for (const p of pkgs) {
    const key = `${p.name}@${p.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ ecosystem: "npm", name: p.name, version: p.version, direct: direct.has(p.name) });
  }
  return out.sort((a, b) =>
    a.name === b.name ? (a.version < b.version ? -1 : 1) : a.name < b.name ? -1 : 1,
  );
}
