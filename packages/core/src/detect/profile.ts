// Stack detection from deterministic markers only (TRD §4.2).
import type { Backend, FileIndex, Framework, PackageManager, ProjectProfile, Service } from "../types.js";
import { BUILD_DIR_NAMES } from "../files/paths.js";
import { PUBLIC_ENV_PREFIXES } from "./public-env-prefixes.js";

interface PackageJson {
  name?: unknown;
  dependencies?: Record<string, unknown>;
  devDependencies?: Record<string, unknown>;
  peerDependencies?: Record<string, unknown>;
  optionalDependencies?: Record<string, unknown>;
}

export function parsePackageJson(text: string | null): PackageJson | null {
  if (text === null) return null;
  try {
    const v: unknown = JSON.parse(text);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as PackageJson) : null;
  } catch {
    return null;
  }
}

export function depNames(pkg: PackageJson): Set<string> {
  const out = new Set<string>();
  for (const field of [
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
  ] as const) {
    const deps = pkg[field];
    if (deps && typeof deps === "object") for (const k of Object.keys(deps)) out.add(k);
  }
  return out;
}

const FRAMEWORK_ORDER: Framework[] = ["next", "vite", "react", "vue", "svelte", "express"];
const PM_ORDER: PackageManager[] = ["npm", "pnpm", "yarn", "bun"];

/** package.json files at the root or up to two levels down (monorepo apps/packages). */
const PACKAGE_JSON_RE = /^(?:[^/]+\/){0,2}package\.json$/;
const LOCKFILES: Array<[RegExp, PackageManager]> = [
  [/(?:^|\/)package-lock\.json$/, "npm"],
  [/(?:^|\/)pnpm-lock\.yaml$/, "pnpm"],
  [/(?:^|\/)yarn\.lock$/, "yarn"],
  [/(?:^|\/)bun\.lockb?$/, "bun"],
];

export async function detectProfile(
  files: FileIndex | undefined,
  folderName: string,
  extraPrefixes: string[],
): Promise<ProjectProfile> {
  const entries = files?.all() ?? [];
  const paths = entries.map((e) => e.path);
  const pathSet = new Set(paths);
  const has = (re: RegExp) => paths.some((p) => re.test(p));

  const deps = new Set<string>();
  let name: string | null = null;
  for (const p of paths.filter((x) => PACKAGE_JSON_RE.test(x))) {
    const pkg = parsePackageJson((await files?.text(p)) ?? null);
    if (!pkg) continue;
    if (p === "package.json" && typeof pkg.name === "string" && pkg.name.trim()) name = pkg.name.trim();
    for (const d of depNames(pkg)) deps.add(d);
  }

  const fw = new Set<Framework>();
  if (deps.has("next") || has(/(?:^|\/)next\.config\.[cm]?[jt]s$/)) fw.add("next");
  if (deps.has("vite") || has(/(?:^|\/)vite\.config\.[cm]?[jt]s$/)) fw.add("vite");
  if (deps.has("react")) fw.add("react");
  if (deps.has("vue")) fw.add("vue");
  if (deps.has("svelte") || deps.has("@sveltejs/kit")) fw.add("svelte");
  if (deps.has("express")) fw.add("express");

  const migrations = has(/(?:^|\/)supabase\/migrations\/[^/]+\.sql$/);
  const backends: Backend[] = [];
  if (
    deps.has("@supabase/supabase-js") ||
    deps.has("@supabase/ssr") ||
    has(/(?:^|\/)supabase\/config\.toml$/) ||
    migrations
  )
    backends.push("supabase");
  if (
    deps.has("firebase") ||
    deps.has("firebase-admin") ||
    has(/(?:^|\/)(?:firebase\.json|firestore\.rules|storage\.rules|database\.rules\.json)$/)
  )
    backends.push("firebase");

  const services: Service[] = deps.has("stripe") || deps.has("@stripe/stripe-js") ? ["stripe"] : [];

  const lockfiles = paths.filter((p) => LOCKFILES.some(([re]) => re.test(p)) && p.split("/").length <= 3);
  const pms = new Set<PackageManager>();
  for (const p of lockfiles) for (const [re, pm] of LOCKFILES) if (re.test(p)) pms.add(pm);

  const buildDirs = new Set<string>();
  for (const p of paths) {
    for (const dir of BUILD_DIR_NAMES) {
      const idx = p.indexOf(dir);
      if (idx === -1) continue;
      if (idx !== 0 && p[idx - 1] !== "/") continue;
      // A nested build dir only counts when it sits next to a package.json (monorepo app).
      const parent = p.slice(0, idx);
      if (parent === "" || pathSet.has(`${parent}package.json`)) buildDirs.add(p.slice(0, idx + dir.length));
    }
  }

  const frameworks = FRAMEWORK_ORDER.filter((f) => fw.has(f));
  const prefixes: string[] = [];
  for (const entry of PUBLIC_ENV_PREFIXES) if (fw.has(entry.framework)) prefixes.push(entry.prefix);
  for (const p of extraPrefixes) if (!prefixes.includes(p)) prefixes.push(p);

  return {
    name: name ?? folderName,
    frameworks,
    backends,
    services,
    packageManagers: PM_ORDER.filter((p) => pms.has(p)),
    lockfiles,
    buildDirs: [...buildDirs].sort(),
    publicEnvPrefixes: prefixes,
    hasGit: files ? has(/^\.git\/(?:HEAD|config)$/) : null,
    supabaseMigrationsFound: migrations,
  };
}
