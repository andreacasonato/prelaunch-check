// package.json reader with line numbers for each dependency entry.
import type { FileIndex } from "../../types.js";
import { parsePackageJson } from "../../detect/profile.js";
import { lineCol } from "../../util/text.js";
import { parseLockfile, type LockedPackage } from "./lockfiles.js";

export const DEPS_BOOK = "Creating a Secure App — Dependencies & the Software Supply Chain";

export type DepField = "dependencies" | "devDependencies" | "optionalDependencies" | "peerDependencies";

export interface ManifestDep {
  name: string;
  spec: string;
  field: DepField;
  line: number;
}

export interface Manifest {
  path: string;
  dir: string;
  name: string | null;
  deps: ManifestDep[];
}

const MANIFEST = /^(?:[^/]+\/){0,2}package\.json$/;
const LOCKFILE =
  /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$/;

export async function loadManifests(files: FileIndex): Promise<Manifest[]> {
  const out: Manifest[] = [];
  for (const e of files.all()) {
    if (!MANIFEST.test(e.path)) continue;
    const text = await files.text(e.path);
    const pkg = parsePackageJson(text);
    if (!pkg || text === null) continue;
    const deps: ManifestDep[] = [];
    for (const field of [
      "dependencies",
      "devDependencies",
      "optionalDependencies",
      "peerDependencies",
    ] as const) {
      const section = pkg[field];
      if (!section || typeof section !== "object") continue;
      const fieldIdx = text.indexOf(`"${field}"`);
      for (const [name, spec] of Object.entries(section)) {
        const idx = text.indexOf(`${JSON.stringify(name)}`, Math.max(0, fieldIdx));
        deps.push({
          name,
          spec: typeof spec === "string" ? spec.trim() : "",
          field,
          line: idx === -1 ? 1 : lineCol(text, idx).line,
        });
      }
    }
    out.push({
      path: e.path,
      dir: e.path.slice(0, e.path.length - "package.json".length),
      name: typeof pkg.name === "string" ? pkg.name : null,
      deps,
    });
  }
  return out;
}

export function lockfilePaths(files: FileIndex): string[] {
  return files
    .all()
    .filter((e) => LOCKFILE.test(e.path) && e.path.split("/").length <= 3)
    .map((e) => e.path);
}

export async function loadLocked(
  files: FileIndex,
): Promise<{ byFile: Array<{ path: string; packages: LockedPackage[] }>; unsupported: string[] }> {
  const byFile: Array<{ path: string; packages: LockedPackage[] }> = [];
  const unsupported: string[] = [];
  for (const path of lockfilePaths(files)) {
    const r = parseLockfile(path, await files.text(path));
    if (r.unsupported) unsupported.push(r.unsupported);
    byFile.push({ path, packages: r.packages });
  }
  return { byFile, unsupported };
}

/** Specs that don't come from the npm registry. */
export function isNonRegistrySpec(spec: string): boolean {
  return (
    /^(?:workspace|file|link|portal|patch|git|git\+[a-z]+|github|gitlab|bitbucket|https?):/.test(spec) ||
    /^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(spec) ||
    spec.startsWith(".") ||
    spec.startsWith("/")
  );
}

/** For "npm:real-name@1.2.3" aliases, the real package name. */
export function registryName(name: string, spec: string): string {
  const m = /^npm:((?:@[^/]+\/)?[^@]+)/.exec(spec);
  return m ? m[1]! : name;
}
