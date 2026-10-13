import type { RawFinding, Rule } from "../../types.js";
import { DEPS_BOOK, isNonRegistrySpec, loadManifests, registryName } from "./manifests.js";

export const DEP_003: Rule = {
  meta: {
    id: "DEP-003",
    title: "Dependency not found on the registry",
    category: "deps",
    severity: "high",
    confidence: "high",
    owasp: "A03",
    requires: ["files", "online"],
    summary: "Checks that every package named in package.json exists on the npm registry.",
    why: "AI coding tools sometimes invent package names that sound right. Attackers register those names with malicious code ('slopsquatting'). A dependency that doesn't exist today can be registered by anyone tomorrow, and your next install would run their code.",
    fix: [
      "Check what the package was supposed to be: search npmjs.com and the library's official docs for the real name.",
      "Remove the dependency or replace it with the real package, then reinstall.",
    ],
    fixPromptTemplate:
      "`{{path}}` line {{line}} depends on `{{detail.package}}`, which doesn't exist on the npm registry. Find the real package this was meant to be (check the library's official documentation), replace or remove it, reinstall, and make sure nothing imports the non-existent name.",
    falsePositiveNotes:
      "Private packages served from your own registry return 'not found' on npmjs.org. Scopes configured in .npmrc (`@scope:registry=…`) are skipped; other scoped packages are reported with medium confidence.",
    sources: [
      { title: "Dependencies & the Software Supply Chain (slopsquatting)", book: DEPS_BOOK },
      { title: "npm registry API", url: "https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md" },
    ],
  },
  async check(ctx) {
    const online = ctx.online;
    if (!online?.npmPackageInfo) return [];
    const files = ctx.files!;
    const manifests = await loadManifests(files);
    const local = new Set(manifests.map((m) => m.name).filter((n): n is string => n !== null));
    const privateScopes = new Set<string>();
    for (const e of files.all().filter((x) => /(?:^|\/)\.npmrc$/.test(x.path))) {
      for (const m of ((await files.text(e.path)) ?? "").matchAll(/^\s*(@[\w.-]+):registry\s*=/gm))
        privateScopes.add(m[1]!);
    }
    const out: RawFinding[] = [];
    const checked = new Map<string, Promise<{ exists: boolean } | null>>();
    for (const m of manifests) {
      for (const d of m.deps) {
        if (d.field === "peerDependencies" || isNonRegistrySpec(d.spec)) continue;
        const name = registryName(d.name, d.spec);
        if (local.has(name)) continue;
        const scope = name.startsWith("@") ? name.split("/")[0]! : null;
        if (scope && privateScopes.has(scope)) continue;
        let p = checked.get(name);
        if (!p) {
          p = online.npmPackageInfo(name).catch(() => null);
          checked.set(name, p);
        }
        const info = await p;
        if (!info || info.exists) continue;
        const f: RawFinding = {
          ruleId: "DEP-003",
          title: `"${name}" doesn't exist on the npm registry`,
          location: { kind: "file", path: m.path, line: d.line },
          evidence: { detail: { package: name } },
        };
        if (scope) f.confidence = "medium";
        out.push(f);
      }
    }
    return out;
  },
};
