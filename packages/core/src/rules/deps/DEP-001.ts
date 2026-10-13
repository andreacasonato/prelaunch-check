import type { PackageRef, RawFinding, Rule } from "../../types.js";
import { DEPS_BOOK, loadLocked, loadManifests } from "./manifests.js";
import { toPackageRefs } from "./lockfiles.js";

const BATCH = 500;

export const DEP_001: Rule = {
  meta: {
    id: "DEP-001",
    title: "Dependency with known vulnerability",
    category: "deps",
    severity: "medium",
    confidence: "high",
    owasp: "A03",
    requires: ["files", "online"],
    summary:
      "Looks up every package version in your lockfile in the OSV vulnerability database (only names and versions are sent) and reports known advisories.",
    why: "Your app runs all the code in your dependencies. A known vulnerability in one of them is a documented, often automated way into your app, and attackers scan for them.",
    fix: [
      "Upgrade the package to a fixed version (see the advisory): `npm install <package>@<fixed-version>`.",
      "If it's a transitive dependency, upgrade the direct dependency that pulls it in, or use `overrides` (npm) / `resolutions` (yarn) / `pnpm.overrides`.",
      "Re-run the scan to confirm the advisory is gone.",
    ],
    fixPromptTemplate:
      "My project uses {{detail.package}}@{{detail.version}}, which has the known vulnerability {{detail.vulnId}} ({{detail.url}}). Fixed in: {{detail.fixedIn}}. Upgrade it to a fixed version (or upgrade the direct dependency that pulls it in, or add an override), update the lockfile, and run the tests.",
    falsePositiveNotes:
      "Advisories can apply only to features you don't use; check the advisory before accepting the risk. Severity comes from the advisory; if it gives none, medium is used.",
    sources: [
      { title: "OSV API", url: "https://google.github.io/osv.dev/api/" },
      { title: "Dependencies & the Software Supply Chain", book: DEPS_BOOK },
    ],
  },
  async check(ctx) {
    const online = ctx.online;
    if (!online?.osvQueryBatch) return [];
    const files = ctx.files!;
    const { byFile } = await loadLocked(files);
    const direct = new Set((await loadManifests(files)).flatMap((m) => m.deps.map((d) => d.name)));
    const where = new Map<string, { path: string; line: number }>();
    for (const f of byFile)
      for (const p of f.packages)
        if (!where.has(`${p.name}@${p.version}`))
          where.set(`${p.name}@${p.version}`, { path: f.path, line: p.line });
    const refs = toPackageRefs(
      byFile.flatMap((f) => f.packages),
      direct,
    );
    if (!refs.length) return [];

    const hits: Array<{ pkg: PackageRef; vulnIds: string[] }> = [];
    try {
      for (let i = 0; i < refs.length; i += BATCH)
        hits.push(...(await online.osvQueryBatch(refs.slice(i, i + BATCH))));
    } catch {
      return []; // the front end records the lookup failure in coverage.online
    }
    const out: RawFinding[] = [];
    for (const { pkg, vulnIds } of hits) {
      for (const id of [...new Set(vulnIds)].sort()) {
        const summary = online.osvGetVuln ? await online.osvGetVuln(id).catch(() => null) : null;
        const loc = where.get(`${pkg.name}@${pkg.version}`) ?? { path: "package.json", line: 1 };
        const f: RawFinding = {
          ruleId: "DEP-001",
          title: `${pkg.name}@${pkg.version}: ${summary?.summary ?? id}`,
          location: { kind: "file", path: loc.path, line: loc.line },
          evidence: {
            detail: {
              package: pkg.name,
              version: pkg.version,
              vulnId: id,
              aliases: (summary?.aliases ?? []).join(", "),
              fixedIn: summary?.fixedIn?.length ? summary.fixedIn.join(", ") : "see advisory",
              url: summary?.url ?? `https://osv.dev/vulnerability/${id}`,
              direct: pkg.direct,
            },
          },
        };
        if (summary?.severity) f.severity = summary.severity;
        out.push(f);
      }
    }
    return out;
  },
};
