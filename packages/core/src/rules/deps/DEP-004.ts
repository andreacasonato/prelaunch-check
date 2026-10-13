import type { RawFinding, Rule } from "../../types.js";
import { DEPS_BOOK, isNonRegistrySpec, loadManifests, registryName } from "./manifests.js";

const DAY = 86_400_000;

export const DEP_004: Rule = {
  meta: {
    id: "DEP-004",
    title: "Very new dependency",
    category: "deps",
    severity: "info",
    confidence: "medium",
    owasp: "A03",
    requires: ["files", "online"],
    summary: "Lists direct dependencies first published less than 30 days ago.",
    why: "Brand-new packages have no track record. Most are fine, but malicious packages are usually caught within days or weeks of publication, so a quick human check is worthwhile.",
    fix: [
      "Look at the package's npm page and repository: who publishes it, how many downloads it has, and whether the code matches what it claims to do.",
      "Prefer a well-established alternative if one exists.",
    ],
    fixPromptTemplate:
      "`{{detail.package}}` (in `{{path}}` line {{line}}) was first published on {{detail.createdAt}}. Help me review it: check its repository, maintainers and download counts, and suggest a well-established alternative if one exists.",
    falsePositiveNotes:
      "New releases of your own packages, or new packages from trusted publishers, are listed too.",
    sources: [{ title: "Dependencies & the Software Supply Chain", book: DEPS_BOOK }],
  },
  async check(ctx) {
    const online = ctx.online;
    if (!online?.npmPackageInfo) return [];
    const manifests = await loadManifests(ctx.files!);
    const local = new Set(manifests.map((m) => m.name));
    const out: RawFinding[] = [];
    const seen = new Set<string>();
    for (const m of manifests) {
      for (const d of m.deps) {
        if (d.field === "peerDependencies" || isNonRegistrySpec(d.spec)) continue;
        const name = registryName(d.name, d.spec);
        if (local.has(name) || seen.has(name)) continue;
        seen.add(name);
        const info = await online.npmPackageInfo(name).catch(() => null);
        if (!info?.exists || !info.createdAt) continue;
        const created = Date.parse(info.createdAt);
        if (Number.isNaN(created) || ctx.now.getTime() - created >= 30 * DAY) continue;
        out.push({
          ruleId: "DEP-004",
          title: `"${name}" was first published ${Math.max(0, Math.floor((ctx.now.getTime() - created) / DAY))} days ago`,
          location: { kind: "file", path: m.path, line: d.line },
          evidence: { detail: { package: name, createdAt: info.createdAt.slice(0, 10) } },
        });
      }
    }
    return out;
  },
};
