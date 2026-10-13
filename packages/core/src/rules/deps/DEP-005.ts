import type { RawFinding, Rule } from "../../types.js";
import { DEPS_BOOK, loadManifests } from "./manifests.js";

const UNPINNED = new Set(["*", "latest", "x", "X", ""]);

export const DEP_005: Rule = {
  meta: {
    id: "DEP-005",
    title: "Unpinned dependency range",
    category: "deps",
    severity: "low",
    confidence: "high",
    owasp: "A03",
    requires: ["files"],
    summary: 'Finds dependencies declared as "*", "latest", "x" or an empty version.',
    why: "These ranges accept any future version, including a major release with breaking changes or a compromised release. Combined with a missing or regenerated lockfile, every install is a gamble.",
    fix: [
      'Replace the range with a specific version range, for example `"^4.17.21"`, matching what you\'ve tested.',
    ],
    fixPromptTemplate:
      'In `{{path}}` line {{line}}, `{{detail.package}}` uses the version "{{detail.spec}}", which accepts any release. Replace it with a caret range for the version currently in my lockfile, and reinstall.',
    sources: [
      {
        title: "npm docs: dependencies and version ranges",
        url: "https://docs.npmjs.com/cli/configuring-npm/package-json#dependencies",
      },
      { title: "Dependencies & the Software Supply Chain", book: DEPS_BOOK },
    ],
  },
  async check(ctx) {
    const out: RawFinding[] = [];
    for (const m of await loadManifests(ctx.files!)) {
      for (const d of m.deps) {
        if (d.field === "peerDependencies" || !UNPINNED.has(d.spec)) continue;
        out.push({
          ruleId: "DEP-005",
          title: `"${d.name}" accepts any version ("${d.spec}")`,
          location: { kind: "file", path: m.path, line: d.line },
          evidence: { detail: { package: d.name, spec: d.spec } },
        });
      }
    }
    return out;
  },
};
