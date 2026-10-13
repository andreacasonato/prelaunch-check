import type { RawFinding, Rule } from "../../types.js";
import { DEPS_BOOK, loadManifests, lockfilePaths } from "./manifests.js";

export const DEP_002: Rule = {
  meta: {
    id: "DEP-002",
    title: "No lockfile",
    category: "deps",
    severity: "medium",
    confidence: "high",
    owasp: "A03",
    requires: ["files"],
    summary:
      "Finds package.json files with dependencies but no package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock in the same folder or above.",
    why: "Without a lockfile, every install can pull different versions, including a freshly published malicious one. A lockfile pins exact versions and checksums so what you tested is what you ship.",
    fix: [
      "Run your package manager's install command once (`npm install`, `pnpm install`, `yarn`, `bun install`) and commit the lockfile it creates.",
      "Use `npm ci` (or the equivalent) in CI and deployments so installs follow the lockfile exactly.",
    ],
    fixPromptTemplate:
      "`{{path}}` has dependencies but no lockfile. Generate one with my package manager, commit it, and change CI/deploy scripts to install with `npm ci` (or pnpm install --frozen-lockfile / yarn install --immutable).",
    sources: [
      {
        title: "npm docs: package-lock.json",
        url: "https://docs.npmjs.com/cli/configuring-npm/package-lock-json",
      },
      { title: "Dependencies & the Software Supply Chain", book: DEPS_BOOK },
    ],
  },
  async check(ctx) {
    const files = ctx.files!;
    const locks = lockfilePaths(files).map((p) => p.slice(0, p.lastIndexOf("/") + 1));
    const out: RawFinding[] = [];
    for (const m of await loadManifests(files)) {
      if (!m.deps.length) continue;
      if (locks.some((dir) => m.dir.startsWith(dir))) continue;
      out.push({
        ruleId: "DEP-002",
        location: { kind: "file", path: m.path, line: 1 },
        evidence: { detail: { manifest: m.path } },
      });
    }
    return out;
  },
};
