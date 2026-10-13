import type { RawFinding, Rule } from "../../types.js";
import { stripJs } from "../../util/js-scan.js";
import { lineCol } from "../../util/text.js";

const NEXT_RE = /\bproductionBrowserSourceMaps\s*:\s*true\b/g;
const VITE_RE = /\bsourcemap\s*:\s*(?:true\b|["']inline["'])/g;

export const CFG_001: Rule = {
  meta: {
    id: "CFG-001",
    title: "Source maps in production build output",
    category: "config",
    severity: "medium",
    confidence: "high",
    owasp: "A02",
    requires: ["files"],
    summary:
      "Finds .map files in build output, or Next.js productionBrowserSourceMaps / Vite build.sourcemap turned on.",
    why: "Source maps rebuild your original source code, comments and file structure from the minified bundle. Publishing them makes it much easier for someone to study your app for weaknesses and can expose internal URLs or leftover secrets.",
    fix: [
      "Turn off production source maps: remove `productionBrowserSourceMaps: true` (Next.js) or set `build.sourcemap` to `false` (Vite).",
      "If you need them for error tracking, upload them privately to your error tracker and delete them from the deployed output.",
      "Rebuild and confirm no `.map` files remain in the build folder.",
    ],
    fixPromptTemplate:
      "{{detail.where}}. Turn off production browser source maps (remove productionBrowserSourceMaps: true in next.config, or set build.sourcemap to false in vite.config). If my error tracker needs them, upload them privately during the build and delete the .map files before deploying.",
    falsePositiveNotes:
      "Vite's `sourcemap: 'hidden'` is not flagged by the config check, but its .map files are still flagged if they're present in the build folder.",
    sources: [
      { title: "Vite build.sourcemap", url: "https://vite.dev/config/build-options#build-sourcemap" },
      {
        title: "Next.js productionBrowserSourceMaps",
        url: "https://nextjs.org/docs/app/api-reference/config/next-config-js/productionBrowserSourceMaps",
      },
    ],
  },
  async check(ctx) {
    const files = ctx.files!;
    const out: RawFinding[] = [];
    for (const dir of ctx.profile.buildDirs) {
      const maps = files.all().filter((e) => e.path.startsWith(dir) && e.path.endsWith(".map"));
      if (!maps.length) continue;
      out.push({
        ruleId: "CFG-001",
        title: `${maps.length} source map file${maps.length === 1 ? "" : "s"} in ${dir}`,
        location: { kind: "file", path: maps[0]!.path },
        evidence: {
          detail: {
            buildDir: dir,
            count: maps.length,
            where: `The build folder ${dir} contains ${maps.length} .map file(s), for example ${maps[0]!.path}`,
          },
        },
      });
    }
    const configs = files.glob("**/{next,vite}.config.{js,mjs,cjs,ts,mts,cts}");
    for (const e of configs) {
      if (e.path.split("/").length > 3) continue;
      const text = await files.text(e.path);
      if (text === null) continue;
      const code = stripJs(text);
      const re = new RegExp((e.path.includes("next.config") ? NEXT_RE : VITE_RE).source, "g");
      for (let m = re.exec(code); m !== null; m = re.exec(code)) {
        const { line } = lineCol(text, m.index);
        const lineText = text.split("\n")[line - 1] ?? "";
        const at = lineText.indexOf(m[0]);
        out.push({
          ruleId: "CFG-001",
          title: `Production source maps enabled in ${e.path}`,
          location: { kind: "file", path: e.path, line },
          evidence: {
            snippet: lineText,
            ...(at !== -1 ? { matchStart: at, matchEnd: at + m[0].length } : {}),
            detail: { where: `In \`${e.path}\` line ${line}, production source maps are enabled` },
          },
        });
      }
    }
    return out;
  },
};
