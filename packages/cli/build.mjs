// Bundles the CLI and @prelaunch-check/core into one file, so the published
// package has zero runtime dependencies (TRD §2 dependency budget).
import { build } from "esbuild";
import { readFile } from "node:fs/promises";

const pkg = JSON.parse(await readFile(new URL("./package.json", import.meta.url), "utf8"));

await build({
  entryPoints: ["src/index.ts"],
  outfile: "dist/index.js",
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  banner: { js: "#!/usr/bin/env node" },
  define: { __TOOL_VERSION__: JSON.stringify(pkg.version) },
  legalComments: "none",
  logLevel: "warning",
});
