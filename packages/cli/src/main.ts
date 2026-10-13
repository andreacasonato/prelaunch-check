// prelaunch-check CLI (docs/02-TRD.md §10). Exit codes: 0 ok · 1 findings at/above --fail-on · 2 usage/config · 3 scan error.
import { parseArgs } from "node:util";
import { DEFAULT_RULES } from "@prelaunch-check/core";
import type { Io } from "./io.js";
import { runScanCommand, ScanError, UsageError } from "./commands/scan.js";
import { runInit } from "./commands/init.js";
import { rulesJson, rulesText } from "./commands/rules.js";
import { closestIds, explainText } from "./commands/explain.js";
import { createGitleaksRule } from "./integrations/gitleaks.js";
import { VERSION } from "./version.js";

export const HELP = `prelaunch-check ${VERSION}
Find the security holes in your app before you launch. Local-first: your code never leaves your computer.

Usage
  prelaunch-check scan [path]          Scan a project folder (default ".")
  prelaunch-check init                 Create a prelaunch-check.config.json
  prelaunch-check rules [--json]       List every rule
  prelaunch-check explain <RULE-ID>    Explain a rule and how to fix it

Scan options
  --offline                  Don't look up dependencies online (OSV, npm registry)
  --format json,md           Report formats to write (json is always written)
  --out <dir>                Where to write reports (default ./prelaunch-check-report)
  --fail-on <level>          critical | high | medium | low | none (default high)
  --config <file>            Config file (default ./prelaunch-check.config.json)
  --use-gitleaks / --no-gitleaks   Scan git history with gitleaks (default: if installed)
  --quiet / --verbose        Less or more output
  --no-color                 Plain output (also honours NO_COLOR)

Exit codes: 0 no findings at or above --fail-on · 1 findings · 2 usage error · 3 scan error
Docs: https://github.com/andreacasonato/prelaunch-check
`;

export async function main(argv: string[], io: Io): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: {
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "v" },
        json: { type: "boolean" },
        url: { type: "string" },
        "yes-i-am-authorized": { type: "boolean" },
        offline: { type: "boolean" },
        format: { type: "string" },
        out: { type: "string" },
        "fail-on": { type: "string" },
        baseline: { type: "string" },
        config: { type: "string" },
        "use-gitleaks": { type: "boolean" },
        "no-gitleaks": { type: "boolean" },
        "use-osv-scanner": { type: "boolean" },
        quiet: { type: "boolean", short: "q" },
        verbose: { type: "boolean" },
        "no-color": { type: "boolean" },
      },
    });
  } catch (e) {
    io.stderr(`${(e as Error).message}\nRun \`prelaunch-check --help\` for usage.\n`);
    return 2;
  }
  const { values: v, positionals } = parsed;
  if (v.version) {
    io.stdout(`${VERSION}\n`);
    return 0;
  }
  const [command, ...rest] = positionals;
  if (v.help || !command) {
    io.stdout(HELP);
    return v.help ? 0 : 2;
  }
  const allRules = [...DEFAULT_RULES, createGitleaksRule(".")].sort((a, b) =>
    a.meta.id < b.meta.id ? -1 : 1,
  );

  try {
    switch (command) {
      case "scan": {
        if (rest.length > 1) throw new UsageError("scan takes one folder path.");
        if (v["use-osv-scanner"])
          io.stderr("Note: --use-osv-scanner isn't supported yet; using the OSV API instead.\n");
        return await runScanCommand(io, {
          path: rest[0] ?? ".",
          ...(v.url !== undefined ? { url: v.url } : {}),
          offline: v.offline ?? false,
          format: v.format ?? "json",
          out: v.out ?? "prelaunch-check-report",
          ...(v["fail-on"] !== undefined ? { failOn: v["fail-on"] } : {}),
          ...(v.baseline !== undefined ? { baseline: v.baseline } : {}),
          ...(v.config !== undefined ? { config: v.config } : {}),
          gitleaks: v["no-gitleaks"] ? "off" : v["use-gitleaks"] ? "on" : "auto",
          quiet: v.quiet ?? false,
          verbose: v.verbose ?? false,
          color: !v["no-color"] && io.env.NO_COLOR === undefined && io.isTTY,
        });
      }
      case "init":
        return await runInit(io);
      case "rules":
        io.stdout(v.json ? rulesJson(allRules) : rulesText(allRules));
        return 0;
      case "explain": {
        const id = rest[0];
        if (!id) throw new UsageError("Usage: prelaunch-check explain <RULE-ID>");
        const rule = allRules.find((r) => r.meta.id === id.toUpperCase());
        if (!rule) {
          io.stderr(`Unknown rule "${id}". Did you mean: ${closestIds(id, allRules).join(", ")}?\n`);
          return 2;
        }
        io.stdout(explainText(rule));
        return 0;
      }
      default:
        throw new UsageError(`Unknown command "${command}".`);
    }
  } catch (e) {
    if (e instanceof UsageError) {
      io.stderr(`${e.message}\nRun \`prelaunch-check --help\` for usage.\n`);
      return 2;
    }
    if (e instanceof ScanError) {
      io.stderr(`${e.message}\n`);
      return 3;
    }
    io.stderr(
      `The scan stopped unexpectedly: ${(e as Error).message}\nPlease report this at https://github.com/andreacasonato/prelaunch-check/issues\n`,
    );
    return 3;
  }
}
