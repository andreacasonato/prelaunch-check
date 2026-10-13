import { readFile, writeFile, appendFile, access } from "node:fs/promises";
import { join } from "node:path";
import type { Io } from "../io.js";

export const CONFIG_FILE = "prelaunch-check.config.json";

export const DEFAULT_CONFIG = {
  $comment: "Prelaunch Check settings. Every key is optional; delete what you don't need.",
  $comment_ignorePaths:
    "Extra folders or files to skip, as globs (node_modules, .git and caches are always skipped).",
  ignorePaths: [] as string[],
  $comment_failOn:
    "Exit with code 1 when an open finding is at or above this severity: critical, high, medium, low or none.",
  failOn: "high",
  $comment_online:
    "Look up known vulnerabilities (OSV) and check packages exist (npm registry). Only names and versions are sent.",
  online: true,
  $comment_rules:
    'Turn a rule off or change its severity, e.g. { "DEP-005": "off", "CFG-003": { "severity": "medium" } }.',
  rules: {},
  $comment_suppressions:
    'Record accepted risks. A reason is required, e.g. { "ruleId": "DB-003", "path": "supabase/migrations/*.sql", "reason": "credits is written only by a trigger" }.',
  suppressions: [] as unknown[],
};

async function exists(p: string): Promise<boolean> {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

export async function runInit(io: Io): Promise<number> {
  const configPath = join(io.cwd, CONFIG_FILE);
  if (await exists(configPath)) {
    io.stderr(`${CONFIG_FILE} already exists. Nothing was changed.\n`);
    return 2;
  }
  await writeFile(configPath, JSON.stringify(DEFAULT_CONFIG, null, 2) + "\n");
  io.stdout(`Created ${CONFIG_FILE}.\n`);

  const gitignore = join(io.cwd, ".gitignore");
  const current = (await exists(gitignore)) ? await readFile(gitignore, "utf8") : "";
  if (!/^\/?prelaunch-check-report\/?$/m.test(current)) {
    if (await io.confirm("Add prelaunch-check-report/ to .gitignore? (y/N) ")) {
      await appendFile(
        gitignore,
        `${current && !current.endsWith("\n") ? "\n" : ""}prelaunch-check-report/\n`,
      );
      io.stdout("Added prelaunch-check-report/ to .gitignore.\n");
    } else {
      io.stdout("Tip: add prelaunch-check-report/ to .gitignore so reports aren't committed.\n");
    }
  }
  io.stdout("\nNext: run `npx prelaunch-check scan .` in this folder.\n");
  return 0;
}
