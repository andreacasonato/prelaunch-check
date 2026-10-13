import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { basename, join, relative, resolve, sep } from "node:path";
import {
  DEFAULT_RULES,
  resolveConfig,
  runScan,
  SEVERITY_ORDER,
  toMarkdown,
  type Report,
  type Rule,
  type ScanStage,
  type Severity,
} from "@prelaunch-check/core";
import type { Io } from "../io.js";
import { NodeFileSource } from "../sources/node-files.js";
import { createOnlineServices, type OnlineStatus } from "../online/services.js";
import { createGitleaksRule, gitleaksAvailable } from "../integrations/gitleaks.js";
import { painter, renderSummary } from "../format/terminal.js";
import { CONFIG_FILE } from "./init.js";
import { VERSION, WEB_APP_URL } from "../version.js";

export interface ScanFlags {
  path: string;
  url?: string;
  offline: boolean;
  format: string;
  out: string;
  failOn?: string;
  baseline?: string;
  config?: string;
  gitleaks: "auto" | "on" | "off";
  quiet: boolean;
  verbose: boolean;
  color: boolean;
}

export class UsageError extends Error {}
export class ScanError extends Error {}

const STAGE_LABEL: Record<ScanStage, string> = {
  reading: "Reading files",
  detecting: "Detecting stack",
  secrets: "Checking secrets",
  data: "Checking database rules",
  deps: "Checking dependencies",
  code: "Checking code patterns",
  config: "Checking config",
  web: "Checking live site",
  building: "Building report",
};

const FRAMEWORK_LABEL: Record<string, string> = {
  next: "Next.js",
  vite: "Vite",
  react: "React",
  vue: "Vue",
  svelte: "Svelte",
  express: "Express",
  supabase: "Supabase",
  firebase: "Firebase",
  stripe: "Stripe",
};

const SUPPORTED_FORMATS = new Set(["json", "md"]);
const LATER_FORMATS = new Set(["sarif", "html"]);

async function loadConfigFile(io: Io, flags: ScanFlags, root: string): Promise<unknown> {
  const candidates = flags.config
    ? [resolve(io.cwd, flags.config)]
    : [join(root, CONFIG_FILE), join(io.cwd, CONFIG_FILE)];
  for (const p of candidates) {
    let text: string;
    try {
      text = await readFile(p, "utf8");
    } catch {
      if (flags.config) throw new UsageError(`Config file not found: ${flags.config}`);
      continue;
    }
    try {
      return JSON.parse(text);
    } catch (e) {
      throw new UsageError(`${basename(p)} is not valid JSON: ${(e as Error).message}`);
    }
  }
  return undefined;
}

function progressReporter(io: Io, quiet: boolean) {
  if (quiet) return { update: () => {}, done: () => {} };
  let last: ScanStage | null = null;
  let lastDraw = 0;
  return {
    update(stage: ScanStage, done?: number, total?: number) {
      if (io.isTTY) {
        const now = Date.now();
        if (stage === last && now - lastDraw < 100) return;
        lastDraw = now;
        const count = total ? ` (${done?.toLocaleString("en-US")} / ${total.toLocaleString("en-US")})` : "";
        io.stderr(`\r\x1b[2K${STAGE_LABEL[stage]}${count}…`);
      } else if (stage !== last) io.stderr(`${STAGE_LABEL[stage]}…\n`);
      last = stage;
    },
    done() {
      if (io.isTTY && last) io.stderr("\r\x1b[2K");
    },
  };
}

function notChecked(r: Report): string[] {
  const out: string[] = [];
  const reasons = new Map(r.coverage.rulesSkipped.map((s) => [s.ruleId, s.reason]));
  if ([...reasons.values()].includes("no_url")) out.push("live site (add --url)");
  if (reasons.get("SEC-006") === "missing_tool") out.push("git history (install gitleaks)");
  if ([...reasons.values()].includes("offline")) out.push("dependency vulnerabilities (online checks off)");
  if (r.coverage.online.osv === "failed") out.push("dependency vulnerabilities (OSV unreachable)");
  for (const n of r.coverage.notes)
    if (n.startsWith("Supabase detected")) out.push("Supabase database rules (no migration files)");
  return out;
}

export function exceedsThreshold(r: Report, failOn: Severity | "none"): boolean {
  if (failOn === "none") return false;
  const limit = SEVERITY_ORDER.indexOf(failOn);
  return r.findings.some(
    (f) =>
      f.status === "open" &&
      f.confidence !== "low" &&
      !f.existing &&
      f.severity !== "info" &&
      SEVERITY_ORDER.indexOf(f.severity) <= limit,
  );
}

export async function runScanCommand(io: Io, flags: ScanFlags): Promise<number> {
  const root = resolve(io.cwd, flags.path);
  try {
    if (!(await stat(root)).isDirectory()) throw new ScanError(`${flags.path} is not a folder.`);
  } catch (e) {
    if (e instanceof ScanError) throw e;
    throw new ScanError(`Couldn't read ${flags.path}: does the folder exist?`);
  }
  if (flags.url) throw new UsageError("Live-site scanning (--url) arrives in version 0.2.0.");
  if (flags.baseline) throw new UsageError("--baseline arrives in version 0.3.0.");

  const formats = flags.format
    .split(",")
    .map((f) => f.trim().toLowerCase())
    .filter(Boolean);
  for (const f of formats) {
    if (LATER_FORMATS.has(f))
      throw new UsageError(`The ${f} format arrives in version 0.3.0. Available now: json, md.`);
    if (!SUPPORTED_FORMATS.has(f)) throw new UsageError(`Unknown format "${f}". Use json and/or md.`);
  }
  if (!formats.includes("json")) formats.unshift("json");

  const { config, warnings, errors } = resolveConfig(await loadConfigFile(io, flags, root));
  if (errors.length) throw new UsageError(`Config problems:\n  ${errors.join("\n  ")}`);
  for (const w of warnings) io.stderr(`Config warning: ${w}\n`);
  if (flags.failOn !== undefined) {
    if (![...SEVERITY_ORDER, "none"].includes(flags.failOn) || flags.failOn === "info")
      throw new UsageError(`--fail-on must be critical, high, medium, low or none.`);
    config.failOn = flags.failOn as Severity | "none";
  }
  const online = config.online && !flags.offline;

  // Don't scan our own previous reports.
  const outDir = resolve(io.cwd, flags.out);
  const outRel = relative(root, outDir);
  if (outRel && !outRel.startsWith("..") && !outRel.startsWith(sep))
    config.ignorePaths.push(`${outRel.split(sep).join("/")}/**`);

  const rules: Rule[] = [...DEFAULT_RULES];
  let gitleaks = false;
  if (flags.gitleaks !== "off") {
    gitleaks = await gitleaksAvailable();
    if (!gitleaks && flags.gitleaks === "on")
      io.stderr("⚠ --use-gitleaks: gitleaks isn't on your PATH, so git history wasn't checked.\n");
    rules.push(createGitleaksRule(root));
  }

  // "used" means the lookups were enabled for this run; any error flips a service to "failed".
  const status: OnlineStatus = online
    ? { osv: "used", npmRegistry: "used" }
    : { osv: "off", npmRegistry: "off" };
  const progress = progressReporter(io, flags.quiet);
  const report = await runScan({
    files: new NodeFileSource(root),
    folderName: basename(root),
    config,
    toolVersion: VERSION,
    now: io.now(),
    rules,
    capabilities: { gitleaks, git: true },
    ...(online ? { online: createOnlineServices(io.fetch, status), onlineStatus: status } : {}),
    onProgress: (p) => progress.update(p.stage, p.done, p.total),
  });
  progress.done();

  // Write reports. File names are fixed, so nothing can be written outside --out.
  await mkdir(outDir, { recursive: true });
  const written: string[] = [];
  const write = async (name: string, content: string) => {
    const target = resolve(outDir, name);
    if (!target.startsWith(outDir + sep)) throw new ScanError("Refusing to write outside the output folder.");
    await writeFile(target, content);
    const shown = relative(io.cwd, target);
    written.push(shown.startsWith("..") ? target : `./${shown.split(sep).join("/")}`);
  };
  await write("prelaunch-check-report.json", JSON.stringify(report, null, 2) + "\n");
  if (formats.includes("md")) await write("prelaunch-check-report.md", toMarkdown(report));

  const p = painter(flags.color);
  if (!flags.quiet) {
    const stack = [...report.profile.frameworks, ...report.profile.backends, ...report.profile.services].map(
      (s) => FRAMEWORK_LABEL[s] ?? s,
    );
    io.stdout(
      `Scanned ${report.target.folderName}${stack.length ? ` (${stack.join(" · ")})` : ""}: ${report.coverage.filesScanned.toLocaleString("en-US")} files, ${report.coverage.filesSkippedTotal.toLocaleString("en-US")} skipped\n\n`,
    );
    if (status.osv === "failed" || status.npmRegistry === "failed")
      io.stderr(
        "⚠ Dependency check skipped: couldn't reach api.osv.dev or the npm registry (use --offline to silence)\n",
      );
  }
  io.stdout(
    flags.quiet
      ? renderSummary(report, {
          verbose: false,
          width: io.columns,
          written: [],
          notChecked: [],
          painter: p,
        }).split("\n")[0] + "\n"
      : renderSummary(report, {
          verbose: flags.verbose,
          width: io.columns,
          written,
          notChecked: notChecked(report),
          painter: p,
        }),
  );
  if (!flags.quiet) {
    const first = report.findings.find((f) => f.status === "open" && f.severity !== "info");
    io.stdout(
      ` Open it at ${WEB_APP_URL}#/open${first ? `  ·  Explain a rule: npx prelaunch-check explain ${first.ruleId}` : ""}\n`,
    );
  }
  return exceedsThreshold(report, config.failOn) ? 1 : 0;
}
