// SEC-006: optional gitleaks integration (TRD §6.1). Runs only if `gitleaks` is on PATH.
// gitleaks' own --redact is used, so raw secrets never reach this process.
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { SEC_006_META, type RawFinding, type Rule } from "@prelaunch-check/core";

const exec = promisify(execFile);

export async function gitleaksAvailable(): Promise<boolean> {
  try {
    await exec("gitleaks", ["version"], { timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

interface GitleaksResult {
  Description?: string;
  RuleID?: string;
  File?: string;
  StartLine?: number;
  Commit?: string;
}

/** Maps gitleaks JSON to findings. Author, email and commit message are dropped (privacy). */
export function mapGitleaks(results: GitleaksResult[]): RawFinding[] {
  return results
    .filter((r) => r.File && r.RuleID)
    .map((r) => {
      const commit = (r.Commit ?? "").slice(0, 7);
      return {
        ruleId: "SEC-006",
        title: `${r.Description ?? r.RuleID} in git history${commit ? ` (commit ${commit})` : ""}`,
        location: { kind: "file" as const, path: r.File!, ...(r.StartLine ? { line: r.StartLine } : {}) },
        evidence: { detail: { gitleaksRule: r.RuleID!, commit } },
      };
    });
}

export function createGitleaksRule(root: string): Rule {
  return {
    meta: SEC_006_META,
    async check() {
      const dir = await mkdtemp(join(tmpdir(), "plc-gitleaks-"));
      const report = join(dir, "report.json");
      try {
        await exec(
          "gitleaks",
          [
            "git",
            root,
            "--report-format",
            "json",
            "--report-path",
            report,
            "--redact",
            "--no-banner",
            "--exit-code",
            "0",
            "--log-level",
            "error",
          ],
          { timeout: 300_000, maxBuffer: 64 * 1024 * 1024 },
        );
        return mapGitleaks(JSON.parse(await readFile(report, "utf8")) as GitleaksResult[]);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    },
  };
}
