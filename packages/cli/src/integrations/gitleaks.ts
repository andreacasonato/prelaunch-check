// SEC-006: optional gitleaks integration (TRD §6.1). Runs only if `gitleaks` is on PATH.
// gitleaks' own --redact is used, so raw secrets never reach this process.
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import type { RawFinding, Rule } from "@prelaunch-check/core";

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
    meta: {
      id: "SEC-006",
      title: "Secret in git history",
      category: "secrets",
      severity: "high",
      confidence: "high",
      owasp: "A04",
      requires: ["files", "gitleaks"],
      summary:
        "Runs gitleaks (if installed) over the git history to find secrets that were committed at any point, even if later deleted.",
      why: "Deleting a key from the latest code doesn't remove it from git history. Anyone with a clone can check out an old commit and copy it.",
      fix: [
        "Rotate every key listed here: assume it is compromised.",
        "Optionally rewrite history (git filter-repo) and force-push, but rotation is what actually protects you; forks and clones keep old history.",
      ],
      fixPromptTemplate:
        "gitleaks found a secret ({{detail.gitleaksRule}}) in git history in `{{path}}` (commit {{detail.commit}}). Tell me which provider this key belongs to and walk me through rotating it, then check the current code reads it from a server-only environment variable.",
      falsePositiveNotes:
        "Test fixtures with fake keys in history are reported too; add them to a .gitleaksignore file.",
      sources: [{ title: "gitleaks", url: "https://github.com/gitleaks/gitleaks" }],
    },
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
