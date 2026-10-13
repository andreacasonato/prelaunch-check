// SEC-006 metadata. The check itself needs git and gitleaks, so it runs in the CLI
// (packages/cli/src/integrations/gitleaks.ts); the web app uses this to explain CLI reports.
import type { RuleMeta } from "../../types.js";

export const SEC_006_META: RuleMeta = {
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
};
