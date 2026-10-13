// Shared helpers for GitHub Actions workflow rules (CFG-003…006).
import type { FileIndex } from "../../types.js";
import { readYamlOutline, type YamlEntry } from "../../util/yaml-outline.js";

export const GHA_SECURE_USE = "https://docs.github.com/en/actions/reference/security/secure-use";

export interface Workflow {
  path: string;
  text: string;
  lines: string[];
  entries: YamlEntry[];
}

export async function loadWorkflows(files: FileIndex): Promise<Workflow[]> {
  const out: Workflow[] = [];
  for (const e of files.glob(".github/workflows/*.{yml,yaml}")) {
    const text = await files.text(e.path);
    if (text === null) continue;
    out.push({ path: e.path, text, lines: text.split(/\r?\n/), entries: readYamlOutline(text) });
  }
  return out;
}

/** Snippet for a single workflow line with the match highlighted. */
export function lineEvidence(wf: Workflow, line: number, needle?: string) {
  const snippet = wf.lines[line - 1] ?? "";
  const at = needle ? snippet.indexOf(needle) : -1;
  return at === -1 ? { snippet } : { snippet, matchStart: at, matchEnd: at + needle!.length };
}
