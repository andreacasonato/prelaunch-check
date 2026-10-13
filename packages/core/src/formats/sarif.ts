// SARIF 2.1.0 for GitHub code scanning (docs/02-TRD.md §9; mapping from spike S4).
// GitHub reads rules[].properties["security-severity"] (a string score) and result levels.
import type { Finding, Report, RuleMeta, Severity } from "../types.js";
import { DEFAULT_RULES } from "../rules/index.js";
import { SEC_006_META } from "../rules/secrets/SEC-006.js";
import { REPO_URL } from "../version.js";

/** Spike S4: over 9.0 = critical, 7.0–8.9 = high, 4.0–6.9 = medium, 0.1–3.9 = low. Info: none. */
export const SECURITY_SEVERITY: Partial<Record<Severity, string>> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "2.0",
};

type Level = "error" | "warning" | "note";
const LEVEL: Record<Severity, Level> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string; markdown: string };
  helpUri: string;
  defaultConfiguration: { level: Level };
  properties: { tags: string[]; precision: string; "security-severity"?: string };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: Level;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number; startColumn?: number };
    };
  }>;
  partialFingerprints: Record<string, string>;
  properties: { confidence: string; category: string; owasp: string; existing?: boolean };
  suppressions?: Array<{ kind: "external" | "inSource"; justification: string }>;
}

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        semanticVersion: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
    automationDetails?: { id: string };
  }>;
}

const ALL_META = new Map<string, RuleMeta>([
  ...DEFAULT_RULES.map((r) => [r.meta.id, r.meta] as const),
  [SEC_006_META.id, SEC_006_META],
]);

function pascal(title: string): string {
  return title
    .replace(/[^A-Za-z0-9]+/g, " ")
    .trim()
    .split(" ")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join("");
}

function ruleFor(id: string, f: Finding): SarifRule {
  const m = ALL_META.get(id);
  const severity = m?.severity ?? f.severity;
  const fix = m ? m.fix.map((s, i) => `${i + 1}. ${s}`).join("\n") : "";
  const rule: SarifRule = {
    id,
    name: pascal(m?.title ?? id),
    shortDescription: { text: m?.title ?? f.title },
    fullDescription: { text: m?.summary ?? f.title },
    help: {
      text: m ? `${m.why}\n\nHow to fix:\n${fix}` : f.fixPrompt,
      markdown: m ? `${m.why}\n\n**How to fix**\n\n${fix}` : f.fixPrompt,
    },
    helpUri: `${REPO_URL}#what-it-checks`,
    defaultConfiguration: { level: LEVEL[severity] },
    properties: {
      tags: ["security", m?.category ?? f.category, `OWASP-${m?.owasp ?? f.owasp}:2025`],
      precision:
        (m?.confidence ?? f.confidence) === "high"
          ? "high"
          : (m?.confidence ?? f.confidence) === "medium"
            ? "medium"
            : "low",
    },
  };
  const ss = SECURITY_SEVERITY[severity];
  if (ss) rule.properties["security-severity"] = ss;
  return rule;
}

export function toSarif(report: Report): SarifLog {
  const rules: SarifRule[] = [];
  const index = new Map<string, number>();
  const results: SarifResult[] = [];
  for (const f of report.findings) {
    if (!index.has(f.ruleId)) {
      index.set(f.ruleId, rules.length);
      rules.push(ruleFor(f.ruleId, f));
    }
    const uri =
      f.location.kind === "url" ? (f.location.url ?? report.target.url ?? "") : (f.location.path ?? "");
    const region = f.location.line
      ? { startLine: f.location.line, ...(f.location.column ? { startColumn: f.location.column } : {}) }
      : undefined;
    const result: SarifResult = {
      ruleId: f.ruleId,
      ruleIndex: index.get(f.ruleId)!,
      level: LEVEL[f.severity],
      message: { text: `${f.title}\n\n${f.fixPrompt}` },
      locations: [{ physicalLocation: { artifactLocation: { uri }, ...(region ? { region } : {}) } }],
      partialFingerprints: { "prelaunchCheck/v1": f.fingerprint },
      properties: {
        confidence: f.confidence,
        category: f.category,
        owasp: f.owasp,
        ...(f.existing ? { existing: true } : {}),
      },
    };
    if (f.status !== "open") {
      result.suppressions = [
        {
          kind: f.decision?.source === "inline" ? "inSource" : "external",
          justification: f.decision?.reason ?? f.status.replace("_", " "),
        },
      ];
    }
    results.push(result);
  }
  return {
    $schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "prelaunch-check",
            version: report.tool.version,
            semanticVersion: report.tool.version.replace(/^(\d+\.\d+\.\d+).*$/, "$1"),
            informationUri: REPO_URL,
            rules,
          },
        },
        results,
        automationDetails: { id: `prelaunch-check/${report.target.kind}/` },
      },
    ],
  };
}
