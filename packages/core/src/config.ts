// Config file shape and resolution (docs/05-SCHEMA.md §4).
import type { Severity } from "./types.js";

export type RuleSetting = "off" | { severity?: Severity };

export interface Suppression {
  ruleId: string;
  fingerprint?: string;
  path?: string;
  reason: string;
  expires?: string;
}

export interface ExtraProbePath {
  path: string;
  validator: "env" | "json" | "html-contains";
  contains?: string;
}

export interface UserConfig {
  $schema?: string;
  ignorePaths?: string[];
  maxFileSizeBytes?: number;
  rules?: Record<string, RuleSetting>;
  failOn?: Severity | "none";
  online?: boolean;
  publicEnvPrefixes?: string[];
  sensitiveColumnNames?: string[];
  suppressions?: Suppression[];
  url?: { extraProbePaths?: ExtraProbePath[] };
}

export interface ResolvedConfig {
  ignorePaths: string[];
  maxFileSizeBytes: number;
  rules: Record<string, RuleSetting>;
  failOn: Severity | "none";
  online: boolean;
  publicEnvPrefixes: string[];
  sensitiveColumnNames: string[];
  suppressions: Suppression[];
  url: { extraProbePaths: ExtraProbePath[] };
}

export const DEFAULT_MAX_FILE_SIZE = 2_097_152;

const SEVERITIES: ReadonlyArray<string> = ["critical", "high", "medium", "low", "info"];
const KNOWN_KEYS = new Set([
  "$schema",
  "$comment",
  "ignorePaths",
  "maxFileSizeBytes",
  "rules",
  "failOn",
  "online",
  "publicEnvPrefixes",
  "sensitiveColumnNames",
  "suppressions",
  "url",
]);

export interface ConfigResult {
  config: ResolvedConfig;
  warnings: string[];
  errors: string[];
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

/**
 * Validates and fills defaults. Unknown keys are warnings (forward compatibility);
 * a suppression without a reason is an error, because suppressions must record a decision.
 */
export function resolveConfig(input: unknown): ConfigResult {
  const warnings: string[] = [];
  const errors: string[] = [];
  const config: ResolvedConfig = {
    ignorePaths: [],
    maxFileSizeBytes: DEFAULT_MAX_FILE_SIZE,
    rules: {},
    failOn: "high",
    online: true,
    publicEnvPrefixes: [],
    sensitiveColumnNames: [],
    suppressions: [],
    url: { extraProbePaths: [] },
  };

  if (input === undefined || input === null) return { config, warnings, errors };
  if (typeof input !== "object" || Array.isArray(input)) {
    errors.push("Config must be a JSON object.");
    return { config, warnings, errors };
  }
  const u = input as Record<string, unknown>;

  for (const key of Object.keys(u)) {
    if (!KNOWN_KEYS.has(key) && !key.startsWith("$comment"))
      warnings.push(`Unknown config key "${key}" ignored.`);
  }

  if (u.ignorePaths !== undefined) {
    if (isStringArray(u.ignorePaths)) config.ignorePaths = [...u.ignorePaths];
    else errors.push('"ignorePaths" must be an array of strings.');
  }
  if (u.maxFileSizeBytes !== undefined) {
    if (
      typeof u.maxFileSizeBytes === "number" &&
      Number.isFinite(u.maxFileSizeBytes) &&
      u.maxFileSizeBytes > 0
    )
      config.maxFileSizeBytes = Math.floor(u.maxFileSizeBytes);
    else errors.push('"maxFileSizeBytes" must be a positive number.');
  }
  if (u.rules !== undefined) {
    if (typeof u.rules === "object" && u.rules !== null && !Array.isArray(u.rules)) {
      for (const [id, setting] of Object.entries(u.rules as Record<string, unknown>)) {
        if (setting === "off") config.rules[id] = "off";
        else if (typeof setting === "object" && setting !== null) {
          const sev = (setting as { severity?: unknown }).severity;
          if (sev === undefined) config.rules[id] = {};
          else if (typeof sev === "string" && SEVERITIES.includes(sev))
            config.rules[id] = { severity: sev as Severity };
          else errors.push(`"rules.${id}.severity" must be one of ${SEVERITIES.join(", ")}.`);
        } else errors.push(`"rules.${id}" must be "off" or { "severity": … }.`);
      }
    } else errors.push('"rules" must be an object.');
  }
  if (u.failOn !== undefined) {
    if (typeof u.failOn === "string" && (SEVERITIES.includes(u.failOn) || u.failOn === "none"))
      config.failOn = u.failOn as Severity | "none";
    else errors.push(`"failOn" must be one of ${SEVERITIES.join(", ")}, none.`);
  }
  if (u.online !== undefined) {
    if (typeof u.online === "boolean") config.online = u.online;
    else errors.push('"online" must be true or false.');
  }
  if (u.publicEnvPrefixes !== undefined) {
    if (isStringArray(u.publicEnvPrefixes)) config.publicEnvPrefixes = [...u.publicEnvPrefixes];
    else errors.push('"publicEnvPrefixes" must be an array of strings.');
  }
  if (u.sensitiveColumnNames !== undefined) {
    if (isStringArray(u.sensitiveColumnNames)) config.sensitiveColumnNames = [...u.sensitiveColumnNames];
    else errors.push('"sensitiveColumnNames" must be an array of strings.');
  }
  if (u.suppressions !== undefined) {
    if (!Array.isArray(u.suppressions)) errors.push('"suppressions" must be an array.');
    else
      u.suppressions.forEach((s: unknown, i: number) => {
        if (typeof s !== "object" || s === null) {
          errors.push(`"suppressions[${i}]" must be an object.`);
          return;
        }
        const o = s as Record<string, unknown>;
        if (typeof o.ruleId !== "string" || o.ruleId === "") {
          errors.push(`"suppressions[${i}].ruleId" is required.`);
          return;
        }
        if (typeof o.reason !== "string" || o.reason.trim() === "") {
          errors.push(
            `"suppressions[${i}]" (${o.ruleId}) needs a non-empty "reason": suppressions must record a decision.`,
          );
          return;
        }
        if (
          o.expires !== undefined &&
          (typeof o.expires !== "string" || Number.isNaN(Date.parse(o.expires)))
        ) {
          errors.push(`"suppressions[${i}].expires" must be an ISO date.`);
          return;
        }
        const sup: Suppression = { ruleId: o.ruleId, reason: o.reason.trim() };
        if (typeof o.fingerprint === "string") sup.fingerprint = o.fingerprint;
        if (typeof o.path === "string") sup.path = o.path;
        if (typeof o.expires === "string") sup.expires = o.expires;
        config.suppressions.push(sup);
      });
  }
  if (u.url !== undefined) {
    const extra = (u.url as { extraProbePaths?: unknown } | null)?.extraProbePaths;
    if (Array.isArray(extra)) {
      for (const p of extra) {
        const o = p as Record<string, unknown>;
        if (
          typeof o?.path === "string" &&
          o.path.startsWith("/") &&
          (o.validator === "env" || o.validator === "json" || o.validator === "html-contains")
        ) {
          const e: ExtraProbePath = { path: o.path, validator: o.validator };
          if (typeof o.contains === "string") e.contains = o.contains;
          config.url.extraProbePaths.push(e);
        } else
          errors.push(
            '"url.extraProbePaths" entries need a "path" starting with "/" and a valid "validator".',
          );
      }
    }
  }

  return { config, warnings, errors };
}
