// The fixed exposure-probe plan (docs/02-TRD.md §6.3 step 5). Shared by the CLI collector
// (which only fetches these paths) and the WEB rules (which decide what counts as a hit).
import type { Severity } from "../../types.js";

export type ProbeKind = "sensitive-file" | "api-docs" | "admin" | "security-txt";

export interface Probe {
  id: string;
  path: string;
  kind: ProbeKind;
  label: string;
  severity: Severity;
  validator:
    | "env"
    | "git-head"
    | "git-config"
    | "npmrc"
    | "ds-store"
    | "zip"
    | "api-docs-html"
    | "openapi-json"
    | "admin-form"
    | "security-txt";
}

export const PROBES: readonly Probe[] = [
  {
    id: "env",
    path: "/.env",
    kind: "sensitive-file",
    label: ".env file",
    severity: "critical",
    validator: "env",
  },
  {
    id: "env-local",
    path: "/.env.local",
    kind: "sensitive-file",
    label: ".env.local file",
    severity: "critical",
    validator: "env",
  },
  {
    id: "env-production",
    path: "/.env.production",
    kind: "sensitive-file",
    label: ".env.production file",
    severity: "critical",
    validator: "env",
  },
  {
    id: "git-head",
    path: "/.git/HEAD",
    kind: "sensitive-file",
    label: "Git repository (.git/HEAD)",
    severity: "critical",
    validator: "git-head",
  },
  {
    id: "git-config",
    path: "/.git/config",
    kind: "sensitive-file",
    label: "Git repository (.git/config)",
    severity: "critical",
    validator: "git-config",
  },
  {
    id: "npmrc",
    path: "/.npmrc",
    kind: "sensitive-file",
    label: ".npmrc with an auth token",
    severity: "critical",
    validator: "npmrc",
  },
  {
    id: "ds-store",
    path: "/.DS_Store",
    kind: "sensitive-file",
    label: ".DS_Store file listing",
    severity: "low",
    validator: "ds-store",
  },
  {
    id: "backup-zip",
    path: "/backup.zip",
    kind: "sensitive-file",
    label: "backup.zip archive",
    severity: "high",
    validator: "zip",
  },
  {
    id: "site-zip",
    path: "/site.zip",
    kind: "sensitive-file",
    label: "site.zip archive",
    severity: "high",
    validator: "zip",
  },
  {
    id: "www-zip",
    path: "/www.zip",
    kind: "sensitive-file",
    label: "www.zip archive",
    severity: "high",
    validator: "zip",
  },
  {
    id: "swagger",
    path: "/swagger",
    kind: "api-docs",
    label: "Swagger UI",
    severity: "medium",
    validator: "api-docs-html",
  },
  {
    id: "swagger-ui",
    path: "/swagger-ui.html",
    kind: "api-docs",
    label: "Swagger UI",
    severity: "medium",
    validator: "api-docs-html",
  },
  {
    id: "api-docs",
    path: "/api-docs",
    kind: "api-docs",
    label: "API docs page",
    severity: "medium",
    validator: "api-docs-html",
  },
  {
    id: "docs",
    path: "/docs",
    kind: "api-docs",
    label: "API docs page",
    severity: "medium",
    validator: "api-docs-html",
  },
  {
    id: "api-docs-2",
    path: "/api/docs",
    kind: "api-docs",
    label: "API docs page",
    severity: "medium",
    validator: "api-docs-html",
  },
  {
    id: "openapi-json",
    path: "/openapi.json",
    kind: "api-docs",
    label: "OpenAPI definition",
    severity: "medium",
    validator: "openapi-json",
  },
  {
    id: "swagger-json",
    path: "/swagger.json",
    kind: "api-docs",
    label: "Swagger definition",
    severity: "medium",
    validator: "openapi-json",
  },
  {
    id: "api-openapi-json",
    path: "/api/openapi.json",
    kind: "api-docs",
    label: "OpenAPI definition",
    severity: "medium",
    validator: "openapi-json",
  },
  {
    id: "admin",
    path: "/admin",
    kind: "admin",
    label: "Admin page",
    severity: "low",
    validator: "admin-form",
  },
  {
    id: "security-txt",
    path: "/.well-known/security.txt",
    kind: "security-txt",
    label: "security.txt",
    severity: "low",
    validator: "security-txt",
  },
  {
    id: "security-txt-legacy",
    path: "/security.txt",
    kind: "security-txt",
    label: "security.txt (legacy location)",
    severity: "low",
    validator: "security-txt",
  },
];

/** Probes fetched only if an earlier one didn't succeed (RFC 9116: well-known first). */
export const FALLBACK_PROBES: Readonly<Record<string, string>> = { "security-txt-legacy": "security-txt" };

/** Origin used for the CORS reflection check. ".invalid" is reserved (RFC 2606), so it can't be a real site. */
export const CORS_TEST_ORIGIN = "https://cors-check.prelaunch-check.invalid";

/** Request plan limits (TRD §6.3). */
export const SITE_LIMITS = {
  maxRequests: 40,
  concurrency: 4,
  timeoutMs: 10_000,
  maxRedirects: 5,
  maxScripts: 15,
  maxBodyBytes: 512 * 1024,
} as const;
