// OnlineServices for the CLI: OSV (vulnerabilities) and the npm registry.
// Only package names and versions are sent. Per-run cache, concurrency 4, 10 s timeouts.
import type { OnlineServices, OsvVulnSummary, PackageRef, Severity } from "@prelaunch-check/core";
import { limiter } from "./limit.js";
import { USER_AGENT } from "../version.js";

const OSV = "https://api.osv.dev/v1";
const NPM = "https://registry.npmjs.org";
const TIMEOUT_MS = 10_000;

export interface OnlineStatus {
  osv: "used" | "off" | "failed";
  npmRegistry: "used" | "off" | "failed";
}

type Fetch = typeof fetch;

/** GHSA advisories carry database_specific.severity; others fall back to null (the rule uses medium). */
export function mapOsvSeverity(v: { database_specific?: { severity?: unknown } }): Severity | null {
  const s =
    typeof v.database_specific?.severity === "string" ? v.database_specific.severity.toUpperCase() : "";
  if (s === "CRITICAL") return "critical";
  if (s === "HIGH") return "high";
  if (s === "MODERATE" || s === "MEDIUM") return "medium";
  if (s === "LOW") return "low";
  return null;
}

interface OsvVuln {
  id: string;
  summary?: string;
  aliases?: string[];
  database_specific?: { severity?: unknown };
  affected?: Array<{
    package?: { ecosystem?: string };
    ranges?: Array<{ events?: Array<{ fixed?: string }> }>;
  }>;
}

export function createOnlineServices(fetchImpl: Fetch, status: OnlineStatus): OnlineServices {
  const run = limiter(4);
  const vulnCache = new Map<string, Promise<OsvVulnSummary>>();
  const npmCache = new Map<string, Promise<{ exists: boolean; createdAt?: string }>>();

  const request = (url: string, init: RequestInit = {}) =>
    run(() =>
      fetchImpl(url, {
        ...init,
        headers: { "user-agent": USER_AGENT, accept: "application/json", ...(init.headers ?? {}) },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      }),
    );

  const guard = async <T>(kind: keyof OnlineStatus, fn: () => Promise<T>): Promise<T> => {
    try {
      const out = await fn();
      if (status[kind] !== "failed") status[kind] = "used";
      return out;
    } catch (err) {
      status[kind] = "failed";
      throw err;
    }
  };

  return {
    osvQueryBatch: (pkgs: PackageRef[]) =>
      guard("osv", async () => {
        const res = await request(`${OSV}/querybatch`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            queries: pkgs.map((p) => ({ package: { ecosystem: "npm", name: p.name }, version: p.version })),
          }),
        });
        if (!res.ok) throw new Error(`OSV querybatch HTTP ${res.status}`);
        const data = (await res.json()) as { results?: Array<{ vulns?: Array<{ id: string }> }> };
        return pkgs.map((pkg, i) => ({ pkg, vulnIds: (data.results?.[i]?.vulns ?? []).map((v) => v.id) }));
      }),

    osvGetVuln: (id: string) => {
      let p = vulnCache.get(id);
      if (!p) {
        p = guard("osv", async () => {
          const res = await request(`${OSV}/vulns/${encodeURIComponent(id)}`);
          if (!res.ok) throw new Error(`OSV vulns HTTP ${res.status}`);
          const v = (await res.json()) as OsvVuln;
          const fixed = new Set<string>();
          for (const a of v.affected ?? [])
            if (a.package?.ecosystem === "npm")
              for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) fixed.add(e.fixed);
          const out: OsvVulnSummary = {
            id: v.id,
            aliases: v.aliases ?? [],
            severity: mapOsvSeverity(v),
            fixedIn: [...fixed],
            url: `https://osv.dev/vulnerability/${encodeURIComponent(v.id)}`,
          };
          if (v.summary) out.summary = v.summary.slice(0, 200);
          return out;
        });
        vulnCache.set(id, p);
      }
      return p;
    },

    npmPackageInfo: (name: string) => {
      let p = npmCache.get(name);
      if (!p) {
        p = guard("npmRegistry", async () => {
          const url = `${NPM}/${name.startsWith("@") ? name.replace("/", "%2F") : encodeURIComponent(name)}`;
          // The abbreviated document is small; the full one (with time.created) is fetched only
          // for packages with few versions, which is where "very new" packages are.
          const res = await request(url, { headers: { accept: "application/vnd.npm.install-v1+json" } });
          if (res.status === 404) return { exists: false };
          if (!res.ok) throw new Error(`npm registry HTTP ${res.status}`);
          const abbreviated = (await res.json()) as { versions?: Record<string, unknown> };
          if (Object.keys(abbreviated.versions ?? {}).length > 10) return { exists: true };
          const full = await request(url);
          if (!full.ok) return { exists: true };
          const doc = (await full.json()) as { time?: { created?: string } };
          return doc.time?.created ? { exists: true, createdAt: doc.time.created } : { exists: true };
        });
        npmCache.set(name, p);
      }
      return p;
    },
  };
}
