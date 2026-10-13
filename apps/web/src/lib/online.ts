// Optional browser lookups (off by default). Only package names and versions are sent, to api.osv.dev,
// which allows cross-origin requests (spike S2). npm registry checks stay CLI-only.
import type { OnlineServices, OsvVulnSummary, PackageRef, Severity } from "@prelaunch-check/core";

const OSV = "https://api.osv.dev/v1";

function severityOf(v: { database_specific?: { severity?: unknown } }): Severity | null {
  const s =
    typeof v.database_specific?.severity === "string" ? v.database_specific.severity.toUpperCase() : "";
  return s === "CRITICAL"
    ? "critical"
    : s === "HIGH"
      ? "high"
      : s === "MODERATE" || s === "MEDIUM"
        ? "medium"
        : s === "LOW"
          ? "low"
          : null;
}

export function createBrowserOnline(status: { osv: "used" | "off" | "failed" }): OnlineServices {
  const cache = new Map<string, Promise<OsvVulnSummary>>();
  const guard = async <T>(fn: () => Promise<T>) => {
    try {
      return await fn();
    } catch (e) {
      status.osv = "failed";
      throw e;
    }
  };
  return {
    osvQueryBatch: (pkgs: PackageRef[]) =>
      guard(async () => {
        const res = await fetch(`${OSV}/querybatch`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            queries: pkgs.map((p) => ({ package: { ecosystem: "npm", name: p.name }, version: p.version })),
          }),
        });
        if (!res.ok) throw new Error(`OSV HTTP ${res.status}`);
        const data = (await res.json()) as { results?: Array<{ vulns?: Array<{ id: string }> }> };
        return pkgs.map((pkg, i) => ({ pkg, vulnIds: (data.results?.[i]?.vulns ?? []).map((v) => v.id) }));
      }),
    osvGetVuln: (id: string) => {
      let p = cache.get(id);
      if (!p) {
        p = guard(async () => {
          const res = await fetch(`${OSV}/vulns/${encodeURIComponent(id)}`);
          if (!res.ok) throw new Error(`OSV HTTP ${res.status}`);
          const v = (await res.json()) as {
            id: string;
            summary?: string;
            aliases?: string[];
            database_specific?: { severity?: unknown };
            affected?: Array<{
              package?: { ecosystem?: string };
              ranges?: Array<{ events?: Array<{ fixed?: string }> }>;
            }>;
          };
          const fixed = new Set<string>();
          for (const a of v.affected ?? [])
            if (a.package?.ecosystem === "npm")
              for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) fixed.add(e.fixed);
          const out: OsvVulnSummary = {
            id: v.id,
            aliases: v.aliases ?? [],
            severity: severityOf(v),
            fixedIn: [...fixed],
            url: `https://osv.dev/vulnerability/${encodeURIComponent(v.id)}`,
          };
          if (v.summary) out.summary = v.summary.slice(0, 200);
          return out;
        });
        cache.set(id, p);
      }
      return p;
    },
  };
}
