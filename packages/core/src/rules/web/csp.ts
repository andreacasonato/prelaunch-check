// Content-Security-Policy parsing (pure).
import type { SiteSnapshot } from "../../types.js";
import { header, htmlOf, metaContent, rootResponse } from "./http.js";

export function parseCsp(policy: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const part of policy.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0]!.toLowerCase();
    if (!out.has(name)) out.set(name, tokens.slice(1));
  }
  return out;
}

export function cspSources(site: SiteSnapshot): { header: string | null; meta: string | null } {
  const r = rootResponse(site);
  return {
    header: header(r, "content-security-policy"),
    meta: metaContent(htmlOf(r), "http-equiv", "content-security-policy"),
  };
}
