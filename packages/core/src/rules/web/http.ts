// Helpers over recorded HTTP exchanges (pure).
import type { HttpExchange, HttpResponse, SiteSnapshot } from "../../types.js";
import { PROBES, type Probe } from "./probes.js";

export const OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/";
export const MDN_HEADERS = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers";

export function res(ex: HttpExchange | undefined): HttpResponse | null {
  return ex && "status" in ex.response ? ex.response : null;
}

export function header(r: HttpResponse | null, name: string): string | null {
  if (!r) return null;
  const n = name.toLowerCase();
  const hit = r.headers.find(([k]) => k.toLowerCase() === n);
  return hit ? hit[1] : null;
}

export function headers(r: HttpResponse | null, name: string): string[] {
  if (!r) return [];
  const n = name.toLowerCase();
  return r.headers.filter(([k]) => k.toLowerCase() === n).map(([, v]) => v);
}

/** The final page response: the HTTPS root. */
export function rootResponse(site: SiteSnapshot): HttpResponse | null {
  return res(site.root);
}

export function htmlOf(r: HttpResponse | null): string {
  if (!r?.bodyText) return "";
  const ct = header(r, "content-type") ?? "";
  return ct === "" || /html/i.test(ct) ? r.bodyText : "";
}

/** Content of <meta http-equiv="…"> or <meta name="…"> tags. */
export function metaContent(html: string, attr: "http-equiv" | "name", value: string): string | null {
  const re = /<meta\b[^>]*>/gi;
  for (let m = re.exec(html); m !== null; m = re.exec(html)) {
    const tag = m[0];
    const a = new RegExp(`\\b${attr}\\s*=\\s*["']?([^"'\\s>]+)`, "i").exec(tag);
    if (!a || a[1]!.toLowerCase() !== value.toLowerCase()) continue;
    const c = /\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(tag);
    return c ? (c[1] ?? c[2] ?? c[3] ?? "") : "";
  }
  return null;
}

export function titleOf(html: string): string {
  const m = /<title\b[^>]*>([^<]{0,300})<\/title>/i.exec(html);
  return m ? m[1]!.replace(/\s+/g, " ").trim() : "";
}

/** True if a response looks like the soft-404 baseline (same status and title, length within ±5%). */
export function matchesBaseline(r: HttpResponse, site: SiteSnapshot): boolean {
  const b = res(site.baseline404);
  if (!b) return false;
  if (b.status !== r.status) return false;
  if (titleOf(b.bodyText ?? "") !== titleOf(r.bodyText ?? "")) return false;
  const lb = (b.bodyText ?? "").length;
  const lr = (r.bodyText ?? "").length;
  if (lb === 0 && lr === 0) return true;
  return Math.abs(lb - lr) <= Math.max(lb, lr) * 0.05;
}

function prefixBytes(r: HttpResponse): Uint8Array {
  if (!r.bodyBytesPrefix) return new Uint8Array();
  try {
    return Uint8Array.from(atob(r.bodyBytesPrefix), (c) => c.charCodeAt(0));
  } catch {
    return new Uint8Array();
  }
}

function startsWithBytes(r: HttpResponse, sig: number[]): boolean {
  const b = prefixBytes(r);
  return sig.every((x, i) => b[i] === x);
}

/** Content validators per probe kind (TRD §6.3 table; .DS_Store signature confirmed in spike S6). */
export function validates(probe: Probe, r: HttpResponse): boolean {
  const body = r.bodyText ?? "";
  switch (probe.validator) {
    case "env":
      return /^[A-Z_][A-Z0-9_]*=/m.test(body) && !/<html|<!doctype/i.test(body);
    case "git-head":
      return body.startsWith("ref: refs/");
    case "git-config":
      return body.includes("[core]");
    case "npmrc":
      return body.includes("_authToken");
    case "ds-store":
      return startsWithBytes(r, [0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31]);
    case "zip":
      return startsWithBytes(r, [0x50, 0x4b, 0x03, 0x04]);
    case "api-docs-html":
      return /swagger-ui|redoc/i.test(body);
    case "openapi-json":
      try {
        const v: unknown = JSON.parse(body);
        return !!v && typeof v === "object" && ("openapi" in v || "swagger" in v);
      } catch {
        return false;
      }
    case "admin-form":
      return /<form\b/i.test(body);
    case "security-txt":
      return /^\s*contact\s*:/im.test(body) && !/<html|<!doctype/i.test(body);
  }
}

/** Validated probe hits: status 200, content validator passes, and not the soft-404 baseline. */
export function probeHits(
  site: SiteSnapshot,
  kind: Probe["kind"],
): Array<{ probe: Probe; url: string; response: HttpResponse }> {
  const out: Array<{ probe: Probe; url: string; response: HttpResponse }> = [];
  for (const p of site.probes) {
    const probe = PROBES.find((x) => x.id === p.id);
    const r = res(p.exchange);
    if (!probe || probe.kind !== kind || !r || r.status !== 200) continue;
    if (matchesBaseline(r, site) || !validates(probe, r)) continue;
    out.push({ probe, url: p.exchange.request.url, response: r });
  }
  return out;
}

export function urlFinding(ruleId: string, url: string) {
  return { ruleId, location: { kind: "url" as const, url } };
}
