// Live-site collector (docs/02-TRD.md §6.3). Builds a SiteSnapshot from a FIXED plan of ordinary
// GET requests: ≤ 40 in total, 4 at a time, 10 s timeout each, redirects followed by hand (≤ 5).
// No payloads, no forms, no logins. All analysis happens later in core, over the snapshot.
import { connect } from "node:tls";
import { randomUUID } from "node:crypto";
import {
  CORS_TEST_ORIGIN,
  FALLBACK_PROBES,
  PROBES,
  SITE_LIMITS,
  type HttpExchange,
  type SiteSnapshot,
  type TlsInfo,
} from "@prelaunch-check/core";
import { limiter } from "../online/limit.js";
import { USER_AGENT, VERSION } from "../version.js";

export class BudgetExceeded extends Error {}

export interface CollectOptions {
  fetch: typeof fetch;
  /** TLS inspection; injectable for tests. Returns undefined to skip (e.g. http:// loopback targets). */
  tls?: (host: string, port: number) => Promise<TlsInfo>;
  onStage?: (stage: string) => void;
  now?: () => Date;
}

export interface CollectResult {
  snapshot: SiteSnapshot;
  durationMs: number;
  /** Every request made, for tests and transparency. */
  log: Array<{ method: string; url: string }>;
}

const LOOPBACK = /^(?:localhost|127\.\d+\.\d+\.\d+|\[::1\])$/i;

/**
 * Validates and normalises a target URL (APP-FLOW C-02 step 1): http(s) only, credentials stripped.
 * A bare host becomes https://. Plain http:// is upgraded to https:// except for loopback hosts,
 * which are used by the integration tests.
 */
export function normaliseTarget(input: string): URL {
  const raw = /^[a-z][a-z0-9+.-]*:/i.test(input) ? input : `https://${input}`;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`"${input}" isn't a valid URL.`);
  }
  if (u.protocol !== "https:" && u.protocol !== "http:")
    throw new Error(`Only http:// and https:// URLs can be scanned (got ${u.protocol}).`);
  u.username = "";
  u.password = "";
  u.hash = "";
  if (u.protocol === "http:" && !LOOPBACK.test(u.hostname)) u.protocol = "https:";
  return u;
}

/** Collects the TLS certificate and negotiated protocol with node:tls. */
export function inspectTls(host: string, port: number): Promise<TlsInfo> {
  return new Promise((resolvePromise) => {
    const socket = connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
      timeout: SITE_LIMITS.timeoutMs,
    });
    const done = (info: TlsInfo) => {
      socket.destroy();
      resolvePromise(info);
    };
    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate();
      if (!socket.authorized)
        return done({ error: String(socket.authorizationError ?? "certificate not trusted") });
      const issuer = cert.issuer ? (cert.issuer.O ?? cert.issuer.CN ?? "") : "";
      done({
        validTo: new Date(cert.valid_to).toISOString(),
        issuer: String(issuer),
        protocol: socket.getProtocol() ?? "unknown",
      });
    });
    socket.once("timeout", () => done({ error: "TLS handshake timed out" }));
    socket.once("error", (e) => done({ error: e.message }));
  });
}

function extractScripts(html: string, base: URL): URL[] {
  const out: URL[] = [];
  const re = /<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)/gi;
  for (let m = re.exec(html); m !== null; m = re.exec(html)) {
    try {
      const u = new URL(m[1]!, base);
      if (u.origin === base.origin && !out.some((x) => x.href === u.href)) out.push(u);
    } catch {
      /* ignore */
    }
    if (out.length >= SITE_LIMITS.maxScripts) break;
  }
  return out;
}

function sourceMapUrl(js: string, scriptUrl: URL): URL | null {
  const m = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)\s*$/m.exec(js.slice(-2000));
  if (!m || m[1]!.startsWith("data:")) return null;
  try {
    const u = new URL(m[1]!, scriptUrl);
    return u.origin === scriptUrl.origin ? u : null;
  } catch {
    return null;
  }
}

export async function collectSite(target: URL, opts: CollectOptions): Promise<CollectResult> {
  const started = Date.now();
  const run = limiter(SITE_LIMITS.concurrency);
  const log: Array<{ method: string; url: string }> = [];
  const stage = opts.onStage ?? (() => {});

  /** One GET within the budget. Never follows redirects itself. */
  const get = (url: URL, extraHeaders: Record<string, string> = {}): Promise<HttpExchange> =>
    run(async () => {
      if (log.length >= SITE_LIMITS.maxRequests) throw new BudgetExceeded("request budget exhausted");
      const headers = { "user-agent": USER_AGENT, accept: "*/*", ...extraHeaders };
      log.push({ method: "GET", url: url.href });
      const request = { method: "GET" as const, url: url.href, headers };
      const t0 = Date.now();
      try {
        const res = await opts.fetch(url, {
          method: "GET",
          headers,
          redirect: "manual",
          signal: AbortSignal.timeout(SITE_LIMITS.timeoutMs),
        });
        const hdrs: Array<[string, string]> = [];
        res.headers.forEach((v, k) => {
          if (k !== "set-cookie") hdrs.push([k, v]);
        });
        for (const c of res.headers.getSetCookie()) hdrs.push(["set-cookie", c]);
        // Read at most maxBodyBytes, then stop downloading.
        const chunks: Uint8Array[] = [];
        let size = 0;
        if (res.body) {
          const reader = res.body.getReader();
          while (size < SITE_LIMITS.maxBodyBytes) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
            size += value.length;
          }
          await reader.cancel().catch(() => {});
        }
        const bytes = new Uint8Array(Math.min(size, SITE_LIMITS.maxBodyBytes));
        let off = 0;
        for (const c of chunks) {
          if (off >= bytes.length) break;
          bytes.set(c.subarray(0, bytes.length - off), off);
          off += c.length;
        }
        const location = res.headers.get("location");
        return {
          request,
          response: {
            status: res.status,
            headers: hdrs,
            bodyText: new TextDecoder("utf-8", { fatal: false }).decode(bytes),
            bodyBytesPrefix: Buffer.from(bytes.subarray(0, 16)).toString("base64"),
            ...(location ? { redirectedTo: new URL(location, url).href } : {}),
            elapsedMs: Date.now() - t0,
          },
        };
      } catch (e) {
        if (e instanceof BudgetExceeded) throw e;
        return {
          request,
          response: {
            error: e instanceof Error ? (e.cause instanceof Error ? e.cause.message : e.message) : String(e),
          },
        };
      }
    });

  /** Follows redirects by hand (≤ 5 hops), recording each hop. Stays on http(s). */
  const follow = async (
    start: URL,
  ): Promise<{ final: HttpExchange; chain: string[]; first: HttpExchange }> => {
    let url = start;
    const chain = [url.href];
    const first = await get(url);
    let ex = first;
    for (let hop = 0; hop < SITE_LIMITS.maxRedirects; hop++) {
      const r = "status" in ex.response ? ex.response : null;
      if (!r || r.status < 300 || r.status >= 400 || !r.redirectedTo) break;
      const next = new URL(r.redirectedTo);
      if (next.protocol !== "https:" && next.protocol !== "http:") break;
      url = next;
      chain.push(url.href);
      ex = await get(url);
    }
    return { final: ex, chain, first };
  };

  // 1–2. HTTP→HTTPS redirect check and the target page.
  stage("Fetching page");
  const isHttps = target.protocol === "https:";
  const httpProbe = isHttps ? Object.assign(new URL(target.href), { protocol: "http:" }) : null;
  const [httpRoot, page] = await Promise.all([
    httpProbe ? get(httpProbe) : Promise.resolve(undefined),
    follow(target),
  ]);
  const finalUrl = new URL(page.chain[page.chain.length - 1]!);
  const origin = new URL(finalUrl.origin);

  // 3. TLS (not an HTTP request; doesn't count toward the budget).
  let tls: TlsInfo | undefined;
  if (finalUrl.protocol === "https:") {
    stage("Checking TLS");
    tls = await (opts.tls ?? inspectTls)(finalUrl.hostname, Number(finalUrl.port || 443));
  }

  // 4. Soft-404 baseline, 5. exposure probes, 7. CORS check on the page.
  stage(`Probing ${PROBES.length - Object.keys(FALLBACK_PROBES).length} known paths`);
  const baselineUrl = new URL(`/plc-${randomUUID()}`, origin);
  const primary = PROBES.filter((p) => !(p.id in FALLBACK_PROBES));
  const [baseline404, cors, ...probeExchanges] = await Promise.all([
    get(baselineUrl),
    get(finalUrl, { origin: CORS_TEST_ORIGIN }),
    ...primary.map((p) => get(new URL(p.path, origin))),
  ]);
  const probes = primary.map((p, i) => ({ id: p.id, path: p.path, exchange: probeExchanges[i]! }));
  for (const [fallbackId, primaryId] of Object.entries(FALLBACK_PROBES)) {
    const first = probes.find((p) => p.id === primaryId);
    const ok = first && "status" in first.exchange.response && first.exchange.response.status === 200;
    if (ok) continue;
    const p = PROBES.find((x) => x.id === fallbackId)!;
    probes.push({ id: p.id, path: p.path, exchange: await get(new URL(p.path, origin)) });
  }
  const corsChecks = [{ url: finalUrl.href, exchange: cors }];

  // 6. Same-origin scripts and their source maps, with whatever budget remains.
  const html = "status" in page.final.response ? (page.final.response.bodyText ?? "") : "";
  const scriptUrls = extractScripts(html, finalUrl);
  stage(`Fetching ${scriptUrls.length} script${scriptUrls.length === 1 ? "" : "s"}`);
  const scripts: SiteSnapshot["scripts"] = [];
  for (const s of scriptUrls) {
    if (log.length >= SITE_LIMITS.maxRequests) break;
    const exchange = await get(s);
    const entry: SiteSnapshot["scripts"][number] = { url: s.href, exchange };
    const body = "status" in exchange.response ? (exchange.response.bodyText ?? "") : "";
    const map = sourceMapUrl(body, s);
    if (map && log.length < SITE_LIMITS.maxRequests) entry.sourceMap = await get(map);
    scripts.push(entry);
  }

  // 7b. CORS check on the first discovered /api/ URL, if budget remains.
  const api = /["'`](\/api\/[\w\-/.]{1,100})["'`]/.exec(
    html +
      scripts
        .map((s) => ("status" in s.exchange.response ? (s.exchange.response.bodyText ?? "") : ""))
        .join("\n"),
  );
  if (api && log.length < SITE_LIMITS.maxRequests) {
    const apiUrl = new URL(api[1]!, origin);
    corsChecks.push({ url: apiUrl.href, exchange: await get(apiUrl, { origin: CORS_TEST_ORIGIN }) });
  }

  const snapshot: SiteSnapshot = {
    target: finalUrl.href,
    collectedAt: (opts.now?.() ?? new Date()).toISOString(),
    toolVersion: VERSION,
    ...(httpRoot ? { httpRoot } : {}),
    root: page.final,
    redirectChain: page.chain,
    ...(tls ? { tls } : {}),
    baseline404,
    probes,
    scripts,
    corsChecks,
    requestCount: log.length,
  };
  return { snapshot, durationMs: Date.now() - started, log };
}
