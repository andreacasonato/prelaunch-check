// Phase 6: the real collector against local misconfigured servers (no internet needed).
import { afterEach, describe, expect, it } from "vitest";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { DEFAULT_RULES, SITE_LIMITS, resolveConfig, runScan } from "@prelaunch-check/core";
import { collectSite, normaliseTarget } from "../src/site/collect.js";
import { main } from "../src/main.js";
import { makeIo, tempDir } from "./helpers.js";

type Handler = (req: IncomingMessage, res: ServerResponse) => void;
const servers: Server[] = [];
const seen: Array<{ method: string; url: string; origin?: string }> = [];

async function serve(handler: Handler): Promise<string> {
  const server = createServer((req, res) => {
    seen.push({
      method: req.method!,
      url: req.url!,
      ...(req.headers.origin ? { origin: String(req.headers.origin) } : {}),
    });
    handler(req, res);
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
}

afterEach(async () => {
  seen.length = 0;
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

const NOT_FOUND = "<!doctype html><title>Not found</title><p>Nothing here</p>";

/** A site with every misconfiguration the WEB rules look for. */
const badSite: Handler = (req, res) => {
  const origin = req.headers.origin;
  const common: Record<string, string> = { "x-powered-by": "Express" };
  if (origin)
    Object.assign(common, {
      "access-control-allow-origin": origin,
      "access-control-allow-credentials": "true",
    });
  switch (req.url) {
    case "/":
      res.writeHead(200, { ...common, "content-type": "text/html", "set-cookie": "sid=abc123; Path=/" });
      return res.end('<!doctype html><title>Bad shop</title><script src="/app.js"></script><p>Hello</p>');
    case "/app.js":
      res.writeHead(200, { ...common, "content-type": "text/javascript" });
      return res.end("console.log('app');\n//# sourceMappingURL=app.js.map\n");
    case "/app.js.map":
      res.writeHead(200, { ...common, "content-type": "application/json" });
      return res.end(
        JSON.stringify({
          version: 3,
          sources: ["src/main.ts"],
          sourcesContent: ["console.log('app')"],
          mappings: "AAAA",
        }),
      );
    case "/.env":
      res.writeHead(200, { ...common, "content-type": "text/plain" });
      return res.end("API_URL=https://api.example.com\nDEBUG=true\n");
    default:
      res.writeHead(404, { ...common, "content-type": "text/html" });
      return res.end(NOT_FOUND);
  }
};

/** A single-page app: every path returns index.html with status 200. */
const spaSite: Handler = (_req, res) => {
  res.writeHead(200, { "content-type": "text/html" });
  res.end(
    '<!doctype html><html><head><title>My SPA</title></head><body><div id="root"></div><script src="/assets/index.js"></script></body></html>',
  );
};

describe("collector", () => {
  it("normalises targets: https by default, credentials stripped, non-http rejected", () => {
    expect(normaliseTarget("example.com").href).toBe("https://example.com/");
    expect(normaliseTarget("http://user:pw@example.com/x#y").href).toBe("https://example.com/x");
    expect(normaliseTarget("http://127.0.0.1:8080/").href).toBe("http://127.0.0.1:8080/");
    expect(() => normaliseTarget("file:///etc/passwd")).toThrow(/http/);
    expect(() => normaliseTarget("javascript:alert(1)")).toThrow(/http/);
  });

  it("finds each intended problem on the bad site exactly once, using only GET within budget", async () => {
    const url = await serve(badSite);
    const { snapshot, log } = await collectSite(normaliseTarget(url), { fetch });
    expect(snapshot.requestCount).toBe(log.length);
    expect(log.length).toBeLessThanOrEqual(SITE_LIMITS.maxRequests);
    expect(seen.length).toBe(log.length);
    expect(new Set(seen.map((s) => s.method))).toEqual(new Set(["GET"]));
    // The only custom Origin is the reserved .invalid test origin.
    expect(new Set(seen.filter((s) => s.origin).map((s) => s.origin))).toEqual(
      new Set(["https://cors-check.prelaunch-check.invalid"]),
    );

    const report = await runScan({
      site: snapshot,
      config: resolveConfig({}).config,
      toolVersion: "test",
      now: new Date("2026-10-13T00:00:00Z"),
      rules: [...DEFAULT_RULES],
    });
    const counts = new Map<string, number>();
    for (const f of report.findings) counts.set(f.ruleId, (counts.get(f.ruleId) ?? 0) + 1);
    const expected = [
      "WEB-001",
      "WEB-002",
      "WEB-003",
      "WEB-005",
      "WEB-006",
      "WEB-007",
      "WEB-008",
      "WEB-009",
      "WEB-010",
      "WEB-013",
      "WEB-015",
      "WEB-016",
    ];
    for (const id of expected) expect(counts.get(id), id).toBe(1);
    expect([...counts.keys()].sort()).toEqual(expected.sort());
    expect(report.target).toEqual({ kind: "url", url });
  });

  it("SPA that returns 200 for everything yields zero exposed-file, API-docs or admin hits", async () => {
    const url = await serve(spaSite);
    const { snapshot } = await collectSite(normaliseTarget(url), { fetch });
    const report = await runScan({
      site: snapshot,
      config: resolveConfig({}).config,
      toolVersion: "test",
      rules: [...DEFAULT_RULES],
    });
    const ids = report.findings.map((f) => f.ruleId);
    for (const id of ["WEB-010", "WEB-011", "WEB-012", "WEB-013"]) expect(ids).not.toContain(id);
  });

  it("never exceeds 40 requests, even with many scripts and source maps", async () => {
    const scripts = Array.from({ length: 30 }, (_, i) => `<script src="/s${i}.js"></script>`).join("");
    const url = await serve((req, res) => {
      if (req.url === "/") {
        res.writeHead(200, { "content-type": "text/html" });
        return res.end(`<!doctype html><title>Many</title>${scripts}`);
      }
      if (/^\/s\d+\.js$/.test(req.url!)) {
        res.writeHead(200, { "content-type": "text/javascript" });
        return res.end(`x();\n//# sourceMappingURL=${req.url}.map\n`);
      }
      res.writeHead(404);
      res.end(NOT_FOUND);
    });
    const { log } = await collectSite(normaliseTarget(url), { fetch });
    expect(log.length).toBeLessThanOrEqual(40);
    expect(seen.length).toBeLessThanOrEqual(40);
  });

  it("records an unreachable site as errors instead of throwing", async () => {
    const url = await serve(badSite);
    await new Promise((r) => servers.pop()!.close(r));
    const { snapshot } = await collectSite(normaliseTarget(url), { fetch });
    expect("error" in snapshot.root.response).toBe(true);
  });
});

describe("scan --url", () => {
  it("refuses to scan without confirmation in a non-interactive shell, and sends nothing", async () => {
    const url = await serve(badSite);
    const io = makeIo({ cwd: tempDir(), fetch });
    expect(await main(["scan", "--url", url, "--offline"], io)).toBe(2);
    expect(io.err).toContain("--yes-i-am-authorized");
    expect(seen).toEqual([]);
  });

  it("asks on a TTY and sends nothing when the answer is no", async () => {
    const url = await serve(badSite);
    const io = makeIo({ cwd: tempDir(), fetch, confirm: false });
    io.isTTY = true;
    expect(await main(["scan", "--url", url], io)).toBe(2);
    expect(io.err).toContain("Nothing was sent");
    expect(seen).toEqual([]);
  });

  it("scans a live site with --yes-i-am-authorized and writes a url report", async () => {
    const url = await serve(badSite);
    const dir = tempDir();
    const io = makeIo({ cwd: dir, fetch });
    expect(await main(["scan", "--url", url, "--yes-i-am-authorized"], io)).toBe(1);
    expect(io.out).toMatch(/^ BLOCKED/m);
    expect(io.out).toMatch(/requests to the site/);
    const report = JSON.parse(
      readFileSync(join(dir, "prelaunch-check-report/prelaunch-check-report.json"), "utf8"),
    );
    expect(report.target.kind).toBe("url");
    expect(report.coverage.site.requestCount).toBeLessThanOrEqual(40);
    expect(report.coverage.online).toEqual({ osv: "off", npmRegistry: "off" });
  });

  it("exits 3 when the site can't be reached", async () => {
    const url = await serve(badSite);
    await new Promise((r) => servers.pop()!.close(r));
    const io = makeIo({ cwd: tempDir(), fetch });
    expect(await main(["scan", "--url", url, "--yes-i-am-authorized"], io)).toBe(3);
    expect(io.err).toContain("Couldn't reach");
  });

  it("rejects non-http URLs as a usage error", async () => {
    const io = makeIo({ cwd: tempDir(), fetch });
    expect(await main(["scan", "--url", "ftp://example.com", "--yes-i-am-authorized"], io)).toBe(2);
  });
});
