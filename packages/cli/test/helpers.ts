import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Io } from "../src/io.js";
import { FIXTURES, writeFixtureDir } from "../../core/test/support/fixtures.js";

export { FIXTURES, allFakeValues } from "../../core/test/support/fixtures.js";

export function tempDir(): string {
  return realpathSync(mkdtempSync(join(tmpdir(), "plc-cli-")));
}

/** Writes a materialized copy of fixtures/projects/<name> and returns its path. */
export function project(name: string, into = tempDir()): string {
  const dest = join(into, name);
  writeFixtureDir(join(FIXTURES, "projects", name), dest);
  return dest;
}

export interface TestIo extends Io {
  out: string;
  err: string;
  fetchCalls: string[];
}

export function makeIo(opts: {
  cwd: string;
  fetch?: typeof fetch;
  confirm?: boolean;
  env?: Record<string, string>;
}): TestIo {
  const io: TestIo = {
    out: "",
    err: "",
    fetchCalls: [],
    stdout: (t) => void (io.out += t),
    stderr: (t) => void (io.err += t),
    env: opts.env ?? {},
    cwd: opts.cwd,
    isTTY: false,
    columns: 120,
    fetch: (async (input: string | URL | Request, init?: RequestInit) => {
      io.fetchCalls.push(String(input instanceof Request ? input.url : input));
      if (!opts.fetch) throw new Error("network access in a test");
      return opts.fetch(input, init);
    }) as typeof fetch,
    confirm: async () => opts.confirm ?? false,
    now: () => new Date("2026-10-13T12:00:00Z"),
  };
  return io;
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
