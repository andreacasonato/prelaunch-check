// Parity (Phase 7 acceptance): the same fixture through the CLI's NodeFileSource and the web's
// BrowserFileSource gives identical finding fingerprints.
import { describe, expect, it } from "vitest";
import { mkdtempSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { resolveConfig, runScan } from "@prelaunch-check/core";
import { NodeFileSource } from "../../../packages/cli/src/sources/node-files.js";
import { BrowserFileSource } from "../src/sources/browser-files.js";
import { FIXTURES, writeFixtureDir } from "../../../packages/core/test/support/fixtures.js";

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

describe("CLI / web parity", () => {
  it.each(["vuln-next-supabase", "clean-next-supabase", "vuln-vite-firebase"])(
    "%s gives identical fingerprints",
    async (name) => {
      const dir = join(realpathSync(mkdtempSync(join(tmpdir(), "plc-parity-"))), name);
      writeFixtureDir(join(FIXTURES, "projects", name), dir);
      const files = walk(dir).map((p) => {
        const rel = relative(dir, p).split(sep).join("/");
        const f = new File([readFileSync(p)], rel.split("/").pop()!);
        return Object.assign(f, { rel });
      });
      const base = {
        folderName: name,
        config: resolveConfig({}).config,
        toolVersion: "t",
        now: new Date("2026-10-13T00:00:00Z"),
      };
      const cli = await runScan({ ...base, files: new NodeFileSource(dir) });
      const web = await runScan({
        ...base,
        files: new BrowserFileSource(files, (f) => (f as File & { rel: string }).rel),
      });
      expect(web.findings.map((f) => f.fingerprint)).toEqual(cli.findings.map((f) => f.fingerprint));
      expect(web.summary).toEqual(cli.summary);
      expect(cli.findings.length).toBeGreaterThan(0);
    },
  );
});
