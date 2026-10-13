import { MemoryFileSource } from "../src/sources/memory.js";
import { resolveConfig } from "../src/config.js";
import { runScan, type ScanInput } from "../src/engine/runScan.js";
import type { Rule } from "../src/types.js";

export const FIXED_NOW = new Date("2026-10-13T14:02:11.456Z");

export function memory(files: Record<string, string | Uint8Array>): MemoryFileSource {
  return new MemoryFileSource(files);
}

export async function scan(
  files: Record<string, string | Uint8Array>,
  opts: Partial<ScanInput> & { rules?: Rule[] } = {},
) {
  return runScan({
    files: memory(files),
    folderName: "my-app",
    config: resolveConfig({}).config,
    toolVersion: "0.0.0-test",
    now: FIXED_NOW,
    ...opts,
  });
}
