// Writes materialized copies of the project fixtures for the folder picker.
import { rmSync } from "node:fs";
import { join } from "node:path";
import { FIXTURES, writeFixtureDir } from "../../../packages/core/test/support/fixtures.js";

export const E2E_FIXTURES = join(import.meta.dirname, "..", "test-results", "fixtures");

export default function globalSetup() {
  rmSync(E2E_FIXTURES, { recursive: true, force: true });
  for (const name of ["vuln-next-supabase", "clean-next-supabase"])
    writeFixtureDir(join(FIXTURES, "projects", name), join(E2E_FIXTURES, name));
}
