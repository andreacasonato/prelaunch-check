import { describe, expect, it } from "vitest";
import { scan } from "./helpers.js";

describe("detectProfile (TRD §4.2)", () => {
  it("detects Next.js + Supabase + Stripe with npm", async () => {
    const r = await scan(
      {
        "package.json": JSON.stringify({
          name: "shop",
          dependencies: { next: "15", react: "19", "@supabase/supabase-js": "2", stripe: "17" },
        }),
        "package-lock.json": "{}",
        "supabase/migrations/0001_init.sql": "create table x();",
        ".git/HEAD": "ref: refs/heads/main\n",
      },
      { rules: [] },
    );
    expect(r.profile).toEqual({
      name: "shop",
      frameworks: ["next", "react"],
      backends: ["supabase"],
      services: ["stripe"],
      packageManagers: ["npm"],
      lockfiles: ["package-lock.json"],
      buildDirs: [],
      publicEnvPrefixes: ["NEXT_PUBLIC_"],
      hasGit: true,
      supabaseMigrationsFound: true,
    });
  });

  it("detects Vite + Firebase from files, build dirs, and config prefixes", async () => {
    const r = await scan(
      {
        "package.json": JSON.stringify({ devDependencies: { vite: "7" }, dependencies: { firebase: "11" } }),
        "vite.config.ts": "export default {}",
        "firestore.rules": "rules_version = '2';",
        "pnpm-lock.yaml": "lockfileVersion: '9.0'",
        "dist/assets/index.js": "x",
      },
      {
        rules: [],
        config: (await import("../src/config.js")).resolveConfig({ publicEnvPrefixes: ["PUBLIC_"] }).config,
      },
    );
    expect(r.profile.name).toBe("my-app");
    expect(r.profile.frameworks).toEqual(["vite"]);
    expect(r.profile.backends).toEqual(["firebase"]);
    expect(r.profile.packageManagers).toEqual(["pnpm"]);
    expect(r.profile.buildDirs).toEqual(["dist/"]);
    expect(r.profile.publicEnvPrefixes).toEqual(["VITE_", "PUBLIC_"]);
    expect(r.profile.hasGit).toBe(false);
  });

  it("detects frameworks from config files alone and copes with broken package.json", async () => {
    const r = await scan(
      { "package.json": "{ not json", "next.config.mjs": "export default {}", "bun.lockb": "x" },
      { rules: [] },
    );
    expect(r.profile.frameworks).toEqual(["next"]);
    expect(r.profile.packageManagers).toEqual(["bun"]);
  });
});
