import { describe, expect, it } from "vitest";
import { parseLockfile } from "../src/rules/deps/lockfiles.js";

describe("lockfile readers", () => {
  it("reads package-lock v3", () => {
    const text = JSON.stringify(
      {
        lockfileVersion: 3,
        packages: {
          "": { name: "app" },
          "node_modules/lodash": { version: "4.17.20" },
          "node_modules/@scope/pkg": { version: "1.0.0" },
          "node_modules/a/node_modules/lodash": { version: "3.10.1" },
          "packages/lib": { version: "0.0.0" },
          "node_modules/lib": { link: true, resolved: "packages/lib" },
        },
      },
      null,
      2,
    );
    const r = parseLockfile("package-lock.json", text);
    expect(r.packages.map((p) => `${p.name}@${p.version}`)).toEqual([
      "lodash@4.17.20",
      "@scope/pkg@1.0.0",
      "lodash@3.10.1",
    ]);
    expect(r.packages[0]!.line).toBe(7);
  });

  it("reads package-lock v1", () => {
    const text = JSON.stringify({
      lockfileVersion: 1,
      dependencies: { a: { version: "1.0.0", dependencies: { b: { version: "2.0.0" } } } },
    });
    expect(parseLockfile("package-lock.json", text).packages.map((p) => `${p.name}@${p.version}`)).toEqual([
      "a@1.0.0",
      "b@2.0.0",
    ]);
  });

  it("reads pnpm-lock v9 and v5", () => {
    const v9 =
      "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4\n\npackages:\n\n  lodash@4.17.20:\n    resolution: {integrity: sha512-x}\n\n  '@babel/core@7.26.0(supports-color@8.1.1)':\n    resolution: {integrity: sha512-y}\n";
    expect(
      parseLockfile("pnpm-lock.yaml", v9).packages.map((p) => `${p.name}@${p.version}:${p.line}`),
    ).toEqual(["lodash@4.17.20:11", "@babel/core@7.26.0:14"]);
    const v5 =
      "lockfileVersion: 5.4\npackages:\n  /lodash/4.17.20:\n    resolution: {}\n  /@types/node/20.1.0:\n    dev: true\n";
    expect(parseLockfile("pnpm-lock.yaml", v5).packages.map((p) => `${p.name}@${p.version}`)).toEqual([
      "lodash@4.17.20",
      "@types/node@20.1.0",
    ]);
  });

  it("reads yarn v1 and Berry", () => {
    const v1 =
      '# yarn lockfile v1\n\nlodash@^4.17.0, lodash@^4.17.20:\n  version "4.17.20"\n  resolved "https://x"\n\n"@scope/pkg@^1.0.0":\n  version "1.2.0"\n';
    expect(parseLockfile("yarn.lock", v1).packages.map((p) => `${p.name}@${p.version}:${p.line}`)).toEqual([
      "lodash@4.17.20:3",
      "@scope/pkg@1.2.0:7",
    ]);
    const berry =
      '__metadata:\n  version: 8\n\n"lodash@npm:^4.17.20":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n';
    expect(parseLockfile("yarn.lock", berry).packages.map((p) => `${p.name}@${p.version}`)).toEqual([
      "lodash@4.17.21",
    ]);
  });

  it("reads bun.lock (JSONC) and reports bun.lockb as unsupported", () => {
    const text =
      '{\n  "lockfileVersion": 1,\n  "packages": {\n    "lodash": ["lodash@4.17.20", "", {}, "sha512-x"],\n  },\n}\n';
    expect(parseLockfile("bun.lock", text).packages.map((p) => `${p.name}@${p.version}:${p.line}`)).toEqual([
      "lodash@4.17.20:4",
    ]);
    expect(parseLockfile("bun.lockb", null).unsupported).toMatch(/binary/);
  });
});
