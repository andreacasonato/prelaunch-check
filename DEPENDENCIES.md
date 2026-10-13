# Dependencies

Every dependency is "other people's code" (Book ch. "Dependencies & the Software Supply Chain"). This file records why each one exists. The **runtime budget for `packages/core` + `packages/cli` is ≤ 5** (TRD §2).

## Runtime dependencies: core + cli

**Count: 0 / 5.**

The published `prelaunch-check` package is a single file bundled by esbuild at build time, with `@prelaunch-check/core` inlined. Installing it pulls no other packages.

The TRD suggested `yaml` and `ignore` as candidates. Neither was needed:
- GitHub workflow files are analysed line by line (CFG rules only need `uses:`, `permissions:`, `on:` and `run:` lines).
- `pnpm-lock.yaml` package keys are read with a small purpose-built reader.
- `.gitignore` matching uses a small in-house matcher with its own tests.

If a contributor finds that these break on real-world files, adding `yaml` (ISC) or `ignore` (MIT) is the fallback. That needs a new entry here.

## Runtime dependencies: web app (`apps/web`, not counted in the budget)

| Package | Version | License | Why | Last publish (checked 2026-10-13) |
|---|---|---|---|---|
| react | 19.3.0 | MIT | UI framework chosen in TRD §2 | 2026-10-12 |
| react-dom | 19.3.0 | MIT | React DOM renderer | 2026-10-12 |

The web app is static and bundled. These ship as part of the built JS, served from the same origin.

## Development dependencies

None of these are shipped to users.

| Package | Version | License | Why | Last publish (checked 2026-10-13) |
|---|---|---|---|---|
| typescript | 6.0.3 | Apache-2.0 | Type checking. Pinned below 6.1 because `typescript-eslint` 8.71 supports `<6.1.0` | 2026-10-13 (registry modified) |
| vitest | 5.0.4 | MIT | Unit and integration tests (TRD §2) | 2026-10-12 |
| eslint | 10.12.0 | MIT | Linting, including the core no-Node/no-DOM boundary | 2026-10-02 |
| @eslint/js | 10.0.1 | MIT | ESLint recommended rules | 2026-07-10 |
| typescript-eslint | 8.71.2 | MIT | TypeScript support for ESLint | 2026-10-13 |
| globals | 17.13.0 | MIT | Global variable sets for ESLint environments | 2026-10-01 |
| prettier | 3.9.10 | MIT | Formatting | 2026-10-10 |
| esbuild | 0.28.2 | MIT | Bundles the CLI into a single zero-dependency file | 2026-08-08 |
| @types/node | 24.x | MIT | Node type definitions for the CLI | 2026-10-09 |
| vite | 8.3.4 | MIT | Web app build tool (TRD §2) | 2026-10-08 |
| @vitejs/plugin-react | 6.1.2 | MIT | React support for Vite | 2026-10-05 |
| @types/react, @types/react-dom | 19.3.0 | MIT | React type definitions | 2026-10-04 |

## GitHub Actions

Each Action is pinned to a full commit SHA with a version comment (TRD §12, CFG-003).

| Action | Version | Commit SHA |
|---|---|---|
| actions/checkout | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| actions/setup-node | v7.1.0 | `949feb2413d6458794dcd2491c4babbbce0c15c1` |
