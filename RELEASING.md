# Releasing the CLI to npm

Releases are published by `.github/workflows/release.yml` when a `v*` tag is pushed. It uses npm **trusted publishing**: GitHub Actions proves its identity to npm with a short-lived OIDC token, so no npm password or token is stored in this repository, and npm attaches a provenance statement automatically.

## One-time setup

1. Create an account on https://www.npmjs.com and turn on two-factor authentication.
2. Check the name is still free: `npm view prelaunch-check` should print `E404`.
3. **First publish.** npm's docs describe adding a trusted publisher from the package's settings page, which implies the package must already exist. If npm doesn't let you add a trusted publisher for a new name, publish 0.1.0 once from your computer:
   ```sh
   npm ci && npm run build && npm test
   npm login
   npm publish --workspace packages/cli
   ```
4. On npmjs.com, open the package → **Settings** → **Trusted Publisher** → GitHub Actions, and enter:
   - Organization or user: `andreacasonato`
   - Repository: `prelaunch-check`
   - Workflow filename: `release.yml`
5. Optional: in the same settings, require two-factor authentication and disallow token publishing, so only the workflow can publish.

## Each release

1. Update `version` in `packages/cli/package.json` (for example `0.2.0`) and commit.
2. Tag and push:
   ```sh
   git tag v0.2.0
   git push origin v0.2.0
   ```
3. The Release workflow checks that the tag matches the version, runs lint, typecheck and tests, and publishes.
4. Check it from a clean folder: `npx prelaunch-check@0.2.0 --version`.
