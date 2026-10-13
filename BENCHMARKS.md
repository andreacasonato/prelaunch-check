# Benchmarks and hardening results

Measured on 2026-10-13 against the targets in the PRD (§6, non-functional requirements).

**Machine:** Apple M1, 8 GB RAM, macOS, Node.js 24.13.0. Web numbers use headless Chromium from Playwright 1.63.

## Performance

The test project was generated: 5,000 source files (4,600 TSX modules with comments and template strings, 200 SQL migrations with RLS policies, 200 API routes) plus a `node_modules` folder of 30,000 files that must be skipped. 155 MB on disk.

| Target | Result | Status |
|---|---|---|
| CLI: 5,000-file project in < 10 s | 4.1–4.3 s over three runs (`scan --offline`) | Met |
| Web: same project in < 20 s, UI never freezes | 4.8 s to receive and pre-filter the 35,000-file folder, plus 7.6 s to scan in a Web Worker: 12.4 s total | Met |
| URL scan: < 30 s and ≤ 40 requests | example.com: 26 requests in 1.3 s. The 40-request cap is enforced in code and asserted in tests (`packages/cli/test/site.test.ts`) | Met |

How to reproduce: `BENCH_DIR=/path/to/project npx playwright test bench` in `apps/web` (web), and `/usr/bin/time node packages/cli/dist/index.js scan <dir> --offline` (CLI).

**Caveat:** in the web test, Playwright hands the folder to the page programmatically. A person using the browser's native folder picker may wait slightly longer while the browser lists the folder, especially on slower disks.

## Robustness

| Project | Files | Time | Rule errors | Notes |
|---|---|---|---|---|
| facebook/react (shallow clone) | 7,207 scanned | 5.8 s | 0 | Every rule completed. |

## False-positive review

Official example apps were scanned and every high or critical finding was triaged:

| Example | Before | After fixes | Findings fixed |
|---|---|---|---|
| vercel/next.js `examples/with-stripe-typescript` | Blocked | No blocking issues found | CODE-006 flagged `import type Stripe from "stripe"`, which is erased at build time. Type-only imports are now ignored. |
| vercel/next.js `with-firebase`, `with-mongodb`; supabase `user-management`, `todo-list`, `slack-clone` | Needs attention | No blocking issues found | SEC-004 treated `.env.local.example` / `.env.production.example` templates as real `.env` files. All `.env.*.example` style templates are now recognised. |
| vercel/next.js `with-supabase`, `api-routes-rest` | No blocking issues found | No change | |

Each fixed case is now a permanent negative test fixture. Remaining findings on these examples are accurate: no lockfile, `"latest"` versions, and (on Next.js's default `.gitignore`, which ignores only `.env*.local`) CFG-002, which is documented as a known, accepted case.

## Other checks

- All 39 source links cited by the rules returned HTTP 200 on 2026-10-13.
- Regex safety: every secret pattern scans 1 MB of adversarial input in under 100 ms (best of three). This test caught and fixed a quadratic private-key scan that took 32 s on a crafted file.
- Accessibility: automated axe checks report no serious or critical violations on the home, report, finding, checklist, live-site and docs pages, on desktop and mobile. Every colour pair meets 4.5:1.

## Still to do before 1.0

These need a person:

- [ ] Manual screen-reader pass (VoiceOver or NVDA) on the web app.
- [ ] Independent review of redaction (`packages/core/src/redact.ts`, `engine/scrub.ts`), the URL collector (`packages/cli/src/site/collect.ts`) and HTML escaping (`packages/core/src/formats/html.ts`) by someone who didn't write them.
- [ ] Upload a SARIF file to a scratch repository and check that findings appear in the Security tab.
- [ ] Manual `localStorage` check in Safari and Firefox private windows (the app is built to work without storage, and a unit test covers that).
