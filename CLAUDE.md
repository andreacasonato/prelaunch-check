# CLAUDE.md: Prelaunch Check

Open-source, local-first security scanner for apps before launch. No AI, no server, no telemetry.
Specs live in `docs/`. Read the relevant doc before changing anything:
- `docs/02-TRD.md` covers architecture, the rule catalog (§6) and scoring (§8);
- `docs/05-SCHEMA.md` covers types and the report format.

## Commands
- `npm ci`: install
- `npm test`: Vitest (all workspaces)
- `npm run lint`, `npm run typecheck`
- `npm run dev -w apps/web`: web app locally
- `node packages/cli/dist/index.js scan fixtures/projects/vuln-next-supabase`: try the CLI

## Hard rules
- `packages/core` never imports `node:*` or uses `window` or `document`. All I/O goes through `FileSource`, `SiteSnapshot` and `OnlineServices`.
- Every rule is **one file** with `meta` filled from TRD §6, including `sources`, plus `positive/` and `negative/` fixtures. No rule ships without both.
- **Never invent secret-key regexes.** Use the vendor docs cited in the TRD or port from gitleaks' default config, with attribution in `NOTICE`.
- Secrets are redacted in core before any output. There is no flag to disable redaction.
- Reports never contain absolute paths or raw secrets (a test enforces this).
- The URL scan sends only GET/HEAD requests from the fixed plan, ≤ 40 requests, after the ownership confirmation. No attack payloads, ever.
- UI copy never calls a user's app "safe" or "secure". Use the fixed verdict words: Blocked / Needs attention / No blocking issues found.
- Use the design tokens in `docs/04-DESIGN-BRIEF.md` §4.1. Don't choose colours, fonts or layouts yourself.
- Runtime dependency budget: ≤ 5 for core + cli. Record any new dependency in `docs/DEPENDENCIES.md` (why, license, maintenance) and ask before adding one.
- GitHub Actions: pin to full commit SHA; set minimal `permissions`.

## Working style
- Show a plan before large changes; one phase from `docs/06-IMPLEMENTATION-PLAN.md` at a time.
- Tests first for scoring, redaction, fingerprints, and HTML escaping.
- If a fact isn't in `docs/` and you can't verify it from an official source, say so instead of guessing.
- Commit after each green step with a clear message.
