# Contributing to Prelaunch Check

Thanks for helping. Most contributions are new rules or fixes to existing ones, so this guide focuses on those.

## Setup

```sh
npm ci
npm test
npm run lint
npm run typecheck
```

Node.js 22.12 or newer is required.

## Ground rules

These come from [CLAUDE.md](CLAUDE.md) and apply to everyone, human or agent:

- `packages/core` never imports `node:*` and never uses `window` or `document`. Lint enforces this.
- **Never invent secret-key regexes.** Use the vendor's own documentation, or port a pattern from gitleaks' default config and add attribution to `NOTICE`.
- Redaction can't be turned off, and reports never contain absolute paths or raw secrets.
- UI copy never calls a user's app "safe" or "secure".
- Runtime dependencies for core + cli are capped at 5 (currently 0). Open an issue before adding one.

## Adding a rule

A rule is **one file plus fixtures plus sources**.

1. **Pick an ID** following `^[A-Z]{2,4}(-INV|-INFO)?-\d{3}$` in the right category (`SEC`, `DB`, `DEP`, `CODE`, `CFG`, `WEB`). IDs are permanent once released.
2. **Write the rule** at `packages/core/src/rules/<category>/<RULE-ID>.ts`. It exports a `Rule` with:
   - `meta`: every field in `RuleMeta` (docs/05-SCHEMA.md §2.2). `sources` must cite the vendor doc, standard or book chapter that justifies the rule. `why` is 2–4 plain sentences. `fix` is ordered steps. `falsePositiveNotes` lists the known false positives.
   - `check(ctx)`: returns `RawFinding[]`. It must be deterministic. For secrets, put the raw value in `secretValue` so the engine can redact it and fingerprint it.
3. **Register it** in `packages/core/src/rules/index.ts`.
4. **Add fixtures**:
   - `fixtures/rules/<RULE-ID>/positive/`: files that must trigger the rule;
   - `fixtures/rules/<RULE-ID>/negative/`: look-alikes that must **not** trigger it (for secrets, always include publishable keys).
   Fixture secrets must be fake. Use obviously fake bodies such as `sk_live_FAKEFAKE…`.
5. **Run `npm test`.** The fixture runner discovers the new folders automatically and asserts positives fire and negatives stay silent.
6. **Choose confidence honestly.** If a known false-positive situation exists, use `medium`. If it's a heuristic, use `low`; it will show as "Worth checking" and never block.

## Reporting false positives

Open an issue with the `false-positive` label. Include the rule ID and a minimal **made-up** example. Never paste real code or secrets.

## Commits

Small commits with clear messages. Every commit should pass `npm test`, `npm run lint` and `npm run typecheck`.
