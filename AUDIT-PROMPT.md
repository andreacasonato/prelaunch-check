# Prelaunch security audit prompt

This is a ready-made prompt for an AI coding agent (Claude Code, Cursor, Windsurf, Copilot Chat and similar). It walks the agent through the same checks that [Prelaunch Check](https://github.com/andreacasonato/prelaunch-check) runs, without installing anything.

**How to use it**

1. Open your project in your coding tool, so the agent can read your files.
2. Copy everything below the line and paste it as one message.
3. Read the report it writes. Approve fixes one at a time.

**Good to know:** an AI agent reads your code with judgement, so it can miss things or report things that aren't problems. For a repeatable, rule-based scan that never sends your code anywhere, also run `npx prelaunch-check scan .` (see the README). Never paste real secret keys into a chat. If one has already been shared anywhere, rotate it.

---

You are auditing this project for security problems before it launches. Work through the steps below in order.

## Ground rules

- **Read only.** Don't change, create or delete files until I approve a fix. Don't install packages, run the app or run scripts from this project.
- **No network** unless a step says so and I've allowed it.
- **Never show a secret in full.** Show only the first 4 and last 4 characters, like `sk_l…9xQz`.
- **Be specific.** Every finding needs the file and line (or URL), what you saw, why it matters in one or two plain sentences, and how to fix it.
- **Be honest about confidence.** Use high, medium or low. Put low-confidence items under "Worth checking".
- **Never call the app "safe" or "secure".** Report what you found and what you couldn't check.

## Step 1: Detect the stack

From package.json dependencies and marker files, work out which of these the project uses: Next.js (`next`, next.config.*), Vite (`vite`, vite.config.*), React, Express, Supabase (`@supabase/supabase-js`, `supabase/` folder), Firebase (`firebase`, firebase.json, *.rules), Stripe (`stripe`, `@stripe/stripe-js`), and the package manager (lockfile). Skip checks for services the project doesn't use.

## Step 2: Secret keys

Search every text file (including build output in dist/, build/, out/ and .next/static/, but not node_modules or lockfiles) for secret keys.
Secret keys to look for (each prefix as it appears in real keys):
- Stripe live secret key: `sk_live`, `sk_prod`, `rk_live`, `rk_prod`
- Stripe test secret key: `sk_test`, `rk_test`
- Supabase secret key: `sb_secret_`
- Anthropic API key: `sk-ant-api03`
- Anthropic admin API key: `sk-ant-admin01`
- OpenAI API key: `T3BlbkFJ`
- AWS access key ID: `A3T`, `AKIA`, `ASIA`, `ABIA`, `ACCA`
- GitHub personal access token: `ghp_`
- GitHub fine-grained personal access token: `github_pat_`
- GitHub OAuth access token: `gho_`
- GitHub app token: `ghu_`, `ghs_`
- GitHub refresh token: `ghr_`
- GitLab personal access token: `glpat-`
- Slack bot token: `xoxb`
- Slack user token: `xoxp-`, `xoxe-`
- Slack app token: `xapp`
- Slack incoming webhook URL: `hooks.slack.com`
- SendGrid API key: `SG.`
- Twilio API key: `SK`
- npm access token: `npm_`
- PyPI upload token: `pypi-AgEIcHlwaS5vcmc`
- Hugging Face access token: `hf_`
- DigitalOcean personal access token: `dop_v1_`
- DigitalOcean OAuth access token: `doo_v1_`
- Shopify access token: `shpat_`, `shpca_`, `shppa_`
- Linear API key: `lin_api_`
- PlanetScale password: `pscale_pw_`
- PlanetScale API token: `pscale_tkn_`
- Doppler API token: `dp.pt.`
- Databricks API token: `dapi`
- Perplexity API key: `pplx-`
- Private keys: `-----BEGIN … PRIVATE KEY-----` blocks with a real body (not placeholders).
- Database URLs with an inline password: `postgres://user:password@host`, `mysql://…`, `mongodb+srv://…`.
Legacy Supabase keys are JWTs (they start with `eyJ`): decode the middle part (base64url) and treat it as secret only if it contains `"role":"service_role"`.
Keys that are designed to be public, and must NOT be reported as problems: Stripe publishable key, Supabase publishable key, Firebase/Google API key, and legacy Supabase `anon` JWTs.
Variables with these prefixes are copied into browser code: `NEXT_PUBLIC_` (Next.js), `VITE_` (Vite).
Ignore obvious placeholders (`xxxx`, `your-key-here`, `${VAR}`, `<password>`) and local development database URLs (localhost, 127.0.0.1, docker service names).

- **SEC-001 · Secret API key in source code** (critical, high confidence)
  - Look for: Finds secret API keys (Stripe, Supabase, AWS, OpenAI, GitHub and more) written directly in project files.
  - Known false positives and limits: Fake keys in tests or documentation that happen to have high entropy still match. Test-mode Stripe keys are reported as medium. .env files are handled by SEC-003/SEC-004 instead.
  - Fix: Move the key into a server-only environment variable (for example in `.env.local`, which must be git-ignored) and read it with `process.env` on the server. Make every call that needs the key from server code (an API route, server action or edge function), never from the browser. Rotate the key in the provider's dashboard. Removing it from the code doesn't un-leak it: anyone who saw it can still use it until it's revoked. Search the whole project, including built files, to confirm the old value is gone.
- **SEC-002 · Secret API key in built client bundle** (critical, high confidence)
  - Look for: Finds secret API keys inside build output (dist/, build/, out/, .next/static/) that is shipped to browsers.
  - Known false positives and limits: Build output of server-only code placed inside a build directory is also scanned.
  - Fix: Find where the key enters the bundle: usually an environment variable with a public prefix (NEXT_PUBLIC_, VITE_) or a hard-coded value in client code. Move the call that needs the key to server code and read the key from a server-only environment variable. Rotate the key in the provider's dashboard. Removing it from the code doesn't un-leak it: anyone who saw it can still use it until it's revoked. Rebuild and search the build folder again to confirm the key is gone.
- **SEC-003 · Secret placed in a client-exposed env var** (critical, high confidence)
  - Look for: Finds .env variables whose name starts with a browser-exposed prefix (NEXT_PUBLIC_, VITE_) but whose value is a secret key or whose name says it's secret.
  - Known false positives and limits: Matches by name only (e.g. NEXT_PUBLIC_PASSWORD_MIN_LENGTH) are reported with medium confidence; numeric and boolean values are ignored.
  - Fix: Rename the variable without the public prefix so it stays on the server. Move the code that uses it into a server-side function (API route, server action, edge function). Rotate the key in the provider's dashboard. Removing it from the code doesn't un-leak it: anyone who saw it can still use it until it's revoked. Rebuild and search the build output to confirm the key is gone.
- **SEC-004 · .env file committed or not git-ignored** (high, high confidence)
  - Look for: .env files that are tracked by git, or that no .gitignore rule covers. Example files are included only when they contain real-looking secrets.
  - Known false positives and limits: Without git (for example in the web app) the rule uses .gitignore rules only, so a file that is ignored but was committed earlier is not detected. Nested repositories with their own .git are treated as part of the project.
  - Fix: Add `.env*` and `!.env.example` to your `.gitignore`. If the file is already committed, stop tracking it with `git rm --cached <file>` and commit that change. Rotate the key in the provider's dashboard. Removing it from the code doesn't un-leak it: anyone who saw it can still use it until it's revoked. Keep a `.env.example` with variable names and empty or fake values for collaborators.
- **SEC-005 · Private key file or block** (critical, high confidence)
  - Look for: Finds PEM private keys (RSA, EC, OpenSSH, PKCS#8) in any scanned text file, including *.pem and id_rsa files.
  - Known false positives and limits: Sample keys in tests or documentation match when they have a full-length body. Short placeholders are ignored. Encrypted keys are reported as high instead of critical.
  - Fix: Delete the key from the project and store it in your host's secret manager or a server-only environment variable. Generate a new key pair and revoke the old one wherever it was trusted (server authorized_keys, JWT verifiers, certificate authority). Add `*.pem`, `id_rsa*` and `*.key` to .gitignore.
- **SEC-007 · Hard-coded database connection string with password** (critical, high confidence)
  - Look for: Finds postgres://, mysql:// and mongodb:// URLs with an inline password in project files.
  - Known false positives and limits: Local development URLs (localhost, 127.0.0.1, docker service names without a dot) and placeholder passwords like ${PASSWORD}, <password> or 'postgres' are ignored. .env files are not checked here (that's where the URL belongs).
  - Fix: Move the connection string into a server-only environment variable (for example DATABASE_URL in a git-ignored .env file). Read it with `process.env.DATABASE_URL` in server code only. Change the database password, since the old one has been exposed. Rotate the key in the provider's dashboard. Removing it from the code doesn't un-leak it: anyone who saw it can still use it until it's revoked.
- **SEC-INFO-001 · Publishable key detected (fine to expose)** (info, high confidence)
  - Look for: Lists keys that are designed to be public (Stripe pk_, Supabase sb_publishable_ and legacy anon keys, Firebase web API keys) so you know they're not a problem.
  - Fix: No change is needed for the key itself. Make sure your access rules are in place: see DB-001 to DB-006 for Supabase and Firebase. For Google/Firebase API keys, restrict the key to the APIs and domains you use in the Google Cloud console.
- **SEC-006 · Secret in git history** (high, high confidence)
  - Look for: Runs gitleaks (if installed) over the git history to find secrets that were committed at any point, even if later deleted.
  - Known false positives and limits: Test fixtures with fake keys in history are reported too; add them to a .gitleaksignore file.
  - Fix: Rotate every key listed here: assume it is compromised. Optionally rewrite history (git filter-repo) and force-push, but rotation is what actually protects you; forks and clones keep old history.

## Step 3: Database access rules (Supabase and Firebase)

Read every `*.sql` file (especially `supabase/migrations/`), plus `firestore.rules`, `storage.rules` and `database.rules.json`. Apply migrations in file-name order: later files can add columns, enable RLS or drop policies.
"Money or power" column names for DB-003 (`*` is a wildcard): `role`, `is_admin`, `admin`, `plan`, `tier`, `subscription*`, `credits`, `balance`, `quota`, `*_limit`, `usage*`, `trial_end*`, `is_premium`, `premium`, `paid`, `stripe_customer_id`.
If the project uses Supabase but has no migration files, say clearly that the database rules couldn't be checked: tables created in the dashboard are invisible in the code.

- **DB-001 · Supabase table without Row Level Security** (high, medium confidence)
  - Look for: Finds tables in the public schema that are created in SQL files but never get `enable row level security`.
  - Known false positives and limits: RLS enabled outside SQL files (in the dashboard) is invisible to a folder scan. Tables in schemas other than public are ignored. Tables that are dropped later in the migrations are ignored.
  - Fix: Enable RLS in a new migration: `alter table <table> enable row level security;` Add policies for exactly what each user may do, for example `create policy "Users read own rows" on <table> for select to authenticated using ((select auth.uid()) = user_id);` Test as a logged-out visitor and as a second user that you can't read or change other people's rows.
- **DB-002 · Policy allows anyone to write** (high, high confidence)
  - Look for: Finds insert, update, delete or all policies whose using or with check expression is just `true`, without being limited to service_role.
  - Known false positives and limits: Policies scoped `to service_role` are not reported. A table intended as a public write-only inbox still needs rate limits.
  - Fix: Replace `true` with a real condition, usually ownership: `using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id)`. If only your server should write, drop the policy and write from server code with the secret key instead.
- **DB-003 · "Money or power" column on a user-editable table** (high, medium confidence)
  - Look for: Finds tables where users may update their own row (an update policy using auth.uid()) and that also hold columns like credits, plan, role or is_admin.
  - Known false positives and limits: Columns protected by a trigger, or by a with check expression that pins the column's value, are only recognised when the with check mentions the column. Column names are matched by name only; extend or narrow the list with config `sensitiveColumnNames`.
  - Fix: Move money and power fields to a separate table (for example `billing`) that users can only read; update it only from server code or a webhook using the secret key. Or block the column for clients: `revoke update (credits) on profiles from authenticated, anon;` Test it: sign in as a normal user and try `supabase.from('profiles').update({ credits: 999999 }).eq('id', myId)`; it must fail.
- **DB-004 · Firebase rules allow open access** (critical, high confidence)
  - Look for: Finds Firestore/Storage rules that allow writes with `if true` or no condition, and Realtime Database rules with ".read": true or ".write": true.
  - Known false positives and limits: Read-only `allow read: if true` on genuinely public collections is not reported by this rule. Rules deployed from the console instead of files are invisible to a folder scan.
  - Fix: Replace open rules with rules that check who is asking, for example `allow read, write: if request.auth != null && request.auth.uid == userId;` inside `match /users/{userId}`. Deny by default: start from `allow read, write: if false;` and open only what each collection needs. Test your rules with the Firebase Emulator Suite before deploying.
- **DB-005 · Firebase rule grants access to any signed-in user** (medium, medium confidence)
  - Look for: Finds write rules whose only condition is `request.auth != null` (Realtime Database: `auth != null`).
  - Known false positives and limits: Some collections are meant to be shared by all members (for example a public chat); confirm that's intended.
  - Fix: Check ownership, not just sign-in: `allow write: if request.auth != null && request.auth.uid == resource.data.ownerId;` (use `request.resource.data` for creates). Realtime Database: `".write": "auth != null && auth.uid === $uid"` under a `$uid` path.
- **DB-006 · Ownership policy without explicit null check** (low, medium confidence)
  - Look for: Finds policies comparing auth.uid() to a column without also checking `auth.uid() is not null`.
  - Fix: Add the explicit check: `using ((select auth.uid()) is not null and (select auth.uid()) = user_id)`.

## Step 4: Dependencies

Read package.json files and the lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock).
For DEP-001, DEP-003 and DEP-004 you need the network. Only do them if I allow it. If you can, run `npm audit --omit=dev` (or the equivalent for my package manager) and `npm view <name> time.created` for unfamiliar packages. Otherwise list them as not checked.

- **DEP-001 · Dependency with known vulnerability** (medium, high confidence)
  - Look for: Looks up every package version in your lockfile in the OSV vulnerability database (only names and versions are sent) and reports known advisories.
  - Known false positives and limits: Advisories can apply only to features you don't use; check the advisory before accepting the risk. Severity comes from the advisory; if it gives none, medium is used.
  - Fix: Upgrade the package to a fixed version (see the advisory): `npm install <package>@<fixed-version>`. If it's a transitive dependency, upgrade the direct dependency that pulls it in, or use `overrides` (npm) / `resolutions` (yarn) / `pnpm.overrides`. Re-run the scan to confirm the advisory is gone.
- **DEP-002 · No lockfile** (medium, high confidence)
  - Look for: Finds package.json files with dependencies but no package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock in the same folder or above.
  - Fix: Run your package manager's install command once (`npm install`, `pnpm install`, `yarn`, `bun install`) and commit the lockfile it creates. Use `npm ci` (or the equivalent) in CI and deployments so installs follow the lockfile exactly.
- **DEP-003 · Dependency not found on the registry** (high, high confidence)
  - Look for: Checks that every package named in package.json exists on the npm registry.
  - Known false positives and limits: Private packages served from your own registry return 'not found' on npmjs.org. Scopes configured in .npmrc (`@scope:registry=…`) are skipped; other scoped packages are reported with medium confidence.
  - Fix: Check what the package was supposed to be: search npmjs.com and the library's official docs for the real name. Remove the dependency or replace it with the real package, then reinstall.
- **DEP-004 · Very new dependency** (info, medium confidence)
  - Look for: Lists direct dependencies first published less than 30 days ago.
  - Known false positives and limits: New releases of your own packages, or new packages from trusted publishers, are listed too.
  - Fix: Look at the package's npm page and repository: who publishes it, how many downloads it has, and whether the code matches what it claims to do. Prefer a well-established alternative if one exists.
- **DEP-005 · Unpinned dependency range** (low, high confidence)
  - Look for: Finds dependencies declared as "*", "latest", "x" or an empty version.
  - Fix: Replace the range with a specific version range, for example `"^4.17.21"`, matching what you've tested.

## Step 5: Code patterns

Read JavaScript and TypeScript files (also .vue and .svelte). Ignore matches inside comments and plain strings. A file is client code if it's under a Vite `src/` folder, starts with `'use client'` in Next.js, or is in build output.

- **CODE-001 · Raw SQL built from strings** (high, medium confidence)
  - Look for: Finds query(), execute(), raw(), $queryRawUnsafe(), $executeRawUnsafe() and sql.unsafe() calls whose SQL is built with ${…} or + concatenation.
  - Known false positives and limits: Interpolating only constants (for example a table name from a fixed list) is reported too; confirm no user input can reach the string.
  - Fix: Pass values as parameters instead of building the string: `db.query('select * from users where id = $1', [id])`. With Prisma, use the tagged template `prisma.$queryRaw`…`` (it parameterizes automatically) instead of the Unsafe variants. Prefer your ORM's query builder for anything that includes user input.
- **CODE-002 · Dynamic code execution** (medium, medium confidence)
  - Look for: Finds eval() and new Function() called with something other than a fixed string.
  - Known false positives and limits: Method calls like redis.eval() are ignored. Build tooling that evaluates trusted config is reported too.
  - Fix: Replace eval with a safe alternative: `JSON.parse` for data, a lookup table for choosing functions, or a proper expression parser. Never build code from user input.
- **CODE-003 · Unsafe HTML sink** (medium, low confidence)
  - Look for: Finds dangerouslySetInnerHTML, .innerHTML = and v-html with a non-literal value that isn't wrapped in a sanitizer such as DOMPurify.sanitize.
  - Known false positives and limits: Shown as Worth checking: many sinks only receive trusted, static HTML. The rule can't follow where a value comes from.
  - Fix: Render text instead of HTML where you can (plain JSX `{value}` or `textContent`). If you must render HTML, sanitize it first: `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}`.
- **CODE-004 · Wildcard CORS with credentials** (high, high confidence)
  - Look for: Finds CORS configuration that allows every origin (`origin: '*'` or `origin: true`) together with `credentials: true`, or the equivalent response headers.
  - Fix: List the exact origins that may call your API: `cors({ origin: ['https://app.example.com'], credentials: true })`. If you don't need cookies cross-origin, remove `credentials: true`.
- **CODE-005 · Environment or secrets logged** (medium, medium confidence)
  - Look for: Finds console calls that print process.env, import.meta.env, or variables named like secrets, passwords or tokens.
  - Known false positives and limits: Names are matched, not values: variables like tokenCount or passwordStrength are reported too. Strings such as 'Enter your password' are ignored.
  - Fix: Remove the log line, or log only non-sensitive facts (for example `console.log('Stripe key set:', Boolean(process.env.STRIPE_SECRET_KEY))`). Rotate any secret that has already reached your logs.
- **CODE-006 · Secret-key SDK in client code** (critical, medium confidence)
  - Look for: In code that ships to the browser (Vite src/, Next.js 'use client' files, build output): the server-side Stripe SDK, or a Supabase client created with a SERVICE_ROLE/SECRET key.
  - Known false positives and limits: Client detection is path-based for Vite (everything under src/), so server code kept in a Vite src/ folder is reported too. Type-only imports (import type … from 'stripe') are ignored because they never reach the browser.
  - Fix: Use the browser SDKs in client code: `@stripe/stripe-js` and a Supabase client with the publishable (anon) key. Move secret operations to server code (API routes, server actions, edge functions) and call them from the client.
- **CODE-INV-001 · API endpoint inventory** (info, high confidence)
  - Look for: Lists Next.js route handlers, pages/api routes, Express routes and Supabase Edge Functions, noting whether each file seems to check who is calling. Admin routes with no auth call are raised as Worth checking.
  - Known false positives and limits: 'Auth call seen' only means the file mentions a common auth function (getUser, getSession, auth(), verifyIdToken, requireAuth, currentUser). Middleware-based protection isn't detected, so admin routes protected by middleware are still flagged as Worth checking.
  - Fix: Go through the list and write down who should reach each endpoint: anonymous, user, or admin. For user and admin endpoints, check the session on the server at the start of the handler, and check the role for admin routes. Test admin routes as a normal user and as a logged-out visitor.

## Step 6: Project configuration

Read `.gitignore`, `next.config.*`, `vite.config.*` and every file in `.github/workflows/`.

- **CFG-001 · Source maps in production build output** (medium, high confidence)
  - Look for: Finds .map files in build output, or Next.js productionBrowserSourceMaps / Vite build.sourcemap turned on.
  - Known false positives and limits: Vite's `sourcemap: 'hidden'` is not flagged by the config check, but its .map files are still flagged if they're present in the build folder.
  - Fix: Turn off production source maps: remove `productionBrowserSourceMaps: true` (Next.js) or set `build.sourcemap` to `false` (Vite). If you need them for error tracking, upload them privately to your error tracker and delete them from the deployed output. Rebuild and confirm no `.map` files remain in the build folder.
- **CFG-002 · .gitignore missing key entries** (medium, high confidence)
  - Look for: Checks that .gitignore covers .env files (.env, .env.local) and, for JavaScript projects, node_modules.
  - Known false positives and limits: Next.js's default .gitignore ignores only `.env*.local`, on the basis that `.env` holds non-secret defaults. If that's how you use `.env`, record this as an accepted risk.
  - Fix: Add these lines to the `.gitignore` at the root of your project:  .env* !.env.example node_modules/  Run `git status` to check that .env files no longer show up.
- **CFG-003 · GitHub Action not pinned to a commit SHA** (low, high confidence)
  - Look for: Finds `uses: owner/repo@ref` in workflows where ref is a tag or branch instead of a full 40-character commit SHA.
  - Known false positives and limits: Local actions (./path) and docker:// images are not checked.
  - Fix: Replace the tag with the full commit SHA it points to, and keep the version as a comment: `uses: actions/checkout@<40-char-sha> # v4.2.2`. Use Dependabot or Renovate to keep pinned SHAs up to date.
- **CFG-004 · Workflow token has broad permissions** (medium, high confidence)
  - Look for: Finds workflows with `permissions: write-all`, or with no top-level `permissions:` key (unless every job sets its own).
  - Fix: Add a top-level block granting only what the workflow needs, usually:  permissions:   contents: read  Grant extra scopes (for example `security-events: write`) only on the job that needs them.
- **CFG-005 · pull_request_target checks out PR code** (high, high confidence)
  - Look for: Finds workflows triggered by pull_request_target that check out the pull request's head commit with actions/checkout.
  - Fix: Use the `pull_request` trigger for anything that builds or tests contributed code. If you need pull_request_target (for example to label PRs), don't check out the PR's code in that workflow. Split privileged follow-up work into a separate `workflow_run` workflow that never executes PR code.
- **CFG-006 · Untrusted input interpolated into a shell step** (high, medium confidence)
  - Look for: Finds `run:` steps that paste attacker-controllable values (issue or PR titles and bodies, comment bodies, branch names, commit messages) directly into the shell script with ${{ }}.
  - Known false positives and limits: Workflows only triggered by trusted events (for example push to a protected branch) are still reported; the value may still be controlled by whoever wrote the commit.
  - Fix: Pass the value through an environment variable and quote it in the script:  - env:     TITLE: ${{ github.event.pull_request.title }}   run: echo "$TITLE" 

## Step 7: Live site (only if I confirm I own it)

Skip this whole section unless I've told you the URL of a live site that I own or am allowed to test. Then use only plain GET requests (for example `curl -sS -D - -o /dev/null <url>` for headers), at most 40 in total. No forms, no logins, no attack payloads.
Paths to request once each: `/.env`, `/.env.local`, `/.env.production`, `/.git/HEAD`, `/.git/config`, `/.npmrc`, `/.DS_Store`, `/backup.zip`, `/site.zip`, `/www.zip`, `/swagger`, `/swagger-ui.html`, `/api-docs`, `/docs`, `/api/docs`, `/openapi.json`, `/swagger.json`, `/api/openapi.json`, `/admin`, `/.well-known/security.txt`, `/security.txt`. A path only counts as exposed if it returns 200 with real content (for example a `VAR=value` line for .env, `ref: refs/` for .git/HEAD) and isn't just the site's normal "not found" page. First request a random path like `/does-not-exist-12345` to see what "not found" looks like; many single-page apps return 200 for every path.
For the CORS check, send one GET to the home page with the header `Origin: https://cors-check.prelaunch-check.invalid`.

- **WEB-001 · Site not served over HTTPS / no redirect** (high, high confidence)
  - Look for: Checks that the site answers over HTTPS and that plain http:// redirects to https://.
  - Fix: Turn on HTTPS at your host (Vercel, Netlify, Cloudflare and most hosts do this automatically with a free certificate). Redirect every http:// request to https:// with a 301 or 308 redirect.
- **WEB-002 · HSTS missing or too short** (medium, high confidence)
  - Look for: Checks for a Strict-Transport-Security header with max-age of at least one year (31536000 seconds).
  - Fix: Send this header on HTTPS responses: `Strict-Transport-Security: max-age=31536000; includeSubDomains`. Most hosts let you set headers in a config file (for example `vercel.json`, `netlify.toml` / `_headers`, or Next.js `headers()` in next.config).
- **WEB-003 · Content-Security-Policy missing** (medium, high confidence)
  - Look for: Checks for a Content-Security-Policy header or <meta http-equiv> policy on the page.
  - Fix: Start with a strict policy and loosen only what you need, for example: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`. Test in report-only mode first (`Content-Security-Policy-Report-Only`) to see what would break.
- **WEB-004 · CSP allows inline/eval scripts** (low, high confidence)
  - Look for: Checks that script-src (or default-src) doesn't allow 'unsafe-inline' without a nonce or hash, or 'unsafe-eval'.
  - Fix: Remove 'unsafe-inline' and use nonces or hashes for the inline scripts you need (most frameworks support nonces). Remove 'unsafe-eval' and replace any code that relies on eval or new Function.
- **WEB-005 · Clickjacking protection missing** (medium, high confidence)
  - Look for: Checks for X-Frame-Options: DENY or SAMEORIGIN, or a CSP header with frame-ancestors. A <meta> CSP can't set frame-ancestors.
  - Fix: Send `Content-Security-Policy: frame-ancestors 'none'` (or `'self'`) as a response header, and `X-Frame-Options: DENY` for older browsers.
- **WEB-006 · X-Content-Type-Options: nosniff missing** (low, high confidence)
  - Look for: Checks for the header `X-Content-Type-Options: nosniff`.
  - Fix: Send `X-Content-Type-Options: nosniff` on every response.
- **WEB-007 · Referrer-Policy missing** (low, high confidence)
  - Look for: Checks for a Referrer-Policy header or <meta name="referrer">.
  - Fix: Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter).
- **WEB-008 · Server/framework version disclosed** (low, high confidence)
  - Look for: Flags an X-Powered-By header, or a Server header that includes a version number.
  - Fix: Remove X-Powered-By (Express: `app.disable('x-powered-by')`; Next.js: `poweredByHeader: false`). Configure your server or proxy to send the Server header without a version (nginx: `server_tokens off;`).
- **WEB-009 · Cookie missing security attributes** (low, medium confidence)
  - Look for: Checks every Set-Cookie on the page: Secure on HTTPS, HttpOnly for session-like cookies, an explicit SameSite, and Secure whenever SameSite=None.
  - Known false positives and limits: Session-like names are guessed from the cookie name (sess, sid, auth, token, jwt). Cookies set later by JavaScript aren't seen.
  - Fix: Set session cookies with `Secure; HttpOnly; SameSite=Lax` (or `Strict`). Most auth libraries have options for these.
- **WEB-010 · Sensitive file publicly accessible** (critical, high confidence)
  - Look for: Requests a fixed list of paths (/.env, /.git/HEAD, /.git/config, /.npmrc, /.DS_Store, backup zips) and reports any that return real content rather than a 'not found' page.
  - Known false positives and limits: A path only counts when it returns status 200, passes a content check (for example a VAR=value line for .env), and differs from the site's normal 'not found' page.
  - Fix: Delete the file from your deployed output, or configure your host to block dotfiles and archives. Rotate every secret the file contained: assume it has been downloaded. Deploy from a build folder instead of your whole project folder.
- **WEB-011 · API documentation publicly accessible** (medium, medium confidence)
  - Look for: Requests common Swagger/OpenAPI/Redoc paths and reports any that serve API documentation.
  - Known false positives and limits: Deliberately public API docs (for a public developer API) are reported too.
  - Fix: Remove the docs route from production, or put it behind authentication. Serve docs from a separate, private environment.
- **WEB-012 · Admin page reachable without login** (low, low confidence)
  - Look for: Requests /admin and reports it when it returns a page with a form instead of 'not found'. Shown as Worth checking.
  - Fix: Check that every admin action is protected on the server, not just hidden in the UI. Add rate limiting and multi-factor authentication to admin login; consider restricting it by IP or moving it to a private URL.
- **WEB-013 · Source maps publicly accessible** (medium, high confidence)
  - Look for: Follows the sourceMappingURL comment in your page's scripts and reports .map files that return real source-map JSON.
  - Fix: Turn off production browser source maps in your build config, or delete .map files before deploying. If your error tracker needs them, upload them privately during the build.
- **WEB-014 · Secret key in served JavaScript** (critical, high confidence)
  - Look for: Runs the secret-key patterns over the JavaScript files your page loads and over inline <script> blocks.
  - Fix: Find where the key enters the bundle (often an env var with NEXT_PUBLIC_ or VITE_) and move the call that needs it to the server. Rotate the key in the provider's dashboard, then redeploy.
- **WEB-015 · CORS reflects any origin with credentials** (high, high confidence)
  - Look for: Sends one ordinary GET with Origin: https://cors-check.prelaunch-check.invalid and checks whether the response allows that origin with credentials.
  - Fix: Only allow an explicit list of your own front-end origins. Don't combine a reflected origin with Access-Control-Allow-Credentials: true.
- **WEB-016 · security.txt missing or expired** (low, high confidence)
  - Look for: Checks for /.well-known/security.txt with a Contact line and an Expires date in the future, as RFC 9116 requires.
  - Fix: Create `/.well-known/security.txt` with at least:  Contact: mailto:security@your-domain.com Expires: 2027-12-31T23:59:59Z  Put a reminder in your calendar to update Expires before it passes.
- **WEB-017 · TLS certificate expiring soon / weak protocol** (medium, high confidence)
  - Look for: Checks the HTTPS certificate is valid, expires more than 30 days from now, and that the connection uses TLS 1.2 or 1.3.
  - Fix: Turn on automatic certificate renewal at your host (most managed hosts do this for you). Disable TLS 1.0 and 1.1 in your server or CDN settings.
- **WEB-018 · Mixed content** (medium, high confidence)
  - Look for: Finds http:// URLs in script, stylesheet, iframe and image tags on an HTTPS page.
  - Fix: Change the URLs to https:// (or protocol-relative paths you host yourself). Add `upgrade-insecure-requests` to your Content-Security-Policy as a safety net.

## Step 8: Endpoint inventory

List every API endpoint (Next.js `app/**/route.*` exports and `pages/api/**`, Express `app.get/post/…` routes, Supabase `functions/*/index.ts`). For each, say whether it checks the user's session on the server, and whether it should be reachable by anonymous visitors, signed-in users or admins only. Flag admin endpoints with no visible server-side check.

## Step 9: Manual checklist

These depend on how the app is meant to work, so a scan can't settle them. For each one, look for evidence in the code and answer **looks handled**, **looks missing**, or **can't tell from the code**, with one line of evidence. Then tell me how to test it myself.

### Try to break in

- **MAN-001** Can I give myself premium or credits by editing my own data? How to test: Sign in as a normal user, then use the browser console or your database client with that user's session to update your own profile's plan, role or credits.
- **MAN-002** Can I read someone else's data by changing an ID in a request? How to test: Open the Network tab, find a request that loads your data by ID, and replay it with another user's ID (create a second test account for this).
- **MAN-003** Can I press the expensive button past its limit? How to test: Click the action that costs you money (AI call, email, export) many times quickly, and from two tabs at once. Check whether the limit holds on the server.
- **MAN-004** Logged-out test: no data or paid features reachable. How to test: Open a private window without signing in. Visit every page and API URL you know about, including deep links to user content.
- **MAN-005** Every endpoint classified as anonymous, user or admin; admin routes verified. How to test: Use the endpoint inventory in this report. For each route, write down who should reach it, then call admin routes as a normal user and as a logged-out visitor.

### Abuse & cost

- **MAN-006** Server-side rate limits on login, sign-up and expensive endpoints. How to test: Send 50 rapid requests to login, sign-up and any AI or email endpoint. Confirm you get blocked, and that per-user limits are stored somewhere users can't edit.
- **MAN-007** Budget caps and spend alerts on every paid service. How to test: Open the billing settings of each provider (cloud, AI API, email, database) and confirm a hard cap or alert is set.
- **MAN-009** Payments: button disabled after first click, idempotency keys, fulfilment only after webhook. How to test: Double-click the pay button, then check that only one charge was created. Confirm orders are fulfilled from the payment provider's webhook, not from the success page.

### Auth & data

- **MAN-008** Paywall and roles enforced on the server, not in the browser. How to test: With a free account, call the paid feature's API directly (copy it from the Network tab). It should refuse.
- **MAN-010** Email verification on; generic 'invalid credentials' login errors. How to test: Sign up with an address you don't control and see if you get in. Try logging in with a wrong password for a real and a fake email: the messages should be identical.
- **MAN-011** Proven auth provider or library; no home-made auth. How to test: Check where sign-in, sessions and password hashing come from. They should come from a maintained provider or library.
- **MAN-012** Server-side input validation, length limits, upload type and size limits. How to test: Send an oversized value, a wrong type, and a large or mislabeled file to each form's API. The server should reject them.
- **MAN-013** Storage buckets private; EXIF stripped from uploaded photos. How to test: Open an uploaded file's URL in a private window. Download an uploaded photo and check it has no GPS location in its metadata.
- **MAN-017** Automated test proving user B can't read or modify user A's data. How to test: Add a test that signs in as two users and asserts that B's reads and writes of A's records fail. Run it in CI.

### Operations

- **MAN-014** Separate dev and prod databases; backups enabled; agents have no prod access. How to test: Confirm your local .env points at a dev project, that backups are on for production, and that no AI agent or script holds production credentials.
- **MAN-015** Any key ever exposed (chat, screenshot, commit) has been rotated. How to test: List every key you've pasted into a chat, shown in a screenshot or committed. Rotate each one in the provider's dashboard.
- **MAN-016** Threat model written. How to test: Write one page answering: what are we building, what can go wrong, what are we doing about it, and did we do a good job?
- **MAN-018** Error tracking and logging with retention; no sensitive data in logs or errors. How to test: Trigger an error and check that it reaches your error tracker, that logs are kept for a set time, and that neither contains passwords, tokens or personal data.

### Legal & trust

Common legal and trust problems for apps that take sign-ups or payments. This isn't legal advice, and no scanner can check these for you. What applies depends on where you are and where your users are. If you handle health, money or children's data, talk to a lawyer. Last reviewed October 2026.

- **MAN-019** A privacy policy is published and matches what the app actually collects. How to test: List every field you store and every third-party SDK or script (analytics, payments, error tracking, AI APIs). Check that each one appears in your privacy policy with what it's for, and that the policy is linked from the footer and the sign-up form.
- **MAN-020** You collect only data the app actually uses. How to test: Go through your sign-up and profile forms and your database tables. For each field, name the feature that needs it. Remove anything you can't name a feature for, such as a birthday or phone number kept "for later".
- **MAN-021** Non-essential cookies and trackers load only after consent, and rejecting is as easy as accepting. How to test: Open the site in a private window and don't touch the banner. In DevTools, check Application → Cookies and the Network tab: no analytics or ad cookies or requests yet. Then check that rejecting takes one click, like accepting.
- **MAN-022** Consent checkboxes start unticked and are separate from accepting the terms. How to test: Look at every form that asks for consent (newsletter, marketing, data sharing). Each one has its own checkbox, unticked by default, and the form still submits without it.
- **MAN-023** Terms of service and a refund policy are published and match how you charge. How to test: Read your terms and refund policy next to your pricing page and checkout. Plan names, prices, renewal periods and the refund window should all match. If you sell to EU consumers, check how you handle their 14-day right to withdraw.
- **MAN-024** The full price is shown before payment, with no pre-ticked extras, and cancelling is no harder than signing up. How to test: Go through checkout as a new user. The total you see before paying is what you're charged. Then cancel a subscription and count the steps compared with signing up.
- **MAN-025** Every review and testimonial comes from a real customer, and insider reviews are labelled. How to test: For each review, testimonial and customer logo on the site, check you could show where it came from. Remove placeholder or AI-written ones. Label reviews from staff, friends or anyone you paid.
- **MAN-026** Every claim on the site can be backed up. How to test: List the factual claims on your landing page ("10,000 users", "#1", "bank-grade security", "saves 5 hours a week", "GDPR compliant"). For each one, write down the evidence you have today. Remove or reword any you can't back up.
- **MAN-027** Basic accessibility: alt text, readable contrast, keyboard navigation. How to test: Use the whole app with only the keyboard (Tab, Enter, Esc) and check you can always see where focus is. Run Lighthouse or axe DevTools on your main pages and fix the contrast and missing-alt-text warnings.
- **MAN-028** Your business name and a way to contact you are easy to find. How to test: Check that the footer or a contact page shows who runs the app (legal name), a postal or registered address and a working email address.
- **MAN-029** You know whether children use the app, and handle their data accordingly. How to test: Decide whether the app is aimed at, or likely to attract, children under 13 (US) or under 16 (EU; the age varies by country). If so, check how you get parental consent. If not, say so in your terms and don't market to children.
- **MAN-030** Marketing emails have a working unsubscribe link and your postal address. How to test: Send yourself each marketing email. Unsubscribe and confirm it works without logging in and that no more emails arrive. Check the footer shows a physical postal address.
- **MAN-031** Users can delete their account and data themselves. How to test: Create a test account, add some data, then delete the account from inside the app. Confirm the data is gone from your database and from services you sent it to (email list, analytics), not just hidden.

## Step 10: Write the report

Start with exactly one verdict line:

- **Blocked** if any high-confidence or medium-confidence critical finding exists;
- otherwise **Needs attention** if any high finding exists;
- otherwise **No blocking issues found**, followed by: "This doesn't mean the app is safe. Work through the checklist."

Then, in this order:

1. **Fix first:** the three most serious findings.
2. **Findings** grouped by severity (Critical, High, Medium, Low), each with: rule ID, title, file:line, confidence, why it matters, how to fix, and a one-paragraph fix instruction I could paste back to you.
3. **Worth checking:** low-confidence items.
4. **What I couldn't check**, and why (for example: no migration files, no network, no live URL, git history not scanned).
5. **Endpoint inventory** as a table.
6. **Manual checklist** with your assessment for each item.

## Step 11: Fix, with my approval

After the report, ask which finding to fix first. Fix one at a time and show me the diff. For any exposed key, remind me to rotate it in the provider's dashboard: removing it from the code doesn't un-leak it. After fixes, re-check the affected rules.
