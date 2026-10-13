# Prelaunch Check

**Find the security holes in your app before you launch.** Free, open source, and your code never leaves your computer.

Prelaunch Check reads your project folder and tells you, in plain English, what to fix before real users arrive. Examples: a secret key that would be visible to every visitor, a database that strangers can read, or a dependency with a known vulnerability. Each problem comes with where it is, why it matters, and how to fix it. There's also a ready-made instruction you can paste into your AI coding tool.

- **No AI, no account, no upload.** Every check is a fixed rule that runs on your computer.
- **Made for apps built quickly**, often with AI tools: Next.js, Vite, React, Supabase, Firebase, Stripe and more.
- **Honest.** It never tells you your app is "safe". It tells you what it found, what it couldn't check, and gives you a short checklist for the things only a human can test.

> **Do I need Supabase, Firebase or Stripe to use this?** No. Prelaunch Check doesn't use any of them. It *recognises* them in your project and runs extra checks if you use them. If you don't, those checks are skipped.

---

## Quick start (about 5 minutes, no experience needed)

### 1. Install Node.js (one time only)

Prelaunch Check runs on Node.js, a free program many apps use.

1. Go to **https://nodejs.org** and download the version marked **LTS**.
2. Open the file you downloaded and click through the installer (the default options are fine).

Already have it? Skip ahead. You need version 22 or newer. Step 2 shows you how to check.

### 2. Open a terminal in your project folder

A terminal is a window where you type commands.

- **Mac:** open the **Terminal** app (press `Cmd + Space`, type *Terminal*, press Enter). Type `cd ` (with a space after it), drag your project folder into the window, and press Enter.
- **Windows:** open your project folder in File Explorer, click the address bar, type `powershell`, and press Enter.
- **VS Code, Cursor or similar:** use the menu **Terminal → New Terminal**. It opens in your project already.

To check Node.js is installed, type this and press Enter:

```sh
node --version
```

You should see something like `v24.13.0`. If you see "command not found", restart your computer after installing Node.js and try again.

### 3. Run the scan

Type this and press Enter:

```sh
npx prelaunch-check scan .
```

The `.` means "this folder". The first time, it may ask `Ok to proceed? (y)`: type `y` and press Enter. This downloads Prelaunch Check temporarily; nothing is installed permanently.

> **If it says the package can't be found**, the first public release isn't out yet. Use [running from the source code](#running-from-the-source-code) for now.

### 4. Read the result

You'll see something like this:

```
 BLOCKED   2 critical · 3 high · 0 medium · 2 low · 1 worth checking   Score 18/100

 CRITICAL  SEC-003      Stripe live secret key in a client-exposed environment variable   .env.local:3
 HIGH      DB-003       "credits" on profiles can be changed by its owner                 supabase/migrations/…_profiles.sql:4
 …
 Report written: ./prelaunch-check-report/prelaunch-check-report.json
```

The first word is the **verdict**:

| Verdict | What it means |
|---|---|
| **Blocked** | At least one *critical* problem: a stranger could probably take data or money right now. Fix these before launching. |
| **Needs attention** | No critical problems, but at least one *high* one. Fix before launch if you can. |
| **No blocking issues found** | Nothing critical or high was found. This does **not** mean your app is safe; work through the checklist in the report too. |

Each line after that is one problem: how serious it is, a rule ID, a short title, and the file and line where it is.

**To understand a problem and how to fix it**, copy its rule ID into:

```sh
npx prelaunch-check explain SEC-003
```

**For the full report** (every problem, code excerpts with secrets hidden, fix steps, and a copy-paste prompt for your AI coding tool), add `--format json,md`:

```sh
npx prelaunch-check scan . --format json,md
```

Then open `prelaunch-check-report/prelaunch-check-report.md` in any editor.

> Add `prelaunch-check-report/` to your `.gitignore` so reports aren't committed. `npx prelaunch-check init` can do this for you.

---

## Check your live website too

Once your app is online, Prelaunch Check can look at it from the outside, the way a stranger would. Only do this for **sites you own or have permission to test**.

```sh
npx prelaunch-check scan . --url https://your-app.com
```

Leave out the `.` to check only the website. It asks you to confirm that you own the site before sending anything. In automated pipelines, add `--yes-i-am-authorized` to confirm in advance.

It checks HTTPS and the redirect from http://, security headers (HSTS, Content-Security-Policy, clickjacking and others), cookie settings, files that should never be public (such as `.env`, `.git` or backup zips), public API docs and source maps, secret keys in the JavaScript your site serves, risky CORS settings, `security.txt`, and your HTTPS certificate.

**What it does not do:** it sends at most 40 ordinary page requests (`GET`), the same kind a browser sends. It never submits forms, never tries to log in, and never sends attack payloads. Its requests identify themselves as `prelaunch-check`.

---

## What it checks

| Area | Examples |
|---|---|
| **Secret keys** | Secret keys in your code or built files; secrets in variables that ship to the browser (`NEXT_PUBLIC_…`, `VITE_…`); `.env` files that aren't git-ignored; private keys; database passwords in code. Keys designed to be public (Stripe `pk_…`, Supabase publishable/anon, Firebase web keys) are listed as fine. |
| **Database access rules** | Supabase tables without Row Level Security; policies that let anyone write; columns like `credits`, `plan` or `is_admin` that users can change on their own row; Firebase rules open to everyone or to any signed-in user. |
| **Dependencies** | Known vulnerabilities (via the OSV database); missing lockfile; packages that don't exist on npm (a sign of an AI-invented name); very new packages; `"*"` versions. |
| **Code patterns** | SQL built from strings, `eval`, unsafe HTML, wide-open CORS with cookies, secrets printed to logs, secret-key SDKs in browser code, and a list of your API endpoints showing which ones check login. |
| **Project config** | Source maps in production builds; missing `.gitignore` entries; risky GitHub Actions workflows. |
| **Live site** (with `--url`) | HTTPS and redirects, security headers, cookie flags, exposed files and API docs, public source maps, secrets in served JavaScript, CORS, `security.txt`, certificate expiry, mixed content. |
| **Manual checklist** | 18 things no scanner can verify, such as "can I give myself premium by editing my own data?". Printed in every report. |

Run `npx prelaunch-check rules` to see every rule.

**Coming next:** SARIF and HTML reports and baselines (0.3), and a website where you can pick a folder and scan it in your browser.

## Privacy: what leaves your computer

- **Your code never does.** Files are read on your computer, and reports are written to your computer.
- **Secrets are always hidden** in every output, e.g. `sk_l…9xQz`. There is no option to show them.
- **Reports never contain full paths** to your files, your username or machine name.
- **For a folder scan, the only network requests** are package names and version numbers, sent to the public [OSV](https://osv.dev) vulnerability database and the npm registry to check your dependencies. Add `--offline` to turn this off completely.
- **For a live-site scan** (`--url`), it requests pages from the site you name, and nothing else.
- No telemetry, no analytics, no account.

## Options

```
npx prelaunch-check scan [folder]        Scan a project folder (default: the current folder)
  --url <https://…>                      Also check your live site (asks you to confirm you own it)
  --yes-i-am-authorized                  Confirm site ownership in advance (for CI)
  --offline                              No online dependency checks
  --format json,md                       Which reports to write (json is always written)
  --out <folder>                         Where to write reports (default: ./prelaunch-check-report)
  --fail-on critical|high|medium|low|none   When to exit with an error (default: high)
  --config <file>                        Use a specific config file
  --use-gitleaks / --no-gitleaks         Also scan git history if gitleaks is installed (default: auto)
  --quiet / --verbose                    Less or more output
  --no-color                             Plain text output

npx prelaunch-check init                 Create a config file
npx prelaunch-check rules [--json]       List every rule
npx prelaunch-check explain <RULE-ID>    Explain one rule and how to fix it
```

**Exit codes** (useful in automated pipelines): `0` = nothing at or above `--fail-on`; `1` = problems found; `2` = wrong option or config; `3` = the scan couldn't run.

### Config file

`npx prelaunch-check init` creates `prelaunch-check.config.json` with comments explaining each setting. You can skip folders, turn rules off, change severities, and record accepted risks. Each accepted risk must include a reason, so the decision stays visible to reviewers.

```json
{
  "ignorePaths": ["scripts/**"],
  "rules": { "DEP-005": "off" },
  "suppressions": [
    { "ruleId": "DB-003", "path": "supabase/migrations/*.sql", "reason": "credits is only written by a database trigger" }
  ]
}
```

### Git history (optional)

Secrets deleted from your code can still be in old commits. If [gitleaks](https://github.com/gitleaks/gitleaks) is installed, Prelaunch Check runs it automatically and reports what it finds (with secrets hidden). Without gitleaks, the report says history wasn't checked.

### Use it in GitHub Actions

Block pull requests that introduce critical or high problems:

```yaml
# .github/workflows/prelaunch-check.yml
name: Prelaunch Check
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with: { node-version: 24 }
      - run: npx prelaunch-check@0.2.0 scan . --fail-on high
```

Actions are pinned to exact commit IDs, which is what Prelaunch Check's own CFG-003 rule recommends.

---

## Running from the source code

Use this before the first npm release, or if you want to try the latest changes.

1. Install [Node.js](https://nodejs.org) (LTS) and [Git](https://git-scm.com/downloads).
2. In a terminal, run these one at a time:

   ```sh
   git clone https://github.com/andreacasonato/prelaunch-check.git
   cd prelaunch-check
   npm ci
   npm run build
   ```

3. Scan any project by giving its folder path:

   ```sh
   node packages/cli/dist/index.js scan /path/to/your/project
   ```

   Tip: type `node packages/cli/dist/index.js scan ` (with a space), then drag your project folder into the terminal window to fill in its path.

## Troubleshooting

| Problem | What to do |
|---|---|
| `command not found: npx` or `node` | Install Node.js from nodejs.org, then close and reopen the terminal. |
| `Unsupported engine` or a syntax error | Your Node.js is too old. Install the current LTS version. |
| "Dependency check skipped: couldn't reach api.osv.dev" | You're offline or behind a firewall. Everything else still ran. Add `--offline` to hide the message. |
| "Supabase detected but no migration files found" | Your tables were created in the Supabase dashboard, so their access rules aren't in your project files. Export them with `supabase db pull` and scan again. |
| A finding is wrong | Record it in the config file with a reason, and please [open an issue](https://github.com/andreacasonato/prelaunch-check/issues) labelled `false-positive` with a made-up example (never real code or keys). |

## Contributing, security and license

- **Contributing:** each rule is one file plus test fixtures. See [CONTRIBUTING.md](CONTRIBUTING.md).
- **Found a security problem in Prelaunch Check itself?** Please report it privately: see [SECURITY.md](SECURITY.md).
- **Dependencies:** zero runtime dependencies; see [DEPENDENCIES.md](DEPENDENCIES.md).
- **License:** MIT. Secret-detection patterns for many providers are adapted from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT); see [NOTICE](NOTICE).
