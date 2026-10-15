// A copy-paste prompt that lets any AI coding agent run the same audit by reading the project.
// Generated from the rule metadata and data tables, so it stays in sync with the scanner.
import type { Category, RuleMeta } from "../types.js";
import { DEFAULT_RULES } from "../rules/index.js";
import { SEC_006_META } from "../rules/secrets/SEC-006.js";
import { CHECKLIST } from "../checklist/items.js";
import { PUBLIC_ENV_PREFIXES } from "../detect/public-env-prefixes.js";
import { SENSITIVE_COLUMNS } from "../rules/data/sensitive-columns.js";
import { PUBLISHABLE_PATTERNS, SECRET_PATTERNS } from "../rules/secrets/patterns.js";
import { PROBES, CORS_TEST_ORIGIN } from "../rules/web/probes.js";
import { REPO_URL } from "../version.js";
import { groupChecklist } from "../checklist/group.js";

const SECTION: Record<Category, { title: string; intro: string }> = {
  secrets: {
    title: "Secret keys",
    intro: [
      "Search every text file (including build output in dist/, build/, out/ and .next/static/, but not node_modules or lockfiles) for secret keys.",
      "Secret keys to look for (each prefix as it appears in real keys):",
      ...secretKeyLines(),
      "- Private keys: `-----BEGIN … PRIVATE KEY-----` blocks with a real body (not placeholders).",
      "- Database URLs with an inline password: `postgres://user:password@host`, `mysql://…`, `mongodb+srv://…`.",
      'Legacy Supabase keys are JWTs (they start with `eyJ`): decode the middle part (base64url) and treat it as secret only if it contains `"role":"service_role"`.',
      `Keys that are designed to be public, and must NOT be reported as problems: ${PUBLISHABLE_PATTERNS.map((p) => p.label).join(", ")}, and legacy Supabase \`anon\` JWTs.`,
      `Variables with these prefixes are copied into browser code: ${PUBLIC_ENV_PREFIXES.map((p) => `\`${p.prefix}\` (${p.framework === "next" ? "Next.js" : "Vite"})`).join(", ")}.`,
      "Ignore obvious placeholders (`xxxx`, `your-key-here`, `${VAR}`, `<password>`) and local development database URLs (localhost, 127.0.0.1, docker service names).",
    ].join("\n"),
  },
  data: {
    title: "Database access rules (Supabase and Firebase)",
    intro: [
      "Read every `*.sql` file (especially `supabase/migrations/`), plus `firestore.rules`, `storage.rules` and `database.rules.json`. Apply migrations in file-name order: later files can add columns, enable RLS or drop policies.",
      `"Money or power" column names for DB-003 (\`*\` is a wildcard): ${SENSITIVE_COLUMNS.map((c) => `\`${c}\``).join(", ")}.`,
      "If the project uses Supabase but has no migration files, say clearly that the database rules couldn't be checked: tables created in the dashboard are invisible in the code.",
    ].join("\n"),
  },
  deps: {
    title: "Dependencies",
    intro: [
      "Read package.json files and the lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock).",
      "For DEP-001, DEP-003 and DEP-004 you need the network. Only do them if I allow it. If you can, run `npm audit --omit=dev` (or the equivalent for my package manager) and `npm view <name> time.created` for unfamiliar packages. Otherwise list them as not checked.",
    ].join("\n"),
  },
  code: {
    title: "Code patterns",
    intro:
      "Read JavaScript and TypeScript files (also .vue and .svelte). Ignore matches inside comments and plain strings. A file is client code if it's under a Vite `src/` folder, starts with `'use client'` in Next.js, or is in build output.",
  },
  config: {
    title: "Project configuration",
    intro: "Read `.gitignore`, `next.config.*`, `vite.config.*` and every file in `.github/workflows/`.",
  },
  web: {
    title: "Live site (only if I confirm I own it)",
    intro: [
      "Skip this whole section unless I've told you the URL of a live site that I own or am allowed to test. Then use only plain GET requests (for example `curl -sS -D - -o /dev/null <url>` for headers), at most 40 in total. No forms, no logins, no attack payloads.",
      `Paths to request once each: ${PROBES.map((p) => `\`${p.path}\``).join(", ")}. A path only counts as exposed if it returns 200 with real content (for example a \`VAR=value\` line for .env, \`ref: refs/\` for .git/HEAD) and isn't just the site's normal "not found" page. First request a random path like \`/does-not-exist-12345\` to see what "not found" looks like; many single-page apps return 200 for every path.`,
      `For the CORS check, send one GET to the home page with the header \`Origin: ${CORS_TEST_ORIGIN}\`.`,
    ].join("\n"),
  },
};

/** One line per key type, with each prefix shown in the casing it has inside the ported regex. */
function secretKeyLines(): string[] {
  const byLabel = new Map<string, Set<string>>();
  for (const p of SECRET_PATTERNS) {
    const set = byLabel.get(p.label) ?? new Set<string>();
    const source = p.regex.source.replace(/\\/g, "");
    for (const k of p.keywords) {
      const at = source.toLowerCase().indexOf(k);
      set.add(at === -1 ? k : source.slice(at, at + k.length));
    }
    byLabel.set(p.label, set);
  }
  return [...byLabel].map(
    ([label, prefixes]) => `- ${label}: ${[...prefixes].map((x) => `\`${x}\``).join(", ")}`,
  );
}

const ORDER: Category[] = ["secrets", "data", "deps", "code", "config", "web"];

function ruleBlock(m: RuleMeta): string {
  const lines = [
    `- **${m.id} · ${m.title}** (${m.severity}, ${m.confidence} confidence)`,
    `  - Look for: ${m.summary}`,
  ];
  if (m.falsePositiveNotes) lines.push(`  - Known false positives and limits: ${m.falsePositiveNotes}`);
  lines.push(`  - Fix: ${m.fix.map((s) => s.replace(/\n+/g, " ").replace(/```[a-z]*/g, "")).join(" ")}`);
  return lines.join("\n");
}

export function auditPrompt(): string {
  const metas = [...DEFAULT_RULES.map((r) => r.meta), SEC_006_META].filter(
    (m) => !m.id.includes("-INFO-") || m.id === "SEC-INFO-001",
  );
  const out: string[] = [];
  out.push("# Prelaunch security audit prompt");
  out.push("");
  out.push(
    `This is a ready-made prompt for an AI coding agent (Claude Code, Cursor, Windsurf, Copilot Chat and similar). It walks the agent through the same checks that [Prelaunch Check](${REPO_URL}) runs, without installing anything.`,
  );
  out.push("");
  out.push("**How to use it**");
  out.push("");
  out.push("1. Open your project in your coding tool, so the agent can read your files.");
  out.push("2. Copy everything below the line and paste it as one message.");
  out.push("3. Read the report it writes. Approve fixes one at a time.");
  out.push("");
  out.push(
    "**Good to know:** an AI agent reads your code with judgement, so it can miss things or report things that aren't problems. For a repeatable, rule-based scan that never sends your code anywhere, also run `npx prelaunch-check scan .` (see the README). Never paste real secret keys into a chat. If one has already been shared anywhere, rotate it.",
  );
  out.push("");
  out.push("---");
  out.push("");
  out.push(
    "You are auditing this project for security problems before it launches. Work through the steps below in order.",
  );
  out.push("");
  out.push("## Ground rules");
  out.push("");
  out.push(
    "- **Read only.** Don't change, create or delete files until I approve a fix. Don't install packages, run the app or run scripts from this project.",
  );
  out.push("- **No network** unless a step says so and I've allowed it.");
  out.push(
    "- **Never show a secret in full.** Show only the first 4 and last 4 characters, like `sk_l…9xQz`.",
  );
  out.push(
    "- **Be specific.** Every finding needs the file and line (or URL), what you saw, why it matters in one or two plain sentences, and how to fix it.",
  );
  out.push(
    '- **Be honest about confidence.** Use high, medium or low. Put low-confidence items under "Worth checking".',
  );
  out.push(
    '- **Never call the app "safe" or "secure".** Report what you found and what you couldn\'t check.',
  );
  out.push("");
  out.push("## Step 1: Detect the stack");
  out.push("");
  out.push(
    "From package.json dependencies and marker files, work out which of these the project uses: Next.js (`next`, next.config.*), Vite (`vite`, vite.config.*), React, Express, Supabase (`@supabase/supabase-js`, `supabase/` folder), Firebase (`firebase`, firebase.json, *.rules), Stripe (`stripe`, `@stripe/stripe-js`), and the package manager (lockfile). Skip checks for services the project doesn't use.",
  );
  let step = 2;
  for (const cat of ORDER) {
    const rules = metas.filter((m) => m.category === cat);
    if (!rules.length) continue;
    out.push("");
    out.push(`## Step ${step++}: ${SECTION[cat].title}`);
    out.push("");
    out.push(SECTION[cat].intro);
    out.push("");
    out.push(rules.map(ruleBlock).join("\n"));
  }
  out.push("");
  out.push(`## Step ${step++}: Endpoint inventory`);
  out.push("");
  out.push(
    "List every API endpoint (Next.js `app/**/route.*` exports and `pages/api/**`, Express `app.get/post/…` routes, Supabase `functions/*/index.ts`). For each, say whether it checks the user's session on the server, and whether it should be reachable by anonymous visitors, signed-in users or admins only. Flag admin endpoints with no visible server-side check.",
  );
  out.push("");
  out.push(`## Step ${step++}: Manual checklist`);
  out.push("");
  out.push(
    "These depend on how the app is meant to work, so a scan can't settle them. For each one, look for evidence in the code and answer **looks handled**, **looks missing**, or **can't tell from the code**, with one line of evidence. Then tell me how to test it myself.",
  );
  out.push("");
  for (const section of groupChecklist(CHECKLIST)) {
    out.push(`### ${section.title}`);
    out.push("");
    if (section.intro) {
      out.push(section.intro);
      out.push("");
    }
    for (const c of section.items)
      out.push(`- **${c.id}** ${c.title}${/[?.!]$/.test(c.title) ? "" : "."} How to test: ${c.howToTest}`);
    out.push("");
  }
  out.push(`## Step ${step++}: Write the report`);
  out.push("");
  out.push("Start with exactly one verdict line:");
  out.push("");
  out.push("- **Blocked** if any high-confidence or medium-confidence critical finding exists;");
  out.push("- otherwise **Needs attention** if any high finding exists;");
  out.push(
    '- otherwise **No blocking issues found**, followed by: "This doesn\'t mean the app is safe. Work through the checklist."',
  );
  out.push("");
  out.push("Then, in this order:");
  out.push("");
  out.push("1. **Fix first:** the three most serious findings.");
  out.push(
    "2. **Findings** grouped by severity (Critical, High, Medium, Low), each with: rule ID, title, file:line, confidence, why it matters, how to fix, and a one-paragraph fix instruction I could paste back to you.",
  );
  out.push("3. **Worth checking:** low-confidence items.");
  out.push(
    "4. **What I couldn't check**, and why (for example: no migration files, no network, no live URL, git history not scanned).",
  );
  out.push("5. **Endpoint inventory** as a table.");
  out.push("6. **Manual checklist** with your assessment for each item.");
  out.push("");
  out.push(`## Step ${step}: Fix, with my approval`);
  out.push("");
  out.push(
    "After the report, ask which finding to fix first. Fix one at a time and show me the diff. For any exposed key, remind me to rotate it in the provider's dashboard: removing it from the code doesn't un-leak it. After fixes, re-check the affected rules.",
  );
  out.push("");
  return out.join("\n");
}
