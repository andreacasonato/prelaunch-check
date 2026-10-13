// W-10 Docs: rules (generated from rule metadata), scoring, privacy, about.
import { WEIGHTS } from "@prelaunch-check/core";
import { SeverityBadge } from "../components/Icons";
import { Markdown } from "../components/Markdown";
import { ALL_RULE_META, REPO_URL, ruleMeta, safeHref } from "../lib/rules";

function DocsNav() {
  return (
    <nav aria-label="Docs">
      <ul className="stack-chips">
        <li>
          <a className="chip" href="#/docs/rules">
            All rules
          </a>
        </li>
        <li>
          <a className="chip" href="#/docs/scoring">
            How scoring works
          </a>
        </li>
        <li>
          <a className="chip" href="#/docs/privacy">
            Privacy
          </a>
        </li>
        <li>
          <a className="chip" href="#/docs/about">
            About &amp; limitations
          </a>
        </li>
      </ul>
    </nav>
  );
}

function Rules() {
  return (
    <>
      <h1>All rules</h1>
      <DocsNav />
      <p>Every check is a fixed rule. Same project, same result: no AI is involved.</p>
      <ul className="rule-list">
        {ALL_RULE_META.map((m) => (
          <li key={m.id}>
            <SeverityBadge severity={m.severity} confidence={m.confidence} />{" "}
            <a href={`#/docs/rules/${m.id}`}>{m.id}</a>: {m.title}
            <br />
            <span className="small muted">{m.summary}</span>
          </li>
        ))}
      </ul>
    </>
  );
}

function Rule({ id }: { id: string }) {
  const m = ruleMeta(id);
  if (!m)
    return (
      <p className="empty">
        Unknown rule {id}. <a href="#/docs/rules">See all rules</a>.
      </p>
    );
  return (
    <>
      <h1>
        {m.id}: {m.title}
      </h1>
      <DocsNav />
      <p>
        <SeverityBadge severity={m.severity} confidence={m.confidence} />{" "}
        <span className="tag">{m.owasp}:2025</span>
        {m.requires.includes("site") && <span className="tag">needs the CLI with --url</span>}
      </p>
      <h2>What it detects</h2>
      <p>{m.summary}</p>
      <h2>Why it matters</h2>
      <p>{m.why}</p>
      <h2>How to fix</h2>
      <ol className="steps">
        {m.fix.map((s, i) => (
          <li key={i}>
            <Markdown text={s} />
          </li>
        ))}
      </ol>
      {m.falsePositiveNotes && (
        <>
          <h2>Known false positives</h2>
          <p>{m.falsePositiveNotes}</p>
        </>
      )}
      <h2>Sources</h2>
      <ul>
        {m.sources.map((s, i) => {
          const href = safeHref(s.url);
          return (
            <li key={i}>
              {href ? (
                <a href={href} target="_blank" rel="noopener noreferrer">
                  {s.title}
                </a>
              ) : (
                s.title
              )}
              {s.book ? ` (book: ${s.book})` : ""}
            </li>
          );
        })}
      </ul>
    </>
  );
}

function Scoring() {
  return (
    <>
      <h1>How scoring works</h1>
      <DocsNav />
      <p>
        <strong>The verdict comes first and never depends on the score.</strong> If any open critical finding
        exists, the verdict is <em>Blocked</em>. Otherwise, if any open high finding exists, it's{" "}
        <em>Needs attention</em>. Otherwise it's <em>No blocking issues found</em>, which doesn't mean your
        app is safe.
      </p>
      <h2>The score (0–100)</h2>
      <p>Start at 100 and subtract a penalty for each open finding:</p>
      <ul>
        <li>Critical: {WEIGHTS.critical} points</li>
        <li>High: {WEIGHTS.high} points</li>
        <li>Medium: {WEIGHTS.medium} points</li>
        <li>Low: {WEIGHTS.low} point</li>
        <li>Info: {WEIGHTS.info} points</li>
      </ul>
      <p>
        Repeats of the same rule count at most twice, so one noisy rule can't sink the score on its own. The
        score never goes below 0.
      </p>
      <p>
        <strong>What doesn't count:</strong> "Worth checking" findings (low confidence), and findings you've
        marked as accepted risk or false positive. They're still listed.
      </p>
      <p className="muted">The weights are a published design decision, not an industry standard.</p>
    </>
  );
}

function Privacy() {
  return (
    <>
      <h1>Privacy</h1>
      <DocsNav />
      <ul>
        <li>
          <strong>Your code never leaves your computer.</strong> When you pick a folder, this page reads the
          files inside your browser. Nothing is uploaded.
        </li>
        <li>
          <strong>No account, no cookies, no analytics, no third-party scripts or fonts.</strong> The site's
          Content-Security-Policy only allows this site itself, plus api.osv.dev when you turn on online
          checks.
        </li>
        <li>
          <strong>Optional online check:</strong> if you turn on "Check dependencies online", only package
          names and version numbers are sent to the public OSV database (api.osv.dev). It's off by default.
        </li>
        <li>
          <strong>Secrets are always hidden</strong> in results and exports (e.g. <code>sk_l…9xQz</code>).
          There is no option to show them.
        </li>
        <li>
          <strong>What this browser remembers</strong> (localStorage): your theme, the online-check setting,
          checklist ticks, the decisions you record, and a summary of your last scan (counts and finding IDs).
          No file contents, code snippets or file paths are stored.
        </li>
        <li>
          Full reports are kept in memory only. Reload the page and they're gone; export them if you want to
          keep them.
        </li>
      </ul>
    </>
  );
}

function About() {
  return (
    <>
      <h1>About &amp; limitations</h1>
      <DocsNav />
      <p>
        Prelaunch Check is free, open-source software (MIT license). Every check is a deterministic rule: no
        AI is involved. <a href={REPO_URL}>Source code on GitHub</a>.
      </p>
      <h2>Limitations</h2>
      <ul>
        <li>
          No scanner can certify that an app is safe. The most serious bugs often depend on your app's logic:
          that's what the pre-launch checklist is for.
        </li>
        <li>
          Database rules created in the Supabase or Firebase dashboard (instead of in files) are invisible to
          a folder scan.
        </li>
        <li>Live-site checks, git-history checks and npm registry checks need the command-line tool.</li>
        <li>
          This site is hosted on GitHub Pages, which doesn't let site owners set custom HTTP headers (as far
          as community reports say; we couldn't find an official statement). So if you scan this site with{" "}
          <code>--url</code>, it will report missing HSTS, clickjacking and nosniff headers. We'd rather tell
          you than hide it.
        </li>
      </ul>
      <p className="small muted">
        Icons: Lucide (ISC license). Secret-detection patterns adapted from gitleaks (MIT).
      </p>
    </>
  );
}

export function Docs({ route }: { route: string }) {
  const parts = route.split("/").filter(Boolean); // ["docs", ...]
  if (parts[1] === "rules" && parts[2]) return <Rule id={decodeURIComponent(parts[2])} />;
  if (parts[1] === "scoring") return <Scoring />;
  if (parts[1] === "privacy") return <Privacy />;
  if (parts[1] === "about") return <About />;
  return <Rules />;
}
