// W-01 Home: what it is, who it's for, why it matters, and four clear doors.
import { VERDICT_LABEL } from "@prelaunch-check/core";
import { getMostRecentScan } from "../lib/storage";

function ago(iso: string): string {
  const days = Math.floor((Date.now() - Date.parse(iso)) / 86_400_000);
  if (Number.isNaN(days) || days < 1) return "today";
  return days === 1 ? "yesterday" : `${days} days ago`;
}

export function Home() {
  const last = getMostRecentScan();
  return (
    <>
      <section className="home-hero">
        <h1>Find the security holes in your app before you launch.</h1>
        <p className="lead">Free, open source, and your code never leaves your computer.</p>
        <div className="btn-row">
          <a className="btn btn-primary" href="#/scan">
            Scan a project folder
          </a>
        </div>
        <p className="small muted" style={{ marginTop: "var(--s3)" }}>
          No AI. No account. No upload. <a href="#/docs/privacy">How your privacy is protected</a>
        </p>
      </section>

      {last && (
        <div className="notice" role="status">
          Last scan: <strong>{last.project}</strong>, {ago(last.generatedAt)}: {VERDICT_LABEL[last.verdict]}
          {last.counts.critical
            ? ` (${last.counts.critical} critical)`
            : last.counts.high
              ? ` (${last.counts.high} high)`
              : ""}
          . <a href="#/scan">Scan again?</a>
        </div>
      )}

      <nav className="doors" aria-label="Other ways to use Prelaunch Check">
        <a className="door" href="#/open">
          <strong>Open a report</strong>
          <span>View a report file someone sent you, or one made by the command-line tool.</span>
        </a>
        <a className="door" href="#/checklist">
          <strong>Pre-launch checklist</strong>
          <span>18 things no scanner can check for you, with how to test each one.</span>
        </a>
        <a className="door" href="#/live">
          <strong>Scan a live site</strong>
          <span>
            Check headers, cookies and exposed files on your deployed app with the command-line tool.
          </span>
        </a>
      </nav>

      <section className="section" aria-labelledby="how-h">
        <h2 id="how-h">How it works</h2>
        <ol className="steps">
          <li>
            <strong>Pick your project folder.</strong> Your browser reads the files on your computer; nothing
            is uploaded.
          </li>
          <li>
            <strong>Get a verdict</strong>: Blocked, Needs attention, or No blocking issues found, with every
            problem explained in plain language.
          </li>
          <li>
            <strong>Fix what matters first.</strong> Each finding shows where it is, why it matters and how to
            fix it, plus a prompt you can paste into your AI coding tool.
          </li>
        </ol>
        <p className="muted">
          It looks for secret keys in the wrong place, open Supabase and Firebase databases, columns users can
          edit to give themselves credits, risky dependencies, unsafe code patterns and risky project
          settings. You don't need Supabase or Firebase to use it; those checks only run if your project uses
          them.
        </p>
      </section>
    </>
  );
}
