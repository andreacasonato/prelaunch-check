// W-09 Scan a live site: why the website can't, and how to use the CLI instead.
import { CopyButton } from "../components/CopyButton";

const CMDS = [
  "npx prelaunch-check scan . --url https://your-app.com",
  "npx prelaunch-check scan --url https://your-app.com",
];

export function LiveSite() {
  return (
    <>
      <h1>Scan a live site</h1>
      <p>
        Browsers don't let one website read another website's security headers, so live-site checks run from
        your computer with the command-line tool. You need Node.js installed (see the{" "}
        <a href="https://github.com/andreacasonato/prelaunch-check#quick-start-about-5-minutes-no-experience-needed">
          quick start
        </a>
        ).
      </p>
      <h2>Commands</h2>
      <p>Check your code and your live site together:</p>
      <div className="cmd">
        <code tabIndex={0} aria-label="Command">
          {CMDS[0]}
        </code>
        <CopyButton text={CMDS[0]!} />
      </div>
      <p>Or only the live site:</p>
      <div className="cmd">
        <code tabIndex={0} aria-label="Command">
          {CMDS[1]}
        </code>
        <CopyButton text={CMDS[1]!} />
      </div>
      <p className="notice">
        <strong>Only scan sites you own or have permission to test.</strong> The tool asks you to confirm
        before it sends anything.
      </p>
      <h2>What it checks</h2>
      <ul>
        <li>That your site uses HTTPS, and that http:// redirects to https://</li>
        <li>
          Security headers: HSTS, Content-Security-Policy, clickjacking protection, nosniff, Referrer-Policy
        </li>
        <li>Headers that reveal server or framework versions</li>
        <li>Cookie settings: Secure, HttpOnly and SameSite</li>
        <li>Files that should never be public: .env, .git, .npmrc, .DS_Store, backup archives</li>
        <li>Public API documentation, admin pages and source maps</li>
        <li>Secret keys in the JavaScript your site serves</li>
        <li>CORS settings that let any website read your users' data</li>
        <li>security.txt, your HTTPS certificate's expiry, and mixed content</li>
      </ul>
      <h2>What it does not do</h2>
      <ul>
        <li>No attack payloads, no form submissions and no logins.</li>
        <li>At most 40 ordinary page requests (GET), identified as prelaunch-check.</li>
      </ul>
      <p>
        Then <a href="#/open">open the report it creates</a> here to read it comfortably.
      </p>
    </>
  );
}
