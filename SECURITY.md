# Security policy

Prelaunch Check is a security tool, so bugs in it can hurt the people who trust it. Thank you for reporting them responsibly.

## Reporting a vulnerability

**Please don't open a public issue for security problems.**

Use GitHub's private vulnerability reporting: go to the repository's **Security** tab and choose **Report a vulnerability**. Include:

- what you found and where (file, function or command);
- steps to reproduce, ideally with a minimal fixture;
- the impact you expect (for example "a crafted repo makes the HTML report run script").

You should get an acknowledgement within 7 days. Once a fix is released, we'll credit you in the release notes unless you'd rather stay anonymous.

## What counts as a vulnerability in this tool

- A raw secret appearing anywhere in output (terminal, JSON, Markdown, SARIF, HTML, web UI, `localStorage`). Redaction is meant to be unconditional.
- Absolute paths, usernames or machine hostnames in a report.
- Script execution or HTML injection from a crafted repo or site (for example in the HTML report or the web app).
- A crafted file that hangs or crashes the scanner (ReDoS, unbounded memory).
- The URL scanner sending anything other than its fixed GET/HEAD plan, sending more than 40 requests, or skipping the ownership confirmation.
- The web app making network requests during a folder scan while the online toggle is off.
- Writing files outside the `--out` directory.

## What is not a vulnerability

- A false positive or false negative in a rule. Please open a normal issue with the `false-positive` label (with no real code or secrets in it).
- Findings the tool reports about its own GitHub Pages site's HTTP headers. GitHub Pages doesn't let us set them; see the About page.

## Supported versions

Only the latest published minor version receives fixes.
