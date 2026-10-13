// Self-contained HTML report (docs/02-TRD.md §9, §12). No JavaScript, no external requests,
// a strict meta CSP that pins the one inline <style> by hash, and every interpolated string escaped.
import type { Finding, Report, RuleMeta, Severity } from "../types.js";
import { DEFAULT_RULES } from "../rules/index.js";
import { SEC_006_META } from "../rules/secrets/SEC-006.js";
import { VERDICT_LABEL, verdictSentence } from "../copy.js";
import { locationText } from "./markdown.js";
import { REPO_URL } from "../version.js";

const ALL_META = new Map<string, RuleMeta>([
  ...DEFAULT_RULES.map((r) => [r.meta.id, r.meta] as const),
  [SEC_006_META.id, SEC_006_META],
]);

/** Escapes text for HTML element content and quoted attribute values. */
export function esc(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeUrl(url: string | undefined): string | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
  } catch {
    return null;
  }
}

/** Rule texts we ship use `code` spans and ``` fences; render them after escaping. */
function mdLite(text: string): string {
  return text
    .split(/```[a-z]*\n?/)
    .map((part, i) =>
      i % 2 === 1
        ? `<pre class="code">${esc(part.replace(/\n$/, ""))}</pre>`
        : esc(part)
            .replace(/`([^`]+)`/g, "<code>$1</code>")
            .replace(/\n{2,}/g, "<br>"),
    )
    .join("");
}

// Same tokens as the web app (Design Brief §4.1), light and dark.
const CSS = `
:root{color-scheme:light dark;--bg:#fafaf7;--surface:#fff;--text:#1c1c1a;--muted:#5c5c57;--accent:#1f5f4a;--critical:#a3171e;--high:#b04a00;--medium:#7a5a00;--low:#3d5a80;--info:#5c5c57;--border:color-mix(in srgb,var(--text) 14%,var(--surface))}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--surface:#1e1e1c;--text:#edede8;--muted:#a3a39c;--accent:#6fc2a2;--critical:#ff8a8a;--high:#ffb066;--medium:#e3c35a;--low:#9db8de;--info:#a3a39c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1040px;margin:0 auto;padding:24px 16px 48px}h1,h2,h3{line-height:1.2;margin:0 0 12px}h1{font-size:28px}h2{font-size:20px;margin-top:32px}h3{font-size:16px;margin-top:16px}
a{color:var(--accent)}code,pre,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px}.muted{color:var(--muted)}.small{font-size:14px}
.verdict{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:24px;border:1px solid var(--border);border-radius:4px;background:var(--surface)}
.verdict.blocked{border-color:var(--critical);background:color-mix(in srgb,var(--critical) 10%,var(--surface))}.verdict.blocked h2{color:var(--critical)}
.verdict.needs_attention{border-color:var(--high);background:color-mix(in srgb,var(--high) 10%,var(--surface))}.verdict.needs_attention h2{color:var(--high)}
.verdict h2{margin:0 0 4px;font-size:28px}.score{font-size:28px;font-weight:700;text-align:right}
.sev{display:inline-flex;gap:4px;align-items:center;font-weight:600;font-size:14px;padding:2px 8px;border-radius:4px;white-space:nowrap}
.sev svg{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:2}
.critical{color:var(--critical);background:color-mix(in srgb,var(--critical) 10%,var(--surface))}.high{color:var(--high);background:color-mix(in srgb,var(--high) 10%,var(--surface))}
.medium{color:var(--medium);background:color-mix(in srgb,var(--medium) 10%,var(--surface))}.low{color:var(--low);background:color-mix(in srgb,var(--low) 10%,var(--surface))}
.info,.worth{color:var(--info);background:color-mix(in srgb,var(--info) 10%,var(--surface))}
details.finding{border-bottom:1px solid var(--border)}details.finding>summary{cursor:pointer;display:grid;grid-template-columns:9.5em 1fr auto;gap:12px;align-items:center;padding:10px 4px;min-height:48px}
details.finding[open]>summary{background:var(--surface)}.loc{color:var(--muted);overflow-wrap:anywhere}.body{padding:8px 4px 16px}
.tag{font-size:14px;color:var(--muted);border:1px solid var(--border);border-radius:4px;padding:0 6px;margin-left:6px}
pre.code{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:12px;overflow-x:auto;white-space:pre}
mark{background:color-mix(in srgb,var(--high) 10%,var(--surface));color:inherit;text-decoration:underline 2px var(--high);text-underline-offset:3px}
.prompt{white-space:pre-wrap;background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:12px;font-size:14px}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border)}th{color:var(--muted)}
ul.plain{list-style:none;padding:0}ul.plain li{padding:8px 0;border-bottom:1px solid var(--border)}
@media (max-width:760px){details.finding>summary{grid-template-columns:1fr}}
@media print{details.finding>.body{display:block}}
`.trim();

const ICONS: Record<Severity | "worth", string> = {
  critical:
    '<svg viewBox="0 0 24 24" aria-hidden="true"><polygon points="7.9,2 16.1,2 22,7.9 22,16.1 16.1,22 7.9,22 2,16.1 2,7.9"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
  high: '<svg viewBox="0 0 24 24" aria-hidden="true"><polygon points="12,3 22,20 2,20"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  medium:
    '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
  low: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
  info: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
  worth:
    '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10" stroke-dasharray="3 2"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
};
const WORD: Record<Severity | "worth", string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
  worth: "Worth checking",
};

function badge(f: Finding): string {
  const k = f.confidence === "low" ? "worth" : f.severity;
  return `<span class="sev ${k}">${ICONS[k]}${WORD[k]}</span>`;
}

function excerpt(f: Finding): string {
  const { snippet, matchStart, matchEnd } = f.evidence;
  if (!snippet) return "";
  if (matchStart === undefined || matchEnd === undefined || matchEnd <= matchStart)
    return `<pre class="code">${esc(snippet)}</pre>`;
  return `<pre class="code">${esc(snippet.slice(0, matchStart))}<mark>${esc(snippet.slice(matchStart, matchEnd))}</mark>${esc(snippet.slice(matchEnd))}</pre>`;
}

function findingHtml(f: Finding): string {
  const m = ALL_META.get(f.ruleId);
  const tags = [
    f.confidence === "medium" ? `<span class="tag">medium confidence</span>` : "",
    f.status !== "open"
      ? `<span class="tag">${f.status === "accepted_risk" ? "accepted risk" : "false positive"}</span>`
      : "",
    f.existing ? `<span class="tag">existing</span>` : "",
  ].join("");
  const refs = (m?.sources ?? [])
    .map((s) => {
      const href = safeUrl(s.url);
      return `<li>${href ? `<a href="${esc(href)}" rel="noopener noreferrer">${esc(s.title)}</a>` : esc(s.title)}${s.book ? ` <span class="muted">(book: ${esc(s.book)})</span>` : ""}</li>`;
    })
    .join("");
  return `<details class="finding"><summary>${badge(f)}<span>${esc(f.title)}${tags}</span><span class="loc mono">${esc(locationText(f))}</span></summary>
<div class="body">
<p class="small muted"><span class="mono">${esc(f.ruleId)}</span> · OWASP ${esc(f.owasp)}:2025 · confidence ${esc(f.confidence)}</p>
${f.decision ? `<p><strong>Decision (${esc(f.decision.source)}):</strong> ${esc(f.decision.reason)}</p>` : ""}
<h3>Where</h3><p class="mono">${esc(locationText(f))}</p>${excerpt(f)}
${m ? `<h3>Why it matters</h3><p>${esc(m.why)}</p><h3>How to fix</h3><ol>${m.fix.map((s) => `<li>${mdLite(s)}</li>`).join("")}</ol>` : ""}
<h3>Fix prompt</h3><div class="prompt">${esc(f.fixPrompt)}</div>
${refs ? `<h3>References</h3><ul>${refs}</ul>` : ""}
</div></details>`;
}

function section(title: string, list: Finding[]): string {
  return list.length ? `<h2>${esc(title)} (${list.length})</h2>${list.map(findingHtml).join("\n")}` : "";
}

async function sha256Base64(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  let bin = "";
  for (const b of digest) bin += String.fromCharCode(b);
  return btoa(bin);
}

export async function toHtml(report: Report): Promise<string> {
  const s = report.summary;
  const c = s.counts;
  const name = report.target.folderName ?? report.target.url ?? report.profile.name;
  const open = report.findings.filter((f) => f.status === "open");
  const main = open.filter((f) => f.confidence !== "low" && f.severity !== "info");
  const worth = open.filter((f) => f.confidence === "low");
  const info = open.filter((f) => f.confidence !== "low" && f.severity === "info");
  const suppressed = report.findings.filter((f) => f.status !== "open");
  const coverage = [
    ...report.coverage.notes,
    ...(report.coverage.rulesSkipped.some((r) => r.reason === "no_url")
      ? ["Live-site checks: run the CLI with --url."]
      : []),
    ...(report.coverage.rulesSkipped.some((r) => r.reason === "offline")
      ? ["Dependency vulnerabilities: online checks were off."]
      : []),
    ...report.coverage.errors.map((e) => `${e.ruleId} stopped with an error: ${e.message}`),
  ];
  const csp = `default-src 'none'; style-src 'sha256-${await sha256Base64(CSS)}'; img-src 'none'; base-uri 'none'; form-action 'none'`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="referrer" content="no-referrer">
<title>Prelaunch Check report: ${esc(name)}</title>
<style>${CSS}</style>
</head>
<body>
<main>
<h1>Prelaunch Check report: ${esc(name)}</h1>
<p class="small muted">Generated ${esc(report.generatedAt)} by ${esc(report.tool.name)} ${esc(report.tool.version)} (rules ${esc(report.tool.rulesetVersion)}). Secrets are always shortened, e.g. <span class="mono">sk_l…9xQz</span>.</p>
<section class="verdict ${esc(s.verdict)}"><div><h2>${esc(VERDICT_LABEL[s.verdict])}</h2><p>${esc(verdictSentence(report))}</p></div><div class="score">${esc(s.score)} <span class="small muted">/ 100</span></div></section>
<p>${esc(`${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low · ${c.worthChecking} worth checking · ${c.info} info · ${c.suppressed} suppressed`)}</p>
${section("Findings", main)}
${section("Worth checking", worth)}
${section("Info", info)}
${section("Suppressed", suppressed)}
${report.findings.length === 0 ? "<p>No findings.</p>" : ""}
<h2>What we couldn't check</h2>
<ul class="plain">${[...coverage, "Some of the most important problems depend on your app's logic, which no scanner can judge. Work through the checklist below."].map((t) => `<li>${esc(t)}</li>`).join("")}</ul>
${
  report.endpoints?.length
    ? `<h2>Endpoint inventory</h2><p class="muted">Decide for each route whether it should be reachable by an anonymous user, a regular user, or an admin.</p><table><thead><tr><th>Method</th><th>Route</th><th>File</th><th>Auth call seen?</th></tr></thead><tbody>${report.endpoints
        .map(
          (e) =>
            `<tr><td class="mono">${esc(e.method)}</td><td class="mono">${esc(e.route)}</td><td class="mono">${esc(`${e.file}:${e.line}`)}</td><td>${e.authCallSeen ? "Yes" : "No"}</td></tr>`,
        )
        .join("")}</tbody></table>`
    : ""
}
<h2>Pre-launch checklist</h2>
<ul class="plain">${report.checklist.map((i) => `<li><strong>${esc(i.id)}</strong> ${esc(i.title)}<br><span class="small">How to test: ${esc(i.howToTest)}</span></li>`).join("")}</ul>
<p class="small muted">Made with <a href="${esc(REPO_URL)}" rel="noopener noreferrer">Prelaunch Check</a>. It lists what was found and what couldn&#39;t be checked; no scanner can prove an app has no problems.</p>
</main>
</body>
</html>
`;
}
