// W-04 Report, with W-05 Finding detail (panel on desktop, page on mobile) and W-08 Export.
import { useEffect, useMemo, useState } from "react";
import {
  CATEGORY_ORDER,
  compareFindings,
  toHtml,
  toMarkdown,
  toSarif,
  type Category,
  type Finding,
  type Report as ReportT,
  type Severity,
} from "@prelaunch-check/core";
import { VerdictBanner } from "../components/Verdict";
import { FindingRow } from "../components/FindingRow";
import { FindingDetail } from "../components/FindingDetail";
import { SEVERITY_WORD, SeverityIcon, sevKey } from "../components/Icons";
import { useApp } from "../lib/state";
import { navigate } from "../lib/router";
import { download } from "../lib/download";
import { getChecklist, setDecision } from "../lib/storage";
import { ruleMeta } from "../lib/rules";

const CATEGORY_LABEL: Record<Category, string> = {
  secrets: "Secrets",
  data: "Database access rules",
  web: "Live site",
  deps: "Dependencies",
  code: "Code patterns",
  config: "Project config",
};

type Level = Severity | "worth";
const PILLS: Level[] = ["critical", "high", "medium", "low", "worth"];

function useNarrow(): boolean {
  const q = "(max-width: 760px)";
  const [narrow, setNarrow] = useState(() => window.matchMedia(q).matches);
  useEffect(() => {
    const m = window.matchMedia(q);
    const on = () => setNarrow(m.matches);
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  return narrow;
}

function coverageItems(r: ReportT): string[] {
  const out: string[] = [];
  const reasons = new Map<string, string[]>();
  for (const s of r.coverage.rulesSkipped)
    reasons.set(s.reason, [...(reasons.get(s.reason) ?? []), s.ruleId]);
  if (reasons.has("no_url")) out.push("Live-site checks need the command-line tool: see Scan a live site.");
  if (reasons.has("offline")) out.push("Dependency vulnerabilities: online check was off.");
  if (r.coverage.online.osv === "failed")
    out.push("Dependency vulnerabilities: couldn't reach the OSV database.");
  if (reasons.get("missing_tool")?.includes("SEC-006"))
    out.push("Git history: needs the command-line tool with gitleaks installed.");
  out.push(...r.coverage.notes);
  const tooLarge = r.coverage.filesSkipped.filter((f) => f.reason === "too_large").length;
  if (tooLarge) out.push(`${tooLarge} file${tooLarge === 1 ? "" : "s"} skipped (larger than 2 MB).`);
  for (const e of r.coverage.errors)
    out.push(`${e.ruleId} stopped with an error and didn't finish: ${e.message}`);
  return out;
}

function Export({ report }: { report: ReportT }) {
  const name = (report.target.folderName ?? "report").replace(/[^\w.-]+/g, "-");
  return (
    <section className="section no-print" aria-labelledby="export-h" id="export">
      <h2 id="export-h">Export</h2>
      <p className="muted">
        Reports contain file paths and redacted snippets of your code. Secrets are always shortened (e.g.{" "}
        <code>sk_l…9xQz</code>), but review before sharing publicly. Your code never leaves your computer:
        files are created right here in your browser.
      </p>
      <div className="btn-row">
        <button
          type="button"
          className="btn btn-quiet"
          onClick={() =>
            download(
              `prelaunch-check-report-${name}.json`,
              JSON.stringify(report, null, 2) + "\n",
              "application/json",
            )
          }
        >
          JSON
        </button>
        <button
          type="button"
          className="btn btn-quiet"
          onClick={() => download(`prelaunch-check-report-${name}.md`, toMarkdown(report), "text/markdown")}
        >
          Markdown
        </button>
        <button
          type="button"
          className="btn btn-quiet"
          onClick={() =>
            download(
              `prelaunch-check-${name}.sarif`,
              JSON.stringify(toSarif(report), null, 2) + "\n",
              "application/sarif+json",
            )
          }
        >
          SARIF
        </button>
        <button
          type="button"
          className="btn btn-quiet"
          onClick={() =>
            void toHtml(report).then((html) =>
              download(`prelaunch-check-report-${name}.html`, html, "text/html"),
            )
          }
        >
          HTML
        </button>
      </div>
    </section>
  );
}

/** W-07: decisions recorded in an opened report can be saved into this browser for this project. */
function ImportDecisions() {
  const { loaded, project } = useApp();
  const [saved, setSaved] = useState(false);
  if (!loaded || !project) return null;
  const decided = loaded.original.findings.filter((f) => f.status !== "open" && f.decision);
  if (!decided.length) return null;
  if (saved)
    return (
      <p className="small">
        Saved {decided.length} decisions in this browser for {project}.
      </p>
    );
  return (
    <p className="small">
      This report includes {decided.length} recorded decision{decided.length === 1 ? "" : "s"}.{" "}
      <button
        type="button"
        className="link-button"
        onClick={() => {
          for (const f of decided) {
            setDecision(project, f.fingerprint, {
              status: f.status as "accepted_risk" | "false_positive",
              reason: f.decision!.reason,
              decidedAt: f.decision!.decidedAt,
            });
          }
          setSaved(true);
        }}
      >
        Save them in this browser
      </button>{" "}
      so they apply to your next scan of {project}.
    </p>
  );
}

export function Report({ fingerprint }: { fingerprint?: string | undefined }) {
  const { report, loaded, project, decide } = useApp();
  const narrow = useNarrow();
  const [levels, setLevels] = useState<Set<Level>>(new Set());
  const [category, setCategory] = useState<Category | "all">("all");
  const [status, setStatus] = useState<"all" | "open" | "accepted_risk" | "false_positive">("open");
  const [query, setQuery] = useState("");

  const findings = useMemo(() => (report ? [...report.findings].sort(compareFindings) : []), [report]);

  if (!report || !loaded) {
    return (
      <>
        <h1>Report</h1>
        <p className="empty">
          No report is loaded. Reports aren't stored in your browser, so they're gone after a reload.
        </p>
        <div className="btn-row">
          <a className="btn btn-primary" href="#/scan">
            Scan a project folder
          </a>
          <a className="btn btn-quiet" href="#/open">
            Open a report file
          </a>
        </div>
      </>
    );
  }

  const comparison = loaded.comparison;
  const visible = findings.filter((f) => {
    if (status !== "all" && f.status !== status) return false;
    if (levels.size && !levels.has(sevKey(f.severity, f.confidence))) return false;
    if (category !== "all" && f.category !== category) return false;
    if (query) {
      const q = query.toLowerCase();
      const hay = `${f.title} ${f.ruleId} ${f.location.path ?? ""} ${f.location.url ?? ""}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  const fixFirst = findings
    .filter((f) => f.status === "open" && f.confidence !== "low" && f.severity !== "info")
    .slice(0, 3);
  const c = report.summary.counts;
  const pillCount: Record<Level, number> = {
    critical: c.critical,
    high: c.high,
    medium: c.medium,
    low: c.low,
    info: c.info,
    worth: c.worthChecking,
  };
  const checklistDone = Object.values(getChecklist(project)).filter(Boolean).length;

  const selected = fingerprint ? findings.find((f) => f.fingerprint === fingerprint) : undefined;
  const ordered = visible.some((f) => f.fingerprint === fingerprint) ? visible : findings;
  const pos = selected ? ordered.indexOf(selected) : -1;
  const close = () => navigate("/report");
  const detail = selected && (
    <FindingDetail
      finding={selected}
      prev={pos > 0 ? ordered[pos - 1] : undefined}
      next={pos >= 0 && pos < ordered.length - 1 ? ordered[pos + 1] : undefined}
      asDialog={!narrow}
      onClose={close}
      onDecide={(d) => decide(selected.fingerprint, d)}
    />
  );
  if (selected && narrow) return <article aria-label="Finding detail">{detail}</article>;

  const groups = CATEGORY_ORDER.map((cat) => ({
    cat,
    items: visible.filter((f) => f.category === cat),
  })).filter((g) => g.items.length);
  const isNew = (f: Finding) => (comparison ? comparison.newFingerprints.has(f.fingerprint) : undefined);
  const where = [report.target.folderName, report.target.url].filter(Boolean).join(" + ");

  return (
    <>
      <h1>{where || "Report"}</h1>
      {loaded.origin === "file" && (
        <div className="notice" role="status">
          Viewing a report file: generated by prelaunch-check {report.tool.version} on{" "}
          {report.generatedAt.slice(0, 10)} for {where}.
          {loaded.newerVersion && (
            <strong> This report was made by a newer version. Some details may not display.</strong>
          )}
          <ImportDecisions />
        </div>
      )}
      <VerdictBanner report={report} />
      {comparison && (
        <p className="muted" role="status">
          Compared with your last scan of this folder: {comparison.newFingerprints.size} new, fixed since last
          scan: {comparison.fixedCount}.
        </p>
      )}

      <div className="filter-bar" role="toolbar" aria-label="Filter by severity">
        {PILLS.map((l) => (
          <button
            key={l}
            type="button"
            className={`pill sev sev-${l}`}
            aria-pressed={levels.has(l)}
            onClick={() =>
              setLevels((prev) => {
                const n = new Set(prev);
                if (n.has(l)) n.delete(l);
                else n.add(l);
                return n;
              })
            }
          >
            <SeverityIcon level={l} />
            {SEVERITY_WORD[l]} <span>{pillCount[l]}</span>
          </button>
        ))}
      </div>

      {fixFirst.length > 0 && (
        <section className="section" aria-labelledby="fix-first-h">
          <h2 id="fix-first-h">Fix first</h2>
          <ul className="finding-list">
            {fixFirst.map((f) => (
              <li key={f.fingerprint}>
                <FindingRow finding={f} isNew={isNew(f)} />
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="section" aria-labelledby="findings-h">
        <h2 id="findings-h">All findings</h2>
        <div className="filters">
          <label>
            Category
            <select value={category} onChange={(e) => setCategory(e.target.value as Category | "all")}>
              <option value="all">All categories</option>
              {CATEGORY_ORDER.map((cat) => (
                <option key={cat} value={cat}>
                  {CATEGORY_LABEL[cat]}
                </option>
              ))}
            </select>
          </label>
          <label>
            Status
            <select value={status} onChange={(e) => setStatus(e.target.value as typeof status)}>
              <option value="open">Open</option>
              <option value="accepted_risk">Accepted risk</option>
              <option value="false_positive">False positive</option>
              <option value="all">All</option>
            </select>
          </label>
          <label className="search">
            Search title, rule ID or path
            <input type="search" value={query} onChange={(e) => setQuery(e.target.value)} />
          </label>
        </div>
        {c.suppressed > 0 && status === "open" && (
          <p className="small">
            <button type="button" className="link-button" onClick={() => setStatus("all")}>
              Show suppressed ({c.suppressed})
            </button>
          </p>
        )}
        {groups.length === 0 ? (
          <p className="empty">No findings match these filters.</p>
        ) : (
          groups.map((g) => (
            <details key={g.cat} className="cat-group" open>
              <summary>
                {CATEGORY_LABEL[g.cat]} <span className="muted small">({g.items.length})</span>
              </summary>
              <ul className="finding-list">
                {g.items.map((f) => (
                  <li key={f.fingerprint}>
                    <FindingRow finding={f} isNew={isNew(f)} />
                  </li>
                ))}
              </ul>
            </details>
          ))
        )}
      </section>

      <section className="section" aria-labelledby="cov-h">
        <h2 id="cov-h">What we couldn't check</h2>
        <ul className="coverage">
          {coverageItems(report).map((t, i) => (
            <li key={i}>{t}</li>
          ))}
          <li>
            Some of the most important problems depend on your app's logic, which no scanner can judge. That's
            what the checklist is for.
          </li>
        </ul>
      </section>

      <section className="section" aria-labelledby="check-h">
        <h2 id="check-h">Pre-launch checklist</h2>
        <p className="progress-line">
          {checklistDone} / {report.checklist.length || 18} done
        </p>
        <a href="#/checklist">Open the checklist</a>
      </section>

      {report.endpoints && report.endpoints.length > 0 && (
        <section className="section" aria-labelledby="ep-h">
          <h2 id="ep-h">Endpoint inventory</h2>
          <p className="muted">
            Go through every endpoint and decide whether it should be reachable by an anonymous user, a
            regular user, or an admin. "Auth call seen" only means the file mentions a common login check; it
            doesn't prove the route is protected.
          </p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Method</th>
                  <th scope="col">Route</th>
                  <th scope="col">File</th>
                  <th scope="col">Auth call seen?</th>
                </tr>
              </thead>
              <tbody>
                {report.endpoints.map((e, i) => (
                  <tr key={i}>
                    <td className="mono">{e.method}</td>
                    <td className="mono">{e.route}</td>
                    <td className="mono">
                      {e.file}:{e.line}
                    </td>
                    <td>{e.authCallSeen ? "Yes" : "No"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <Export report={report} />
      <div className="btn-row no-print">
        <a className="btn btn-quiet" href="#/scan">
          Scan again
        </a>
      </div>
      {detail}
      {selected && !ruleMeta(selected.ruleId) && (
        <span className="visually-hidden">Rule details are not available for {selected.ruleId}.</span>
      )}
    </>
  );
}
