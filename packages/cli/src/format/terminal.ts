// Terminal summary (docs/04-DESIGN-BRIEF.md §6): verdict first, fixed columns, labels always in caps,
// colour never the only signal, NO_COLOR honoured, output that pastes cleanly into issues.
import { locationText, type Finding, type Report, type Severity, VERDICT_LABEL } from "@prelaunch-check/core";

const ANSI = {
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
  reset: "\x1b[0m",
};

export interface Painter {
  sev(s: Severity, text: string): string;
  verdict(v: Report["summary"]["verdict"], text: string): string;
  dim(text: string): string;
  bold(text: string): string;
}

export function painter(color: boolean): Painter {
  const wrap = (code: string, t: string) => (color ? `${code}${t}${ANSI.reset}` : t);
  const sevCode: Record<Severity, string> = {
    critical: ANSI.bold + ANSI.red,
    high: ANSI.red,
    medium: ANSI.yellow,
    low: ANSI.blue,
    info: ANSI.dim,
  };
  return {
    sev: (s, t) => wrap(sevCode[s], t),
    verdict: (v, t) =>
      wrap(v === "blocked" ? ANSI.bold + ANSI.red : v === "needs_attention" ? ANSI.yellow : ANSI.bold, t),
    dim: (t) => wrap(ANSI.dim, t),
    bold: (t) => wrap(ANSI.bold, t),
  };
}

function truncate(s: string, n: number): string {
  if (n <= 1) return "";
  return s.length <= n ? s : `${s.slice(0, n - 1)}…`;
}

/** Truncates in the middle so the file name and line stay visible: src/…/route.ts:42 */
export function truncateMiddle(s: string, n: number): string {
  if (s.length <= n) return s;
  const keep = n - 1;
  const tail = Math.ceil(keep * 0.6);
  return `${s.slice(0, keep - tail)}…${s.slice(s.length - tail)}`;
}

function row(p: Painter, f: Finding, titleWidth: number, locWidth: number): string {
  const label = f.confidence === "low" ? "CHECK" : f.severity.toUpperCase();
  const sev = p.sev(f.severity, label.padEnd(9));
  const id = f.ruleId.padEnd(13);
  const loc = truncateMiddle(locationText(f), locWidth);
  return ` ${sev} ${id}${truncate(f.title, titleWidth).padEnd(titleWidth)}  ${p.dim(loc)}`;
}

/** Column widths shared by every row: location gets up to 40% of the line, the title the rest. */
function columns(rows: Finding[], width: number): { titleWidth: number; locWidth: number } {
  const longestLoc = Math.max(0, ...rows.map((f) => locationText(f).length));
  const locWidth = Math.min(longestLoc, Math.max(20, Math.floor(width * 0.4)));
  const titleWidth = Math.max(20, width - 1 - 10 - 13 - 2 - locWidth);
  return { titleWidth, locWidth };
}

export interface SummaryOptions {
  verbose: boolean;
  width: number;
  written: string[];
  notChecked: string[];
  painter: Painter;
}

export function countsLine(r: Report): string {
  const c = r.summary.counts;
  return `${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low · ${c.worthChecking} worth checking`;
}

export function renderSummary(r: Report, o: SummaryOptions): string {
  const p = o.painter;
  const lines: string[] = [];
  const verdict = VERDICT_LABEL[r.summary.verdict].toUpperCase();
  lines.push(` ${p.verdict(r.summary.verdict, verdict)}   ${countsLine(r)}   Score ${r.summary.score}/100`);

  const open = r.findings.filter((f) => f.status === "open" && f.severity !== "info" && !f.existing);
  const main = open.filter((f) => f.confidence !== "low");
  const worth = open.filter((f) => f.confidence === "low");
  const shown = o.verbose ? [...main, ...worth] : main.slice(0, 10);
  if (shown.length) {
    lines.push("");
    const { titleWidth, locWidth } = columns(shown, o.width);
    for (const f of shown) lines.push(row(p, f, titleWidth, locWidth));
    const hidden = main.length + worth.length - shown.length;
    if (hidden > 0)
      lines.push(p.dim(` … and ${hidden} more in the report (use --verbose to list everything)`));
  }
  if (o.notChecked.length) {
    lines.push("");
    lines.push(` Not checked: ${o.notChecked.join(", ")}`);
  }
  if (o.written.length) {
    lines.push("");
    for (const w of o.written) lines.push(` Report written: ${w}`);
  }
  return lines.join("\n") + "\n";
}
