// W-05 Finding detail. A dialog on desktop (focus trap, Esc closes, focus returns to the row);
// a full page on mobile. Section order is fixed by the Design Brief §4.5.
import { useEffect, useRef, useState, type FormEvent } from "react";
import { X } from "lucide-react";
import { locationText, type Finding } from "@prelaunch-check/core";
import { SeverityBadge } from "./Icons";
import { CodeExcerpt } from "./CodeExcerpt";
import { CopyButton } from "./CopyButton";
import { Markdown } from "./Markdown";
import { OWASP_2025, REPO_URL, ruleMeta, safeHref } from "../lib/rules";
import { findingPath, navigate } from "../lib/router";
import type { StoredDecision } from "../lib/storage";

interface Props {
  finding: Finding;
  prev?: Finding | undefined;
  next?: Finding | undefined;
  asDialog: boolean;
  onClose(): void;
  onDecide(d: StoredDecision | null): void;
}

const MAX_REASON = 280;

function falsePositiveIssueUrl(f: Finding): string {
  const title = `False positive: ${f.ruleId}`;
  const body = [
    `Rule: ${f.ruleId}`,
    "",
    "What I expected: (describe)",
    "",
    "Please add a small MADE-UP example that reproduces it. Don't paste real code, keys or URLs.",
  ].join("\n");
  return `${REPO_URL}/issues/new?labels=false-positive&title=${encodeURIComponent(title)}&body=${encodeURIComponent(body)}`;
}

export function FindingDetail({ finding: f, prev, next, asDialog, onClose, onDecide }: Props) {
  const meta = ruleMeta(f.ruleId);
  const ref = useRef<HTMLDivElement>(null);
  const [mode, setMode] = useState<"accepted_risk" | "false_positive" | null>(null);
  const [reason, setReason] = useState("");

  useEffect(() => {
    setMode(null);
    setReason("");
  }, [f.fingerprint]);

  useEffect(() => {
    if (!asDialog) return;
    const root = ref.current;
    const opener = document.activeElement as HTMLElement | null;
    root?.querySelector<HTMLElement>("h2")?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
      if (e.key !== "Tab" || !root) return;
      const items = [
        ...root.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), textarea, input, [tabindex="0"]',
        ),
      ];
      if (!items.length) return;
      const first = items[0]!;
      const last = items[items.length - 1]!;
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      const row = document.querySelector<HTMLElement>(`[data-fingerprint="${CSS.escape(f.fingerprint)}"]`);
      (row ?? opener)?.focus();
    };
  }, [asDialog, f.fingerprint, onClose]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!mode || !reason.trim()) return;
    onDecide({
      status: mode,
      reason: reason.trim().slice(0, MAX_REASON),
      decidedAt: new Date().toISOString(),
    });
    setMode(null);
    setReason("");
  };

  const owaspName = OWASP_2025[f.owasp];
  const content = (
    <div
      ref={ref}
      className={asDialog ? "detail-panel" : undefined}
      {...(asDialog ? { role: "dialog", "aria-modal": true, "aria-labelledby": "finding-title" } : {})}
    >
      <div className="detail-head">
        <h2 id="finding-title" tabIndex={-1}>
          {f.title}
        </h2>
        <button type="button" className="btn btn-quiet" onClick={onClose} aria-label="Close finding">
          <X size={18} aria-hidden />
        </button>
      </div>
      <div className="detail-meta">
        <SeverityBadge severity={f.severity} confidence={f.confidence} />
        {f.confidence !== "high" && <span className="tag">{f.confidence} confidence</span>}
        <span className="tag mono">{f.ruleId}</span>
        <span className="tag">
          {f.owasp}:2025{owaspName ? ` ${owaspName}` : ""}
        </span>
      </div>

      <section className="detail-section" aria-labelledby="where-h">
        <h3 id="where-h">Where</h3>
        <p className="mono">{locationText(f)}</p>
        <CodeExcerpt finding={f} />
      </section>

      {meta && (
        <section className="detail-section" aria-labelledby="why-h">
          <h3 id="why-h">Why it matters</h3>
          <p>{meta.why}</p>
        </section>
      )}

      {meta && (
        <section className="detail-section" aria-labelledby="fix-h">
          <h3 id="fix-h">How to fix</h3>
          <ol className="steps">
            {meta.fix.map((step, i) => (
              <li key={i}>
                <Markdown text={step} />
              </li>
            ))}
          </ol>
        </section>
      )}

      <section className="detail-section" aria-labelledby="prompt-h">
        <h3 id="prompt-h">Copy fix prompt</h3>
        <p className="muted small">
          A pre-written instruction to paste into your AI coding tool. It's a template, not AI-generated.
        </p>
        <div className="prompt-box">{f.fixPrompt}</div>
        <div className="btn-row mt2">
          <CopyButton text={f.fixPrompt} label="Copy fix prompt" />
        </div>
      </section>

      {meta && meta.sources.length > 0 && (
        <section className="detail-section" aria-labelledby="refs-h">
          <h3 id="refs-h">References</h3>
          <ul>
            {meta.sources.map((s, i) => {
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
                  {s.book ? <span className="muted"> (book: {s.book})</span> : null}
                </li>
              );
            })}
            {typeof f.evidence.detail?.url === "string" && safeHref(f.evidence.detail.url) && (
              <li>
                <a href={safeHref(f.evidence.detail.url)} target="_blank" rel="noopener noreferrer">
                  Advisory: {String(f.evidence.detail.vulnId ?? f.evidence.detail.url)}
                </a>
              </li>
            )}
          </ul>
        </section>
      )}

      <section className="detail-section" aria-labelledby="status-h">
        <h3 id="status-h">Status</h3>
        {f.status !== "open" ? (
          <div className="notice">
            <p>
              Marked as <strong>{f.status === "accepted_risk" ? "accepted risk" : "false positive"}</strong>
              {f.decision ? `: ${f.decision.reason}` : ""}
            </p>
            {f.decision?.source === "ui" && (
              <button type="button" className="btn btn-quiet" onClick={() => onDecide(null)}>
                Undo
              </button>
            )}
          </div>
        ) : mode ? (
          <form className="decision-form" onSubmit={submit}>
            <label htmlFor="reason">
              Reason ({mode === "accepted_risk" ? "why this risk is acceptable" : "why this finding is wrong"}
              ), up to {MAX_REASON} characters
            </label>
            <textarea
              id="reason"
              required
              maxLength={MAX_REASON}
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
            <div className="btn-row">
              <button type="submit" className="btn btn-primary" disabled={!reason.trim()}>
                Save
              </button>
              <button type="button" className="btn btn-quiet" onClick={() => setMode(null)}>
                Cancel
              </button>
              {mode === "false_positive" && (
                <a href={falsePositiveIssueUrl(f)} target="_blank" rel="noopener noreferrer">
                  Report false positive (no code is included)
                </a>
              )}
            </div>
          </form>
        ) : (
          <div className="btn-row">
            <button type="button" className="btn btn-quiet" onClick={() => setMode("accepted_risk")}>
              Mark as accepted risk
            </button>
            <button type="button" className="btn btn-quiet" onClick={() => setMode("false_positive")}>
              Mark as false positive
            </button>
          </div>
        )}
      </section>

      <nav className="detail-nav" aria-label="Finding navigation">
        {prev ? (
          <button
            type="button"
            className="btn btn-quiet"
            onClick={() => navigate(findingPath(prev.fingerprint))}
          >
            ← Previous finding
          </button>
        ) : (
          <span />
        )}
        {next ? (
          <button
            type="button"
            className="btn btn-quiet"
            onClick={() => navigate(findingPath(next.fingerprint))}
          >
            Next finding →
          </button>
        ) : (
          <span />
        )}
      </nav>
    </div>
  );

  if (!asDialog) return content;
  return (
    <>
      <div className="panel-backdrop" onClick={onClose} aria-hidden />
      {content}
    </>
  );
}
