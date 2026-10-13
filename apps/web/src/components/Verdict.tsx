import type { Report } from "@prelaunch-check/core";
import { VERDICT_LABEL, verdictSentence } from "@prelaunch-check/core";
import { VerdictIcon } from "./Icons";

export function VerdictBanner({ report }: { report: Report }) {
  const { verdict, score } = report.summary;
  return (
    <section className={`verdict verdict-${verdict}`} aria-labelledby="verdict-heading">
      <div className="verdict-main">
        <VerdictIcon verdict={verdict} />
        <div>
          <h2 id="verdict-heading">{VERDICT_LABEL[verdict]}</h2>
          <p>{verdictSentence(report)}</p>
        </div>
      </div>
      <div className="verdict-score">
        <strong>
          {score} <span className="muted small">/ 100</span>
        </strong>
        <a href="#/docs/scoring">How is this calculated?</a>
      </div>
    </section>
  );
}
