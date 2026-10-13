import { ChevronRight } from "lucide-react";
import { locationText, truncateMiddle, type Finding } from "@prelaunch-check/core";
import { SeverityBadge } from "./Icons";
import { findingPath } from "../lib/router";

export function FindingRow({ finding, isNew }: { finding: Finding; isNew?: boolean | undefined }) {
  const loc = locationText(finding);
  return (
    <a
      className="finding-row"
      href={`#${findingPath(finding.fingerprint)}`}
      data-fingerprint={finding.fingerprint}
    >
      <span className="sev-cell">
        <SeverityBadge severity={finding.severity} confidence={finding.confidence} />
      </span>
      <span className="title">
        {finding.title}
        {finding.confidence === "medium" && <span className="tag">medium confidence</span>}
        {finding.status !== "open" && (
          <span className="tag">
            {finding.status === "accepted_risk" ? "accepted risk" : "false positive"}
          </span>
        )}
        {finding.existing && <span className="tag">existing</span>}
        {isNew === true && <span className="tag tag-new">New</span>}
        {isNew === false && <span className="tag">Still open</span>}
      </span>
      <span className="loc" title={loc}>
        {truncateMiddle(loc, 44)}
      </span>
      <ChevronRight className="chev" size={18} aria-hidden />
    </a>
  );
}
