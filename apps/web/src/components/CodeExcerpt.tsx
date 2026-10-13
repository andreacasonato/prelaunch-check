// Code excerpt: line numbers, the match highlighted with background AND underline, redacted secrets
// outlined. Text is rendered as text nodes only.
import type { ReactNode } from "react";
import type { Finding } from "@prelaunch-check/core";

const REDACTED = /(\S{4}…\S{4}|••••)/g;

function withRedactions(text: string, key: string): ReactNode[] {
  return text.split(REDACTED).map((part, i) =>
    i % 2 === 1 ? (
      <span key={`${key}-${i}`} className="redacted" title="Hidden by Prelaunch Check">
        {part}
      </span>
    ) : (
      part
    ),
  );
}

export function CodeExcerpt({ finding }: { finding: Finding }) {
  const { snippet, matchStart, matchEnd } = finding.evidence;
  if (!snippet) return null;
  const linesBefore = matchStart !== undefined ? snippet.slice(0, matchStart).split("\n").length - 1 : 0;
  const first = Math.max(1, (finding.location.line ?? 1) - linesBefore);
  let offset = 0;
  const lines = snippet.split("\n");
  return (
    <div className="code" role="region" aria-label="Code excerpt" tabIndex={0}>
      <ol>
        {lines.map((line, i) => {
          const start = offset;
          const end = offset + line.length;
          offset = end + 1;
          let content: ReactNode[] = withRedactions(line, `l${i}`);
          if (matchStart !== undefined && matchEnd !== undefined && matchEnd > start && matchStart < end) {
            const a = Math.max(matchStart, start) - start;
            const b = Math.min(matchEnd, end) - start;
            content = [
              ...withRedactions(line.slice(0, a), `a${i}`),
              <mark key={`m${i}`}>{withRedactions(line.slice(a, b), `m${i}`)}</mark>,
              ...withRedactions(line.slice(b), `b${i}`),
            ];
          }
          return (
            <li key={i}>
              <span className="ln">{first + i}</span>
              <span>{content.length ? content : " "}</span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
