// Minimal, safe Markdown for rule texts we ship: paragraphs, `inline code` and ``` fences.
// Builds React elements only; nothing is ever injected as HTML.
import { Fragment, type ReactNode } from "react";

function inline(text: string): ReactNode[] {
  return text
    .split(/(`[^`]+`)/g)
    .map((part, i) =>
      part.startsWith("`") && part.endsWith("`") && part.length > 1 ? (
        <code key={i}>{part.slice(1, -1)}</code>
      ) : (
        <Fragment key={i}>{part}</Fragment>
      ),
    );
}

export function Markdown({ text }: { text: string }) {
  const blocks = text.split(/```[a-z]*\n?/);
  return (
    <>
      {blocks.map((b, i) =>
        i % 2 === 1 ? (
          <pre key={i} className="code md-pre">
            <code>{b.replace(/\n$/, "")}</code>
          </pre>
        ) : (
          b
            .split(/\n{2,}/)
            .filter((p) => p.trim())
            .map((p, j) => (
              <span key={`${i}-${j}`} className="md-p">
                {inline(p.trim())}
              </span>
            ))
        ),
      )}
    </>
  );
}
