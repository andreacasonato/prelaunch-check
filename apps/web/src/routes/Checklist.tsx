// W-06 Pre-launch checklist: native checkboxes, how to test, expandable why. Works without a scan.
import { useState } from "react";
import { CHECKLIST, CHECKLIST_GROUPS } from "@prelaunch-check/core";
import { getChecklist, setChecklist, storageAvailable } from "../lib/storage";
import { useApp } from "../lib/state";

const GROUPS = CHECKLIST_GROUPS.map((g) => ({
  ...g,
  // aria-labelledby takes a space-separated id list, so the heading id must not contain spaces.
  slug: g.title.toLowerCase().replace(/[^a-z0-9]+/g, "-"),
  items: CHECKLIST.filter((c) => c.group === g.title),
}));

export function Checklist() {
  const { project } = useApp();
  const [ticks, setTicks] = useState<Record<string, boolean>>(() => getChecklist(project));
  const done = CHECKLIST.filter((i) => ticks[i.id]).length;
  const toggle = (id: string, value: boolean) => {
    const next = { ...ticks, [id]: value };
    setTicks(next);
    setChecklist(project, next);
  };
  return (
    <>
      <h1>Pre-launch checklist</h1>
      <p>
        No scanner can check these, because they depend on how your app is meant to work. Try each one
        yourself before you launch.
        {project ? ` Ticks are saved in this browser for ${project}.` : " Ticks are saved in this browser."}
      </p>
      {!storageAvailable() && (
        <p className="notice">
          Your browser isn't allowing local storage, so ticks won't be remembered after you leave this page.
        </p>
      )}
      <p className="progress-line" aria-live="polite">
        {done} / {CHECKLIST.length} done
      </p>
      <div className="btn-row no-print">
        <button type="button" className="btn btn-quiet" onClick={() => window.print()}>
          Print
        </button>
        <button
          type="button"
          className="btn btn-quiet"
          onClick={() => {
            setTicks({});
            setChecklist(project, null);
          }}
        >
          Reset
        </button>
      </div>
      {GROUPS.map((g) => (
        <section key={g.title} className="checklist-group" aria-labelledby={`g-${g.slug}`}>
          <h2 id={`g-${g.slug}`}>{g.title}</h2>
          {g.intro && <p>{g.intro}</p>}
          {g.items.map((item) => {
            const id = item.id;
            return (
              <div key={id} className="check-item">
                <input
                  id={id}
                  type="checkbox"
                  checked={!!ticks[id]}
                  onChange={(e) => toggle(id, e.target.checked)}
                />
                <div>
                  <label htmlFor={id}>{item.title}</label>
                  <p className="small">
                    <strong>How to test:</strong> {item.howToTest}
                  </p>
                  <details>
                    <summary>Why</summary>
                    <p className="small">{item.why}</p>
                    {item.links ? (
                      <ul className="small">
                        {item.links.map((l) => (
                          <li key={l.url + l.label}>
                            <a href={l.url} target="_blank" rel="noopener noreferrer">
                              {l.label}
                            </a>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="small muted">Source: {item.source}</p>
                    )}
                  </details>
                </div>
              </div>
            );
          })}
        </section>
      ))}
    </>
  );
}
