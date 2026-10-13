// W-06 Pre-launch checklist: native checkboxes, how to test, expandable why. Works without a scan.
import { useState } from "react";
import { CHECKLIST } from "@prelaunch-check/core";
import { getChecklist, setChecklist, storageAvailable } from "../lib/storage";
import { useApp } from "../lib/state";

const GROUPS: Array<{ title: string; ids: string[] }> = [
  { title: "Try to break in", ids: ["MAN-001", "MAN-002", "MAN-003", "MAN-004", "MAN-005"] },
  { title: "Abuse & cost", ids: ["MAN-006", "MAN-007", "MAN-009"] },
  { title: "Auth & data", ids: ["MAN-008", "MAN-010", "MAN-011", "MAN-012", "MAN-013", "MAN-017"] },
  { title: "Operations", ids: ["MAN-014", "MAN-015", "MAN-016", "MAN-018"] },
];

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
        <section key={g.title} className="checklist-group" aria-labelledby={`g-${g.title}`}>
          <h2 id={`g-${g.title}`}>{g.title}</h2>
          {g.ids.map((id) => {
            const item = CHECKLIST.find((c) => c.id === id)!;
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
                    <p className="small muted">Source: {item.source}</p>
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
