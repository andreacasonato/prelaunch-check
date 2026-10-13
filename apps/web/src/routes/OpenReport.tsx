// W-07 Open a report file. The file is read locally and validated; nothing is uploaded.
import { useRef, useState, type DragEvent } from "react";
import { MAX_REPORT_BYTES, validateReport } from "../lib/validate";
import { useApp } from "../lib/state";
import { navigate } from "../lib/router";

export function OpenReport() {
  const { load } = useApp();
  const input = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);

  const open = async (file: File | undefined) => {
    setError(null);
    if (!file) return;
    if (file.size > MAX_REPORT_BYTES) {
      setError("This file is too large to be a Prelaunch Check report.");
      return;
    }
    const result = validateReport(await file.text());
    if (!result.ok) {
      setError(result.message);
      return;
    }
    load(result.report, "file", result.newerVersion);
    navigate("/report");
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    void open(e.dataTransfer.files[0]);
  };

  return (
    <>
      <h1>Open a report</h1>
      <p>
        Open a prelaunch-check-report.json made by the command-line tool or exported from this site. It's read
        in this page; nothing is uploaded.
      </p>
      <div
        className={`dropzone${dragging ? " dragging" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        <p>Drop the .json file here, or</p>
        <input
          ref={input}
          id="report-file"
          type="file"
          accept=".json,application/json"
          className="visually-hidden"
          onChange={(e) => void open(e.currentTarget.files?.[0])}
        />
        <button type="button" className="btn btn-primary" onClick={() => input.current?.click()}>
          Choose a report file
        </button>
        <label htmlFor="report-file" className="visually-hidden">
          Report file
        </label>
      </div>
      {error && (
        <p className="notice" role="alert">
          {error}
        </p>
      )}
    </>
  );
}
