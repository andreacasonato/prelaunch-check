// W-02 Scan setup and W-03 Scanning. Pre-flight uses only paths and sizes (plus package.json for the stack).
import { useEffect, useRef, useState } from "react";
import { LoaderCircle, Check } from "lucide-react";
import {
  depNames,
  ignoredDirOf,
  normalisePath,
  parsePackageJson,
  type ScanStage,
} from "@prelaunch-check/core";
import { relativePath, rootName } from "../sources/browser-files";
import type { FromWorker, ToWorker } from "../worker/protocol";
import { getOnlineDeps, setOnlineDeps } from "../lib/storage";
import { useApp } from "../lib/state";
import { navigate } from "../lib/router";
import { REPO_URL } from "../lib/rules";

const WARN_FILES = 20_000;
const WARN_BYTES = 200 * 1024 * 1024;

const STAGES: Array<{ id: ScanStage; label: string }> = [
  { id: "reading", label: "Reading files" },
  { id: "detecting", label: "Detecting stack" },
  { id: "secrets", label: "Checking secrets" },
  { id: "data", label: "Checking database rules" },
  { id: "deps", label: "Checking dependencies" },
  { id: "code", label: "Checking code patterns" },
  { id: "config", label: "Checking config" },
  { id: "building", label: "Building report" },
];

interface Preflight {
  files: File[];
  folder: string;
  scannable: number;
  skipped: number;
  bytes: number;
  stack: string[];
}

async function preflight(files: File[]): Promise<Preflight> {
  let scannable = 0;
  let skipped = 0;
  let bytes = 0;
  let pkgFile: File | undefined;
  const paths = new Set<string>();
  for (const f of files) {
    const p = normalisePath(relativePath(f));
    if (!p) continue;
    if (ignoredDirOf(p)) {
      skipped++;
      continue;
    }
    scannable++;
    bytes += f.size;
    paths.add(p);
    if (p === "package.json") pkgFile = f;
  }
  const stack: string[] = [];
  const pkg = pkgFile ? parsePackageJson(await pkgFile.text().catch(() => null)) : null;
  const deps = pkg ? depNames(pkg) : new Set<string>();
  const has = (re: RegExp) => [...paths].some((p) => re.test(p));
  if (deps.has("next") || has(/^next\.config\./)) stack.push("Next.js");
  if (deps.has("vite") || has(/^vite\.config\./)) stack.push("Vite");
  if (deps.has("@supabase/supabase-js") || has(/(?:^|\/)supabase\/(?:config\.toml|migrations\/)/))
    stack.push("Supabase");
  if (deps.has("firebase") || has(/(?:^|\/)(?:firebase\.json|firestore\.rules)$/)) stack.push("Firebase");
  if (deps.has("stripe") || deps.has("@stripe/stripe-js")) stack.push("Stripe");
  return { files, folder: rootName(files), scannable, skipped, bytes, stack };
}

export function Scan() {
  const { load } = useApp();
  const input = useRef<HTMLInputElement>(null);
  const worker = useRef<Worker | null>(null);
  const [pre, setPre] = useState<Preflight | null>(null);
  const [online, setOnline] = useState(getOnlineDeps());
  const [confirmedLarge, setConfirmedLarge] = useState(false);
  const [stage, setStage] = useState<{
    id: ScanStage;
    done?: number | undefined;
    total?: number | undefined;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => () => worker.current?.terminate(), []);

  const choose = async (list: FileList | null) => {
    setError(null);
    setConfirmedLarge(false);
    if (!list || !list.length) return;
    setPre(await preflight([...list]));
  };

  const start = () => {
    if (!pre) return;
    setError(null);
    setStage({ id: "reading" });
    const w = new Worker(new URL("../worker/scan.worker.ts", import.meta.url), { type: "module" });
    worker.current = w;
    w.onmessage = (e: MessageEvent<FromWorker>) => {
      const m = e.data;
      if (m.type === "progress") setStage({ id: m.stage, done: m.done, total: m.total });
      else if (m.type === "done") {
        w.terminate();
        worker.current = null;
        load(m.report, "scan");
        navigate("/report");
      } else {
        w.terminate();
        worker.current = null;
        setStage(null);
        setError(m.message);
      }
    };
    w.onerror = (e) => {
      w.terminate();
      worker.current = null;
      setStage(null);
      setError(e.message || "Worker crashed");
    };
    const msg: ToWorker = { type: "scan", files: pre.files, folderName: pre.folder, online };
    w.postMessage(msg);
  };

  const cancel = () => {
    worker.current?.terminate();
    worker.current = null;
    setStage(null);
  };

  if (stage) {
    const idx = STAGES.findIndex((s) => s.id === stage.id);
    const current = STAGES[idx];
    return (
      <>
        <h1>Scanning {pre?.folder}</h1>
        <p className="visually-hidden" aria-live="polite">
          {current?.label}
        </p>
        <ul className="stage-list">
          {STAGES.map((s, i) => (
            <li key={s.id} data-state={i < idx ? "done" : i === idx ? "current" : "todo"}>
              {i < idx ? (
                <Check size={18} aria-hidden />
              ) : i === idx ? (
                <LoaderCircle size={18} className="spin" aria-hidden />
              ) : (
                <span style={{ width: 18 }} />
              )}
              {s.label}
              {i === idx && s.id === "reading" && stage.total
                ? ` (${(stage.done ?? 0).toLocaleString()} / ${stage.total.toLocaleString()})`
                : ""}
            </li>
          ))}
        </ul>
        <button type="button" className="btn btn-quiet" onClick={cancel}>
          Cancel
        </button>
      </>
    );
  }

  const tooBig = pre && (pre.scannable > WARN_FILES || pre.bytes > WARN_BYTES);
  return (
    <>
      <h1>Scan a project folder</h1>
      <p>
        Pick your project's root folder (the one with package.json). Prelaunch Check reads it inside this
        page; nothing leaves your computer.
      </p>
      <div className="panel">
        <input
          ref={input}
          id="folder"
          type="file"
          className="visually-hidden"
          // @ts-expect-error non-standard but widely supported (Baseline 2025)
          webkitdirectory=""
          multiple
          onChange={(e) => void choose(e.currentTarget.files)}
        />
        <div className="btn-row">
          <button type="button" className="btn btn-primary" onClick={() => input.current?.click()}>
            Choose folder
          </button>
          <label htmlFor="folder" className="visually-hidden">
            Project folder
          </label>
        </div>
        <p className="small muted" style={{ marginTop: "var(--s3)" }}>
          Your browser will ask to "upload" files. Nothing leaves your computer: files are read locally by
          this page.
        </p>
      </div>

      {error && (
        <div className="notice" role="alert">
          <p>
            <strong>The scan stopped unexpectedly.</strong>
          </p>
          <div className="btn-row">
            <button
              type="button"
              className="btn btn-quiet"
              onClick={() =>
                void navigator.clipboard.writeText(`Prelaunch Check web ${__APP_VERSION__}\n${error}`)
              }
            >
              Copy error details
            </button>
            <a href={`${REPO_URL}/issues/new`} target="_blank" rel="noopener noreferrer">
              Open a GitHub issue
            </a>
          </div>
          <p className="small muted">The error details contain no file contents.</p>
        </div>
      )}

      {pre && (
        <section className="panel" aria-labelledby="pre-h">
          <h2 id="pre-h">{pre.folder}</h2>
          <dl className="stats">
            <dt>Files to scan</dt>
            <dd>{pre.scannable.toLocaleString()}</dd>
            <dt>Skipped</dt>
            <dd>{pre.skipped.toLocaleString()} (node_modules, .git and caches)</dd>
          </dl>
          {pre.stack.length > 0 && (
            <ul className="stack-chips" aria-label="Detected stack">
              {pre.stack.map((s) => (
                <li key={s} className="chip">
                  {s}
                </li>
              ))}
            </ul>
          )}
          {pre.scannable === 0 ? (
            <p role="alert">
              This folder looks empty or contains only ignored folders. Pick your project's root folder (the
              one with package.json).
            </p>
          ) : (
            <>
              <div className="toggle">
                <input
                  id="online"
                  type="checkbox"
                  checked={online}
                  onChange={(e) => {
                    setOnline(e.target.checked);
                    setOnlineDeps(e.target.checked);
                  }}
                />
                <label htmlFor="online">
                  <strong>Check dependencies online</strong>
                  <br />
                  <span className="small muted">
                    Sends only package names and versions to the public OSV vulnerability database
                    (api.osv.dev). Off by default.
                  </span>
                </label>
              </div>
              {tooBig && !confirmedLarge ? (
                <div className="notice" role="alert">
                  <p>
                    This folder is large ({pre.scannable.toLocaleString()} files). Scanning may be slow in the
                    browser.
                  </p>
                  <div className="btn-row">
                    <button type="button" className="btn btn-quiet" onClick={() => setConfirmedLarge(true)}>
                      Continue anyway
                    </button>
                    <button type="button" className="btn btn-quiet" onClick={() => input.current?.click()}>
                      Pick a sub-folder
                    </button>
                  </div>
                </div>
              ) : (
                <button type="button" className="btn btn-primary" onClick={start}>
                  Start scan
                </button>
              )}
            </>
          )}
        </section>
      )}
    </>
  );
}
