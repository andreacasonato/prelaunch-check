// App state: the report being viewed lives in memory only. Full reports are never persisted (TRD §11).
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import type { Report } from "@prelaunch-check/core";
import { applyDecisions, compare, projectName, type Comparison } from "./report";
import { getDecisions, getLastScan, setDecision, setLastScan, type StoredDecision } from "./storage";

export interface Loaded {
  /** The report as produced or opened, before UI decisions. */
  original: Report;
  origin: "scan" | "file";
  newerVersion?: boolean;
  comparison: Comparison | null;
}

interface AppState {
  loaded: Loaded | null;
  /** The report with UI decisions applied and the summary recomputed. */
  report: Report | null;
  project: string | null;
  load(report: Report, origin: Loaded["origin"], newerVersion?: boolean): void;
  decide(fingerprint: string, d: StoredDecision | null): void;
}

const Ctx = createContext<AppState | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [version, setVersion] = useState(0);

  const load = useCallback((report: Report, origin: Loaded["origin"], newerVersion?: boolean) => {
    const project = projectName(report);
    // Read the previous summary before saving this one, for "compare with previous".
    const previous = origin === "scan" ? getLastScan(project) : null;
    const comparison = compare(report, previous?.fingerprints ?? null);
    if (origin === "scan") {
      setLastScan({
        project,
        generatedAt: report.generatedAt,
        verdict: report.summary.verdict,
        score: report.summary.score,
        counts: report.summary.counts,
        fingerprints: report.findings.map((f) => f.fingerprint),
      });
    }
    setLoaded({ original: report, origin, comparison, ...(newerVersion ? { newerVersion } : {}) });
  }, []);

  const project = loaded ? projectName(loaded.original) : null;

  const report = useMemo(() => {
    if (!loaded) return null;
    void version;
    return applyDecisions(loaded.original, getDecisions(projectName(loaded.original)));
  }, [loaded, version]);

  const decide = useCallback(
    (fingerprint: string, d: StoredDecision | null) => {
      if (!project) return;
      setDecision(project, fingerprint, d);
      setVersion((v) => v + 1);
    },
    [project],
  );

  return <Ctx.Provider value={{ loaded, report, project, load, decide }}>{children}</Ctx.Provider>;
}

export function useApp(): AppState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useApp outside AppProvider");
  return v;
}
