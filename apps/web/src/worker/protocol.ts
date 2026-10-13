import type { Report, ScanStage } from "@prelaunch-check/core";

export type ToWorker = { type: "scan"; files: File[]; folderName: string; online: boolean };

export type FromWorker =
  | { type: "progress"; stage: ScanStage; done?: number; total?: number }
  | { type: "done"; report: Report }
  | { type: "error"; message: string };
