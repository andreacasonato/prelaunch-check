// Runs the engine off the main thread so the UI never freezes (TRD §11).
import { resolveConfig, runScan, type Coverage } from "@prelaunch-check/core";
import { BrowserFileSource } from "../sources/browser-files";
import { createBrowserOnline } from "../lib/online";
import type { FromWorker, ToWorker } from "./protocol";

const post = (m: FromWorker) => (self as unknown as Worker).postMessage(m);

self.onmessage = async (e: MessageEvent<ToWorker>) => {
  if (e.data.type !== "scan") return;
  const { files, folderName, online } = e.data;
  let last = 0;
  let lastStage = "";
  try {
    const status: Coverage["online"] = { osv: online ? "used" : "off", npmRegistry: "off" };
    const report = await runScan({
      files: new BrowserFileSource(files),
      folderName,
      config: resolveConfig({}).config,
      toolVersion: __APP_VERSION__,
      ...(online ? { online: createBrowserOnline(status), onlineStatus: status } : { onlineStatus: status }),
      onProgress: (p) => {
        // At most one message every 100 ms, but always on a stage change.
        const now = Date.now();
        if (p.stage === lastStage && now - last < 100) return;
        last = now;
        lastStage = p.stage;
        post({ type: "progress", ...p });
      },
    });
    post({ type: "done", report });
  } catch (err) {
    post({ type: "error", message: err instanceof Error ? err.message : String(err) });
  }
};
