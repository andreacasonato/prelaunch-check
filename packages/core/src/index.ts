// Public API of @prelaunch-check/core.
export * from "./types.js";
export * from "./config.js";
export * from "./version.js";
export * from "./copy.js";
export { redact, redactAll } from "./redact.js";
export { computeFingerprintKey, normaliseUrl, sha256Hex } from "./fingerprint.js";
export { computeScore, computeVerdict, computeCounts, countsTowardScore, WEIGHTS } from "./score.js";
export { runScan, type ScanInput, type ScanProgress, type ScanStage } from "./engine/runScan.js";
export { compareFindings, SEVERITY_ORDER, CATEGORY_ORDER, CONFIDENCE_ORDER } from "./engine/sort.js";
export { MemoryFileSource } from "./sources/memory.js";
export { ALWAYS_IGNORED_DIRS, ignoredDirOf, isIgnoredDir, normalisePath } from "./files/paths.js";
export { matchGlob } from "./files/glob.js";
export { CHECKLIST } from "./checklist/items.js";
export { DEFAULT_RULES } from "./rules/index.js";
export { toMarkdown, locationText } from "./formats/markdown.js";
export { PROBES, FALLBACK_PROBES, CORS_TEST_ORIGIN, SITE_LIMITS, type Probe } from "./rules/web/probes.js";
