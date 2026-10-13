import type { RuleMeta } from "../../types.js";

/** Common fields for WEB rules: category "web", needs a site snapshot (CLI --url only). */
export function webMeta(m: Omit<RuleMeta, "category" | "requires">): RuleMeta {
  return { ...m, category: "web", requires: ["site"] };
}

export const INPUTS_BOOK = "Creating a Secure App — Inputs, Outputs & Web Hardening";
export const DB_BOOK = "Creating a Secure App — Locking Down the Database";
