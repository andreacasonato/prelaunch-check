import type { RawFinding, Rule } from "../../types.js";

export const CFG_INFO_002: Rule = {
  meta: {
    id: "CFG-INFO-002",
    title: "Expired suppression",
    category: "config",
    severity: "info",
    confidence: "high",
    owasp: "A09",
    requires: [],
    summary:
      "Lists config suppressions whose `expires` date has passed. They no longer apply, so the findings they covered are open again.",
    why: "Expiry dates make accepted risks get reviewed again instead of being forgotten.",
    fix: [
      "Fix the finding, or review the decision and set a new `expires` date in prelaunch-check.config.json.",
    ],
    fixPromptTemplate:
      "The suppression for {{detail.ruleId}} in prelaunch-check.config.json expired on {{detail.expires}}. Help me decide whether to fix the underlying finding or renew the suppression with a new reason and expiry date.",
    sources: [{ title: "Prelaunch Check config format (README: Config file)" }],
  },
  async check(ctx) {
    const out: RawFinding[] = [];
    for (const s of ctx.config.suppressions) {
      if (!s.expires || Date.parse(s.expires) > ctx.now.getTime()) continue;
      out.push({
        ruleId: "CFG-INFO-002",
        title: `Suppression for ${s.ruleId} expired on ${s.expires}`,
        location: { kind: "file", path: "prelaunch-check.config.json" },
        evidence: {
          detail: {
            ruleId: s.ruleId,
            expires: s.expires,
            reason: s.reason,
            target: s.fingerprint ?? s.path ?? "all findings",
          },
        },
      });
    }
    return out;
  },
};
