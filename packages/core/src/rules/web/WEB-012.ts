import type { RawFinding, Rule } from "../../types.js";
import { probeHits } from "./http.js";
import { DB_BOOK, webMeta } from "./meta.js";

export const WEB_012: Rule = {
  meta: webMeta({
    id: "WEB-012",
    title: "Admin page reachable without login",
    severity: "low",
    confidence: "low",
    owasp: "A01",
    summary:
      "Requests /admin and reports it when it returns a page with a form instead of 'not found'. Shown as Worth checking.",
    why: "A login form at /admin is normal, but it's also the first place attackers try passwords. Make sure it requires login, uses strong authentication and is rate-limited.",
    fix: [
      "Check that every admin action is protected on the server, not just hidden in the UI.",
      "Add rate limiting and multi-factor authentication to admin login; consider restricting it by IP or moving it to a private URL.",
    ],
    fixPromptTemplate:
      "My site has an admin page at {{url}}. Verify every admin route checks the user's role on the server, and add rate limiting and MFA to the admin login.",
    sources: [{ title: "Locking Down the Database", book: DB_BOOK }],
  }),
  async check(ctx) {
    return probeHits(ctx.site!, "admin").map(({ url }): RawFinding => ({
      ruleId: "WEB-012",
      location: { kind: "url", url },
      evidence: {},
    }));
  },
};
