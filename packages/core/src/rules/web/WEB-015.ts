import type { RawFinding, Rule } from "../../types.js";
import { header, res } from "./http.js";
import { CORS_TEST_ORIGIN } from "./probes.js";
import { webMeta } from "./meta.js";

export const WEB_015: Rule = {
  meta: webMeta({
    id: "WEB-015",
    title: "CORS reflects any origin with credentials",
    severity: "high",
    confidence: "high",
    owasp: "A01",
    summary: `Sends one ordinary GET with Origin: ${CORS_TEST_ORIGIN} and checks whether the response allows that origin with credentials.`,
    why: "If your server echoes back any Origin and allows credentials, any website your users visit can call your API with their cookies and read the answers: their data, their account, their actions.",
    fix: [
      "Only allow an explicit list of your own front-end origins.",
      "Don't combine a reflected origin with Access-Control-Allow-Credentials: true.",
    ],
    fixPromptTemplate:
      "{{url}} reflects any Origin in Access-Control-Allow-Origin and allows credentials. Replace the reflection with an explicit allow-list of my front-end origins in the CORS configuration.",
    sources: [
      { title: "MDN: CORS", url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS" },
      { title: "RFC 2606 (.invalid is reserved)", url: "https://www.rfc-editor.org/rfc/rfc2606" },
    ],
  }),
  async check(ctx) {
    const out: RawFinding[] = [];
    for (const c of ctx.site!.corsChecks) {
      const r = res(c.exchange);
      if (!r) continue;
      if (
        header(r, "access-control-allow-origin") === CORS_TEST_ORIGIN &&
        (header(r, "access-control-allow-credentials") ?? "").trim().toLowerCase() === "true"
      ) {
        out.push({
          ruleId: "WEB-015",
          location: { kind: "url", url: c.url },
          evidence: { detail: { origin: CORS_TEST_ORIGIN } },
        });
      }
    }
    return out;
  },
};
