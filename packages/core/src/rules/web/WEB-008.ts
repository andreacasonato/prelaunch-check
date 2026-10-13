import type { RawFinding, Rule } from "../../types.js";
import { header, OWASP_HEADERS, rootResponse } from "./http.js";
import { webMeta } from "./meta.js";

export const WEB_008: Rule = {
  meta: webMeta({
    id: "WEB-008",
    title: "Server/framework version disclosed",
    severity: "low",
    confidence: "high",
    owasp: "A02",
    summary: "Flags an X-Powered-By header, or a Server header that includes a version number.",
    why: "Version numbers tell attackers exactly which known vulnerabilities to try. Removing them doesn't fix anything by itself, but it stops making their job easy.",
    fix: [
      "Remove X-Powered-By (Express: `app.disable('x-powered-by')`; Next.js: `poweredByHeader: false`).",
      "Configure your server or proxy to send the Server header without a version (nginx: `server_tokens off;`).",
    ],
    fixPromptTemplate:
      "{{url}} sends `{{detail.header}}: {{detail.value}}`. Remove the X-Powered-By header and strip version numbers from the Server header in my framework or server config.",
    sources: [{ title: "OWASP Secure Headers Project (headers to remove)", url: OWASP_HEADERS }],
  }),
  async check(ctx) {
    const site = ctx.site!;
    const r = rootResponse(site);
    const out: RawFinding[] = [];
    const powered = header(r, "x-powered-by");
    if (powered)
      out.push({
        ruleId: "WEB-008",
        title: `X-Powered-By header reveals "${powered.slice(0, 60)}"`,
        location: { kind: "url", url: site.target },
        evidence: { detail: { header: "X-Powered-By", value: powered.slice(0, 100) } },
      });
    const server = header(r, "server");
    if (server && /\d/.test(server))
      out.push({
        ruleId: "WEB-008",
        title: `Server header reveals a version: "${server.slice(0, 60)}"`,
        location: { kind: "url", url: site.target },
        evidence: { detail: { header: "Server", value: server.slice(0, 100) } },
      });
    return out;
  },
};
