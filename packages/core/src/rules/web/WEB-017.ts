import type { RawFinding, Rule } from "../../types.js";
import { webMeta } from "./meta.js";

const DAY = 86_400_000;

export const WEB_017: Rule = {
  meta: webMeta({
    id: "WEB-017",
    title: "TLS certificate expiring soon / weak protocol",
    severity: "medium",
    confidence: "high",
    owasp: "A04",
    summary:
      "Checks the HTTPS certificate is valid, expires more than 30 days from now, and that the connection uses TLS 1.2 or 1.3.",
    why: "When a certificate expires or is invalid, browsers show a full-page warning and most visitors leave. Old TLS versions have known weaknesses.",
    fix: [
      "Turn on automatic certificate renewal at your host (most managed hosts do this for you).",
      "Disable TLS 1.0 and 1.1 in your server or CDN settings.",
    ],
    fixPromptTemplate:
      "The HTTPS setup for {{url}} has a problem: {{detail.problem}}. Help me fix it at my host or CDN (automatic renewal, valid certificate chain, TLS 1.2+ only).",
    sources: [
      {
        title: "Mozilla server-side TLS guidelines",
        url: "https://wiki.mozilla.org/Security/Server_Side_TLS",
      },
    ],
  }),
  async check(ctx): Promise<RawFinding[]> {
    const site = ctx.site!;
    const tls = site.tls;
    if (!tls) return [];
    const url = site.target;
    if ("error" in tls) {
      return [
        {
          ruleId: "WEB-017",
          severity: "high",
          title: "TLS certificate is invalid",
          location: { kind: "url", url },
          evidence: {
            detail: { problem: `the certificate couldn't be verified (${tls.error.slice(0, 120)})` },
          },
        },
      ];
    }
    const out: RawFinding[] = [];
    const left = Date.parse(tls.validTo) - ctx.now.getTime();
    if (!Number.isNaN(left) && left < 30 * DAY) {
      const days = Math.floor(left / DAY);
      out.push({
        ruleId: "WEB-017",
        severity: left < 7 * DAY ? ("high" as const) : ("medium" as const),
        title:
          left <= 0
            ? "TLS certificate has expired"
            : `TLS certificate expires in ${days} day${days === 1 ? "" : "s"}`,
        location: { kind: "url" as const, url },
        evidence: {
          detail: {
            problem:
              left <= 0
                ? `the certificate expired on ${tls.validTo}`
                : `the certificate expires on ${tls.validTo}`,
            validTo: tls.validTo,
          },
        },
      });
    }
    if (!/^TLSv1\.[23]$/.test(tls.protocol)) {
      out.push({
        ruleId: "WEB-017",
        title: `Outdated TLS protocol (${tls.protocol})`,
        location: { kind: "url" as const, url },
        evidence: {
          detail: { problem: `the connection negotiated ${tls.protocol}`, protocol: tls.protocol },
        },
      });
    }
    return out;
  },
};
