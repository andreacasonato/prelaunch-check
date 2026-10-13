import type { RawFinding, Rule } from "../../types.js";
import { headers, res } from "./http.js";
import { webMeta } from "./meta.js";

const SESSION_LIKE = /sess|sid|auth|token|jwt/i;

export const WEB_009: Rule = {
  meta: webMeta({
    id: "WEB-009",
    title: "Cookie missing security attributes",
    severity: "low",
    confidence: "medium",
    owasp: "A07",
    summary:
      "Checks every Set-Cookie on the page: Secure on HTTPS, HttpOnly for session-like cookies, an explicit SameSite, and Secure whenever SameSite=None.",
    why: "Session cookies are the keys to your users' accounts. Without HttpOnly, injected scripts can steal them; without Secure, they can travel over plain HTTP; without SameSite, other sites can make requests that carry them.",
    fix: [
      "Set session cookies with `Secure; HttpOnly; SameSite=Lax` (or `Strict`). Most auth libraries have options for these.",
    ],
    fixPromptTemplate:
      "The cookie `{{detail.cookie}}` set by {{url}} is missing: {{detail.missing}}. Update the code or auth library settings that set it so it has Secure, HttpOnly (if it's a session cookie) and an explicit SameSite attribute.",
    falsePositiveNotes:
      "Session-like names are guessed from the cookie name (sess, sid, auth, token, jwt). Cookies set later by JavaScript aren't seen.",
    sources: [
      {
        title: "MDN: Set-Cookie",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie",
      },
    ],
  }),
  async check(ctx) {
    const site = ctx.site!;
    const r = res(site.root);
    const https = new URL(site.target).protocol === "https:";
    const out: RawFinding[] = [];
    for (const raw of headers(r, "set-cookie")) {
      const [pair, ...attrs] = raw.split(";").map((s) => s.trim());
      const name = (pair ?? "").split("=")[0]!.trim();
      if (!name) continue;
      const lower = attrs.map((a) => a.toLowerCase());
      const has = (a: string) => lower.some((x) => x === a || x.startsWith(`${a}=`));
      const sameSite = lower.find((x) => x.startsWith("samesite="))?.slice(9);
      const sessionLike = SESSION_LIKE.test(name);
      const missing: string[] = [];
      if (!has("secure") && sameSite === "none") missing.push("Secure (required with SameSite=None)");
      else if (https && !has("secure")) missing.push("Secure");
      if (sessionLike && !has("httponly")) missing.push("HttpOnly");
      if (!sameSite) missing.push("SameSite");
      if (!missing.length) continue;
      const f: RawFinding = {
        ruleId: "WEB-009",
        title: `Cookie "${name}" is missing ${missing.join(", ")}`,
        location: { kind: "url", url: site.target },
        evidence: { detail: { cookie: name, missing: missing.join(", "), sessionLike } },
      };
      if (sessionLike) f.severity = "medium";
      out.push(f);
    }
    return out;
  },
};
