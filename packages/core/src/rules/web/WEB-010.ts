import type { RawFinding, Rule } from "../../types.js";
import { probeHits } from "./http.js";
import { DB_BOOK, webMeta } from "./meta.js";

export const WEB_010: Rule = {
  meta: webMeta({
    id: "WEB-010",
    title: "Sensitive file publicly accessible",
    severity: "critical",
    confidence: "high",
    owasp: "A02",
    summary:
      "Requests a fixed list of paths (/.env, /.git/HEAD, /.git/config, /.npmrc, /.DS_Store, backup zips) and reports any that return real content rather than a 'not found' page.",
    why: "These files often contain secrets (.env, .npmrc), your entire source code and history (.git), or a list of your private files (.DS_Store). Bots request them on every site they find.",
    fix: [
      "Delete the file from your deployed output, or configure your host to block dotfiles and archives.",
      "Rotate every secret the file contained: assume it has been downloaded.",
      "Deploy from a build folder instead of your whole project folder.",
    ],
    fixPromptTemplate:
      "My site serves {{detail.label}} publicly at {{url}}. Make sure it's not part of the deployed output (deploy only the build folder, and block dotfiles and *.zip in the host config), then remind me to rotate any secrets it contained.",
    falsePositiveNotes:
      "A path only counts when it returns status 200, passes a content check (for example a VAR=value line for .env), and differs from the site's normal 'not found' page.",
    sources: [
      {
        title: "OWASP WSTG: Review old backup and unreferenced files",
        url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
      },
      { title: "Locking Down the Database", book: DB_BOOK },
    ],
  }),
  async check(ctx) {
    return probeHits(ctx.site!, "sensitive-file").map(({ probe, url }): RawFinding => ({
      ruleId: "WEB-010",
      severity: probe.severity,
      title: `${probe.label} is publicly accessible`,
      location: { kind: "url", url },
      evidence: { detail: { label: probe.label, path: probe.path } },
    }));
  },
};
