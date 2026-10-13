import { describe, expect, it } from "vitest";
import { createOnlineServices, mapOsvSeverity, type OnlineStatus } from "../src/online/services.js";
import { mapGitleaks } from "../src/integrations/gitleaks.js";
import { limiter } from "../src/online/limit.js";
import { json } from "./helpers.js";

describe("online services", () => {
  it("maps GHSA severities", () => {
    expect(mapOsvSeverity({ database_specific: { severity: "CRITICAL" } })).toBe("critical");
    expect(mapOsvSeverity({ database_specific: { severity: "MODERATE" } })).toBe("medium");
    expect(mapOsvSeverity({})).toBeNull();
  });

  it("reports missing npm packages, encodes scoped names, and skips the full document for big packages", async () => {
    const calls: string[] = [];
    const status: OnlineStatus = { osv: "used", npmRegistry: "used" };
    const s = createOnlineServices(
      (async (input: string | URL | Request) => {
        const url = String(input);
        calls.push(url);
        if (url.endsWith("/ghost-pkg")) return new Response("{}", { status: 404 });
        if (url.endsWith("/@acme%2Fui")) return json({ versions: { "1.0.0": {} } });
        if (url.endsWith("/react"))
          return json({
            versions: Object.fromEntries(Array.from({ length: 50 }, (_, i) => [`1.${i}.0`, {}])),
          });
        return json({ time: { created: "2026-10-01T00:00:00.000Z" }, versions: { "1.0.0": {} } });
      }) as typeof fetch,
      status,
    );
    expect(await s.npmPackageInfo!("ghost-pkg")).toEqual({ exists: false });
    expect(await s.npmPackageInfo!("react")).toEqual({ exists: true });
    expect((await s.npmPackageInfo!("@acme/ui")).exists).toBe(true);
    expect(calls.filter((c) => c.endsWith("/react"))).toHaveLength(1); // abbreviated only
    expect(calls.filter((c) => c.endsWith("/@acme%2Fui"))).toHaveLength(2); // abbreviated + full
    await s.npmPackageInfo!("react"); // cached
    expect(calls.filter((c) => c.endsWith("/react"))).toHaveLength(1);
    expect(status.npmRegistry).toBe("used");
  });

  it("marks a service as failed on errors", async () => {
    const status: OnlineStatus = { osv: "used", npmRegistry: "used" };
    const s = createOnlineServices(
      (async () => new Response("down", { status: 503 })) as typeof fetch,
      status,
    );
    await expect(
      s.osvQueryBatch!([{ ecosystem: "npm", name: "a", version: "1.0.0", direct: true }]),
    ).rejects.toThrow();
    expect(status.osv).toBe("failed");
  });

  it("limits concurrency", async () => {
    const run = limiter(4);
    let active = 0;
    let peak = 0;
    await Promise.all(
      Array.from({ length: 20 }, () =>
        run(async () => {
          active++;
          peak = Math.max(peak, active);
          await new Promise((r) => setTimeout(r, 5));
          active--;
        }),
      ),
    );
    expect(peak).toBe(4);
  });
});

describe("gitleaks mapping", () => {
  it("keeps rule, file, line and short commit, and drops author, email and message", () => {
    const [f] = mapGitleaks([
      {
        Description: "Stripe Access Token",
        RuleID: "stripe-access-token",
        File: "src/old.ts",
        StartLine: 3,
        Commit: "0123456789abcdef0123456789abcdef01234567",
        // @ts-expect-error extra fields gitleaks emits
        Author: "Jane Doe",
        Email: "jane@example.com",
        Message: "oops",
        Secret: "REDACTED",
      },
    ]);
    expect(f).toMatchObject({
      ruleId: "SEC-006",
      title: "Stripe Access Token in git history (commit 0123456)",
      location: { kind: "file", path: "src/old.ts", line: 3 },
    });
    expect(JSON.stringify(f)).not.toMatch(/Jane|jane@|oops|REDACTED/);
  });
});
