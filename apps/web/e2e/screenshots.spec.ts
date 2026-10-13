// Design screenshots (Design Brief §7.3). Run with: SCREENSHOTS=1 npx playwright test screenshots
import { expect, test } from "@playwright/test";
import { join } from "node:path";
import { E2E_FIXTURES } from "./global-setup";

const OUT = join(import.meta.dirname, "..", "..", "..", "docs", "design");
test.skip(!process.env.SCREENSHOTS, "set SCREENSHOTS=1 to regenerate");

for (const width of [375, 1280]) {
  for (const scheme of ["light", "dark"] as const) {
    test(`screens ${width} ${scheme}`, async ({ page }) => {
      await page.setViewportSize({ width, height: width === 375 ? 812 : 900 });
      await page.emulateMedia({ colorScheme: scheme });
      const shot = (name: string) =>
        page.screenshot({ path: join(OUT, `${name}-${width}-${scheme}.png`), fullPage: true });
      await page.goto("/");
      await shot("W-01-home");
      await page.goto("/#/scan");
      await page.locator("#folder").setInputFiles(join(E2E_FIXTURES, "vuln-next-supabase"));
      await page.getByRole("button", { name: "Start scan" }).click();
      await expect(page.getByRole("heading", { level: 2, name: "Blocked" })).toBeVisible();
      await shot("W-04-report");
      await page.locator(".finding-row", { hasText: "credits" }).first().click();
      await expect(page.getByRole("heading", { name: "Where" })).toBeVisible();
      await page.waitForTimeout(250);
      await page.screenshot({
        path: join(OUT, `W-05-finding-${width}-${scheme}.png`),
        fullPage: width === 375,
      });
      await page.goto("/#/checklist");
      await shot("W-06-checklist");
    });
  }
}
