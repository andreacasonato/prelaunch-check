// Web benchmark (Phase 9) and spike S1. Run with: BENCH_DIR=/path/to/project npx playwright test bench
import { expect, test } from "@playwright/test";

test.skip(!process.env.BENCH_DIR, "set BENCH_DIR to a project folder to benchmark");
test.setTimeout(180_000);

test("scan time for a large folder, including node_modules", async ({ page }) => {
  await page.goto("/#/scan");
  const t0 = Date.now();
  await page.locator("#folder").setInputFiles(process.env.BENCH_DIR!);
  await expect(page.getByRole("button", { name: "Start scan" })).toBeVisible({ timeout: 120_000 });
  const pickedMs = Date.now() - t0;
  const files = await page.locator(".stats dd").first().textContent();
  const skipped = await page.locator(".stats dd").nth(1).textContent();
  const t1 = Date.now();
  await page.getByRole("button", { name: "Start scan" }).click();
  await expect(page).toHaveURL(/#\/report$/, { timeout: 120_000 });
  const scanMs = Date.now() - t1;
  console.log(JSON.stringify({ pickedMs, scanMs, files, skipped }));
});
