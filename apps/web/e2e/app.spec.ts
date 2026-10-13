import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { join } from "node:path";
import { E2E_FIXTURES } from "./global-setup";

const ORIGIN = "http://127.0.0.1:4173";

/** Fails the test on any request to another origin, and on CSP violations. */
function guard(page: Page) {
  const foreign: string[] = [];
  const cspErrors: string[] = [];
  page.on("request", (r) => {
    const u = r.url();
    if (!u.startsWith(ORIGIN) && !u.startsWith("blob:") && !u.startsWith("data:")) foreign.push(u);
  });
  page.on("console", (m) => {
    if (m.type() === "error" && /Content Security Policy/i.test(m.text())) cspErrors.push(m.text());
  });
  return { foreign, cspErrors };
}

async function axe(page: Page) {
  const results = await new AxeBuilder({ page }).analyze();
  return results.violations
    .filter((v) => v.impact === "serious" || v.impact === "critical")
    .map((v) => `${v.id}: ${v.help}`);
}

async function scanFixture(page: Page, name: string) {
  await page.goto("/#/scan");
  await page.locator("#folder").setInputFiles(join(E2E_FIXTURES, name));
  await expect(page.getByRole("heading", { name })).toBeVisible();
  await page.getByRole("button", { name: "Start scan" }).click();
  await expect(page).toHaveURL(/#\/report$/);
}

test("home has no serious accessibility violations and makes no third-party requests @mobile", async ({
  page,
}) => {
  const g = guard(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    "Find the security holes in your app before you launch.",
  );
  expect(await axe(page)).toEqual([]);
  expect(g.foreign).toEqual([]);
  expect(g.cspErrors).toEqual([]);
});

test("scanning the vulnerable fixture shows Blocked, with zero network requests during the scan", async ({
  page,
}) => {
  const g = guard(page);
  await page.goto("/");
  const before = g.foreign.length;
  await scanFixture(page, "vuln-next-supabase");
  await expect(page.getByRole("heading", { level: 2, name: "Blocked" })).toBeVisible();
  await expect(
    page.getByText("Stripe live secret key in a client-exposed environment variable").first(),
  ).toBeVisible();
  expect(g.foreign.length).toBe(before);
  expect(g.cspErrors).toEqual([]);
  expect(await axe(page)).toEqual([]);
});

test("the clean fixture shows No blocking issues found", async ({ page }) => {
  await scanFixture(page, "clean-next-supabase");
  await expect(page.getByRole("heading", { level: 2, name: "No blocking issues found" })).toBeVisible();
});

test("finding detail opens as a dialog, is accessible, closes with Escape and returns focus", async ({
  page,
}) => {
  await scanFixture(page, "vuln-next-supabase");
  const row = page.locator(".finding-row", { hasText: "Stripe live secret key" }).first();
  await row.focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("heading", { name: "Where" })).toBeVisible();
  await expect(dialog.getByRole("heading", { name: "Copy fix prompt" })).toBeVisible();
  // The secret is redacted in the excerpt.
  await expect(dialog.locator(".redacted").first()).toBeVisible();
  expect(await axe(page)).toEqual([]);
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(page.locator(".finding-row:focus")).toHaveCount(1);
});

test("accepting a risk needs a reason and updates the verdict", async ({ page }) => {
  await scanFixture(page, "vuln-next-supabase");
  for (const title of ["Stripe live secret key", "Server-side Stripe SDK"]) {
    await page.locator(".finding-row", { hasText: title }).first().click();
    await page.getByRole("button", { name: "Mark as accepted risk" }).click();
    await expect(page.getByRole("button", { name: "Save" })).toBeDisabled();
    await page.getByLabel(/Reason/).fill("Test key only used in a demo");
    await page.getByRole("button", { name: "Save" }).click();
    await page.keyboard.press("Escape");
  }
  await expect(page.getByRole("heading", { level: 2, name: "Needs attention" })).toBeVisible();
});

test("keyboard focus is never hidden behind the sticky filter bar", async ({ page }) => {
  await scanFixture(page, "vuln-next-supabase");
  await page.locator(".filter-bar .pill").last().focus();
  let checked = 0;
  for (let i = 0; i < 60; i++) {
    await page.keyboard.press("Tab");
    const isRow = await page.evaluate(
      () => document.activeElement?.classList.contains("finding-row") ?? false,
    );
    if (!isRow) continue;
    const bar = await page.locator(".filter-bar").boundingBox();
    const box = await page.locator(".finding-row:focus").boundingBox();
    if (bar && box && bar.y <= 1) expect(box.y).toBeGreaterThanOrEqual(bar.y + bar.height - 1);
    checked++;
  }
  expect(checked).toBeGreaterThan(5);
  // And back up with Shift+Tab, where the bar is most likely to cover the target.
  for (let i = 0; i < 30; i++) {
    await page.keyboard.press("Shift+Tab");
    const isRow = await page.evaluate(
      () => document.activeElement?.classList.contains("finding-row") ?? false,
    );
    if (!isRow) continue;
    const bar = await page.locator(".filter-bar").boundingBox();
    const box = await page.locator(".finding-row:focus").boundingBox();
    if (bar && box && bar.y <= 1) expect(box.y).toBeGreaterThanOrEqual(bar.y + bar.height - 1);
  }
});

test("checklist is accessible and remembers ticks @mobile", async ({ page }) => {
  await page.goto("/#/checklist");
  expect(await axe(page)).toEqual([]);
  await page.getByLabel("Can I give myself premium or credits by editing my own data?").check();
  await page.reload();
  await expect(page.getByLabel("Can I give myself premium or credits by editing my own data?")).toBeChecked();
  await expect(page.getByText("1 / 18 done")).toBeVisible();
});

test("opening a report file works, and junk files are rejected", async ({ page }) => {
  await page.goto("/#/open");
  await page.locator("#report-file").setInputFiles({
    name: "x.json",
    mimeType: "application/json",
    buffer: Buffer.from('{"hello":"world"}'),
  });
  await expect(page.getByRole("alert")).toHaveText("This doesn't look like a Prelaunch Check report.");
});

test("live-site and docs pages are accessible @mobile", async ({ page }) => {
  for (const path of ["/#/live", "/#/docs", "/#/docs/rules/DB-003", "/#/docs/scoring", "/#/docs/privacy"]) {
    await page.goto(path);
    expect(await axe(page), path).toEqual([]);
  }
});

test("finding detail is a full page on mobile @mobile", async ({ page }) => {
  await scanFixture(page, "vuln-next-supabase");
  await page.locator(".finding-row").first().click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Where" })).toBeVisible();
  expect(await axe(page)).toEqual([]);
});

test("exports JSON, Markdown, SARIF and a script-free HTML report", async ({ page }) => {
  await scanFixture(page, "vuln-next-supabase");
  const grab = async (name: string) => {
    const [dl] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("button", { name, exact: true }).click(),
    ]);
    const path = await dl.path();
    return (await import("node:fs")).readFileSync(path!, "utf8");
  };
  expect(JSON.parse(await grab("JSON")).summary.verdict).toBe("blocked");
  expect(await grab("Markdown")).toContain("# Prelaunch Check report: vuln-next-supabase");
  expect(JSON.parse(await grab("SARIF")).version).toBe("2.1.0");
  const html = await grab("HTML");
  expect(html).toContain("Content-Security-Policy");
  expect(html).not.toMatch(/<script/i);
});

test("decisions in an opened report can be saved into this browser", async ({ page }) => {
  await scanFixture(page, "vuln-next-supabase");
  await page.locator(".finding-row", { hasText: "Stripe live secret key" }).first().click();
  await page.getByRole("button", { name: "Mark as accepted risk" }).click();
  await page.getByLabel(/Reason/).fill("Demo key");
  await page.getByRole("button", { name: "Save" }).click();
  await page.keyboard.press("Escape");
  const [dl] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "JSON", exact: true }).click(),
  ]);
  const reportPath = await dl.path();
  // A fresh browser profile: open the exported file and import its decision.
  await page.evaluate(() => localStorage.clear());
  await page.goto("/#/open");
  await page.locator("#report-file").setInputFiles(reportPath!);
  await expect(page.getByText("This report includes 1 recorded decision.")).toBeVisible();
  await page.getByRole("button", { name: "Save them in this browser" }).click();
  await expect(page.getByText(/Saved 1 decisions in this browser/)).toBeVisible();
});
