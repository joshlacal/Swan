import { expect, test } from '@playwright/test';

test.describe('account portal over local HTTPS', () => {
  test('renders an accessible account shell and does not expose secrets in storage', async ({ page }) => {
    await page.goto('/account');
    await expect(page).toHaveTitle(/Swan/);
    await expect(page.locator('main')).toBeVisible();
    expect(await page.evaluate(() => Object.keys(localStorage))).toEqual([]);
    expect(await page.evaluate(() => document.querySelector('script'))).toBeTruthy();
  });

  test('keeps the OAuth page script-free and self-contained', async ({ page }) => {
    await page.goto('/oauth/authorize');
    // The OAuth pages inline their daisyUI stylesheet under a CSP hash, so they
    // fetch no stylesheet and run no script.
    await expect(page.locator('link[rel="stylesheet"]')).toHaveCount(0);
    await expect(page.locator('script')).toHaveCount(0);
  });
});
