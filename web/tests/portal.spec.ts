import { expect, test } from '@playwright/test';

test.describe('account portal over local HTTPS', () => {
  test('renders an accessible account shell and does not expose secrets in storage', async ({ page }) => {
    await page.goto('/account');
    await expect(page).toHaveTitle(/Swan/);
    await expect(page.locator('main')).toBeVisible();
    expect(await page.evaluate(() => Object.keys(localStorage))).toEqual([]);
    expect(await page.evaluate(() => document.querySelector('script'))).toBeTruthy();
  });

  test('keeps the OAuth page script-free and uses the shared auth stylesheet', async ({ page }) => {
    await page.goto('/oauth/authorize');
    await expect(page.locator('link[href="/account/auth-tokens.css"]')).toHaveCount(1);
    await expect(page.locator('script')).toHaveCount(0);
  });
});
