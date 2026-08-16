import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  timeout: 15_000,
  use: { baseURL: process.env.SWAN_PORTAL_TEST_URL ?? 'https://127.0.0.1:3443', ignoreHTTPSErrors: true },
  reporter: [['list']]
});
