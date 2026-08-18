import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';

describe('Tier 1 - F19: Production Build & Deployment', () => {
  it('T1-F19-01: Static SPA configuration: +layout.ts exports prerender=true and ssr=false', () => {
    const layoutPath = path.resolve(__dirname, '../../../src/routes/+layout.ts');
    expect(fs.existsSync(layoutPath)).toBe(true);

    const layoutContent = fs.readFileSync(layoutPath, 'utf8');
    expect(layoutContent).toContain('prerender = true');
    expect(layoutContent).toContain('ssr = false');
  });

  it('T1-F19-02: Strict CSP and shell template: app.html contains no external CDN scripts or stylesheet links', () => {
    const appHtmlPath = path.resolve(__dirname, '../../../src/app.html');
    expect(fs.existsSync(appHtmlPath)).toBe(true);

    const appHtml = fs.readFileSync(appHtmlPath, 'utf8');
    expect(appHtml).toContain('%sveltekit.head%');
    expect(appHtml).toContain('%sveltekit.body%');

    // CSP: No third-party tracking, fonts, or CDN imports
    expect(appHtml).not.toContain('https://cdn.');
    expect(appHtml).not.toContain('https://fonts.googleapis.com');
    expect(appHtml).not.toContain('https://unpkg.com');
  });

  it('T1-F19-03: Static build output directory contains compiled index.html and assets', () => {
    const buildIndexPath = path.resolve(__dirname, '../../../build/index.html');
    expect(fs.existsSync(buildIndexPath)).toBe(true);

    const indexHtml = fs.readFileSync(buildIndexPath, 'utf8');
    expect(indexHtml).toContain('_app/immutable');
  });

  it('T1-F19-04: Security cookie policies enforce SameSite=Strict and Secure flags', async () => {
    const env = setupTestEnv({ authenticated: false });
    const backend = env.backend;

    const resp = await fetch('/account/api/bootstrap');
    const setCookie = resp.headers.get('set-cookie');

    expect(setCookie).toBeDefined();
    expect(setCookie).toContain('SameSite=Strict');
    expect(setCookie).toContain('Secure');

    teardownTestEnv();
  });

  it('T1-F19-05: Cross-origin mutation defense rejects unauthorized Origin headers', async () => {
    const env = setupTestEnv({ authenticated: true });
    const session = env.session!;

    const resp = await fetch('/account/api/sessions/revoke-others', {
      method: 'POST',
      headers: {
        'Origin': 'https://attacker-domain.evil',
        'Content-Type': 'application/json',
        'X-Swan-CSRF': session.csrfToken
      },
      body: '{}'
    });

    expect(resp.status).toBe(403);
    const body = await resp.json();
    expect(body.code).toBe('request_not_allowed');

    teardownTestEnv();
  });
});
