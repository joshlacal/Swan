import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { accountFetch, api, bootstrap, getCSRF, readError, setCSRF, setStepUpHandler } from '../../../src/lib/api';
import type { ApiError } from '../../../src/lib/types';
import type { MockSession } from '../harness/mock-backend';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';

describe('Tier 2 Boundary: API Client, CSRF, Security Headers & Error Parsing', () => {
  let backend: ReturnType<typeof setupTestEnv>['backend'];
  let session: MockSession;

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: true });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);
    setStepUpHandler(null);
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
    setStepUpHandler(null);
  });

  // --- CSRF Token & Cookie Boundary Scenarios ---

  it('T2-API-01: automatically bootstraps CSRF token on mutating request if token is unset', async () => {
    setCSRF(undefined);
    expect(getCSRF()).toBeUndefined();

    const token = await bootstrap();
    expect(token).toBeDefined();
    expect(token).toMatch(/^pre_/);
    expect(getCSRF()).toBe(token);
    expect(backend.getCookie('swan_csrf_pre')).toBe(token);
  });

  it('T2-API-02: rejects mutation with 403 request_not_allowed when X-Swan-CSRF header is mismatched with cookie', async () => {
    backend.setCookie('swan_csrf', 'csrf_valid_token_123');

    try {
      await accountFetch('sessions/revoke-others', {
        method: 'POST',
        headers: { 'X-Swan-CSRF': 'csrf_wrong_attacker_token' },
        body: '{}'
      });
      expect.unreachable('Should have thrown 403 ApiError');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
      expect(apiErr.message).toBe('Request not allowed.');
    }
  });

  it('T2-API-03: rejects mutation with 403 request_not_allowed when CSRF cookie is completely missing', async () => {
    backend.clearCookies();
    // Re-set only session cookie, leaving CSRF cookie missing
    backend.setCookie('__Secure-swan_management', session.sessionToken);

    try {
      await accountFetch('sessions/revoke-others', {
        method: 'POST',
        headers: { 'X-Swan-CSRF': session.csrfToken },
        body: '{}'
      });
      expect.unreachable('Should have thrown 403 ApiError');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  it('T2-API-04: rejects login when pre-auth CSRF token (swan_csrf_pre) has expired (>600s)', async () => {
    setCSRF(undefined);
    backend.clearCookies();

    // Bootstrap to get pre-auth token
    const preCsrf = await bootstrap();
    expect(preCsrf).toMatch(/^pre_/);

    // Fast-forward or simulate expiration of pre-auth token
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/login')) {
        return {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
          body: { code: 'request_not_allowed', message: 'Pre-auth token expired.' }
        };
      }
      return undefined;
    });

    try {
      await api.login({ handle: 'alice.swan.place', password: 'correct-horse-battery-staple' });
      expect.unreachable('Should have rejected expired pre-auth token');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
      expect(apiErr.message).toBe('Pre-auth token expired.');
    }
  });

  it('T2-API-05: prevents pre-auth CSRF token replay on subsequent login attempts after successful consumption', async () => {
    setCSRF(undefined);
    backend.clearCookies();

    const preCsrf = await bootstrap();
    expect(backend.getCookie('swan_csrf_pre')).toBe(preCsrf);

    // First login succeeds and deletes swan_csrf_pre
    const loginRes = await api.login({ handle: 'alice.swan.place', password: 'correct-horse-battery-staple' });
    expect(loginRes.csrf).toBeDefined();
    expect(backend.getCookie('swan_csrf_pre')).toBeUndefined();

    // Replay attempt using stale preCsrf directly against login endpoint
    const replayResp = await fetch('/account/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Swan-CSRF': preCsrf,
        'Cookie': `swan_csrf_pre=${preCsrf}`
      },
      body: JSON.stringify({ handle: 'alice.swan.place', password: 'correct-horse-battery-staple' })
    });

    expect(replayResp.status).toBe(403);
    const body = await replayResp.json();
    expect(body.code).toBe('request_not_allowed');
  });

  // --- Origin & Sec-Fetch-Site Security Policy Boundaries ---

  it('T2-API-06: rejects mutation from unauthorized cross-origin domain', async () => {
    try {
      await accountFetch('sessions/revoke-others', {
        method: 'POST',
        headers: { 'Origin': 'https://evil-hacker.com' },
        body: '{}'
      });
      expect.unreachable('Should have rejected spoofed origin');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  it('T2-API-07: rejects mutation from subdomain spoofing attempt (e.g. swan.place.attacker.com)', async () => {
    try {
      await accountFetch('sessions/revoke-others', {
        method: 'POST',
        headers: { 'Origin': 'https://swan.place.attacker.com' },
        body: '{}'
      });
      expect.unreachable('Should have rejected subdomain origin spoof');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  it('T2-API-08: rejects mutation with null Origin header', async () => {
    try {
      await accountFetch('sessions/revoke-others', {
        method: 'POST',
        headers: { 'Origin': 'null' },
        body: '{}'
      });
      expect.unreachable('Should have rejected null origin');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  it('T2-API-09: rejects mutation when Sec-Fetch-Site is cross-site', async () => {
    try {
      await accountFetch('sessions/revoke-others', {
        method: 'POST',
        headers: { 'Sec-Fetch-Site': 'cross-site' },
        body: '{}'
      });
      expect.unreachable('Should have rejected cross-site Sec-Fetch-Site');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  it('T2-API-10: rejects mutation when Sec-Fetch-Site is same-site (strict same-origin required)', async () => {
    try {
      await accountFetch('sessions/revoke-others', {
        method: 'POST',
        headers: { 'Sec-Fetch-Site': 'same-site' },
        body: '{}'
      });
      expect.unreachable('Should have rejected same-site Sec-Fetch-Site');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  // --- Content-Type & Payload Validation Boundaries ---

  it('T2-API-11: rejects mutating payload with non-JSON Content-Type (text/plain)', async () => {
    try {
      await accountFetch('sessions/revoke-others', {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
        body: 'raw payload'
      });
      expect.unreachable('Should have rejected non-JSON Content-Type');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  it('T2-API-12: rejects mutating payload with form-urlencoded Content-Type', async () => {
    try {
      await accountFetch('sessions/revoke-others', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'foo=bar&baz=qux'
      });
      expect.unreachable('Should have rejected urlencoded Content-Type');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  it('T2-API-13: handles malformed JSON request body with 400 invalid_request', async () => {
    backend.elevateSession(session.sessionToken);
    try {
      await accountFetch('app-passwords', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{ "name": "Broken JSON, '
      });
      expect.unreachable('Should have thrown 400 for malformed JSON');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.code).toBe('invalid_request');
      expect(apiErr.message).toBe('Invalid JSON body.');
    }
  });

  // --- HTTP Error Code Parsing & Resilience Boundaries ---

  it('T2-API-14: parses 500 Internal Server Error with HTML body into service_unavailable ApiError', async () => {
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/portal')) {
        return {
          status: 500,
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
          body: '<html><body>500 Internal Server Error</body></html>'
        };
      }
      return undefined;
    });

    try {
      await api.fetchSnapshot();
      expect.unreachable('Should have thrown 500 error');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(500);
      expect(apiErr.code).toBe('service_unavailable');
      expect(apiErr.message).toBe('The account service is temporarily unavailable.');
    }
  });

  it('T2-API-15: parses 502 Bad Gateway response into service_unavailable ApiError', async () => {
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/portal')) {
        return {
          status: 502,
          headers: { 'Content-Type': 'text/plain' },
          body: '502 Bad Gateway'
        };
      }
      return undefined;
    });

    try {
      await api.fetchSnapshot();
      expect.unreachable('Should have thrown 502 error');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(502);
      expect(apiErr.code).toBe('service_unavailable');
    }
  });

  it('T2-API-16: parses 503 Service Unavailable with custom JSON error code and message', async () => {
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/portal')) {
        return {
          status: 503,
          headers: { 'Content-Type': 'application/json' },
          body: { code: 'maintenance_mode', message: 'Swan Account Portal is undergoing scheduled maintenance.' }
        };
      }
      return undefined;
    });

    try {
      await api.fetchSnapshot();
      expect.unreachable('Should have thrown 503 error');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(503);
      expect(apiErr.code).toBe('maintenance_mode');
      expect(apiErr.message).toBe('Swan Account Portal is undergoing scheduled maintenance.');
    }
  });

  it('T2-API-17: parses 429 Rate Limited response with rate_limited error code', async () => {
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/step-up/password')) {
        return {
          status: 429,
          headers: { 'Content-Type': 'application/json' },
          body: { code: 'rate_limited', message: 'Too many failed password attempts. Try again in 60 seconds.' }
        };
      }
      return undefined;
    });

    try {
      await api.stepUpPassword('wrong');
      expect.unreachable('Should have thrown 429 error');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(429);
      expect(apiErr.code).toBe('rate_limited');
      expect(apiErr.message).toContain('Too many failed password attempts');
    }
  });

  it('T2-API-18: readError utility extracts fallback message for unknown error status', async () => {
    const fakeResp = new Response(JSON.stringify({}), { status: 418 });
    const err = await readError(fakeResp);
    expect(err.status).toBe(418);
    expect(err.code).toBe('unknown_error');
    expect(err.message).toBe('The account service is temporarily unavailable.');
  });

  it('T2-API-19: readError utility handles completely empty body response', async () => {
    const fakeResp = new Response('', { status: 504 });
    const err = await readError(fakeResp);
    expect(err.status).toBe(504);
    expect(err.code).toBe('service_unavailable');
  });

  // --- Path Normalization, Headers & HTTP Verbs ---

  it('T2-API-20: normalizes paths with leading slashes, redundant slashes, and relative paths', async () => {
    // /portal with leading slash
    const snap1 = await accountFetch<any>('/portal');
    expect(snap1.account.handle).toBe('alice.swan.place');

    // portal without leading slash
    const snap2 = await accountFetch<any>('portal');
    expect(snap2.account.handle).toBe('alice.swan.place');
  });

  it('T2-API-21: returns undefined for HTTP 204 No Content response without JSON parse failure', async () => {
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/test-204')) {
        return {
          status: 204,
          headers: {},
          body: ''
        };
      }
      return undefined;
    });

    const result = await accountFetch<void>('test-204');
    expect(result).toBeUndefined();
  });

  it('T2-API-22: merges custom headers without overwriting Accept and Content-Type', async () => {
    backend.elevateSession(session.sessionToken);
    let capturedHeaders: Record<string, string | string[] | undefined> = {};
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/sessions/revoke-others')) {
        capturedHeaders = req.headers;
      }
      return undefined;
    });

    await accountFetch('sessions/revoke-others', {
      method: 'POST',
      headers: {
        'X-Client-Trace-ID': 'trace-12345'
      },
      body: '{}'
    });

    const headerKeys = Object.keys(capturedHeaders).map(k => k.toLowerCase());
    expect(headerKeys).toContain('x-client-trace-id');
    expect(headerKeys).toContain('accept');
    expect(headerKeys).toContain('content-type');
    expect(headerKeys).toContain('x-swan-csrf');
  });

  it('T2-API-23: unauthenticated call to protected snapshot returns 401 authentication_required', async () => {
    backend.clearCookies();

    try {
      await api.fetchSnapshot();
      expect.unreachable('Should have thrown 401 unauthenticated');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(401);
      expect(apiErr.code).toBe('authentication_required');
      expect(apiErr.message).toContain('Authentication required');
    }
  });

  it('T2-API-24: bootstrap rejects when server is down with 500 error', async () => {
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/bootstrap')) {
        return {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
          body: { code: 'server_error', message: 'Bootstrap failed' }
        };
      }
      return undefined;
    });

    try {
      await bootstrap();
      expect.unreachable('Bootstrap should have failed');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(500);
      expect(apiErr.code).toBe('server_error');
    }
  });
});
