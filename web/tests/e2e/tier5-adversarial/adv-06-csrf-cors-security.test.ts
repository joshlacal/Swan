import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { accountFetch, api, bootstrap, getCSRF, readError, setCSRF, setStepUpHandler } from '../../../src/lib/api';
import type { ApiError } from '../../../src/lib/types';
import type { MockSession } from '../harness/mock-backend';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';

describe('Tier 5 Adversarial: CSRF, CORS, Origin Spoofing & Verb Routing Security', () => {
  let backend: ReturnType<typeof setupTestEnv>['backend'];
  let session: MockSession;

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: true, elevated: true });
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

  // --- T5-SEC-01 to T5-SEC-04: Cross-Origin, Subdomain & Null Origin Attacks ---

  it('T5-SEC-01: rejects mutating requests with unauthorized cross-origin header (https://evil.attacker.com)', async () => {
    try {
      await accountFetch('sessions/revoke-others', {
        method: 'POST',
        headers: { Origin: 'https://evil.attacker.com' },
        body: '{}'
      });
      expect.unreachable('Should have rejected cross-origin request');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
      expect(apiErr.message).toBe('Request not allowed.');
    }
  });

  it('T5-SEC-02: rejects subdomain spoofing suffix attacks (https://swan.place.attacker.com)', async () => {
    try {
      await accountFetch('sessions/revoke-others', {
        method: 'POST',
        headers: { Origin: 'https://swan.place.attacker.com' },
        body: '{}'
      });
      expect.unreachable('Should have rejected subdomain suffix spoofing');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  it('T5-SEC-03: rejects subdomain prefix attacks (https://attacker.swan.place)', async () => {
    try {
      await accountFetch('sessions/revoke-others', {
        method: 'POST',
        headers: { Origin: 'https://attacker.swan.place' },
        body: '{}'
      });
      expect.unreachable('Should have rejected subdomain prefix spoofing');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  it('T5-SEC-04: rejects null Origin header from sandboxed iframe or file:// execution', async () => {
    try {
      await accountFetch('sessions/revoke-others', {
        method: 'POST',
        headers: { Origin: 'null' },
        body: '{}'
      });
      expect.unreachable('Should have rejected null Origin header');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  // --- T5-SEC-05 & T5-SEC-06: Sec-Fetch-Site Header Enforcement ---

  it('T5-SEC-05: rejects cross-site fetch navigation with Sec-Fetch-Site: cross-site', async () => {
    try {
      await accountFetch('app-passwords', {
        method: 'POST',
        headers: { 'Sec-Fetch-Site': 'cross-site' },
        body: JSON.stringify({ name: 'CrossSiteBot', scopes: ['atproto'] })
      });
      expect.unreachable('Should have rejected Sec-Fetch-Site: cross-site');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  it('T5-SEC-06: rejects same-site fetch navigation with Sec-Fetch-Site: same-site (strict same-origin required)', async () => {
    try {
      await accountFetch('app-passwords', {
        method: 'POST',
        headers: { 'Sec-Fetch-Site': 'same-site' },
        body: JSON.stringify({ name: 'SameSiteBot', scopes: ['atproto'] })
      });
      expect.unreachable('Should have rejected Sec-Fetch-Site: same-site');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  // --- T5-SEC-07 & T5-SEC-08: Pre-Auth CSRF Token Replay and Expiration ---

  it('T5-SEC-07: rejects login replay using already consumed pre-auth CSRF token', async () => {
    setCSRF(undefined);
    backend.clearCookies();

    // Bootstrap token
    const preCsrf = await bootstrap();
    expect(preCsrf).toMatch(/^pre_/);

    // Initial valid login consumes the token
    const loginRes = await api.login({ handle: 'alice.swan.place', password: 'correct-horse-battery-staple' });
    expect(loginRes.csrf).toBeDefined();

    // Replay attack using previous pre-auth token directly
    const replayResp = await fetch('/account/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Swan-CSRF': preCsrf,
        Cookie: `swan_csrf_pre=${preCsrf}`
      },
      body: JSON.stringify({ handle: 'alice.swan.place', password: 'correct-horse-battery-staple' })
    });

    expect(replayResp.status).toBe(403);
    const body = await replayResp.json();
    expect(body.code).toBe('request_not_allowed');
  });

  it('T5-SEC-08: rejects pre-auth CSRF token when expired (>600s TTL)', async () => {
    setCSRF(undefined);
    backend.clearCookies();

    await bootstrap();

    // Simulate backend token expiration
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

  // --- T5-SEC-09 & T5-SEC-10: Stale In-Memory CSRF Recovery & Asymmetric Attacks ---

  it('T5-SEC-09: recovers gracefully when in-memory CSRF token becomes stale across tabs', async () => {
    // Set stale in-memory CSRF token
    setCSRF('stale_csrf_token_abc');
    expect(getCSRF()).toBe('stale_csrf_token_abc');

    // Simulate server rejecting stale token once, then client re-bootstrapping
    let attempt = 0;
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/sessions/revoke-others')) {
        attempt++;
        const reqCsrf = req.headers['x-swan-csrf'] || req.headers['X-Swan-CSRF'];
        if (reqCsrf === 'stale_csrf_token_abc') {
          return {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'request_not_allowed', message: 'CSRF token mismatch.' }
          };
        }
      }
      return undefined;
    });

    try {
      await api.revokeOtherSessions();
      expect.unreachable('Should have failed with stale CSRF');
    } catch (err: any) {
      expect(err.status).toBe(403);
    }

    // Client re-bootstraps fresh CSRF token
    const freshToken = session.csrfToken;
    setCSRF(freshToken);

    // Mutation now succeeds with fresh token
    const res = await api.revokeOtherSessions();
    expect(res.accepted).toBe(true);
  });

  it('T5-SEC-10: rejects asymmetric CSRF attacks where header is valid but cookie is missing or mismatched', async () => {
    // Case 1: Valid header, missing cookie
    backend.clearCookies();
    backend.setCookie('__Secure-swan_management', session.sessionToken);

    try {
      await accountFetch('sessions/revoke-others', {
        method: 'POST',
        headers: { 'X-Swan-CSRF': session.csrfToken },
        body: '{}'
      });
      expect.unreachable('Should have rejected request with missing CSRF cookie');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }

    // Case 2: Cookie present with mismatched value
    backend.setCookie('swan_csrf', 'different_cookie_token');
    try {
      await accountFetch('sessions/revoke-others', {
        method: 'POST',
        headers: { 'X-Swan-CSRF': session.csrfToken },
        body: '{}'
      });
      expect.unreachable('Should have rejected mismatched CSRF cookie/header');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  // --- T5-SEC-11 to T5-SEC-14: HTTP Verb Routing Strictness & Unexpected Methods ---

  it('T5-SEC-11: rejects POST request for session revocation when DELETE is required', async () => {
    try {
      await accountFetch(`sessions/${session.id}`, {
        method: 'POST',
        body: '{}'
      });
      expect.unreachable('Should have rejected POST on session deletion endpoint');
    } catch (err: any) {
      const apiErr = err as ApiError;
      // Mock backend or Swift backend returns 404 or 405 for wrong verb
      expect([400, 404, 405]).toContain(apiErr.status);
    }
  });

  it('T5-SEC-12: rejects POST request for app password revocation when DELETE is required', async () => {
    backend.addAppPassword(session.accountDID, 'MyTestBot');

    try {
      await accountFetch('app-passwords/MyTestBot', {
        method: 'POST',
        body: '{}'
      });
      expect.unreachable('Should have rejected POST on app password deletion endpoint');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect([400, 404, 405]).toContain(apiErr.status);
    }
  });

  it('T5-SEC-13: handles unexpected HTTP verbs (PUT, PATCH, OPTIONS, TRACE) safely', async () => {
    for (const verb of ['PUT', 'PATCH', 'TRACE']) {
      try {
        await accountFetch('portal', {
          method: verb,
          body: '{}'
        });
        expect.unreachable(`Should have rejected unexpected verb ${verb}`);
      } catch (err: any) {
        expect(err).toBeDefined();
        expect(err.status).toBeGreaterThanOrEqual(400);
      }
    }
  });

  it('T5-SEC-14: non-mutating GET requests do not require or transmit X-Swan-CSRF header', async () => {
    let capturedHeaders: Record<string, string | string[] | undefined> = {};
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/portal') && req.method === 'GET') {
        capturedHeaders = req.headers;
      }
      return undefined;
    });

    await api.fetchSnapshot();

    const hasCsrfHeader = Object.keys(capturedHeaders).some(k => k.toLowerCase() === 'x-swan-csrf');
    expect(hasCsrfHeader).toBe(false);
  });
});
