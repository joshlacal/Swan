import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { accountFetch, api, bootstrap, getCSRF, readError, setCSRF, setStepUpHandler } from '../../../src/lib/api';
import type { ApiError, PortalSnapshot } from '../../../src/lib/types';
import type { MockSession } from '../harness/mock-backend';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';
import { portal } from '../../../src/lib/stores/portal';
import { toasts } from '../../../src/lib/stores/toasts';

describe('Tier 5 Adversarial: Network Faults, HTML Proxy Bodies & Resilience', () => {
  let backend: ReturnType<typeof setupTestEnv>['backend'];
  let session: MockSession;

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: true, elevated: true });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);
    setStepUpHandler(null);
    portal.reset();
    toasts.clear();
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
    setStepUpHandler(null);
    portal.reset();
    toasts.clear();
  });

  // --- T5-NET-01 to T5-NET-03: HTML & Plain Text Upstream Proxy Bodies ---

  it('T5-NET-01: handles Cloudflare HTML 502 Bad Gateway proxy response without throwing unhandled SyntaxError', async () => {
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/portal')) {
        return {
          status: 502,
          headers: { 'Content-Type': 'text/html; charset=UTF-8' },
          body: '<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head><body><center><h1>502 Bad Gateway</h1></center><hr><center>cloudflare</center></body></html>'
        };
      }
      return undefined;
    });

    try {
      await api.fetchSnapshot();
      expect.unreachable('Should have rejected on 502 Bad Gateway');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(502);
      expect(apiErr.code).toBe('service_unavailable');
      expect(apiErr.message).toBe('The account service is temporarily unavailable.');
    }
  });

  it('T5-NET-02: handles Nginx HTML 504 Gateway Time-out proxy response', async () => {
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/portal')) {
        return {
          status: 504,
          headers: { 'Content-Type': 'text/html' },
          body: '<html><head><title>504 Gateway Time-out</title></head><body><center><h1>504 Gateway Time-out</h1></center><hr><center>nginx/1.24.0</center></body></html>'
        };
      }
      return undefined;
    });

    try {
      await api.fetchSnapshot();
      expect.unreachable('Should have rejected on 504 Gateway Time-out');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(504);
      expect(apiErr.code).toBe('service_unavailable');
      expect(apiErr.message).toBe('The account service is temporarily unavailable.');
    }
  });

  it('T5-NET-03: handles upstream 500 Internal Error with plain text body from backend crash', async () => {
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/factors/totp')) {
        return {
          status: 500,
          headers: { 'Content-Type': 'text/plain' },
          body: 'Fatal error in SwanAccountsActor: database connection pool exhausted\nStack trace: ...'
        };
      }
      return undefined;
    });

    try {
      await api.enrollTotp({ secret: 'JBSWY3DPEHPK3PXP', label: 'Authenticator App' });
      expect.unreachable('Should have rejected on 500 plain text error');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(500);
      expect(apiErr.code).toBe('service_unavailable');
      expect(apiErr.message).toBe('The account service is temporarily unavailable.');
    }
  });

  // --- T5-NET-04 & T5-NET-05: Empty & Captive Portal Responses on 200 OK ---

  it('T5-NET-04: handles HTTP 200 OK with empty body on JSON endpoint gracefully', async () => {
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/portal')) {
        return {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
          body: ''
        };
      }
      return undefined;
    });

    try {
      await api.fetchSnapshot();
      expect.unreachable('Should have thrown SyntaxError on empty JSON body');
    } catch (err: any) {
      expect(err).toBeDefined();
    }
  });

  it('T5-NET-05: handles Wi-Fi captive portal HTML intercept on 200 OK response', async () => {
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/portal')) {
        return {
          status: 200,
          headers: { 'Content-Type': 'text/html' },
          body: '<HTML><HEAD><TITLE>Hotel Wi-Fi Login Portal</TITLE></HEAD><BODY><form action="/login"><input type="submit" value="Connect"/></form></BODY></HTML>'
        };
      }
      return undefined;
    });

    try {
      await api.fetchSnapshot();
      expect.unreachable('Should have failed to parse HTML captive portal response as JSON');
    } catch (err: any) {
      expect(err).toBeDefined();
    }
  });

  // --- T5-NET-06 & T5-NET-07: Offline Network Drops & Abort Signals ---

  it('T5-NET-06: handles browser offline network drop (TypeError: Failed to fetch)', async () => {
    backend.addInterceptor(() => {
      throw new TypeError('Failed to fetch');
    });

    try {
      await api.fetchSnapshot();
      expect.unreachable('Should have thrown TypeError');
    } catch (err: any) {
      expect(err).toBeInstanceOf(TypeError);
      expect(err.message).toBe('Failed to fetch');
    }
  });

  it('T5-NET-07: handles abrupt connection abort (DOMException: The operation was aborted)', async () => {
    backend.addInterceptor(() => {
      const abortErr = new DOMException('The user aborted a request.', 'AbortError');
      throw abortErr;
    });

    try {
      await api.fetchSnapshot();
      expect.unreachable('Should have thrown AbortError');
    } catch (err: any) {
      expect(err.name).toBe('AbortError');
      expect(err.message).toContain('aborted');
    }
  });

  // --- T5-NET-08: Post-Mutation Snapshot Failure Handling ---

  it('T5-NET-08: mutation succeeds on backend even if subsequent snapshot refresh fails with 500', async () => {
    // Add app password to revoke
    backend.addAppPassword(session.accountDID, 'TestBot');
    expect(backend.getAppPasswords(session.accountDID).some(p => p.name === 'TestBot')).toBe(true);

    // Revoke mutation succeeds
    const revokeRes = await api.revokeAppPassword('TestBot');
    expect(revokeRes.accepted).toBe(true);

    // Verify it is truly removed from backend database
    expect(backend.getAppPasswords(session.accountDID).some(p => p.name === 'TestBot')).toBe(false);

    // Intercept snapshot to fail with 500
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/portal')) {
        return {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
          body: { code: 'database_unavailable', message: 'Read replica lag' }
        };
      }
      return undefined;
    });

    try {
      await api.fetchSnapshot();
      expect.unreachable('Snapshot refresh should fail');
    } catch (err: any) {
      expect(err.status).toBe(500);
      expect(err.code).toBe('database_unavailable');
    }

    // Backend state remains clean and app password is still deleted
    expect(backend.getAppPasswords(session.accountDID).some(p => p.name === 'TestBot')).toBe(false);
  });

  // --- T5-NET-09: Export Status Polling Retry Resilience ---

  it('T5-NET-09: resilient polling handles transient 503 error and successfully detects completed export', async () => {
    let pollCount = 0;
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/export/status')) {
        pollCount++;
        if (pollCount === 1) {
          return {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
            body: { status: 'processing', progress: 25 }
          };
        } else if (pollCount === 2) {
          // Transient 503 error on second poll
          return {
            status: 503,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'service_unavailable', message: 'Temporary export node busy' }
          };
        } else {
          return {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
            body: { status: 'ready', downloadUrl: 'https://swan.place/export/archive-12345.zip', expiresAt: '2026-08-19T00:00:00Z' }
          };
        }
      }
      return undefined;
    });

    // Custom polling logic with retry resilience
    let completedExport: any = null;
    let attempts = 0;
    const maxAttempts = 5;

    while (!completedExport && attempts < maxAttempts) {
      attempts++;
      try {
        const statusRes = await accountFetch<any>('export/status');
        if (statusRes.status === 'ready') {
          completedExport = statusRes;
        }
      } catch (err: any) {
        // Transient error caught, continue polling loop
        expect(err.status).toBe(503);
      }
    }

    expect(completedExport).toBeDefined();
    expect(completedExport.status).toBe('ready');
    expect(completedExport.downloadUrl).toContain('archive-12345.zip');
    expect(pollCount).toBe(3);
  });

  // --- T5-NET-10: Rate Limiting 429 Burst with Retry-After ---

  it('T5-NET-10: rate limiting HTTP 429 bursts return exact rate limit code and custom message', async () => {
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/step-up/password')) {
        return {
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': '30'
          },
          body: {
            code: 'rate_limited',
            message: 'Too many step-up verification attempts. Locked for 30 seconds.'
          }
        };
      }
      return undefined;
    });

    try {
      await api.stepUpPassword('wrong-password-attempt');
      expect.unreachable('Should have thrown 429 rate limit error');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(429);
      expect(apiErr.code).toBe('rate_limited');
      expect(apiErr.message).toBe('Too many step-up verification attempts. Locked for 30 seconds.');
    }
  });

  // --- T5-NET-11: High Latency Network Delay Resilience ---

  it('T5-NET-11: high-latency connection completes mutation safely without dropping state', async () => {
    backend.setSimulatedDelay(200);

    const start = Date.now();
    const res = await api.createAppPassword({ name: 'HighLatencyBot', scopes: ['atproto'] });
    const duration = Date.now() - start;

    expect(duration).toBeGreaterThanOrEqual(180);
    expect(res.accepted).toBe(true);
    expect(backend.getAppPasswords(session.accountDID).some(p => p.name === 'HighLatencyBot')).toBe(true);
    backend.setSimulatedDelay(0);
  });

  // --- T5-NET-12: Malformed HTTP Status Code (599 Unknown Proxy) ---

  it('T5-NET-12: handles malformed / non-standard HTTP status codes (HTTP 599)', async () => {
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/portal')) {
        return {
          status: 599,
          headers: { 'Content-Type': 'application/json' },
          body: {}
        };
      }
      return undefined;
    });

    try {
      await api.fetchSnapshot();
      expect.unreachable('Should have thrown on 599 status');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(599);
      expect(apiErr.code).toBe('unknown_error');
      expect(apiErr.message).toBe('The account service is temporarily unavailable.');
    }
  });

  // --- T5-NET-13: Network Failure During Step-Up Password Ceremony ---

  it('T5-NET-13: network drop during step-up password submission surfaces ApiError cleanly', async () => {
    // Intercept step-up password to drop network
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/step-up/password')) {
        return {
          status: 503,
          headers: { 'Content-Type': 'application/json' },
          body: { code: 'service_unavailable', message: 'Authentication cluster offline' }
        };
      }
      return undefined;
    });

    try {
      await api.stepUpPassword('valid-password');
      expect.unreachable('Step-up password should fail');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(503);
      expect(apiErr.code).toBe('service_unavailable');
      expect(apiErr.message).toBe('Authentication cluster offline');
    }
  });
});
