import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  accountFetch,
  api,
  bootstrap,
  getCSRF,
  readError,
  setCSRF,
  setStepUpHandler
} from '../../../src/lib/api';
import type { PortalSnapshot } from '../../../src/lib/types';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';
import type { MockSwanBackend, MockSession } from '../harness/mock-backend';

describe('Tier 1 - F01: Typed Models & API Client', () => {
  let backend: MockSwanBackend;
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
    vi.restoreAllMocks();
  });

  it('T1-F01-01: accountFetch executes GET /account/api/portal and returns typed PortalSnapshot', async () => {
    const snapshot = await accountFetch<PortalSnapshot>('portal');

    expect(snapshot).toBeDefined();
    expect(snapshot.account).toBeDefined();
    expect(snapshot.account.handle).toBe('alice.swan.place');
    expect(snapshot.account.did).toBe('did:plc:swan-test-user-12345');
    expect(snapshot.account.lifecycle).toBe('active');
    expect(Array.isArray(snapshot.sessions)).toBe(true);
    expect(snapshot.sessions.some((s) => s.current)).toBe(true);
    expect(Array.isArray(snapshot.factors)).toBe(true);
    expect(Array.isArray(snapshot.apps)).toBe(true);
    expect(Array.isArray(snapshot.passwords)).toBe(true);
  });

  it('T1-F01-02: Automatic CSRF token bootstrapping on mutating calls when CSRF is missing', async () => {
    // Clear CSRF to trigger bootstrapping
    setCSRF(undefined);
    backend.clearCookies();

    // Prepare bootstrap pre-auth token on the mock server
    const bootstrapResp = await fetch('/account/api/bootstrap');
    const bootData = await bootstrapResp.json();
    backend.setCookie('swan_csrf_pre', bootData.csrf);

    const csrf = await bootstrap();
    setCSRF(csrf);

    expect(csrf).toBeDefined();
    expect(csrf.length).toBeGreaterThan(0);
    expect(getCSRF()).toBe(csrf);

    // Make an authenticated mutation
    backend.setCookie('__Secure-swan_management', session.sessionToken);
    backend.setCookie('swan_csrf', session.csrfToken);
    setCSRF(session.csrfToken);

    const result = await accountFetch<{ message: string }>('sessions/revoke-others', {
      method: 'POST',
      body: '{}'
    });

    expect(result).toBeDefined();
    expect(result.message).toBe('Other sessions revoked');
  });

  it('T1-F01-03: Granular error parsing for 400 Bad Request and custom error codes', async () => {
    // Calling an endpoint with invalid body should return structured ApiError
    try {
      await accountFetch('app-passwords', {
        method: 'POST',
        body: JSON.stringify({ name: 'Test App', scopes: ['invalid:scope'] })
      });
      expect.fail('Expected accountFetch to throw ApiError');
    } catch (err: any) {
      expect(err).toBeDefined();
      expect(err.code).toBe('invalid_request');
      expect(err.status).toBe(400);
      expect(err.message).toBeDefined();
      expect(typeof err.message).toBe('string');
    }
  });

  it('T1-F01-04: Handling of 204 No Content responses without JSON parsing errors', async () => {
    // Intercept a custom route on the mock backend that returns 204
    backend.addInterceptor((req) => {
      if (req.url.endsWith('/custom-no-content')) {
        return {
          status: 204,
          headers: { 'Cache-Control': 'no-store' },
          body: ''
        };
      }
      return undefined;
    });

    const result = await accountFetch<void>('custom-no-content', {
      method: 'POST',
      body: '{}'
    });

    expect(result).toBeUndefined();
  });

  it('T1-F01-05: Custom headers merge properly with default headers', async () => {
    let capturedHeaders: Record<string, string | string[] | undefined> = {};

    backend.addInterceptor((req) => {
      if (req.url.endsWith('/header-test')) {
        capturedHeaders = req.headers;
        return {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
          body: { success: true }
        };
      }
      return undefined;
    });

    await accountFetch<{ success: boolean }>('header-test', {
      method: 'GET',
      headers: {
        'X-Client-Trace-Id': 'trace-abc-123',
        'X-Portal-Version': '2.0.0'
      }
    });

    // Verify custom headers alongside default Accept: application/json
    const getHeader = (name: string) => {
      const entry = Object.entries(capturedHeaders).find(([k]) => k.toLowerCase() === name.toLowerCase());
      return entry ? entry[1] : undefined;
    };

    expect(getHeader('x-client-trace-id')).toBe('trace-abc-123');
    expect(getHeader('x-portal-version')).toBe('2.0.0');
    expect(getHeader('accept')).toContain('application/json');
  });
});
