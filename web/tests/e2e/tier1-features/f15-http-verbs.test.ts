import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api, setCSRF } from '../../../src/lib/api';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';
import type { MockSwanBackend, MockSession } from '../harness/mock-backend';

describe('Tier 1 - F15: Correct HTTP Verb Routing', () => {
  let backend: MockSwanBackend;
  let session: MockSession;
  let recordedRequests: Array<{ method: string; url: string }> = [];

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: true, elevated: true });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);
    recordedRequests = [];

    backend.addInterceptor((req) => {
      recordedRequests.push({ method: req.method, url: req.url });
      return undefined; // allow default handler to continue
    });
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
    vi.restoreAllMocks();
  });

  it('T1-F15-01: Enforces HTTP DELETE verb for session revocations', async () => {
    const otherSession = backend.createSession(session.accountDID, { label: 'Old Phone', activeCookie: false });

    await api.revokeSession(otherSession.id);

    const match = recordedRequests.find((r) => r.url.includes(`/account/api/sessions/${otherSession.id}`));
    expect(match).toBeDefined();
    expect(match?.method).toBe('DELETE');
  });

  it('T1-F15-02: Enforces HTTP DELETE verb for app password revocations', async () => {
    backend.addAppPassword(session.accountDID, 'Desktop Bot');

    await api.revokeAppPassword('Desktop Bot');

    const match = recordedRequests.find((r) => r.url.includes('/account/api/app-passwords/Desktop%20Bot'));
    expect(match).toBeDefined();
    expect(match?.method).toBe('DELETE');
  });

  it('T1-F15-03: Enforces HTTP DELETE verb for connected OAuth app revocations', async () => {
    backend.addConnectedApp(session.accountDID, { id: 'app_sample', name: 'Sample App', scopes: ['atproto'] });

    await api.revokeConnectedApp('app_sample');

    const match = recordedRequests.find((r) => r.url.includes('/account/api/connected-apps/app_sample'));
    expect(match).toBeDefined();
    expect(match?.method).toBe('DELETE');
  });

  it('T1-F15-04: Enforces HTTP DELETE verb for factor revocations (passkeys and totp)', async () => {
    backend.addFactor(session.accountDID, {
      id: 'passkey_to_delete',
      kind: 'passkey',
      label: 'Old Key',
      enabled: true
    });
    backend.addFactor(session.accountDID, {
      kind: 'totp',
      label: 'Old TOTP',
      enabled: true
    });

    await api.revokePasskey('passkey_to_delete');
    const passkeyMatch = recordedRequests.find((r) => r.url.includes('/account/api/factors/passkeys/passkey_to_delete'));
    expect(passkeyMatch?.method).toBe('DELETE');

    await api.revokeTotp();
    const totpMatch = recordedRequests.find((r) => r.url.endsWith('/account/api/factors/totp'));
    expect(totpMatch?.method).toBe('DELETE');
  });

  it('T1-F15-05: Enforces HTTP GET verb for reads and HTTP POST for mutations', async () => {
    // Reads
    await api.fetchSignupPolicy();
    const policyReq = recordedRequests.find((r) => r.url.endsWith('/account/api/signup/policy'));
    expect(policyReq?.method).toBe('GET');

    await api.fetchSnapshot();
    const portalReq = recordedRequests.find((r) => r.url.endsWith('/account/api/portal'));
    expect(portalReq?.method).toBe('GET');

    // Mutations
    await api.revokeOtherSessions();
    const revokeOthersReq = recordedRequests.find((r) => r.url.endsWith('/account/api/sessions/revoke-others'));
    expect(revokeOthersReq?.method).toBe('POST');
  });
});
