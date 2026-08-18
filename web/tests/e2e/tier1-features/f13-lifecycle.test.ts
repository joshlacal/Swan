import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { accountFetch, api, setCSRF } from '../../../src/lib/api';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';
import type { MockSwanBackend, MockSession } from '../harness/mock-backend';

describe('Tier 1 - F13: Export & Lifecycle Modals', () => {
  let backend: MockSwanBackend;
  let session: MockSession;

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: true, elevated: true });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
  });

  it('T1-F13-01: requestExport triggers data export job on backend', async () => {
    const result = await api.requestExport();

    expect(result).toBeDefined();
    expect(result.accepted).toBe(true);
    expect(result.message).toContain('Export request');
  });

  it('T1-F13-02: Export job status is queryable via GET /account/api/export', async () => {
    await api.requestExport();

    const statusResp = await accountFetch<{ export: { id: string; status: string; requestedAt: string } }>('export');

    expect(statusResp).toBeDefined();
    expect(statusResp.export).toBeDefined();
    expect(statusResp.export.id).toBeDefined();
    expect(['pending', 'ready', 'completed']).toContain(statusResp.export.status);
  });

  it('T1-F13-03: Account deactivation marks account lifecycle as deactivated', async () => {
    const result = await accountFetch<{ accepted: boolean; message: string }>('lifecycle/deactivate', {
      method: 'POST',
      body: '{}'
    });

    expect(result.accepted).toBe(true);
    const account = backend.getAccount(session.accountDID);
    expect(account?.lifecycle).toBe('deactivated');
  });

  it('T1-F13-04: Permanent account deletion requires elevated session and deletes account', async () => {
    const result = await api.deleteAccount();

    expect(result).toBeDefined();
    expect(result.accepted).toBe(true);
    expect(result.message).toContain('Account deletion');

    const account = backend.getAccount(session.accountDID);
    expect(account?.lifecycle).toBe('deleted');
  });

  it('T1-F13-05: Deleted account rejects subsequent login attempts', async () => {
    // Delete account
    await api.deleteAccount();

    // Bootstrap fresh CSRF for login
    backend.clearCookies();
    const boot = await fetch('/account/api/bootstrap');
    const bootData = await boot.json();

    // Attempt login to deleted account
    const loginResp = await fetch('/account/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Swan-CSRF': bootData.csrf
      },
      body: JSON.stringify({
        handle: 'alice.swan.place',
        password: 'correct-horse-battery-staple'
      })
    });

    expect(loginResp.status).toBe(401);
    const errorBody = await loginResp.json();
    expect(errorBody.code).toBe('authentication_required');
    expect(errorBody.message).toContain('deleted');
  });
});
