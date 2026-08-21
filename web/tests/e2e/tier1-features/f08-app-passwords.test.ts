import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api, setCSRF } from '../../../src/lib/api';
import { APP_PASSWORD_SCOPES } from '../../../src/lib/types';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';
import type { MockSwanBackend, MockSession } from '../harness/mock-backend';

describe('Tier 1 - F08: App Password Workflow Modal', () => {
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

  it('T1-F08-01: createAppPassword captures name and scope selection and submits POST request', async () => {
    const scopes = ['atproto', 'transition:chat.bsky'];
    const result = await api.createAppPassword({ name: 'Chat Client Bot', scopes });

    expect(result).toBeDefined();
    expect(result.accepted).toBe(true);
    expect(result.message).toBe('App password created');

    const appPasswords = backend.getAppPasswords(session.accountDID);
    const created = appPasswords.find((p) => p.name === 'Chat Client Bot');
    expect(created).toBeDefined();
    expect(created?.scopes).toEqual(scopes);
  });

  it('T1-F08-02: createAppPassword returns a one-time secret password starting with swan-app-', async () => {
    const result = await api.createAppPassword({
      name: 'Mobile Backup Client',
      scopes: ['atproto', 'transition:email']
    });

    expect(result.password).toBeDefined();
    expect(typeof result.password).toBe('string');
    expect(result.password).toMatch(/^swan-app-[a-z0-9]+-[a-z0-9]+/);
  });

  it('T1-F08-03: createAppPassword transmits X-Swan-Step-Up receipt header when session is not elevated', async () => {
    // Expire session elevation
    backend.expireSessionStepUp(session.sessionToken);

    // Issue a valid single-use receipt
    const receipt = backend.issueStepUpReceipt(session.id, session.accountDID, 'app-passwords.create');

    const result = await api.createAppPassword(
      { name: 'Receipt Authenticated Client', scopes: ['atproto'] },
      receipt.receiptToken
    );

    expect(result.password).toBeDefined();
    expect(receipt.consumed).toBe(true);
  });

  it('T1-F08-04: revokeAppPassword issues HTTP DELETE with proper URL percent-encoding', async () => {
    const appName = 'My Special App / #1 & Test';
    backend.addAppPassword(session.accountDID, appName, ['atproto']);

    expect(backend.getAppPasswords(session.accountDID).some((p) => p.name === appName)).toBe(true);

    const result = await api.revokeAppPassword(appName);

    expect(result.accepted).toBe(true);
    expect(result.message).toBe('App password revoked');
    expect(backend.getAppPasswords(session.accountDID).some((p) => p.name === appName)).toBe(false);
  });

  it('T1-F08-05: Scope validation enforces base atproto scope requirement and checks known scope definitions', async () => {
    expect(APP_PASSWORD_SCOPES).toContain('atproto');
    expect(APP_PASSWORD_SCOPES).toContain('transition:chat.bsky');
    expect(APP_PASSWORD_SCOPES).toContain('transition:email');
    expect(APP_PASSWORD_SCOPES).toContain('transition:generic');

    // Missing required atproto scope
    await expect(
      api.createAppPassword({ name: 'Invalid App', scopes: ['transition:email'] })
    ).rejects.toMatchObject({
      status: 400,
      code: 'invalid_request'
    });
  });
});
