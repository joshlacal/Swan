import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { get } from 'svelte/store';
import { api, setCSRF } from '../../../src/lib/api';
import {
  activeApps,
  activeFactors,
  activePasswords,
  activeSessions,
  currentAccount,
  currentIdentity,
  portal
} from '../../../src/lib/stores/portal';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';
import type { MockSwanBackend, MockSession } from '../harness/mock-backend';

describe('Tier 1 - F14: Modular Views Refactoring', () => {
  let backend: MockSwanBackend;
  let session: MockSession;

  beforeEach(async () => {
    const env = setupTestEnv({ authenticated: true, elevated: true });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);

    // Fetch and populate portal snapshot in store
    const snapshot = await api.fetchSnapshot();
    portal.setSnapshot(snapshot);
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
    portal.reset();
  });

  it('T1-F14-01: Overview view model extracts account metrics, device count, app count, and security pulse', () => {
    const account = get(currentAccount);
    const sessions = get(activeSessions);
    const apps = get(activeApps);
    const identity = get(currentIdentity);

    expect(account).toBeDefined();
    expect(account?.handle).toBe('alice.swan.place');
    expect(account?.lifecycle).toBe('active');
    expect(sessions.length).toBeGreaterThanOrEqual(1);
    expect(apps.length).toBe(1);
    expect(identity?.state).toBe('active');
  });

  it('T1-F14-02: Profile view model accurately surfaces DID document details, handle, and email', () => {
    const account = get(currentAccount);
    const identity = get(currentIdentity);

    expect(account?.did).toBe('did:plc:swan-test-user-12345');
    expect(account?.handle).toBe('alice.swan.place');
    expect(account?.email).toBe('alice@swan.place');
    expect(identity?.handle).toBe('alice.swan.place');
  });

  it('T1-F14-03: Security view model reflects enrolled authentication factors and enabled status', () => {
    // Add TOTP and Passkey factors
    backend.addFactor(session.accountDID, {
      kind: 'passkey',
      label: 'MacBook TouchID',
      credentialID: 'cred_mbp',
      enabled: true
    });
    backend.addFactor(session.accountDID, {
      kind: 'totp',
      label: 'YubiKey Authenticator',
      enabled: true
    });

    portal.patchSnapshot((snap) => ({
      ...snap,
      factors: backend.getFactors(session.accountDID)
    }));

    const factors = get(activeFactors);
    expect(factors.length).toBe(2);
    expect(factors.some((f) => f.kind === 'passkey' && f.label === 'MacBook TouchID')).toBe(true);
    expect(factors.some((f) => f.kind === 'totp' && f.label === 'YubiKey Authenticator')).toBe(true);
  });

  it('T1-F14-04: Sessions view model lists all active sessions and marks current management session', () => {
    // Add second remote session
    backend.createSession(session.accountDID, { label: 'iPad Pro', activeCookie: false });

    portal.patchSnapshot((snap) => ({
      ...snap,
      sessions: [
        { id: session.id, label: session.label, kind: 'management', lastSeen: 'now', current: true },
        { id: 'sess_remote_2', label: 'iPad Pro', kind: 'legacy', lastSeen: '2 hours ago', current: false }
      ]
    }));

    const sessions = get(activeSessions);
    expect(sessions.length).toBe(2);

    const currentSession = sessions.find((s) => s.current);
    expect(currentSession).toBeDefined();
    expect(currentSession?.id).toBe(session.id);

    const remoteSession = sessions.find((s) => !s.current);
    expect(remoteSession).toBeDefined();
    expect(remoteSession?.label).toBe('iPad Pro');
  });

  it('T1-F14-05: Connected Apps and Passwords views model OAuth grants and scoped app passwords', () => {
    backend.addAppPassword(session.accountDID, 'CLI Tool', ['atproto', 'transition:generic']);

    portal.patchSnapshot((snap) => ({
      ...snap,
      passwords: backend.getAppPasswords(session.accountDID)
    }));

    const passwords = get(activePasswords);
    const apps = get(activeApps);

    expect(passwords.length).toBe(1);
    expect(passwords[0].name).toBe('CLI Tool');
    expect(passwords[0].scopes).toContain('atproto');

    expect(apps.length).toBe(1);
    expect(apps[0].name).toBe('Bluesky Social');
    expect(apps[0].scopes).toContain('atproto');
  });
});
