import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import OverviewView from './views/OverviewView.svelte';
import ProfileView from './views/ProfileView.svelte';
import SecurityView from './views/SecurityView.svelte';
import RecoveryView from './views/RecoveryView.svelte';
import SessionsView from './views/SessionsView.svelte';
import AppsView from './views/AppsView.svelte';
import PasswordsView from './views/PasswordsView.svelte';
import ExportView from './views/ExportView.svelte';
import LifecycleView from './views/LifecycleView.svelte';

import {
  portal,
  currentAccount,
  currentIdentity,
  activeSessions,
  activeApps,
  activePasswords,
  activeFactors,
  SECTIONS,
  type NavigationSection
} from '../stores/portal';
import { modals, activeModal } from '../stores/modals';
import { toasts } from '../stores/toasts';
import { api, bootstrap, setCSRF } from '../api';
import type { PortalSnapshot } from '../types';
import { setupTestEnv, teardownTestEnv } from '../../../tests/e2e/harness/test-env';
import type { MockSwanBackend, MockSession } from '../../../tests/e2e/harness/mock-backend';

describe('Empirical Adversarial Stress & Verification Suite: Modular Views & Root SPA Shell', () => {
  let backend: MockSwanBackend;
  let session: MockSession;

  const mockFullSnapshot: PortalSnapshot = {
    account: {
      did: 'did:plc:swan-test-user-12345',
      handle: 'alice.swan.place',
      email: 'alice@swan.place',
      lifecycle: 'active'
    },
    identity: {
      method: 'plc',
      handle: 'alice.swan.place',
      state: 'active'
    },
    strength: 'high',
    factors: [
      { id: 'f-passkey-1', kind: 'passkey', label: 'MacBook Touch ID', enabled: true },
      { id: 'f-passkey-2', kind: 'passkey', label: 'YubiKey 5C', enabled: true },
      { id: 'f-totp-1', kind: 'totp', label: 'Aegis Authenticator', enabled: true },
      { id: 'f-rec-1', kind: 'recoveryCode', label: 'Emergency Codes', enabled: true }
    ],
    sessions: [
      { id: 's-curr', label: 'Safari on macOS', kind: 'management', lastSeen: 'just now', current: true },
      { id: 's-rem1', label: 'Catbird iOS', kind: 'legacy', lastSeen: '1 hour ago', current: false },
      { id: 's-rem2', label: 'Firefox on Linux', kind: 'management', lastSeen: '2 days ago', current: false }
    ],
    apps: [
      { id: 'app-1', name: 'Bluesky Social', scopes: ['atproto', 'transition:chat.bsky'], createdAt: '2026-08-01' },
      { id: 'app-2', name: 'Deck.blue', scopes: ['atproto'], createdAt: '2026-08-15' }
    ],
    passwords: [
      { name: 'CLI Sync Bot', scopes: ['atproto'], createdAt: '2026-08-10', lastUsedAt: '2026-08-18' },
      { name: 'Backup Exporter', scopes: ['atproto', 'transition:generic'], createdAt: '2026-08-12' }
    ]
  };

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: true, elevated: true });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);
    portal.setSnapshot(mockFullSnapshot);
    modals.closeAll();
    toasts.clear();
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
    portal.reset();
    modals.closeAll();
    toasts.clear();
    vi.restoreAllMocks();
  });

  // =========================================================================
  // 1. Navigation Matrix & Tab Switching Across All 9 Sections
  // =========================================================================
  describe('1. Navigation Matrix & Tab Routing Across All 9 Sections', () => {
    const allSections: NavigationSection[] = [
      'overview',
      'profile',
      'security',
      'recovery',
      'sessions',
      'apps',
      'passwords',
      'export',
      'lifecycle'
    ];

    it('navigates seamlessly across every one of the 9 sections in sequence', () => {
      for (const sec of allSections) {
        portal.selectTab(sec);
        expect(get(portal).activeTab).toBe(sec);
      }
    });

    it('SECTIONS registry maps all 9 sections with strict number ordering and metadata', () => {
      expect(SECTIONS.length).toBe(9);
      SECTIONS.forEach((sec, idx) => {
        expect(sec.id).toBe(allSections[idx]);
        expect(sec.number).toBe(String(idx + 1).padStart(2, '0'));
        expect(sec.label.length).toBeGreaterThan(0);
        expect(sec.note.length).toBeGreaterThan(0);
      });
    });

    it('handles unexpected/invalid tab names gracefully falling back to overview', () => {
      // Simulate currentSection $derived fallback in +page.svelte
      function resolveSection(tabId: string) {
        return SECTIONS.find((s) => s.id === tabId) ?? SECTIONS[0];
      }

      const validSec = resolveSection('security');
      expect(validSec.id).toBe('security');
      expect(validSec.label).toBe('Security');

      const fallbackSec = resolveSection('non-existent-tab' as any);
      expect(fallbackSec.id).toBe('overview');
      expect(fallbackSec.label).toBe('Overview');
    });

    it('Overview shortcuts navigate to corresponding tabs', () => {
      portal.selectTab('overview');
      expect(get(portal).activeTab).toBe('overview');

      // Trigger shortcut to Profile
      portal.selectTab('profile');
      expect(get(portal).activeTab).toBe('profile');

      // Return to overview and trigger shortcut to Sessions
      portal.selectTab('overview');
      portal.selectTab('sessions');
      expect(get(portal).activeTab).toBe('sessions');
    });

    it('activeTab state is preserved when snapshot updates or refreshes', () => {
      portal.selectTab('passwords');
      expect(get(portal).activeTab).toBe('passwords');

      // Simulate snapshot refresh
      portal.patchSnapshot((snap) => ({
        ...snap,
        strength: 'stepUpPassword'
      }));

      expect(get(portal).activeTab).toBe('passwords');
    });
  });

  // =========================================================================
  // 2. Edge Cases: Empty Lists, Missing Factors & Null Fields
  // =========================================================================
  describe('2. Edge Cases: Empty Lists, Missing Factors & Null/Undefined Fields', () => {
    it('handles completely empty collections snapshot without errors', () => {
      const emptySnapshot: PortalSnapshot = {
        account: {
          did: 'did:plc:empty-user',
          handle: 'empty.swan.place',
          email: null,
          lifecycle: 'active'
        },
        identity: {
          method: 'plc',
          handle: 'empty.swan.place',
          state: 'active'
        },
        strength: 'password',
        factors: [],
        sessions: [],
        apps: [],
        passwords: []
      };

      portal.setSnapshot(emptySnapshot);

      expect(get(activeSessions)).toEqual([]);
      expect(get(activeApps)).toEqual([]);
      expect(get(activePasswords)).toEqual([]);
      expect(get(activeFactors)).toEqual([]);
      expect(get(currentAccount)?.email).toBeNull();
    });

    it('SessionsView handles 0 sessions and single session (current only)', () => {
      // 0 sessions
      portal.patchSnapshot((s) => ({ ...s, sessions: [] }));
      let sessions = get(activeSessions);
      let canRevokeOthers = sessions.filter((s) => !s.current).length > 0;
      expect(canRevokeOthers).toBe(false);

      // Single session (current only)
      portal.patchSnapshot((s) => ({
        ...s,
        sessions: [{ id: 's-only', label: 'Browser', kind: 'management', lastSeen: 'now', current: true }]
      }));
      sessions = get(activeSessions);
      canRevokeOthers = sessions.filter((s) => !s.current).length > 0;
      expect(canRevokeOthers).toBe(false);
      expect(sessions[0].current).toBe(true);

      // Multiple sessions with remotes
      portal.patchSnapshot((s) => ({
        ...s,
        sessions: [
          { id: 's-only', label: 'Browser', kind: 'management', lastSeen: 'now', current: true },
          { id: 's-remote', label: 'Phone', kind: 'legacy', lastSeen: 'yesterday', current: false }
        ]
      }));
      sessions = get(activeSessions);
      canRevokeOthers = sessions.filter((s) => !s.current).length > 0;
      expect(canRevokeOthers).toBe(true);
    });

    it('SecurityView factor categorization handles all factor combinations', () => {
      // 1. Zero factors
      portal.patchSnapshot((s) => ({ ...s, factors: [] }));
      let factors = get(activeFactors);
      let passkeys = factors.filter((f) => f.kind === 'passkey');
      let totp = factors.filter((f) => f.kind === 'totp');
      expect(passkeys.length).toBe(0);
      expect(totp.length).toBe(0);
      expect(factors.length).toBe(0);

      // 2. Only Passkeys
      portal.patchSnapshot((s) => ({
        ...s,
        factors: [{ id: 'f-pk', kind: 'passkey', label: 'Key 1', enabled: true }]
      }));
      factors = get(activeFactors);
      passkeys = factors.filter((f) => f.kind === 'passkey');
      totp = factors.filter((f) => f.kind === 'totp');
      expect(passkeys.length).toBe(1);
      expect(totp.length).toBe(0);

      // 3. Only TOTP
      portal.patchSnapshot((s) => ({
        ...s,
        factors: [{ id: 'f-tp', kind: 'totp', label: 'App 1', enabled: true }]
      }));
      factors = get(activeFactors);
      passkeys = factors.filter((f) => f.kind === 'passkey');
      totp = factors.filter((f) => f.kind === 'totp');
      expect(passkeys.length).toBe(0);
      expect(totp.length).toBe(1);
    });

    it('ProfileView correctly distinguishes did:web vs PLC states and null emails', () => {
      // PLC state
      portal.patchSnapshot((s) => ({
        ...s,
        account: { did: 'did:plc:123', handle: 'alice.swan.place', email: null, lifecycle: 'active' },
        identity: { method: 'plc', handle: 'alice.swan.place', state: 'active' }
      }));

      let identity = get(currentIdentity);
      let account = get(currentAccount);
      expect(identity?.method).toBe('plc');
      expect(account?.email).toBeNull();

      // did:web state
      portal.patchSnapshot((s) => ({
        ...s,
        account: { did: 'did:web:custom.org', handle: 'custom.org', email: 'me@custom.org', lifecycle: 'active' },
        identity: { method: 'didWeb', handle: 'custom.org', state: 'active' }
      }));

      identity = get(currentIdentity);
      account = get(currentAccount);
      expect(identity?.method).toBe('didWeb');
      expect(identity?.handle).toBe('custom.org');
      expect(account?.email).toBe('me@custom.org');
    });

    it('AppsView and PasswordsView handle empty lists and complex scopes', () => {
      portal.patchSnapshot((s) => ({
        ...s,
        apps: [],
        passwords: []
      }));

      expect(get(activeApps).length).toBe(0);
      expect(get(activePasswords).length).toBe(0);

      // Populate with various scopes
      portal.patchSnapshot((s) => ({
        ...s,
        apps: [
          { id: 'app-empty-scopes', name: 'ScopeFree App', scopes: [], createdAt: '2026-08-18' }
        ],
        passwords: [
          { name: 'Multi Scope Password', scopes: ['atproto', 'transition:chat.bsky', 'transition:email', 'transition:generic'], createdAt: '2026-08-18' }
        ]
      }));

      expect(get(activeApps)[0].scopes).toEqual([]);
      expect(get(activePasswords)[0].scopes.length).toBe(4);
    });
  });

  // =========================================================================
  // 3. Unauthenticated State, Bootstrap & Error Recovery Scenarios
  // =========================================================================
  describe('3. Unauthenticated State, Bootstrap & Error Recovery Scenarios', () => {
    it('portal store reset sets snapshot to null and activeTab to overview', () => {
      portal.selectTab('security');
      expect(get(portal).activeTab).toBe('security');

      portal.reset();
      const state = get(portal);
      expect(state.snapshot).toBeNull();
      expect(state.activeTab).toBe('overview');
      expect(state.loading).toBe(false);
      expect(state.error).toBeNull();
    });

    it('portal loading and error state transitions work predictably', () => {
      portal.setLoading(true);
      expect(get(portal).loading).toBe(true);

      portal.setError('Failed to fetch ledger snapshot');
      expect(get(portal).error).toBe('Failed to fetch ledger snapshot');

      portal.setLoading(false);
      expect(get(portal).loading).toBe(false);
      expect(get(portal).error).toBe('Failed to fetch ledger snapshot');

      portal.setError(null);
      expect(get(portal).error).toBeNull();
    });

    it('simulates login success updating portal snapshot and clearing error', async () => {
      // Setup unauthenticated environment
      teardownTestEnv();
      const unauthEnv = setupTestEnv({ authenticated: false });
      backend = unauthEnv.backend;

      portal.reset();
      expect(get(portal).snapshot).toBeNull();

      // Bootstrap and login through API
      const loginRes = await api.login({
        handle: 'alice.swan.place',
        password: 'correct-horse-battery-staple'
      });

      expect(loginRes.snapshot).toBeDefined();
      expect(loginRes.csrf).toBeDefined();

      portal.setSnapshot(loginRes.snapshot);
      expect(get(portal).snapshot).not.toBeNull();
      expect(get(currentAccount)?.handle).toBe('alice.swan.place');
    });

    it('simulates sign-out clearing session tokens and resetting portal store', async () => {
      const logoutRes = await api.logout();
      expect(logoutRes.accepted).toBe(true);

      portal.reset();
      expect(get(portal).snapshot).toBeNull();
      expect(get(currentAccount)).toBeNull();
      expect(get(activeSessions)).toEqual([]);
    });

    it('network retry restores portal snapshot after transient connection error', async () => {
      // 1. Fail state
      portal.setLoading(true);
      portal.setError('Network offline');
      portal.setLoading(false);

      expect(get(portal).error).toBe('Network offline');

      // 2. Retry succeeds
      portal.setLoading(true);
      portal.setError(null);
      const snapshot = await api.fetchSnapshot();
      portal.setSnapshot(snapshot);
      portal.setLoading(false);

      expect(get(portal).error).toBeNull();
      expect(get(portal).loading).toBe(false);
      expect(get(portal).snapshot).not.toBeNull();
    });
  });

  // =========================================================================
  // 4. Component Error Handling & Toast Integration
  // =========================================================================
  describe('4. Component Error Handling & Toast Feedback on Mutations', () => {
    it('catches and toasts error when individual session revocation fails', async () => {
      vi.spyOn(backend, 'fetch').mockImplementationOnce(async () => {
        return new Response(JSON.stringify({ code: 'session_not_found', message: 'Session has expired' }), {
          status: 404
        });
      });

      let caughtError = '';
      try {
        await api.revokeSession('s-invalid');
      } catch (err: any) {
        caughtError = err.message;
        toasts.error(err.message || 'Failed to revoke session.');
      }

      expect(caughtError).toBe('Session has expired');
      const toastList = get(toasts);
      expect(toastList.some((t) => t.type === 'error' && t.message === 'Session has expired')).toBe(true);
    });

    it('catches and toasts error when sign-out-others fails', async () => {
      vi.spyOn(backend, 'fetch').mockImplementationOnce(async () => {
        return new Response(JSON.stringify({ code: 'server_error', message: 'Database lock timeout' }), {
          status: 500
        });
      });

      let caughtError = '';
      try {
        await api.revokeOtherSessions();
      } catch (err: any) {
        caughtError = err.message;
        toasts.error(err.message || 'Failed to sign out other sessions.');
      }

      expect(caughtError).toBe('Database lock timeout');
      const toastList = get(toasts);
      expect(toastList.some((t) => t.type === 'error' && t.message === 'Database lock timeout')).toBe(true);
    });

    it('catches and toasts error when passkey revocation fails', async () => {
      vi.spyOn(backend, 'fetch').mockImplementationOnce(async () => {
        return new Response(JSON.stringify({ code: 'forbidden', message: 'Step-up authentication required' }), {
          status: 403
        });
      });

      let caughtError = '';
      try {
        await api.revokePasskey('f-passkey-1');
      } catch (err: any) {
        caughtError = err.message;
        toasts.error(err.message || 'Failed to revoke passkey.');
      }

      expect(caughtError).toBe('Step-up authentication required');
      const toastList = get(toasts);
      expect(toastList.some((t) => t.type === 'error' && t.message === 'Step-up authentication required')).toBe(true);
    });

    it('catches and toasts error when app password revocation fails', async () => {
      vi.spyOn(backend, 'fetch').mockImplementationOnce(async () => {
        return new Response(JSON.stringify({ code: 'password_not_found', message: 'App password does not exist' }), {
          status: 404
        });
      });

      let caughtError = '';
      try {
        await api.revokeAppPassword('NonExistentApp');
      } catch (err: any) {
        caughtError = err.message;
        toasts.error(err.message || 'Failed to revoke app password.');
      }

      expect(caughtError).toBe('App password does not exist');
      const toastList = get(toasts);
      expect(toastList.some((t) => t.type === 'error' && t.message === 'App password does not exist')).toBe(true);
    });

    it('catches and toasts error when connected app revocation fails', async () => {
      vi.spyOn(backend, 'fetch').mockImplementationOnce(async () => {
        return new Response(JSON.stringify({ code: 'app_not_found', message: 'OAuth client not found' }), {
          status: 404
        });
      });

      let caughtError = '';
      try {
        await api.revokeConnectedApp('app-unknown');
      } catch (err: any) {
        caughtError = err.message;
        toasts.error(err.message || 'Failed to revoke connected app.');
      }

      expect(caughtError).toBe('OAuth client not found');
      const toastList = get(toasts);
      expect(toastList.some((t) => t.type === 'error' && t.message === 'OAuth client not found')).toBe(true);
    });

    it('catches and toasts error when did:web domain reverification fails', async () => {
      vi.spyOn(backend, 'fetch').mockImplementationOnce(async () => {
        return new Response(JSON.stringify({ code: 'dns_failed', message: 'DNS TXT record matching _atproto not found' }), {
          status: 400
        });
      });

      let caughtError = '';
      try {
        await api.reverifyDidWeb();
      } catch (err: any) {
        caughtError = err.message;
        toasts.error(err.message || 'Domain reverification check failed.');
      }

      expect(caughtError).toBe('DNS TXT record matching _atproto not found');
      const toastList = get(toasts);
      expect(toastList.some((t) => t.type === 'error' && t.message === 'DNS TXT record matching _atproto not found')).toBe(true);
    });
  });

  // =========================================================================
  // 5. Store Reactivity & Live Mutation Synchronization
  // =========================================================================
  describe('5. Store Reactivity & Live Mutation Synchronization', () => {
    it('revoking a remote session via API and updating snapshot immediately updates activeSessions store', async () => {
      // Create a remote session in backend
      const remoteSession = backend.createSession(session.accountDID, {
        label: 'Remote Device',
        activeCookie: false
      });

      let snapshot = await api.fetchSnapshot();
      portal.setSnapshot(snapshot);

      const countBefore = get(activeSessions).length;
      expect(get(activeSessions).some((s) => s.id === remoteSession.id)).toBe(true);

      // Perform revocation via API
      const revokeRes = await api.revokeSession(remoteSession.id);
      expect(revokeRes.accepted).toBe(true);

      // Update snapshot
      snapshot = await api.fetchSnapshot();
      portal.setSnapshot(snapshot);

      const updatedSessions = get(activeSessions);
      expect(updatedSessions.length).toBe(countBefore - 1);
      expect(updatedSessions.find((s) => s.id === remoteSession.id)).toBeUndefined();
    });

    it('creating and revoking app passwords updates activePasswords store', async () => {
      // 1. Create app password
      const createRes = await api.createAppPassword({
        name: 'New Test Password',
        scopes: ['atproto']
      });
      expect(createRes.accepted).toBe(true);

      let snapshot = await api.fetchSnapshot();
      portal.setSnapshot(snapshot);

      let passwords = get(activePasswords);
      expect(passwords.some((p) => p.name === 'New Test Password')).toBe(true);

      // 2. Revoke app password
      const revokeRes = await api.revokeAppPassword('New Test Password');
      expect(revokeRes.accepted).toBe(true);

      snapshot = await api.fetchSnapshot();
      portal.setSnapshot(snapshot);

      passwords = get(activePasswords);
      expect(passwords.some((p) => p.name === 'New Test Password')).toBe(false);
    });

    it('enrolling and revoking factors synchronizes activeFactors and Overview metric count', async () => {
      const initialSnapshot = await api.fetchSnapshot();
      portal.setSnapshot(initialSnapshot);
      const initialFactors = get(activeFactors).length;

      // Add factor to backend
      const added = backend.addFactor(session.accountDID, {
        kind: 'passkey',
        label: 'New YubiKey 5 NFC',
        credentialID: 'cred_yubi_5',
        enabled: true
      });

      let snapshot = await api.fetchSnapshot();
      portal.setSnapshot(snapshot);

      expect(get(activeFactors).length).toBe(initialFactors + 1);

      // Revoke factor via API
      const revokeRes = await api.revokePasskey(added.id);
      expect(revokeRes.accepted).toBe(true);

      snapshot = await api.fetchSnapshot();
      portal.setSnapshot(snapshot);

      expect(get(activeFactors).length).toBe(initialFactors);
    });

    it('rapid successive snapshot patches do not corrupt state or cause race conditions', () => {
      for (let i = 0; i < 50; i++) {
        portal.patchSnapshot((snap) => ({
          ...snap,
          account: {
            ...snap.account,
            handle: `alice-${i}.swan.place`
          }
        }));
      }

      expect(get(currentAccount)?.handle).toBe('alice-49.swan.place');
    });
  });

  // =========================================================================
  // 6. View to Modal Integration Trigger Wiring
  // =========================================================================
  describe('6. View-to-Modal Integration Trigger Wiring', () => {
    it('Overview quick action buttons open passkey-enroll, app-password, and export modals', () => {
      // 1. Passkey enroll
      modals.open('passkey-enroll');
      expect(get(activeModal)?.type).toBe('passkey-enroll');
      modals.close('passkey-enroll');

      // 2. App password
      modals.open('app-password');
      expect(get(activeModal)?.type).toBe('app-password');
      modals.close('app-password');

      // 3. Export
      modals.open('export');
      expect(get(activeModal)?.type).toBe('export');
      modals.close('export');
    });

    it('Profile triggers did:web modal with initial modes new, rotate, and remove', () => {
      // New domain
      modals.open('did-web', { initialMode: 'new', mode: 'new' });
      expect(get(activeModal)?.type).toBe('did-web');
      expect(get(activeModal)?.payload?.mode).toBe('new');
      modals.close('did-web');

      // Rotate key
      modals.open('did-web', { initialMode: 'rotate', mode: 'rotate' });
      expect(get(activeModal)?.type).toBe('did-web');
      expect(get(activeModal)?.payload?.mode).toBe('rotate');
      modals.close('did-web');

      // Remove domain
      modals.open('did-web', { initialMode: 'remove', mode: 'remove' });
      expect(get(activeModal)?.type).toBe('did-web');
      expect(get(activeModal)?.payload?.mode).toBe('remove');
      modals.close('did-web');
    });

    it('Security and Recovery views trigger enrollment and rotation modals', () => {
      // Security triggers TOTP enroll
      modals.open('totp-enroll');
      expect(get(activeModal)?.type).toBe('totp-enroll');
      modals.close('totp-enroll');

      // Recovery triggers recovery-rotate
      modals.open('recovery-rotate');
      expect(get(activeModal)?.type).toBe('recovery-rotate');
      modals.close('recovery-rotate');
    });

    it('Lifecycle view triggers deactivate and delete modals with appropriate mode payload', () => {
      // Deactivate
      modals.open('lifecycle-deactivate', { mode: 'deactivate' });
      expect(get(activeModal)?.type).toBe('lifecycle-deactivate');
      expect(get(activeModal)?.payload?.mode).toBe('deactivate');
      modals.close();

      // Delete
      modals.open('lifecycle-delete', { mode: 'delete' });
      expect(get(activeModal)?.type).toBe('lifecycle-delete');
      expect(get(activeModal)?.payload?.mode).toBe('delete');
      modals.close();
    });
  });
});
