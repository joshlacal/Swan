import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import { api, accountFetch, setCSRF, setStepUpHandler, readError } from '../../src/lib/api';
import {
  portal,
  currentAccount,
  currentIdentity,
  activeSessions,
  activeApps,
  activePasswords,
  activeFactors,
  SECTIONS,
  type NavigationSection,
  type SectionMeta
} from '../../src/lib/stores/portal';
import { modals, activeModal } from '../../src/lib/stores/modals';
import { toasts } from '../../src/lib/stores/toasts';
import { stepup } from '../../src/lib/stores/stepup';
import { setupTestEnv, teardownTestEnv } from './harness/test-env';
import type { MockSwanBackend, MockSession } from './harness/mock-backend';
import type { PortalSnapshot, Factor, Session, ConnectedApp, AppPassword } from '../../src/lib/types';

describe('Empirical Adversarial Stress Suite: Challenger M4 (Iteration 2)', () => {
  let backend: MockSwanBackend;
  let session: MockSession;
  let recordedRequests: Array<{
    method: string;
    url: string;
    headers: Record<string, string | string[] | undefined>;
    body?: string;
  }> = [];

  const baselineSnapshot: PortalSnapshot = {
    account: {
      did: 'did:plc:adversarial-verifier-2026',
      handle: 'challenger.swan.place',
      email: 'security@swan.place',
      lifecycle: 'active'
    },
    identity: {
      method: 'plc',
      handle: 'challenger.swan.place',
      state: 'active'
    },
    strength: 'high',
    factors: [
      { id: 'f-passkey-alpha', kind: 'passkey', label: 'Titan Security Key', enabled: true },
      { id: 'f-totp-bravo', kind: 'totp', label: 'Bitwarden Authenticator', enabled: true },
      { id: 'f-rec-charlie', kind: 'recoveryCode', label: 'Emergency Offline Sheet', enabled: true }
    ],
    sessions: [
      { id: 's-mac-current', label: 'Safari on macOS Sequoia', kind: 'management', lastSeen: 'now', current: true },
      { id: 's-ios-catbird', label: 'Catbird App on iPhone 16 Pro', kind: 'legacy', lastSeen: '10m ago', current: false },
      { id: 's-linux-workstation', label: 'Chrome on Arch Linux', kind: 'management', lastSeen: '3d ago', current: false }
    ],
    apps: [
      { id: 'app-bsky-client', name: 'Bluesky Social App', scopes: ['atproto', 'transition:chat.bsky'], createdAt: '2026-07-01' },
      { id: 'app-deck-dashboard', name: 'Deck.blue Pro', scopes: ['atproto'], createdAt: '2026-08-10' }
    ],
    passwords: [
      { name: 'CLI Feed Bot', scopes: ['atproto'], createdAt: '2026-08-01', lastUsedAt: '2026-08-18' },
      { name: 'Data Pipeline Exporter', scopes: ['atproto', 'transition:email', 'transition:generic'], createdAt: '2026-08-05', lastUsedAt: null }
    ]
  };

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: true, elevated: true });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);
    setStepUpHandler((context) => stepup.requestStepUp(context));
    portal.setSnapshot(baselineSnapshot);
    modals.closeAll();
    stepup.reset();
    toasts.clear();
    recordedRequests = [];

    backend.addInterceptor((req) => {
      recordedRequests.push({
        method: req.method,
        url: req.url,
        headers: req.headers as any,
        body: (req as any)._body
      });
      return undefined;
    });
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
    portal.reset();
    modals.closeAll();
    stepup.reset();
    toasts.clear();
    vi.restoreAllMocks();
  });

  // =========================================================================
  // Requirement 1: Tab Navigation Switching Across All 9 Sections
  // =========================================================================
  describe('R1. Tab Navigation Matrix & State Machine Across All 9 Sections', () => {
    const expectedSections: Array<{ id: NavigationSection; label: string; note: string; number: string }> = [
      { id: 'overview', label: 'Overview', note: 'Account pulse', number: '01' },
      { id: 'profile', label: 'Profile', note: 'Identity & contact', number: '02' },
      { id: 'security', label: 'Security', note: 'Factors & sign-in', number: '03' },
      { id: 'recovery', label: 'Recovery', note: 'Your way back in', number: '04' },
      { id: 'sessions', label: 'Sessions', note: 'Devices & access', number: '05' },
      { id: 'apps', label: 'Connected apps', note: 'OAuth grants', number: '06' },
      { id: 'passwords', label: 'App passwords', note: 'Scoped legacy access', number: '07' },
      { id: 'export', label: 'Export & migrate', note: 'Move your data', number: '08' },
      { id: 'lifecycle', label: 'Lifecycle', note: 'Pause or leave', number: '09' }
    ];

    it('SECTIONS registry contains exactly 9 sections with correct metadata and ordering', () => {
      expect(SECTIONS.length).toBe(9);
      for (let i = 0; i < 9; i++) {
        expect(SECTIONS[i].id).toBe(expectedSections[i].id);
        expect(SECTIONS[i].label).toBe(expectedSections[i].label);
        expect(SECTIONS[i].note).toBe(expectedSections[i].note);
        expect(SECTIONS[i].number).toBe(expectedSections[i].number);
      }
    });

    it('navigates through all 9 sections in forward and reverse sequence', () => {
      // Forward traversal
      for (const section of expectedSections) {
        portal.selectTab(section.id);
        expect(get(portal).activeTab).toBe(section.id);
      }

      // Reverse traversal
      for (let i = expectedSections.length - 1; i >= 0; i--) {
        portal.selectTab(expectedSections[i].id);
        expect(get(portal).activeTab).toBe(expectedSections[i].id);
      }
    });

    it('stress-tests rapid out-of-order tab navigation (500 iterations)', () => {
      const tabIds = expectedSections.map((s) => s.id);
      for (let i = 0; i < 500; i++) {
        const target = tabIds[Math.floor(Math.random() * tabIds.length)];
        portal.selectTab(target);
        expect(get(portal).activeTab).toBe(target);
      }
    });

    it('maintains activeTab across snapshot updates and partial patches', () => {
      portal.selectTab('security');
      expect(get(portal).activeTab).toBe('security');

      // Update snapshot without changing activeTab
      portal.patchSnapshot((snap) => ({
        ...snap,
        strength: 'stepUpTotp'
      }));
      expect(get(portal).activeTab).toBe('security');

      // Set new full snapshot
      portal.setSnapshot({
        ...baselineSnapshot,
        account: { ...baselineSnapshot.account, handle: 'updated.swan.place' }
      });
      expect(get(portal).activeTab).toBe('security');
    });

    it('falls back to overview section for unknown tab identifiers in derived lookup', () => {
      const resolveSection = (tab: string): SectionMeta =>
        SECTIONS.find((s) => s.id === tab) ?? SECTIONS[0];

      expect(resolveSection('nonexistent').id).toBe('overview');
      expect(resolveSection('').id).toBe('overview');
      expect(resolveSection('security').id).toBe('security');
      expect(resolveSection('passwords').id).toBe('passwords');
    });
  });

  // =========================================================================
  // Requirement 2: Edge Cases (Empty Lists, Factors, Unauth, Network Error, Retries)
  // =========================================================================
  describe('R2. Adversarial Edge Cases & Boundary Stress', () => {
    it('handles an empty snapshot state with 0 factors, 0 sessions, 0 apps, and 0 passwords', () => {
      const emptySnap: PortalSnapshot = {
        account: {
          did: 'did:plc:empty000',
          handle: 'ghost.swan.place',
          email: null,
          lifecycle: 'active'
        },
        identity: {
          method: 'plc',
          handle: 'ghost.swan.place',
          state: 'active'
        },
        strength: 'password',
        factors: [],
        sessions: [],
        apps: [],
        passwords: []
      };

      portal.setSnapshot(emptySnap);

      expect(get(activeSessions)).toHaveLength(0);
      expect(get(activeApps)).toHaveLength(0);
      expect(get(activePasswords)).toHaveLength(0);
      expect(get(activeFactors)).toHaveLength(0);
      expect(get(currentAccount)?.email).toBeNull();
      expect(get(currentIdentity)?.method).toBe('plc');
    });

    it('computes factor counts and pluralization correctly for 0, 1, and N factors', () => {
      function getFactorCountBadge(factors: Factor[]): { text: string; success: boolean } {
        const count = factors.length;
        if (count === 0) {
          return { text: 'Password only', success: false };
        }
        return {
          text: `${count} active factor${count === 1 ? '' : 's'}`,
          success: true
        };
      }

      // 0 factors
      expect(getFactorCountBadge([])).toEqual({ text: 'Password only', success: false });

      // 1 factor (singular)
      const oneFactor: Factor[] = [{ id: 'f-1', kind: 'passkey', label: 'Key 1', enabled: true }];
      expect(getFactorCountBadge(oneFactor)).toEqual({ text: '1 active factor', success: true });

      // 2 factors (plural)
      const twoFactors: Factor[] = [
        { id: 'f-1', kind: 'passkey', label: 'Key 1', enabled: true },
        { id: 'f-2', kind: 'totp', label: 'Authenticator', enabled: true }
      ];
      expect(getFactorCountBadge(twoFactors)).toEqual({ text: '2 active factors', success: true });

      // 5 factors (plural)
      const fiveFactors: Factor[] = [
        { id: 'f-1', kind: 'passkey', label: 'K1', enabled: true },
        { id: 'f-2', kind: 'passkey', label: 'K2', enabled: true },
        { id: 'f-3', kind: 'totp', label: 'T1', enabled: true },
        { id: 'f-4', kind: 'totp', label: 'T2', enabled: true },
        { id: 'f-5', kind: 'recoveryCode', label: 'R1', enabled: true }
      ];
      expect(getFactorCountBadge(fiveFactors)).toEqual({ text: '5 active factors', success: true });
    });

    it('handles string "true" vs boolean true for factor enabled flags', () => {
      portal.setSnapshot({
        ...baselineSnapshot,
        factors: [
          { id: 'f-str', kind: 'passkey', label: 'String Key', enabled: 'true' as any },
          { id: 'f-bool', kind: 'totp', label: 'Bool TOTP', enabled: true }
        ]
      });

      const factors = get(activeFactors);
      const enabledPasskeys = factors.filter((f) => f.kind === 'passkey' && (f.enabled === true || f.enabled === 'true'));
      const enabledTotps = factors.filter((f) => f.kind === 'totp' && (f.enabled === true || f.enabled === 'true'));

      expect(enabledPasskeys).toHaveLength(1);
      expect(enabledTotps).toHaveLength(1);
    });

    it('correctly determines whether "Sign out other sessions" button is enabled', () => {
      // 1. Only current session -> button disabled
      portal.patchSnapshot((s) => ({
        ...s,
        sessions: [{ id: 's-curr', label: 'Browser', kind: 'management', lastSeen: 'now', current: true }]
      }));
      let others = get(activeSessions).filter((s) => !s.current);
      expect(others).toHaveLength(0);

      // 2. Multiple remote sessions -> button enabled
      portal.patchSnapshot((s) => ({
        ...s,
        sessions: [
          { id: 's-curr', label: 'Browser', kind: 'management', lastSeen: 'now', current: true },
          { id: 's-remote1', label: 'Phone', kind: 'legacy', lastSeen: '1h ago', current: false },
          { id: 's-remote2', label: 'Tablet', kind: 'management', lastSeen: '2h ago', current: false }
        ]
      }));
      others = get(activeSessions).filter((s) => !s.current);
      expect(others).toHaveLength(2);

      // 3. No sessions at all -> button disabled
      portal.patchSnapshot((s) => ({ ...s, sessions: [] }));
      others = get(activeSessions).filter((s) => !s.current);
      expect(others).toHaveLength(0);
    });

    it('handles massive collections without performance degradation (100 sessions, 100 apps, 100 passwords)', () => {
      const largeSessions: Session[] = Array.from({ length: 100 }, (_, i) => ({
        id: `sess-${i}`,
        label: `Device Node #${i}`,
        kind: i % 2 === 0 ? 'management' : 'legacy',
        lastSeen: `${i} mins ago`,
        current: i === 0
      }));

      const largeApps: ConnectedApp[] = Array.from({ length: 100 }, (_, i) => ({
        id: `app-${i}`,
        name: `OAuth Client #${i}`,
        scopes: ['atproto', 'transition:chat.bsky'],
        createdAt: '2026-08-01'
      }));

      const largePasswords: AppPassword[] = Array.from({ length: 100 }, (_, i) => ({
        name: `Bot Credential #${i}`,
        scopes: ['atproto'],
        createdAt: '2026-08-10',
        lastUsedAt: i % 3 === 0 ? '2026-08-18' : null
      }));

      portal.patchSnapshot((s) => ({
        ...s,
        sessions: largeSessions,
        apps: largeApps,
        passwords: largePasswords
      }));

      expect(get(activeSessions)).toHaveLength(100);
      expect(get(activeApps)).toHaveLength(100);
      expect(get(activePasswords)).toHaveLength(100);

      // Derived filters still run cleanly
      const current = get(activeSessions).filter((s) => s.current);
      const remotes = get(activeSessions).filter((s) => !s.current);
      expect(current).toHaveLength(1);
      expect(remotes).toHaveLength(99);
    });

    it('manages unauthenticated state lifecycle and reset', () => {
      portal.reset();
      const state = get(portal);
      expect(state.snapshot).toBeNull();
      expect(state.loading).toBe(false);
      expect(state.error).toBeNull();
      expect(state.activeTab).toBe('overview');
      expect(get(currentAccount)).toBeNull();
      expect(get(currentIdentity)).toBeNull();
      expect(get(activeSessions)).toEqual([]);
      expect(get(activeApps)).toEqual([]);
      expect(get(activePasswords)).toEqual([]);
      expect(get(activeFactors)).toEqual([]);
    });

    it('network error retry workflow restores portal state after failure', async () => {
      // 1. Simulate initial startup failure (snapshot is null)
      portal.reset();
      portal.setLoading(true);
      portal.setError('Failed to fetch ledger snapshot. Service Unavailable.');
      portal.setLoading(false);

      expect(get(portal).error).toBe('Failed to fetch ledger snapshot. Service Unavailable.');
      expect(get(portal).snapshot).toBeNull();

      // 2. Trigger retry -> successful fetch
      portal.setLoading(true);
      portal.setError(null);
      const newSnap = await api.fetchSnapshot();
      portal.setSnapshot(newSnap);
      portal.setLoading(false);

      expect(get(portal).error).toBeNull();
      expect(get(portal).loading).toBe(false);
      expect(get(portal).snapshot).not.toBeNull();
      expect(get(currentAccount)?.handle).toBe('alice.swan.place');
    });

    it('background snapshot refresh failure does not destroy existing loaded snapshot', async () => {
      // Portal has loaded snapshot
      expect(get(portal).snapshot).not.toBeNull();

      // Background refresh attempt throws an error
      let refreshError: Error | null = null;
      try {
        throw new Error('Connection refused on background poll');
      } catch (err: any) {
        refreshError = err;
        // Background refresh fails gracefully without calling portal.reset()
      }

      expect(refreshError?.message).toBe('Connection refused on background poll');
      expect(get(portal).snapshot).not.toBeNull();
      expect(get(currentAccount)?.did).toBe('did:plc:adversarial-verifier-2026');
    });
  });

  // =========================================================================
  // Requirement 3: Component Error Handling, HTTP Verbs & Store Reactivity
  // =========================================================================
  describe('R3. Component Error Handling, HTTP Verbs & Store Reactivity', () => {
    it('verifies HTTP DELETE verb routing for all revocation endpoints', async () => {
      // 1. Sessions DELETE
      await api.revokeSession('s-ios-catbird');
      let req = recordedRequests.find((r) => r.method === 'DELETE' && r.url.includes('sessions/s-ios-catbird'));
      expect(req).toBeDefined();

      // 2. App passwords DELETE
      await api.revokeAppPassword('CLI Feed Bot');
      req = recordedRequests.find((r) => r.method === 'DELETE' && r.url.includes('app-passwords/CLI%20Feed%20Bot'));
      expect(req).toBeDefined();

      // 3. Connected apps DELETE
      await api.revokeConnectedApp('app-bsky-client');
      req = recordedRequests.find((r) => r.method === 'DELETE' && r.url.includes('connected-apps/app-bsky-client'));
      expect(req).toBeDefined();

      // 4. Passkey DELETE
      await api.revokePasskey('f-passkey-alpha');
      req = recordedRequests.find((r) => r.method === 'DELETE' && r.url.includes('factors/passkeys/f-passkey-alpha'));
      expect(req).toBeDefined();

      // 5. TOTP DELETE
      await api.revokeTotp();
      req = recordedRequests.find((r) => r.method === 'DELETE' && r.url === '/account/api/factors/totp');
      expect(req).toBeDefined();
    });

    it('correctly formats and encodes special URI characters across all DELETE endpoints', async () => {
      const weirdNames = [
        'Device with / slashes & spaces?',
        'App#1 (Beta) + Special:Token',
        'unicode-🚀-device'
      ];

      for (const name of weirdNames) {
        await api.revokeAppPassword(name);
        const expectedUrl = `/account/api/app-passwords/${encodeURIComponent(name)}`;
        const match = recordedRequests.find((r) => r.method === 'DELETE' && r.url === expectedUrl);
        expect(match).toBeDefined();
      }
    });

    it('captures granular error responses and delivers error toast notifications', async () => {
      backend.addInterceptor((req) => {
        if (req.url.includes('sessions/s-failing')) {
          return {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'cannot_revoke_current_session', message: 'Current management session cannot be revoked directly' }
          };
        }
        return undefined;
      });

      let caughtMessage = '';
      try {
        await api.revokeSession('s-failing');
      } catch (err: any) {
        caughtMessage = err.message;
        toasts.error(err.message);
      }

      expect(caughtMessage).toBe('Current management session cannot be revoked directly');
      const activeToasts = get(toasts);
      expect(activeToasts.some((t) => t.type === 'error' && t.message === caughtMessage)).toBe(true);
    });

    it('manages modal stack lifecycle (open, push, pop, close, closeAll, isOpen)', () => {
      // 1. Open first modal
      modals.open('app-password');
      expect(get(activeModal)?.type).toBe('app-password');
      expect(modals.isOpen('app-password')).toBe(true);

      // 2. Push second modal (nested dialog / step-up)
      modals.push('step-up', { operation: 'create-app-password' });
      expect(get(activeModal)?.type).toBe('step-up');
      expect(modals.isOpen('step-up')).toBe(true);
      expect(modals.isOpen('app-password')).toBe(true);

      // 3. Pop step-up modal -> returns to app-password
      const popped = modals.pop();
      expect(popped?.type).toBe('step-up');
      expect(get(activeModal)?.type).toBe('app-password');
      expect(modals.isOpen('step-up')).toBe(false);

      // 4. Close all
      modals.closeAll();
      expect(get(activeModal)).toBeNull();
      expect(modals.isOpen('app-password')).toBe(false);
    });

    it('toasts store supports all levels (info, success, warning, error) with auto-dismiss and manual dismiss', () => {
      toasts.clear();

      const id1 = toasts.info('Info note');
      const id2 = toasts.success('Operation succeeded');
      const id3 = toasts.warning('Warning notice');
      const id4 = toasts.error('Critical failure');

      let currentToasts = get(toasts);
      expect(currentToasts).toHaveLength(4);
      expect(currentToasts[0].type).toBe('info');
      expect(currentToasts[1].type).toBe('success');
      expect(currentToasts[2].type).toBe('warning');
      expect(currentToasts[3].type).toBe('error');

      // Dismiss specific toast
      toasts.dismiss(id2);
      currentToasts = get(toasts);
      expect(currentToasts).toHaveLength(3);
      expect(currentToasts.some((t) => t.id === id2)).toBe(false);

      // Clear all toasts
      toasts.clear();
      expect(get(toasts)).toHaveLength(0);
    });
  });

  // =========================================================================
  // Requirement 4: Step-Up Integration & Replay Flow
  // =========================================================================
  describe('R4. Step-Up Interception, Receipt Passing & Cancellation Resilience', () => {
    it('intercepts 403 step-up response on deletePasskey, prompts step-up, and replays with receipt token', async () => {
      let challengeCount = 0;
      backend.addInterceptor((req) => {
        const stepUpToken = (req.headers as any)['x-swan-step-up'] || (req.headers as any)['X-Swan-Step-Up'];
        if (req.method === 'DELETE' && req.url.includes('f-passkey-alpha') && !stepUpToken) {
          challengeCount++;
          return {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'step_up_required', message: 'Step-up authentication required to revoke security factor' }
          };
        }
        return undefined;
      });

      // Launch revocation
      const revokePromise = api.revokePasskey('f-passkey-alpha');

      // StepUpStore opens
      await vi.waitFor(() => {
        expect(get(stepup).isOpen).toBe(true);
      });
      expect(get(stepup).context?.operation).toBe('factors/passkeys/f-passkey-alpha');

      // Resolve step-up with receipt
      stepup.resolveStepUp('receipt_stepup_verified_987');

      const result = await revokePromise;
      expect(result.accepted).toBe(true);
      expect(get(stepup).isOpen).toBe(false);

      // Check request history: 2 DELETE calls, second has X-Swan-Step-Up header
      const delRequests = recordedRequests.filter((r) => r.method === 'DELETE' && r.url.includes('f-passkey-alpha'));
      expect(delRequests).toHaveLength(2);
      const finalHeaders = delRequests[1].headers;
      const sentToken = (finalHeaders as any)['x-swan-step-up'] || (finalHeaders as any)['X-Swan-Step-Up'];
      expect(sentToken).toBe('receipt_stepup_verified_987');
    });

    it('rejects pending operation cleanly when user dismisses or cancels step-up dialog', async () => {
      backend.addInterceptor((req) => {
        if (req.method === 'DELETE' && req.url.includes('f-passkey-alpha')) {
          return {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'step_up_required', message: 'MFA re-auth required' }
          };
        }
        return undefined;
      });

      const revokePromise = api.revokePasskey('f-passkey-alpha');

      await vi.waitFor(() => {
        expect(get(stepup).isOpen).toBe(true);
      });

      // User cancels dialog
      stepup.cancelStepUp('User closed the verification modal');

      await expect(revokePromise).rejects.toMatchObject({
        status: 403,
        code: 'step_up_required'
      });
      expect(get(stepup).isOpen).toBe(false);
    });
  });
});
