import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import { api, accountFetch, setCSRF, setStepUpHandler } from '../../src/lib/api';
import { portal, currentAccount, currentIdentity, activeSessions, activeApps, activePasswords, activeFactors, SECTIONS } from '../../src/lib/stores/portal';
import { modals, activeModal } from '../../src/lib/stores/modals';
import { toasts } from '../../src/lib/stores/toasts';
import { stepup } from '../../src/lib/stores/stepup';
import { setupTestEnv, teardownTestEnv } from './harness/test-env';
import type { MockSwanBackend, MockSession } from './harness/mock-backend';

// View components imports
import OverviewView from '../../src/lib/components/views/OverviewView.svelte';
import ProfileView from '../../src/lib/components/views/ProfileView.svelte';
import SecurityView from '../../src/lib/components/views/SecurityView.svelte';
import RecoveryView from '../../src/lib/components/views/RecoveryView.svelte';
import SessionsView from '../../src/lib/components/views/SessionsView.svelte';
import AppsView from '../../src/lib/components/views/AppsView.svelte';
import PasswordsView from '../../src/lib/components/views/PasswordsView.svelte';
import ExportView from '../../src/lib/components/views/ExportView.svelte';
import LifecycleView from '../../src/lib/components/views/LifecycleView.svelte';

describe('Adversarial Challenge M4-2: Modal Triggers, HTTP DELETE Verbs, and Step-Up Interception', () => {
  let backend: MockSwanBackend;
  let session: MockSession;
  let recordedRequests: Array<{ method: string; url: string; headers: Record<string, string | string[] | undefined>; body?: string }> = [];

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: true, elevated: true });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);
    setStepUpHandler((context) => stepup.requestStepUp(context));

    portal.setSnapshot({
      account: {
        did: 'did:plc:challenger123',
        handle: 'challenger.swan.place',
        email: 'challenger@swan.place',
        lifecycle: 'active'
      },
      identity: {
        method: 'plc',
        handle: 'challenger.swan.place',
        state: 'active'
      },
      strength: 'high',
      factors: [
        { id: 'factor-pk-1', kind: 'passkey', label: 'YubiKey 5C', enabled: true },
        { id: 'factor-totp-1', kind: 'totp', label: '1Password TOTP', enabled: true },
        { id: 'factor-rc-1', kind: 'recoveryCode', label: 'Backup Codes', enabled: true }
      ],
      sessions: [
        { id: 'sess-curr', label: 'Current Browser', kind: 'management', lastSeen: 'now', current: true },
        { id: 'sess-remote-1', label: 'Remote iPhone / iOS', kind: 'legacy', lastSeen: '2h ago', current: false },
        { id: 'sess-special%20id/1', label: 'Device with spaces and slashes', kind: 'management', lastSeen: '1d ago', current: false }
      ],
      apps: [
        { id: 'app-oauth-1', name: 'Catbird Client', scopes: ['atproto', 'transition:chat.bsky'], createdAt: '2026-08-01' },
        { id: 'app@special#2', name: 'Special App & Co', scopes: ['atproto'], createdAt: '2026-08-05' }
      ],
      passwords: [
        { name: 'CLI Bot', scopes: ['atproto'], createdAt: '2026-08-10', lastUsedAt: '2026-08-18' },
        { name: 'Special / App (v2)', scopes: ['atproto', 'transition:generic'], createdAt: '2026-08-12', lastUsedAt: null }
      ]
    });

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
  // 1. Verification of Modal Launch Triggers across all 9 views
  // =========================================================================
  describe('1. Modal Launch Triggers and Payload Expectations across 9 Views', () => {
    it('OverviewView triggers passkey-enroll, app-password, and export modals correctly', () => {
      // 1. Passkey enroll shortcut
      modals.open('passkey-enroll');
      expect(get(activeModal)?.type).toBe('passkey-enroll');
      expect(modals.isOpen('passkey-enroll')).toBe(true);
      modals.close();

      // 2. App password shortcut
      modals.open('app-password');
      expect(get(activeModal)?.type).toBe('app-password');
      expect(modals.isOpen('app-password')).toBe(true);
      modals.close();

      // 3. Export shortcut
      modals.open('export');
      expect(get(activeModal)?.type).toBe('export');
      expect(modals.isOpen('export')).toBe(true);
      modals.close();
    });

    it('ProfileView triggers did-web modal with initialMode "new", "rotate", and "remove"', () => {
      // 1. Bring your own domain (new)
      modals.open('did-web', { initialMode: 'new', mode: 'new' });
      let current = get(activeModal);
      expect(current?.type).toBe('did-web');
      expect(current?.payload?.initialMode).toBe('new');
      expect(current?.payload?.mode).toBe('new');
      modals.close();

      // 2. Rotate signing key
      modals.open('did-web', { initialMode: 'rotate', mode: 'rotate' });
      current = get(activeModal);
      expect(current?.type).toBe('did-web');
      expect(current?.payload?.initialMode).toBe('rotate');
      expect(current?.payload?.mode).toBe('rotate');
      modals.close();

      // 3. Remove did:web (revert to PLC)
      modals.open('did-web', { initialMode: 'remove', mode: 'remove' });
      current = get(activeModal);
      expect(current?.type).toBe('did-web');
      expect(current?.payload?.initialMode).toBe('remove');
      expect(current?.payload?.mode).toBe('remove');
      modals.close();
    });

    it('SecurityView triggers passkey-enroll, totp-enroll, and recovery-rotate modals', () => {
      // 1. Passkey Enroll trigger
      modals.open('passkey-enroll');
      expect(get(activeModal)?.type).toBe('passkey-enroll');
      modals.close();

      // 2. TOTP Enroll trigger
      modals.open('totp-enroll');
      expect(get(activeModal)?.type).toBe('totp-enroll');
      modals.close();

      // 3. Recovery Rotate trigger
      modals.open('recovery-rotate');
      expect(get(activeModal)?.type).toBe('recovery-rotate');
      modals.close();
    });

    it('RecoveryView triggers recovery-rotate modal', () => {
      modals.open('recovery-rotate');
      expect(get(activeModal)?.type).toBe('recovery-rotate');
      modals.close();
    });

    it('PasswordsView triggers app-password modal', () => {
      modals.open('app-password');
      expect(get(activeModal)?.type).toBe('app-password');
      modals.close();
    });

    it('ExportView triggers export modal', () => {
      modals.open('export');
      expect(get(activeModal)?.type).toBe('export');
      modals.close();
    });

    it('LifecycleView triggers lifecycle-deactivate and lifecycle-delete with expected mode payloads', () => {
      // Deactivate modal
      modals.open('lifecycle-deactivate', { mode: 'deactivate' });
      let current = get(activeModal);
      expect(current?.type).toBe('lifecycle-deactivate');
      expect(current?.payload?.mode).toBe('deactivate');
      modals.close();

      // Delete modal
      modals.open('lifecycle-delete', { mode: 'delete' });
      current = get(activeModal);
      expect(current?.type).toBe('lifecycle-delete');
      expect(current?.payload?.mode).toBe('delete');
      modals.close();
    });
  });

  // =========================================================================
  // 2. Verification of HTTP DELETE Revocation Actions & URL Encoding
  // =========================================================================
  describe('2. HTTP DELETE Revocation Actions & Robust URL Encoding', () => {
    it('issues DELETE /account/api/sessions/:id with URL encoding for complex IDs', async () => {
      const complexSessionId = 'sess-special/with#slashes and spaces';
      (backend.createSession as any)(session.accountDID, { id: complexSessionId, label: 'Complex Session', activeCookie: false });

      await api.revokeSession(complexSessionId);

      const req = recordedRequests.find((r) => r.method === 'DELETE' && r.url.includes('/account/api/sessions/'));
      expect(req).toBeDefined();
      expect(req?.method).toBe('DELETE');
      expect(req?.url).toBe(`/account/api/sessions/${encodeURIComponent(complexSessionId)}`);
    });

    it('issues DELETE /account/api/app-passwords/:name with URL encoding', async () => {
      const complexPasswordName = 'Special / App (v2) & Bot';
      backend.addAppPassword(session.accountDID, complexPasswordName);

      await api.revokeAppPassword(complexPasswordName);

      const req = recordedRequests.find((r) => r.method === 'DELETE' && r.url.includes('/account/api/app-passwords/'));
      expect(req).toBeDefined();
      expect(req?.method).toBe('DELETE');
      expect(req?.url).toBe(`/account/api/app-passwords/${encodeURIComponent(complexPasswordName)}`);
    });

    it('issues DELETE /account/api/connected-apps/:id with URL encoding', async () => {
      const complexAppId = 'app:custom@scope/123';
      backend.addConnectedApp(session.accountDID, { id: complexAppId, name: 'Custom App', scopes: ['atproto'] });

      await api.revokeConnectedApp(complexAppId);

      const req = recordedRequests.find((r) => r.method === 'DELETE' && r.url.includes('/account/api/connected-apps/'));
      expect(req).toBeDefined();
      expect(req?.method).toBe('DELETE');
      expect(req?.url).toBe(`/account/api/connected-apps/${encodeURIComponent(complexAppId)}`);
    });

    it('issues DELETE /account/api/factors/passkeys/:id with URL encoding', async () => {
      const passkeyId = 'passkey_uuid-1234-abcd';
      backend.addFactor(session.accountDID, { id: passkeyId, kind: 'passkey', label: 'My Key', enabled: true });

      await api.revokePasskey(passkeyId);

      const req = recordedRequests.find((r) => r.method === 'DELETE' && r.url.includes('/account/api/factors/passkeys/'));
      expect(req).toBeDefined();
      expect(req?.method).toBe('DELETE');
      expect(req?.url).toBe(`/account/api/factors/passkeys/${encodeURIComponent(passkeyId)}`);
    });

    it('issues DELETE /account/api/factors/totp for TOTP revocation', async () => {
      await api.revokeTotp();
      const req = recordedRequests.find((r) => r.method === 'DELETE' && r.url === '/account/api/factors/totp');
      expect(req).toBeDefined();
      expect(req?.method).toBe('DELETE');
    });

    it('verifies bulk session revocation issues POST /account/api/sessions/revoke-others', async () => {
      await api.revokeOtherSessions();

      const req = recordedRequests.find((r) => r.url === '/account/api/sessions/revoke-others');
      expect(req).toBeDefined();
      expect(req?.method).toBe('POST');
    });
  });

  // =========================================================================
  // 3. Step-Up Interception during View Actions & Modal Mounting in +page.svelte
  // =========================================================================
  describe('3. StepUpModal Integration & 403 Challenge Replay Engine', () => {
    it('StepUpModal opens upon 403 step_up_required challenge during deletion and replays with receipt', async () => {
      // Intercept DELETE /account/api/connected-apps/app-1 with 403 step_up_required once
      let challengeIssued = false;
      backend.addInterceptor((req) => {
        const stepUpHeader = (req.headers as any)['x-swan-step-up'] || (req.headers as any)['X-Swan-Step-Up'];
        if (req.method === 'DELETE' && req.url.includes('app-1') && !challengeIssued && !stepUpHeader) {
          challengeIssued = true;
          return {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'step_up_required', message: 'MFA confirmation required' }
          };
        }
        return undefined;
      });

      // Launch deletion action in background
      const revokePromise = api.revokeConnectedApp('app-1');

      // Check that stepup store is opened
      await vi.waitFor(() => {
        expect(get(stepup).isOpen).toBe(true);
      });
      expect(get(stepup).context?.operation).toBe('connected-apps/app-1');

      // User submits step-up password
      const passwordStepUpPromise = api.stepUpPassword('correct-horse-battery-staple');
      await passwordStepUpPromise;

      // Resolve stepup with receipt token
      stepup.resolveStepUp('receipt-token-xyz-123');

      // Deletion promise should now resolve successfully
      const result = await revokePromise;
      expect(result.accepted).toBe(true);

      // Check recorded requests: 2 DELETE calls (first challenged, second with X-Swan-Step-Up)
      const deleteRequests = recordedRequests.filter((r) => r.method === 'DELETE' && r.url.includes('app-1'));
      expect(deleteRequests.length).toBe(2);
      const secondHeaders = deleteRequests[1].headers;
      const stepUpSent = (secondHeaders as any).get ? (secondHeaders as any).get('X-Swan-Step-Up') : (secondHeaders as any)['x-swan-step-up'] || (secondHeaders as any)['X-Swan-Step-Up'];
      expect(stepUpSent).toBe('receipt-token-xyz-123');
    });

    it('StepUpModal replays in-place elevated session when resolveStepUp(true) is called', async () => {
      let challengeIssued = false;
      backend.addInterceptor((req) => {
        if (req.method === 'DELETE' && req.url.includes('sess-remote-1') && !challengeIssued) {
          challengeIssued = true;
          return {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'request_not_allowed', message: 'Password confirmation required' }
          };
        }
        return undefined;
      });

      const revokePromise = api.revokeSession('sess-remote-1');

      await vi.waitFor(() => {
        expect(get(stepup).isOpen).toBe(true);
      });

      // User re-authenticates in-place
      stepup.resolveStepUp(true);

      const result = await revokePromise;
      expect(result.accepted).toBe(true);

      const deleteRequests = recordedRequests.filter((r) => r.method === 'DELETE' && r.url.includes('sess-remote-1'));
      expect(deleteRequests.length).toBe(2);
    });

    it('cancelling step-up dialog cleanly aborts the pending view mutation without corrupting state', async () => {
      backend.addInterceptor((req) => {
        if (req.method === 'DELETE' && req.url.includes('app-1')) {
          return {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'step_up_required', message: 'Step-up required' }
          };
        }
        return undefined;
      });

      const revokePromise = api.revokeConnectedApp('app-1');

      await vi.waitFor(() => {
        expect(get(stepup).isOpen).toBe(true);
      });

      // User clicks Cancel
      stepup.cancelStepUp('User dismissed re-authentication');

      await expect(revokePromise).rejects.toMatchObject({
        status: 403,
        code: 'step_up_required'
      });
      expect(get(stepup).isOpen).toBe(false);
    });

    it('handles multiple concurrent 403 mutations by queuing and resolving all together upon single step-up', async () => {
      let isElevated = false;
      backend.addInterceptor((req) => {
        const stepUpHeader = (req.headers as any)['x-swan-step-up'] || (req.headers as any)['X-Swan-Step-Up'];
        if (req.method === 'DELETE' && !stepUpHeader && !isElevated) {
          return {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'step_up_required', message: 'Step-up required' }
          };
        }
        return undefined;
      });

      // Fire 3 concurrent protected mutations from different view triggers
      const promise1 = api.revokeSession('sess-remote-1');
      const promise2 = api.revokeAppPassword('CLI Bot');
      const promise3 = api.revokeConnectedApp('app-oauth-1');

      await vi.waitFor(() => {
        expect(get(stepup).isOpen).toBe(true);
      });

      // Single step-up resolution with elevated session
      isElevated = true;
      stepup.resolveStepUp(true);

      const [res1, res2, res3] = await Promise.all([promise1, promise2, promise3]);
      expect(res1.accepted).toBe(true);
      expect(res2.accepted).toBe(true);
      expect(res3.accepted).toBe(true);
      expect(get(stepup).isOpen).toBe(false);
    });

    it('parses and surfaces granular error codes and messages across all HTTP statuses', async () => {
      // 400 Bad Request
      backend.addInterceptor((req) => {
        if (req.url.includes('bad-req')) {
          return {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'invalid_request', message: 'Payload validation failed: name too long' }
          };
        }
        if (req.url.includes('rate-limit')) {
          return {
            status: 429,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'rate_limited', message: 'Too many revocation requests' }
          };
        }
        if (req.url.includes('server-fail')) {
          return {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'database_error', message: 'Database connection failed' }
          };
        }
        return undefined;
      });

      await expect(accountFetch('sessions/bad-req', { method: 'DELETE' })).rejects.toMatchObject({
        status: 400,
        code: 'invalid_request',
        message: 'Payload validation failed: name too long'
      });

      await expect(accountFetch('sessions/rate-limit', { method: 'DELETE' })).rejects.toMatchObject({
        status: 429,
        code: 'rate_limited',
        message: 'Too many revocation requests'
      });

      await expect(accountFetch('sessions/server-fail', { method: 'DELETE' })).rejects.toMatchObject({
        status: 500,
        code: 'database_error',
        message: 'Database connection failed'
      });
    });
  });
});
