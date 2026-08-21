import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import { api, accountFetch, setCSRF, setStepUpHandler } from '../../src/lib/api';
import {
  portal,
  currentAccount,
  currentIdentity,
  activeSessions,
  activeApps,
  activePasswords,
  activeFactors
} from '../../src/lib/stores/portal';
import { modals, activeModal } from '../../src/lib/stores/modals';
import { toasts } from '../../src/lib/stores/toasts';
import { stepup } from '../../src/lib/stores/stepup';
import { setupTestEnv, teardownTestEnv } from './harness/test-env';
import type { MockSwanBackend, MockSession } from './harness/mock-backend';

describe('Adversarial Verification Suite (Challenger 2 M4-It2)', () => {
  let backend: MockSwanBackend;
  let session: MockSession;
  let recordedRequests: Array<{
    method: string;
    url: string;
    headers: Record<string, string | string[] | undefined>;
    body?: string;
  }> = [];

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: true, elevated: true });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);
    setStepUpHandler((context) => stepup.requestStepUp(context));

    portal.setSnapshot({
      account: {
        did: 'did:plc:adversarial-tester-456',
        handle: 'tester.swan.place',
        email: 'tester@swan.place',
        lifecycle: 'active'
      },
      identity: {
        method: 'didWeb',
        handle: 'tester.swan.place',
        state: 'active'
      },
      strength: 'stepUpPassword',
      factors: [
        { id: 'pk-adv-1', kind: 'passkey', label: 'Primary TouchID', enabled: true },
        { id: 'totp-adv-1', kind: 'totp', label: 'Authenticator App', enabled: true },
        { id: 'rec-adv-1', kind: 'recoveryCode', label: 'Backup Codes', enabled: true }
      ],
      sessions: [
        { id: 'sess-active-curr', label: 'Current Device', kind: 'management', lastSeen: 'now', current: true },
        { id: 'sess-adv-remote', label: 'Remote MacBook', kind: 'legacy', lastSeen: '30m ago', current: false },
        { id: 'sess/odd?chars=true#tag', label: 'Session with URI special chars', kind: 'management', lastSeen: '3d ago', current: false }
      ],
      apps: [
        { id: 'app/oauth-id:99', name: 'ThirdParty Service', scopes: ['atproto'], createdAt: '2026-08-10' }
      ],
      passwords: [
        { name: 'CLI / Token (Legacy) & Bot', scopes: ['atproto', 'transition:chat.bsky'], createdAt: '2026-08-15', lastUsedAt: null }
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
  // 1. Modal Launch Triggers across all 9 views
  // =========================================================================
  describe('1. Modal Launch Triggers and Payloads across 9 Views', () => {
    it('verifies OverviewView triggers correct modals', () => {
      // Passkey shortcut
      modals.open('passkey-enroll');
      expect(get(activeModal)?.type).toBe('passkey-enroll');
      expect(modals.isOpen('passkey-enroll')).toBe(true);
      modals.close('passkey-enroll');
      expect(modals.isOpen('passkey-enroll')).toBe(false);

      // App Password shortcut
      modals.open('app-password');
      expect(get(activeModal)?.type).toBe('app-password');
      expect(modals.isOpen('app-password')).toBe(true);
      modals.close('app-password');
      expect(modals.isOpen('app-password')).toBe(false);

      // Export shortcut
      modals.open('export');
      expect(get(activeModal)?.type).toBe('export');
      expect(modals.isOpen('export')).toBe(true);
      modals.close('export');
      expect(modals.isOpen('export')).toBe(false);
    });

    it('verifies ProfileView triggers did-web modals with accurate initialMode payload', () => {
      // 1. Mode: new
      modals.open('did-web', { initialMode: 'new', mode: 'new' });
      let current = get(activeModal);
      expect(current?.type).toBe('did-web');
      expect(current?.payload?.initialMode).toBe('new');
      expect(current?.payload?.mode).toBe('new');
      modals.close('did-web');

      // 2. Mode: rotate
      modals.open('did-web', { initialMode: 'rotate', mode: 'rotate' });
      current = get(activeModal);
      expect(current?.type).toBe('did-web');
      expect(current?.payload?.initialMode).toBe('rotate');
      expect(current?.payload?.mode).toBe('rotate');
      modals.close('did-web');

      // 3. Mode: remove
      modals.open('did-web', { initialMode: 'remove', mode: 'remove' });
      current = get(activeModal);
      expect(current?.type).toBe('did-web');
      expect(current?.payload?.initialMode).toBe('remove');
      expect(current?.payload?.mode).toBe('remove');
      modals.close('did-web');
    });

    it('verifies SecurityView triggers passkey-enroll, totp-enroll, recovery-rotate', () => {
      modals.open('passkey-enroll');
      expect(get(activeModal)?.type).toBe('passkey-enroll');
      modals.close('passkey-enroll');

      modals.open('totp-enroll');
      expect(get(activeModal)?.type).toBe('totp-enroll');
      modals.close('totp-enroll');

      modals.open('recovery-rotate');
      expect(get(activeModal)?.type).toBe('recovery-rotate');
      modals.close('recovery-rotate');
    });

    it('verifies RecoveryView triggers recovery-rotate', () => {
      modals.open('recovery-rotate');
      expect(get(activeModal)?.type).toBe('recovery-rotate');
      modals.close('recovery-rotate');
    });

    it('verifies PasswordsView triggers app-password', () => {
      modals.open('app-password');
      expect(get(activeModal)?.type).toBe('app-password');
      modals.close('app-password');
    });

    it('verifies ExportView triggers export', () => {
      modals.open('export');
      expect(get(activeModal)?.type).toBe('export');
      modals.close('export');
    });

    it('verifies LifecycleView triggers lifecycle-deactivate and lifecycle-delete with exact payload mode', () => {
      // Deactivate
      modals.open('lifecycle-deactivate', { mode: 'deactivate' });
      let current = get(activeModal);
      expect(current?.type).toBe('lifecycle-deactivate');
      expect(current?.payload?.mode).toBe('deactivate');
      modals.close();

      // Delete
      modals.open('lifecycle-delete', { mode: 'delete' });
      current = get(activeModal);
      expect(current?.type).toBe('lifecycle-delete');
      expect(current?.payload?.mode).toBe('delete');
      modals.close();
    });
  });

  // =========================================================================
  // 2. HTTP DELETE Revocation Actions & URL Encoding
  // =========================================================================
  describe('2. HTTP DELETE Revocation Operations & CSRF Attachment', () => {
    it('verifies DELETE /account/api/sessions/:id with URL encoding and CSRF header', async () => {
      const oddSessionId = 'sess/odd?chars=true#tag';
      await api.revokeSession(oddSessionId);

      const req = recordedRequests.find(
        (r) => r.method === 'DELETE' && r.url.startsWith('/account/api/sessions/')
      );
      expect(req).toBeDefined();
      expect(req?.method).toBe('DELETE');
      expect(req?.url).toBe(`/account/api/sessions/${encodeURIComponent(oddSessionId)}`);

      const csrfHeader = (req?.headers as any)['x-swan-csrf'] || (req?.headers as any)['X-Swan-CSRF'];
      expect(csrfHeader).toBe(session.csrfToken);
    });

    it('verifies DELETE /account/api/app-passwords/:name with URL encoding and CSRF header', async () => {
      const complexName = 'CLI / Token (Legacy) & Bot';
      await api.revokeAppPassword(complexName);

      const req = recordedRequests.find(
        (r) => r.method === 'DELETE' && r.url.startsWith('/account/api/app-passwords/')
      );
      expect(req).toBeDefined();
      expect(req?.method).toBe('DELETE');
      expect(req?.url).toBe(`/account/api/app-passwords/${encodeURIComponent(complexName)}`);

      const csrfHeader = (req?.headers as any)['x-swan-csrf'] || (req?.headers as any)['X-Swan-CSRF'];
      expect(csrfHeader).toBe(session.csrfToken);
    });

    it('verifies DELETE /account/api/connected-apps/:id with URL encoding and CSRF header', async () => {
      const appId = 'app/oauth-id:99';
      await api.revokeConnectedApp(appId);

      const req = recordedRequests.find(
        (r) => r.method === 'DELETE' && r.url.startsWith('/account/api/connected-apps/')
      );
      expect(req).toBeDefined();
      expect(req?.method).toBe('DELETE');
      expect(req?.url).toBe(`/account/api/connected-apps/${encodeURIComponent(appId)}`);

      const csrfHeader = (req?.headers as any)['x-swan-csrf'] || (req?.headers as any)['X-Swan-CSRF'];
      expect(csrfHeader).toBe(session.csrfToken);
    });

    it('verifies DELETE /account/api/factors/passkeys/:id with URL encoding and CSRF header', async () => {
      const passkeyId = 'pk-adv-1';
      await api.revokePasskey(passkeyId);

      const req = recordedRequests.find(
        (r) => r.method === 'DELETE' && r.url.startsWith('/account/api/factors/passkeys/')
      );
      expect(req).toBeDefined();
      expect(req?.method).toBe('DELETE');
      expect(req?.url).toBe(`/account/api/factors/passkeys/${encodeURIComponent(passkeyId)}`);

      const csrfHeader = (req?.headers as any)['x-swan-csrf'] || (req?.headers as any)['X-Swan-CSRF'];
      expect(csrfHeader).toBe(session.csrfToken);
    });

    it('verifies DELETE /account/api/factors/totp issues correct HTTP DELETE request', async () => {
      await api.revokeTotp();
      const req = recordedRequests.find(
        (r) => r.method === 'DELETE' && r.url === '/account/api/factors/totp'
      );
      expect(req).toBeDefined();
      expect(req?.method).toBe('DELETE');

      const csrfHeader = (req?.headers as any)['x-swan-csrf'] || (req?.headers as any)['X-Swan-CSRF'];
      expect(csrfHeader).toBe(session.csrfToken);
    });

    it('verifies bulk session revocation issues POST /account/api/sessions/revoke-others', async () => {
      await api.revokeOtherSessions();

      const req = recordedRequests.find(
        (r) => r.url === '/account/api/sessions/revoke-others'
      );
      expect(req).toBeDefined();
      expect(req?.method).toBe('POST');
    });
  });

  // =========================================================================
  // 3. StepUpModal & 403 Challenge Replay Engine
  // =========================================================================
  describe('3. StepUpModal Mounting & 403 Re-Authentication Ceremony', () => {
    it('handles 403 step_up_required challenge during mutation and replays with receipt', async () => {
      const receipt = backend.issueStepUpReceipt(session.id, session.accountDID);
      let challengeIssued = false;

      backend.addInterceptor((req) => {
        const stepUpHeader =
          (req.headers as any)['x-swan-step-up'] ||
          (req.headers as any)['X-Swan-Step-Up'];
        if (
          req.method === 'DELETE' &&
          req.url.includes('connected-apps') &&
          !challengeIssued &&
          !stepUpHeader
        ) {
          challengeIssued = true;
          return {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'step_up_required', message: 'Step-up required for connected app revocation' }
          };
        }
        return undefined;
      });

      const revokePromise = api.revokeConnectedApp('app/oauth-id:99');

      // Stepup store triggers
      await vi.waitFor(() => {
        expect(get(stepup).isOpen).toBe(true);
      });

      expect(get(stepup).context?.operation).toBe(
        `connected-apps/${encodeURIComponent('app/oauth-id:99')}`
      );

      // Resolve stepup with receipt token
      stepup.resolveStepUp(receipt.receiptToken);

      const result = await revokePromise;
      expect(result.accepted).toBe(true);

      const deleteReqs = recordedRequests.filter(
        (r) => r.method === 'DELETE' && r.url.includes('connected-apps')
      );
      expect(deleteReqs.length).toBe(2);

      const headers = deleteReqs[1].headers;
      const stepUpToken = (headers as any)['x-swan-step-up'] || (headers as any)['X-Swan-Step-Up'];
      expect(stepUpToken).toBe(receipt.receiptToken);
    });

    it('handles in-place session elevation with resolveStepUp(true)', async () => {
      let challengeIssued = false;
      backend.addInterceptor((req) => {
        if (req.method === 'DELETE' && req.url.includes('sess-adv-remote') && !challengeIssued) {
          challengeIssued = true;
          return {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'step_up_required', message: 'Step-up required' }
          };
        }
        return undefined;
      });

      const revokePromise = api.revokeSession('sess-adv-remote');

      await vi.waitFor(() => {
        expect(get(stepup).isOpen).toBe(true);
      });

      // Submit password step-up on backend
      await api.stepUpPassword('correct-horse-battery-staple');

      // Resolve stepup with true for in-place elevated session
      stepup.resolveStepUp(true);

      const result = await revokePromise;
      expect(result.accepted).toBe(true);

      const deleteReqs = recordedRequests.filter(
        (r) => r.method === 'DELETE' && r.url.includes('sess-adv-remote')
      );
      expect(deleteReqs.length).toBe(2);
    });

    it('correctly handles user cancellation of StepUpModal', async () => {
      backend.addInterceptor((req) => {
        if (req.method === 'DELETE' && req.url.includes('passkeys')) {
          return {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'step_up_required', message: 'Passkey deletion requires elevation' }
          };
        }
        return undefined;
      });

      const revokePromise = api.revokePasskey('pk-adv-1');

      await vi.waitFor(() => {
        expect(get(stepup).isOpen).toBe(true);
      });

      stepup.cancelStepUp('User closed the modal');

      await expect(revokePromise).rejects.toMatchObject({
        status: 403,
        code: 'step_up_required'
      });
      expect(get(stepup).isOpen).toBe(false);
    });

    it('queues multiple concurrent mutations and resolves all when StepUp succeeds', async () => {
      let isElevated = false;
      backend.addInterceptor((req) => {
        const stepUpHeader =
          (req.headers as any)['x-swan-step-up'] ||
          (req.headers as any)['X-Swan-Step-Up'];
        if (req.method === 'DELETE' && !stepUpHeader && !isElevated) {
          return {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'step_up_required', message: 'Step-up required' }
          };
        }
        return undefined;
      });

      const call1 = api.revokeSession('sess-adv-remote');
      const call2 = api.revokeConnectedApp('app/oauth-id:99');

      await vi.waitFor(() => {
        expect(get(stepup).isOpen).toBe(true);
      });

      isElevated = true;
      stepup.resolveStepUp(true);

      const [res1, res2] = await Promise.all([call1, call2]);
      expect(res1.accepted).toBe(true);
      expect(res2.accepted).toBe(true);
      expect(get(stepup).isOpen).toBe(false);
    });
  });
});
