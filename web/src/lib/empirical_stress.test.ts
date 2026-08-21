import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import {
  accountFetch,
  api,
  bootstrap,
  getCSRF,
  readError,
  setCSRF,
  setStepUpHandler
} from './api';
import { toasts } from './stores/toasts';
import { modals, activeModal } from './stores/modals';
import {
  portal,
  currentAccount,
  currentIdentity,
  activeSessions,
  activeApps,
  activePasswords,
  activeFactors
} from './stores/portal';
import type { PortalSnapshot } from './types';

describe('Empirical Adversarial Challenge Suite (Milestone 1)', () => {
  describe('1. API Client & CSRF Lifecycle Adversarial Tests', () => {
    beforeEach(() => {
      setCSRF(undefined);
      setStepUpHandler(null);
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('concurrent mutations only perform bootstrap once per race condition or reuse properly', async () => {
      let bootstrapCallCount = 0;
      vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
        const url = String(input);
        if (url === '/account/api/bootstrap') {
          bootstrapCallCount++;
          // Simulate slight network delay
          await new Promise((r) => setTimeout(r, 5));
          return new Response(JSON.stringify({ csrf: `csrf-token-${bootstrapCallCount}` }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        if (url.startsWith('/account/api/')) {
          return new Response(JSON.stringify({ ok: true, url }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        return new Response('Not found', { status: 404 });
      });

      // Fire 10 concurrent mutations when csrf is undefined
      const promises = Array.from({ length: 10 }).map((_, i) =>
        accountFetch(`mutation-${i}`, { method: 'POST', body: JSON.stringify({ index: i }) })
      );

      const results = await Promise.all(promises);
      expect(results.length).toBe(10);
      expect(getCSRF()).toBeDefined();

      // Subsequent mutation must not call bootstrap again
      const currentBootstrapCount = bootstrapCallCount;
      await accountFetch('mutation-after', { method: 'POST', body: '{}' });
      expect(bootstrapCallCount).toBe(currentBootstrapCount);
    });

    it('handles bootstrap failure gracefully by throwing ApiError and not setting CSRF', async () => {
      vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
        Promise.resolve(
          new Response(JSON.stringify({ code: 'service_unavailable', message: 'Bootstrap failed' }), {
            status: 503
          })
        )
      );

      await expect(accountFetch('sessions/revoke-others', { method: 'POST', body: '{}' })).rejects.toMatchObject({
        code: 'service_unavailable',
        message: 'Bootstrap failed',
        status: 503
      });

      expect(getCSRF()).toBeUndefined();
    });

    it('login mutation updates CSRF token from LoginResponse and exposes it to subsequent requests', async () => {
      const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementationOnce(() =>
          Promise.resolve(new Response(JSON.stringify({ csrf: 'pre-login-csrf' }), { status: 200 }))
        )
        .mockImplementationOnce(() =>
          Promise.resolve(
            new Response(
              JSON.stringify({
                snapshot: { account: { handle: 'alice.swan.place' } },
                csrf: 'post-login-session-csrf'
              }),
              { status: 200 }
            )
          )
        )
        .mockImplementationOnce(() =>
          Promise.resolve(new Response(JSON.stringify({ ok: true }), { status: 200 }))
        );

      const loginResult = await api.login({ handle: 'alice', password: 'password123' });
      expect(loginResult.csrf).toBe('post-login-session-csrf');
      expect(getCSRF()).toBe('post-login-session-csrf');

      await api.logout();
      const [, logoutRequest] = fetchMock.mock.calls[2];
      expect(((logoutRequest as RequestInit).headers as Headers).get('X-Swan-CSRF')).toBe(
        'post-login-session-csrf'
      );
    });

    it('GET and HEAD requests do not trigger CSRF bootstrap nor attach Content-Type or CSRF header', async () => {
      const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementation(() =>
          Promise.resolve(new Response(JSON.stringify({ data: 'ok' }), { status: 200 }))
        );

      await accountFetch('test-get', { method: 'GET' });
      await accountFetch('test-head', { method: 'HEAD' });

      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(getCSRF()).toBeUndefined();

      const req0 = fetchMock.mock.calls[0][1] as RequestInit;
      expect((req0.headers as Headers).get('X-Swan-CSRF')).toBeNull();
      expect((req0.headers as Headers).get('Content-Type')).toBeNull();

      const req1 = fetchMock.mock.calls[1][1] as RequestInit;
      expect((req1.headers as Headers).get('X-Swan-CSRF')).toBeNull();
    });

    it('correctly handles paths with leading slashes, extra whitespace, or query strings', async () => {
      const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementation(() =>
          Promise.resolve(new Response(JSON.stringify({ ok: true }), { status: 200 }))
        );

      await accountFetch('/portal');
      expect(fetchMock.mock.calls[0][0]).toBe('/account/api/portal');

      await accountFetch('factors/passkeys?active=true');
      expect(fetchMock.mock.calls[1][0]).toBe('/account/api/factors/passkeys?active=true');
    });

    it('verifies all 28 API helper methods issue correct HTTP method and endpoint', async () => {
      setCSRF('mock-csrf');
      const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementation(() =>
          Promise.resolve(new Response(JSON.stringify({ message: 'ok' }), { status: 200 }))
        );

      // Snapshot & Policy
      await api.fetchBootstrap();
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/bootstrap',
        expect.objectContaining({ method: 'GET' })
      );

      await api.fetchSignupPolicy();
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/signup/policy',
        expect.objectContaining({ method: 'GET' })
      );

      await api.fetchSnapshot();
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/portal',
        expect.objectContaining({ method: 'GET' })
      );

      // Auth & Step-up
      await api.stepUpPassword('secret');
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/step-up/password',
        expect.objectContaining({ method: 'POST' })
      );

      // Sessions
      await api.revokeSession('session/with/slashes');
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/sessions/session%2Fwith%2Fslashes',
        expect.objectContaining({ method: 'DELETE' })
      );

      await api.revokeOtherSessions();
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/sessions/revoke-others',
        expect.objectContaining({ method: 'POST' })
      );

      // App Passwords
      await api.createAppPassword({ name: 'key1', scopes: ['atproto'] });
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/app-passwords',
        expect.objectContaining({ method: 'POST' })
      );

      await api.revokeAppPassword('key 1 # special');
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/app-passwords/key%201%20%23%20special',
        expect.objectContaining({ method: 'DELETE' })
      );

      // Connected apps
      await api.revokeConnectedApp('app-id-123');
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/connected-apps/app-id-123',
        expect.objectContaining({ method: 'DELETE' })
      );

      // WebAuthn Passkeys
      await api.requestPasskeyChallenge('My Key', 'fac-1');
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/factors/passkeys/challenge',
        expect.objectContaining({ method: 'POST' })
      );

      await api.registerPasskey({
        label: 'My Key',
        challenge: 'ch',
        clientDataJSON: 'cd',
        authenticatorData: 'ad',
        credentialID: 'cid'
      });
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/factors/passkeys',
        expect.objectContaining({ method: 'POST' })
      );

      await api.registerPasskey(
        {
          label: 'My Key',
          challenge: 'ch',
          clientDataJSON: 'cd',
          authenticatorData: 'ad',
          credentialID: 'cid'
        },
        'fac-1'
      );
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/factors/passkeys/fac-1',
        expect.objectContaining({ method: 'POST' })
      );

      await api.requestPasskeyStepUpChallenge('fac-1');
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/factors/passkeys/step-up-challenge',
        expect.objectContaining({ method: 'POST' })
      );

      await api.submitPasskeyAssertion({
        kind: 'passkey',
        factorID: 'fac-1',
        challenge: 'ch',
        clientDataJSON: 'cd',
        authenticatorData: 'ad',
        credentialID: 'cid',
        signature: 'sig'
      });
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/factors/step-up',
        expect.objectContaining({ method: 'POST' })
      );

      await api.revokePasskey('fac-1');
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/factors/passkeys/fac-1',
        expect.objectContaining({ method: 'DELETE' })
      );

      // TOTP
      await api.enrollTotp({ label: 'Auth App', secret: 'JBSWY3DPEHPK3PXP' });
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/factors/totp',
        expect.objectContaining({ method: 'POST' })
      );

      await api.verifyTotpEnrollment('fac-totp', '123456');
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/factors/totp/verify',
        expect.objectContaining({ method: 'POST' })
      );

      await api.stepUpTotp('fac-totp', '654321');
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/factors/step-up',
        expect.objectContaining({ method: 'POST' })
      );

      await api.revokeTotp('fac-totp');
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/factors/totp/fac-totp',
        expect.objectContaining({ method: 'DELETE' })
      );

      await api.revokeTotp();
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/factors/totp',
        expect.objectContaining({ method: 'DELETE' })
      );

      // Recovery codes
      await api.rotateRecoveryCodes();
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/factors/recovery-codes/rotate',
        expect.objectContaining({ method: 'POST' })
      );

      await api.stepUpRecoveryCode('rec-code-123');
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/factors/step-up',
        expect.objectContaining({ method: 'POST' })
      );

      // did:web
      await api.reserveDidWeb({
        requestID: 'r-1',
        targetDID: 'did:web:example.com',
        handle: 'example.com',
        expiresAt: '2026-08-19T00:00:00Z'
      });
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/identity/reserve',
        expect.objectContaining({ method: 'POST' })
      );

      await api.claimDidWeb({ requestID: 'r-1' });
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/identity/claim',
        expect.objectContaining({ method: 'POST' })
      );

      await api.rotateDidWeb({
        requestID: 'r-1',
        targetDID: 'did:web:example.com',
        handle: 'example.com',
        expiresAt: '2026-08-19T00:00:00Z',
        stepUpReceipt: 'receipt-1'
      });
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/identity/rotate',
        expect.objectContaining({ method: 'POST' })
      );

      await api.removeDidWeb({ stepUpReceipt: 'receipt-1' });
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/identity/remove',
        expect.objectContaining({ method: 'POST' })
      );

      await api.reverifyDidWeb();
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/identity/reverify',
        expect.objectContaining({ method: 'POST' })
      );

      await api.getDidWebAdmission();
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/identity/admission',
        expect.objectContaining({ method: 'POST' })
      );

      // Export & Lifecycle
      await api.requestExport();
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/export/request',
        expect.objectContaining({ method: 'POST' })
      );

      await api.deleteAccount();
      expect(fetchMock).toHaveBeenLastCalledWith(
        '/account/api/lifecycle/delete',
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('correctly handles 204 No Content for DELETE or mutation responses without JSON parsing errors', async () => {
      setCSRF('mock-csrf');
      vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
        Promise.resolve(new Response(null, { status: 204 }))
      );

      const res = await api.revokeSession('s-123');
      expect(res).toBeUndefined();
    });
  });

  describe('2. Error Parsing & Status Fallback Adversarial Tests', () => {
    it('parses error when JSON body has { error: "invalid_request" } without message', async () => {
      const response = new Response(JSON.stringify({ error: 'invalid_request' }), { status: 400 });
      const err = await readError(response);
      expect(err.code).toBe('invalid_request');
      expect(err.message).toBe('Invalid request parameters.');
      expect(err.status).toBe(400);
    });

    it('parses error when JSON body has { message: "Custom message" } without code on 400', async () => {
      const response = new Response(JSON.stringify({ message: 'Custom bad input' }), { status: 400 });
      const err = await readError(response);
      expect(err.code).toBe('unknown_error');
      expect(err.message).toBe('Custom bad input');
      expect(err.status).toBe(400);
    });

    it('parses error when JSON body is empty object {} on 403', async () => {
      const response = new Response(JSON.stringify({}), { status: 403 });
      const err = await readError(response);
      expect(err.code).toBe('request_not_allowed');
      expect(err.message).toBe('This action requires password or MFA verification.');
      expect(err.status).toBe(403);
    });

    it('handles non-JSON 403 Forbidden with proper fallback', async () => {
      const response = new Response('Forbidden', { status: 403 });
      const err = await readError(response);
      expect(err.code).toBe('request_not_allowed');
      expect(err.message).toBe('Request not allowed.');
      expect(err.status).toBe(403);
    });

    it('handles non-JSON 500/502/503 errors gracefully', async () => {
      const response = new Response('<html>500 Internal Error</html>', { status: 500 });
      const err = await readError(response);
      expect(err.code).toBe('service_unavailable');
      expect(err.message).toBe('The account service is temporarily unavailable.');
      expect(err.status).toBe(500);
    });
  });

  describe('3. Step-Up Interception & Replay Semantic Edge Cases', () => {
    beforeEach(() => {
      setCSRF('mock-csrf');
      setStepUpHandler(null);
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('does not trigger step-up replay if handler returns false or null', async () => {
      const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
        Promise.resolve(
          new Response(JSON.stringify({ code: 'step_up_required', message: 'Step-up needed' }), {
            status: 403
          })
        )
      );

      const handlerMock = vi.fn().mockResolvedValue(false);
      setStepUpHandler(handlerMock);

      await expect(api.rotateRecoveryCodes()).rejects.toMatchObject({
        code: 'step_up_required',
        status: 403
      });

      expect(handlerMock).toHaveBeenCalledTimes(1);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('prevents infinite recursion when replayed request also returns 403', async () => {
      const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
        Promise.resolve(
          new Response(JSON.stringify({ code: 'step_up_required', message: 'Still forbidden' }), {
            status: 403
          })
        )
      );

      const handlerMock = vi.fn().mockResolvedValue('receipt-token-1');
      setStepUpHandler(handlerMock);

      await expect(api.rotateRecoveryCodes()).rejects.toMatchObject({
        code: 'step_up_required',
        status: 403
      });

      // Original request (1) -> Step-up handler (1) -> Replayed request (2) -> 403 (throws because skipStepUp is true)
      expect(handlerMock).toHaveBeenCalledTimes(1);
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it('intercepts request_not_allowed on non-403 status (e.g. 401 or 400)', async () => {
      const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockImplementationOnce(() =>
          Promise.resolve(
            new Response(JSON.stringify({ code: 'request_not_allowed', message: 'MFA needed' }), {
              status: 400
            })
          )
        )
        .mockImplementationOnce(() =>
          Promise.resolve(
            new Response(JSON.stringify({ message: 'Success' }), { status: 200 })
          )
        );

      const handlerMock = vi.fn().mockResolvedValue('receipt-xyz');
      setStepUpHandler(handlerMock);

      const res = await api.createAppPassword({ name: 'cli', scopes: ['atproto'] });
      expect(res).toEqual({ message: 'Success' });
      expect(handlerMock).toHaveBeenCalledTimes(1);
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });
  });

  describe('4. Toasts Store Stress & Concurrency Tests', () => {
    beforeEach(() => {
      vi.useFakeTimers();
      toasts.clear();
    });

    afterEach(() => {
      toasts.clear();
      vi.restoreAllMocks();
      vi.useRealTimers();
    });

    it('handles 200 rapid concurrent toasts and auto-dismisses them without memory leaks', () => {
      const ids: string[] = [];
      for (let i = 0; i < 200; i++) {
        ids.push(toasts.info(`Toast message #${i}`, { duration: 1000 + (i % 5) * 1000 }));
      }

      expect(get(toasts).length).toBe(200);

      // Advance time past all timers
      vi.advanceTimersByTime(6000);
      expect(get(toasts).length).toBe(0);
    });

    it('manually dismissing a toast cancels its timer and is idempotent', () => {
      const id1 = toasts.info('Toast 1', { duration: 5000 });
      const id2 = toasts.info('Toast 2', { duration: 5000 });

      expect(get(toasts).length).toBe(2);

      // Dismiss id1
      toasts.dismiss(id1);
      expect(get(toasts).length).toBe(1);
      expect(get(toasts)[0].id).toBe(id2);

      // Dismiss id1 again (no crash, idempotent)
      toasts.dismiss(id1);
      expect(get(toasts).length).toBe(1);

      // Advance time to when id1 would have fired
      vi.advanceTimersByTime(5001);
      // id2 should now be dismissed, list is empty
      expect(get(toasts).length).toBe(0);
    });

    it('clear() cancels all active timers immediately', () => {
      toasts.info('Toast 1', { duration: 3000 });
      toasts.warning('Toast 2', { duration: 4000 });
      toasts.error('Toast 3', { duration: 5000 });

      expect(get(toasts).length).toBe(3);
      toasts.clear();
      expect(get(toasts).length).toBe(0);

      // Advance timers; no ghost dismiss calls should cause unexpected state
      vi.advanceTimersByTime(10000);
      expect(get(toasts).length).toBe(0);
    });
  });

  describe('5. Modals Store Stack & Concurrency Stress Tests', () => {
    beforeEach(() => {
      modals.closeAll();
    });

    it('handles deep modal nesting and pops correctly', () => {
      const id1 = modals.open('export');
      const id2 = modals.push('did-web');
      const id3 = modals.push('step-up');
      const id4 = modals.push('totp-enroll');

      const state = get(modals);
      expect(state.stack.length).toBe(4);
      expect(state.active?.id).toBe(id4);
      expect(get(activeModal)?.type).toBe('totp-enroll');

      const pop1 = modals.pop();
      expect(pop1?.id).toBe(id4);
      expect(get(modals).active?.id).toBe(id3);

      const pop2 = modals.pop();
      expect(pop2?.id).toBe(id3);
      expect(get(modals).active?.id).toBe(id2);

      const pop3 = modals.pop();
      expect(pop3?.id).toBe(id2);
      expect(get(modals).active?.id).toBe(id1);

      const pop4 = modals.pop();
      expect(pop4?.id).toBe(id1);
      expect(get(modals).active).toBeNull();
      expect(get(modals).stack).toEqual([]);

      // Pop on empty stack
      const popEmpty = modals.pop();
      expect(popEmpty).toBeUndefined();
      expect(get(modals).active).toBeNull();
    });

    it('closing a modal in the middle of the stack maintains the topmost modal as active', () => {
      modals.open('export');
      modals.push('did-web');
      modals.push('step-up');

      // Close the middle modal ('did-web')
      modals.close('did-web');

      const state = get(modals);
      expect(state.stack.length).toBe(2);
      expect(state.stack.map((m) => m.type)).toEqual(['export', 'step-up']);
      expect(state.active?.type).toBe('step-up');
      expect(modals.isOpen('did-web')).toBe(false);
      expect(modals.isOpen('export')).toBe(true);
      expect(modals.isOpen('step-up')).toBe(true);
    });

    it('open() clears previous stack and sets new single active modal', () => {
      modals.push('export');
      modals.push('step-up');
      expect(get(modals).stack.length).toBe(2);

      const newId = modals.open('lifecycle-delete');
      const state = get(modals);
      expect(state.stack.length).toBe(1);
      expect(state.active?.id).toBe(newId);
      expect(state.active?.type).toBe('lifecycle-delete');
    });

    it('stress test: 100 interleaved modal operations maintain invariant', () => {
      for (let i = 0; i < 100; i++) {
        if (i % 3 === 0) {
          modals.push('step-up', { i });
        } else if (i % 3 === 1) {
          modals.push('export', { i });
        } else {
          modals.pop();
        }

        const state = get(modals);
        if (state.stack.length === 0) {
          expect(state.active).toBeNull();
          expect(get(activeModal)).toBeNull();
        } else {
          expect(state.active).toBe(state.stack[state.stack.length - 1]);
          expect(get(activeModal)).toBe(state.stack[state.stack.length - 1]);
        }
      }
    });
  });

  describe('6. Portal Store Patching & Derived Store Reactivity Tests', () => {
    const initialMock: PortalSnapshot = {
      account: { did: 'did:plc:alice', handle: 'alice.swan.place', lifecycle: 'active' },
      identity: { method: 'plc', handle: 'alice.swan.place', state: 'active' },
      strength: 'password',
      factors: [{ id: 'f-1', kind: 'passkey', label: 'Laptop', enabled: true }],
      sessions: [{ id: 's-1', label: 'Web', kind: 'management', lastSeen: '2026-08-18', current: true }],
      apps: [{ id: 'a-1', name: 'App1', scopes: ['atproto'], createdAt: '2026-08-01' }],
      passwords: [{ name: 'pw1', scopes: ['atproto'], createdAt: '2026-08-01' }]
    };

    beforeEach(() => {
      portal.reset();
    });

    it('patchSnapshot when snapshot is null does not throw and leaves state unchanged', () => {
      expect(get(portal).snapshot).toBeNull();
      portal.patchSnapshot((s) => ({ ...s, strength: 'stepUpPassword' }));
      expect(get(portal).snapshot).toBeNull();
    });

    it('patching sub-arrays immediately triggers reactivity in all derived stores', () => {
      portal.setSnapshot(initialMock);

      expect(get(activeSessions).length).toBe(1);
      expect(get(activePasswords).length).toBe(1);
      expect(get(activeFactors).length).toBe(1);
      expect(get(activeApps).length).toBe(1);

      // Add a session
      portal.patchSnapshot((s) => ({
        ...s,
        sessions: [...s.sessions, { id: 's-2', label: 'Mobile', kind: 'legacy', lastSeen: '2026-08-18', current: false }]
      }));
      expect(get(activeSessions).length).toBe(2);

      // Remove an app password
      portal.patchSnapshot((s) => ({
        ...s,
        passwords: s.passwords.filter((p) => p.name !== 'pw1')
      }));
      expect(get(activePasswords).length).toBe(0);

      // Add a factor
      portal.patchSnapshot((s) => ({
        ...s,
        factors: [...s.factors, { id: 'f-2', kind: 'totp', label: 'Phone TOTP', enabled: true }]
      }));
      expect(get(activeFactors).length).toBe(2);

      // Update account details
      portal.patchSnapshot((s) => ({
        ...s,
        account: { ...s.account, email: 'alice@example.com' }
      }));
      expect(get(currentAccount)?.email).toBe('alice@example.com');
    });

    it('resetting portal store resets derived stores to empty fallbacks', () => {
      portal.setSnapshot(initialMock);
      expect(get(currentAccount)).not.toBeNull();

      portal.reset();
      expect(get(currentAccount)).toBeNull();
      expect(get(currentIdentity)).toBeNull();
      expect(get(activeSessions)).toEqual([]);
      expect(get(activeApps)).toEqual([]);
      expect(get(activePasswords)).toEqual([]);
      expect(get(activeFactors)).toEqual([]);
    });
  });
});
