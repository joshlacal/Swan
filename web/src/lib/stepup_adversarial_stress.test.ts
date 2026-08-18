import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import {
  accountFetch,
  api,
  getCSRF,
  setCSRF,
  setStepUpHandler
} from './api';
import { stepup } from './stores/stepup';
import { modals } from './stores/modals';
import { portal } from './stores/portal';
import * as webauthnModule from './webauthn';
import type { ApiError, PortalSnapshot } from './types';

function flush(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 15));
}

describe('Empirical Adversarial Challenge Suite: Step-Up Interceptor & Re-Auth Engine', () => {
  beforeEach(() => {
    setCSRF('mock-valid-csrf');
    stepup.reset();
    modals.closeAll();
    portal.reset();
    setStepUpHandler((context) => stepup.requestStepUp(context));
  });

  afterEach(() => {
    stepup.reset();
    modals.closeAll();
    portal.reset();
    vi.restoreAllMocks();
  });

  // ==========================================================================
  // 1. Concurrency Coalescing Stress Tests
  // ==========================================================================
  describe('1. Concurrency Coalescing & Batch Replays', () => {
    it('coalesces 100 simultaneous 403 mutations into a single prompt and replays with receipt token', async () => {
      let callCount = 0;
      const replayedReceipts: (string | null)[] = [];

      vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
        const url = String(input);
        callCount++;
        const headers = new Headers(init?.headers);
        const receipt = headers.get('X-Swan-Step-Up');

        if (receipt === 'shared-receipt-100') {
          replayedReceipts.push(receipt);
          return new Response(
            JSON.stringify({ accepted: true, password: `swan-app-${url.split('/').pop()}` }),
            { status: 200, headers: { 'Content-Type': 'application/json' } }
          );
        }

        // Initial call returns 403 step_up_required
        return new Response(
          JSON.stringify({ code: 'step_up_required', message: 'Elevation required' }),
          { status: 403, headers: { 'Content-Type': 'application/json' } }
        );
      });

      // Launch 100 concurrent mutations
      const promises = Array.from({ length: 100 }).map((_, i) =>
        api.createAppPassword({ name: `App-${i}`, scopes: ['atproto'] })
      );

      // Wait for fetch promises to return 403 and trigger step-up interceptor
      await flush();

      // Verify only 1 prompt opened in stepup store and modals store
      expect(get(stepup).isOpen).toBe(true);
      expect(get(modals).stack.length).toBe(1);
      expect(get(modals).active?.type).toBe('step-up');

      // User satisfies step-up in modal, resolving with receipt token
      stepup.resolveStepUp('shared-receipt-100');

      const results = await Promise.all(promises);

      expect(results.length).toBe(100);
      results.forEach((res) => {
        expect(res.accepted).toBe(true);
        expect((res as any).password).toMatch(/^swan-app-/);
      });

      // Verify all 100 replayed requests attached the shared receipt header
      expect(replayedReceipts.length).toBe(100);
      expect(replayedReceipts.every((r) => r === 'shared-receipt-100')).toBe(true);

      // Verify modal and stepup state reset to idle
      expect(get(stepup).isOpen).toBe(false);
      expect(get(modals).stack.length).toBe(0);
      expect(get(modals).active).toBeNull();
    });

    it('coalesces 50 simultaneous 403 mutations and replays with in-place session elevation (true)', async () => {
      let callCount = 0;
      let sessionElevated = false;

      vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
        callCount++;
        const headers = new Headers(init?.headers);
        const receipt = headers.get('X-Swan-Step-Up');

        if (sessionElevated) {
          // Verify in-place elevation replay does NOT send X-Swan-Step-Up header
          expect(receipt).toBeNull();
          return new Response(
            JSON.stringify({ accepted: true, rotated: true }),
            { status: 200, headers: { 'Content-Type': 'application/json' } }
          );
        }

        return new Response(
          JSON.stringify({ code: 'step_up_required', message: 'Password step-up required' }),
          { status: 403, headers: { 'Content-Type': 'application/json' } }
        );
      });

      // Launch 50 concurrent mutations requiring elevation
      const promises = Array.from({ length: 50 }).map(() =>
        api.rotateRecoveryCodes()
      );

      await flush();

      expect(get(stepup).isOpen).toBe(true);
      expect(get(modals).stack.length).toBe(1);

      // Simulate in-place elevation (e.g. user entered password)
      sessionElevated = true;
      stepup.resolveStepUp(true);

      const results = await Promise.all(promises);
      expect(results.length).toBe(50);
      results.forEach((res) => {
        expect(res.accepted).toBe(true);
        expect((res as any).rotated).toBe(true);
      });

      expect(get(stepup).isOpen).toBe(false);
      expect(get(modals).stack.length).toBe(0);
    });

    it('handles mixed traffic: simultaneous GET requests and step-up mutations', async () => {
      let stepUpCount = 0;
      vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
        const url = String(input);
        const method = (init?.method || 'GET').toUpperCase();
        const headers = new Headers(init?.headers);

        if (method === 'GET') {
          return new Response(
            JSON.stringify({ account: { handle: 'alice.swan.place' } }),
            { status: 200, headers: { 'Content-Type': 'application/json' } }
          );
        }

        if (headers.get('X-Swan-Step-Up') === 'token-mixed') {
          return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          });
        }

        stepUpCount++;
        return new Response(
          JSON.stringify({ code: 'step_up_required', message: 'Step-up required' }),
          { status: 403, headers: { 'Content-Type': 'application/json' } }
        );
      });

      // Interleave 10 GETs and 10 mutations
      const gets = Array.from({ length: 10 }).map(() => api.fetchSnapshot());
      const mutations = Array.from({ length: 10 }).map((_, i) =>
        api.revokeAppPassword(`key-${i}`)
      );

      // GETs resolve immediately
      const getResults = await Promise.all(gets);
      expect(getResults.length).toBe(10);
      getResults.forEach((r) => expect(r.account.handle).toBe('alice.swan.place'));

      // Mutations are waiting for step-up
      await flush();
      expect(get(stepup).isOpen).toBe(true);
      stepup.resolveStepUp('token-mixed');

      const mutationResults = await Promise.all(mutations);
      expect(mutationResults.length).toBe(10);
      mutationResults.forEach((r) => expect((r as any).success).toBe(true));
    });
  });

  // ==========================================================================
  // 2. User Cancellation Stress Tests
  // ==========================================================================
  describe('2. User Cancellation & Error Propagation', () => {
    it('coalesces 50 concurrent requests and cleanly rejects all 50 when user cancels', async () => {
      vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
        return new Response(
          JSON.stringify({ code: 'step_up_required', message: 'Elevate session' }),
          { status: 403, headers: { 'Content-Type': 'application/json' } }
        );
      });

      const promises = Array.from({ length: 50 }).map((_, i) =>
        api.createAppPassword({ name: `App-${i}`, scopes: ['atproto'] })
      );

      await flush();
      expect(get(stepup).isOpen).toBe(true);

      // User dismisses modal
      stepup.cancelStepUp('User closed dialog via Escape');

      const settled = await Promise.allSettled(promises);
      expect(settled.length).toBe(50);

      settled.forEach((res) => {
        expect(res.status).toBe('rejected');
        if (res.status === 'rejected') {
          const err = res.reason as ApiError;
          expect(err.status).toBe(403);
          expect(err.code).toBe('step_up_required');
          expect(err.message).toBe('Elevate session');
        }
      });

      // Verify complete store cleanup
      expect(get(stepup).isOpen).toBe(false);
      expect(get(stepup).context).toBeNull();
      expect(get(stepup).loading).toBe(false);
      expect(get(stepup).error).toBeNull();
      expect(get(modals).stack.length).toBe(0);
    });

    it('allows clean subsequent step-up request immediately after cancellation without stale state', async () => {
      let callCount = 0;
      vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
        callCount++;
        const headers = new Headers(init?.headers);
        if (headers.get('X-Swan-Step-Up') === 'fresh-token-after-cancel') {
          return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        return new Response(
          JSON.stringify({ code: 'request_not_allowed', message: 'Step-up needed' }),
          { status: 403, headers: { 'Content-Type': 'application/json' } }
        );
      });

      // 1. First request cancelled
      const p1 = api.revokeSession('s-1');
      await flush();
      stepup.cancelStepUp();
      await expect(p1).rejects.toMatchObject({ code: 'request_not_allowed', status: 403 });

      // 2. Second request triggered
      const p2 = api.revokeSession('s-2');
      await flush();
      expect(get(stepup).isOpen).toBe(true);
      stepup.resolveStepUp('fresh-token-after-cancel');
      const res2 = await p2;
      expect((res2 as any).success).toBe(true);
      expect(get(stepup).isOpen).toBe(false);
    });
  });

  // ==========================================================================
  // 3. Chained and Sequential Step-Up Cycles
  // ==========================================================================
  describe('3. Chained & Sequential Step-Up Cycles', () => {
    it('handles chained step-up triggered inside .then() handler of previous step-up', async () => {
      let callCount = 0;
      vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
        callCount++;
        const headers = new Headers(init?.headers);
        const receipt = headers.get('X-Swan-Step-Up');

        if (receipt === 'token-1' || receipt === 'token-2') {
          return new Response(JSON.stringify({ step: receipt }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          });
        }

        return new Response(
          JSON.stringify({ code: 'step_up_required', message: 'Step-up required' }),
          { status: 403, headers: { 'Content-Type': 'application/json' } }
        );
      });

      // Step 1
      const p1 = api.createAppPassword({ name: 'App1', scopes: ['atproto'] });
      await flush();
      expect(get(stepup).isOpen).toBe(true);
      stepup.resolveStepUp('token-1');
      const res1 = await p1;
      expect((res1 as any).step).toBe('token-1');
      expect(get(stepup).isOpen).toBe(false);

      // Step 2 chained
      const p2 = api.createAppPassword({ name: 'App2', scopes: ['atproto'] });
      await flush();
      expect(get(stepup).isOpen).toBe(true);
      stepup.resolveStepUp('token-2');
      const res2 = await p2;
      expect((res2 as any).step).toBe('token-2');
      expect(get(stepup).isOpen).toBe(false);
    });
  });

  // ==========================================================================
  // 4. Factor Selection Filtering & Fallback Matrix
  // ==========================================================================
  describe('4. Factor Selection Filtering & Fallback Matrix', () => {
    it('defaults to password factor when portal snapshot has no registered MFA factors', () => {
      portal.setSnapshot({
        account: { did: 'did:plc:alice', handle: 'alice.swan.place', lifecycle: 'active' },
        strength: 'password',
        factors: [],
        sessions: [],
        apps: [],
        passwords: []
      });

      stepup.requestStepUp();
      const state = get(stepup);
      expect(state.allowedFactors).toEqual(['password']);
      expect(state.selectedFactor).toBe('password');
    });

    it('includes totp and recoveryCode and defaults to totp when only TOTP is enabled', () => {
      portal.setSnapshot({
        account: { did: 'did:plc:alice', handle: 'alice.swan.place', lifecycle: 'active' },
        strength: 'password',
        factors: [
          { id: 'f-totp', kind: 'totp', label: 'Auth App', enabled: true }
        ],
        sessions: [],
        apps: [],
        passwords: []
      });

      stepup.requestStepUp();
      const state = get(stepup);
      expect(state.allowedFactors).toEqual(['password', 'totp', 'recoveryCode']);
      expect(state.selectedFactor).toBe('totp');
    });

    it('includes passkey and recoveryCode and defaults to passkey when WebAuthn is supported', () => {
      vi.spyOn(webauthnModule, 'isWebAuthnSupported').mockReturnValue(true);

      portal.setSnapshot({
        account: { did: 'did:plc:alice', handle: 'alice.swan.place', lifecycle: 'active' },
        strength: 'password',
        factors: [
          { id: 'f-pk', kind: 'passkey', label: 'MacBook', enabled: true }
        ],
        sessions: [],
        apps: [],
        passwords: []
      });

      stepup.requestStepUp();
      const state = get(stepup);
      expect(state.allowedFactors).toEqual(['password', 'passkey', 'recoveryCode']);
      expect(state.selectedFactor).toBe('passkey');
    });

    it('filters out passkey when browser does NOT support WebAuthn even if passkey is registered', () => {
      vi.spyOn(webauthnModule, 'isWebAuthnSupported').mockReturnValue(false);

      portal.setSnapshot({
        account: { did: 'did:plc:alice', handle: 'alice.swan.place', lifecycle: 'active' },
        strength: 'password',
        factors: [
          { id: 'f-pk', kind: 'passkey', label: 'MacBook', enabled: true }
        ],
        sessions: [],
        apps: [],
        passwords: []
      });

      stepup.requestStepUp();
      const state = get(stepup);
      // Passkey filtered out because isWebAuthnSupported() is false
      expect(state.allowedFactors).not.toContain('passkey');
      expect(state.allowedFactors).toEqual(['password', 'recoveryCode']);
      expect(state.selectedFactor).toBe('password');
    });

    it('ignores disabled factors (enabled: false)', () => {
      portal.setSnapshot({
        account: { did: 'did:plc:alice', handle: 'alice.swan.place', lifecycle: 'active' },
        strength: 'password',
        factors: [
          { id: 'f-totp', kind: 'totp', label: 'Old TOTP', enabled: false }
        ],
        sessions: [],
        apps: [],
        passwords: []
      });

      stepup.requestStepUp();
      const state = get(stepup);
      expect(state.allowedFactors).toEqual(['password']);
      expect(state.selectedFactor).toBe('password');
    });

    it('handles string "true" for factor enabled property', () => {
      portal.setSnapshot({
        account: { did: 'did:plc:alice', handle: 'alice.swan.place', lifecycle: 'active' },
        strength: 'password',
        factors: [
          { id: 'f-totp', kind: 'totp', label: 'String TOTP', enabled: 'true' as any }
        ],
        sessions: [],
        apps: [],
        passwords: []
      });

      stepup.requestStepUp();
      const state = get(stepup);
      expect(state.allowedFactors).toContain('totp');
    });

    it('respects explicit allowedFactors passed in context override', () => {
      stepup.requestStepUp({ allowedFactors: ['password', 'recoveryCode'] });
      const state = get(stepup);
      expect(state.allowedFactors).toEqual(['password', 'recoveryCode']);
      expect(state.selectedFactor).toBe('password');
    });

    it('selectFactor updates factor and clears previous error message', () => {
      stepup.requestStepUp({ allowedFactors: ['password', 'totp'] });
      stepup.setError('Invalid password');
      expect(get(stepup).error).toBe('Invalid password');

      stepup.selectFactor('totp');
      expect(get(stepup).selectedFactor).toBe('totp');
      expect(get(stepup).error).toBeNull();
    });
  });

  // ==========================================================================
  // 5. Infinite Loop & Replay Defense
  // ==========================================================================
  describe('5. Infinite Loop & Replay Defense', () => {
    it('terminates cleanly and throws error when replayed request fails with 403', async () => {
      let callCount = 0;
      vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
        callCount++;
        return new Response(
          JSON.stringify({ code: 'step_up_required', message: 'Elevation failed' }),
          { status: 403, headers: { 'Content-Type': 'application/json' } }
        );
      });

      const p = api.createAppPassword({ name: 'LoopTest', scopes: ['atproto'] });
      await flush();
      stepup.resolveStepUp('invalid-or-stale-receipt');

      await expect(p).rejects.toMatchObject({
        code: 'step_up_required',
        status: 403,
        message: 'Elevation failed'
      });

      // Exactly 2 calls: initial call (1) -> stepup replay (2) -> stops (no infinite loop)
      expect(callCount).toBe(2);
      expect(get(stepup).isOpen).toBe(false);
    });

    it('correctly propagates replay error: 500 on replayed request throws actual 500 error instead of stale 403', async () => {
      let callCount = 0;
      vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
        callCount++;
        const headers = new Headers(init?.headers);
        if (headers.get('X-Swan-Step-Up')) {
          return new Response(
            JSON.stringify({ code: 'internal_error', message: 'Database failure' }),
            { status: 500, headers: { 'Content-Type': 'application/json' } }
          );
        }
        return new Response(
            JSON.stringify({ code: 'step_up_required', message: 'Step-up needed' }),
            { status: 403, headers: { 'Content-Type': 'application/json' } }
        );
      });

      const p = api.rotateRecoveryCodes();
      await flush();
      stepup.resolveStepUp('valid-receipt');

      const err = await p.catch((e) => e);
      expect(err.status).toBe(500);
      expect(err.code).toBe('internal_error');
      expect(err.message).toBe('Database failure');
      expect(callCount).toBe(2);
    });

    it('bypasses step-up handler entirely when skipStepUp option is explicitly true', async () => {
      const handlerMock = vi.fn();
      setStepUpHandler(handlerMock);

      vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
        return new Response(
          JSON.stringify({ code: 'step_up_required', message: 'Forbidden' }),
          { status: 403, headers: { 'Content-Type': 'application/json' } }
        );
      });

      await expect(
        accountFetch('app-passwords', { method: 'POST', body: '{}' }, { skipStepUp: true })
      ).rejects.toMatchObject({
        code: 'step_up_required',
        status: 403
      });

      expect(handlerMock).not.toHaveBeenCalled();
    });
  });
});
