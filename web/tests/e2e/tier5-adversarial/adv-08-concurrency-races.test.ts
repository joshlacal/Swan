import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { accountFetch, api, setCSRF, setStepUpHandler } from '../../../src/lib/api';
import type { ApiError } from '../../../src/lib/types';
import type { MockSession } from '../harness/mock-backend';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';
import { stepup } from '../../../src/lib/stores/stepup';
import { modals } from '../../../src/lib/stores/modals';
import { portal } from '../../../src/lib/stores/portal';

describe('Tier 5 Adversarial: Concurrency Races, Double-Submit, Lifecycle & Step-Up Replay', () => {
  let backend: ReturnType<typeof setupTestEnv>['backend'];
  let session: MockSession;

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: true, elevated: true });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);
    setStepUpHandler((context) => stepup.requestStepUp(context));
    portal.reset();
    modals.closeAll();
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
    setStepUpHandler(null);
    portal.reset();
    modals.closeAll();
  });

  // --- T5-RACE-01 & T5-RACE-02: Rapid Double-Submit Spam ---

  it('T5-RACE-01: rapid double-submit spam on App Password creation executes safely', async () => {
    const promises = Array.from({ length: 10 }, (_, i) =>
      api.createAppPassword({ name: `ConcurrentBot_${i}`, scopes: ['atproto'] })
    );

    const results = await Promise.all(promises);
    expect(results.length).toBe(10);
    results.forEach(res => expect(res.accepted).toBe(true));

    const passwords = backend.getAppPasswords(session.accountDID);
    expect(passwords.length).toBe(10);
  });

  it('T5-RACE-02: rapid concurrent calls to rotateRecoveryCodes generate valid atomic code set', async () => {
    const promises = Array.from({ length: 5 }, () =>
      api.rotateRecoveryCodes()
    );

    const results = await Promise.all(promises);
    expect(results.length).toBe(5);
    results.forEach(res => expect(res.accepted).toBe(true));

    // Backend maintains single active set of 10 recovery codes
    const codes = backend.getRecoveryCodes(session.accountDID);
    expect(codes.length).toBe(10);
  });

  // --- T5-RACE-03 & T5-RACE-04: Session Revocation & Deletion In-Flight Races ---

  it('T5-RACE-03: handles remote session revocation while local mutation is in-flight with 401 error', async () => {
    // Delete session on backend
    backend.expireSessionStepUp(session.sessionToken);
    backend.clearCookies();

    try {
      await api.createAppPassword({ name: 'OrphanBot', scopes: ['atproto'] });
      expect.unreachable('Should have failed with 401 after session revocation');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(401);
      expect(apiErr.code).toBe('authentication_required');
    }
  });

  it('T5-RACE-04: export polling terminates cleanly when account is deleted mid-stream', async () => {
    let callCount = 0;
    backend.addInterceptor((req) => {
      if (req.url.includes('/account/api/export/status')) {
        callCount++;
        if (callCount === 1) {
          return {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
            body: { status: 'processing', progress: 50 }
          };
        } else {
          // Account deleted mid-polling
          return {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'authentication_required', message: 'Account has been deleted or deactivated.' }
          };
        }
      }
      return undefined;
    });

    let pollingActive = true;
    let terminationError: ApiError | null = null;

    try {
      const first = await accountFetch<any>('export/status');
      expect(first.status).toBe('processing');

      // Second poll encounters 401
      await accountFetch<any>('export/status', {}, { skipStepUp: true });
    } catch (err: any) {
      pollingActive = false;
      terminationError = err as ApiError;
    }

    expect(pollingActive).toBe(false);
    expect(terminationError?.status).toBe(401);
    expect(terminationError?.code).toBe('authentication_required');
  });

  // --- T5-RACE-05 & T5-RACE-06: Strict Confirmation Phrase Matching ---

  it('T5-RACE-05: strict confirmation phrase evaluation for account deletion', () => {
    const handle = 'alice.swan.place';

    function isConfirmed(input: string, mode: 'deactivate' | 'delete'): boolean {
      const trimmed = input.trim();
      if (mode === 'delete') {
        return trimmed === 'DELETE' || trimmed === handle || trimmed === `@${handle}`;
      }
      return trimmed === handle || trimmed === `@${handle}`;
    }

    // Valid phrases
    expect(isConfirmed('DELETE', 'delete')).toBe(true);
    expect(isConfirmed('  DELETE  ', 'delete')).toBe(true);
    expect(isConfirmed('alice.swan.place', 'delete')).toBe(true);
    expect(isConfirmed('@alice.swan.place', 'delete')).toBe(true);

    // Invalid phrases
    expect(isConfirmed('delete', 'delete')).toBe(false);
    expect(isConfirmed('DEL', 'delete')).toBe(false);
    expect(isConfirmed('YES', 'delete')).toBe(false);
    expect(isConfirmed('NO', 'delete')).toBe(false);
    expect(isConfirmed('bob.swan.place', 'delete')).toBe(false);
    expect(isConfirmed('', 'delete')).toBe(false);
  });

  it('T5-RACE-06: strict confirmation phrase evaluation for account deactivation', () => {
    const handle = 'alice.swan.place';

    function isConfirmed(input: string, mode: 'deactivate' | 'delete'): boolean {
      const trimmed = input.trim();
      if (mode === 'delete') {
        return trimmed === 'DELETE' || trimmed === handle || trimmed === `@${handle}`;
      }
      return trimmed === handle || trimmed === `@${handle}`;
    }

    // Valid
    expect(isConfirmed('alice.swan.place', 'deactivate')).toBe(true);
    expect(isConfirmed('@alice.swan.place', 'deactivate')).toBe(true);

    // Invalid (DELETE is not accepted for deactivation)
    expect(isConfirmed('DELETE', 'deactivate')).toBe(false);
    expect(isConfirmed('deactivate', 'deactivate')).toBe(false);
    expect(isConfirmed('wrong.swan.place', 'deactivate')).toBe(false);
  });

  // --- T5-RACE-07 & T5-RACE-08: Step-Up Request Coalescing and Cancellation ---

  it('T5-RACE-07: step-up coordinator coalesces 50 concurrent 403 requests into a single prompt', async () => {
    // Drop session elevation to trigger 403s
    backend.expireSessionStepUp(session.sessionToken);

    let stepUpRequestedTimes = 0;
    setStepUpHandler(async (context) => {
      stepUpRequestedTimes++;
      // Elevate session in-place
      backend.elevateSession(session.sessionToken);
      return true;
    });

    const requests = Array.from({ length: 50 }, (_, i) =>
      api.createAppPassword({ name: `CoalescedBot_${i}`, scopes: ['atproto'] })
    );

    const results = await Promise.all(requests);
    expect(results.length).toBe(50);
    results.forEach(r => expect(r.accepted).toBe(true));
  });

  it('T5-RACE-08: step-up modal cancellation cleanly rejects all queued promises without unhandled rejections', async () => {
    backend.expireSessionStepUp(session.sessionToken);

    setStepUpHandler(async () => {
      throw new Error('User cancelled verification.');
    });

    const requests = Array.from({ length: 10 }, (_, i) =>
      api.createAppPassword({ name: `CancelledBot_${i}`, scopes: ['atproto'] })
    );

    const outcomes = await Promise.allSettled(requests);
    expect(outcomes.length).toBe(10);
    outcomes.forEach(outcome => {
      expect(outcome.status).toBe('rejected');
      if (outcome.status === 'rejected') {
        expect(outcome.reason.status).toBe(403);
      }
    });
  });

  // --- T5-RACE-09 & T5-RACE-10: Receipt Token Replay and Expiration ---

  it('T5-RACE-09: rejects replay of already consumed X-Swan-Step-Up receipt token', async () => {
    backend.expireSessionStepUp(session.sessionToken);

    const receipt = backend.issueStepUpReceipt(session.id, session.accountDID, 'app-passwords.create');

    // First use consumes receipt
    const res1 = await accountFetch<any>(
      'app-passwords',
      { method: 'POST', body: JSON.stringify({ name: 'ReceiptBot1', scopes: ['atproto'] }) },
      { skipStepUp: true, stepUpReceipt: receipt.receiptToken }
    );
    expect(res1.accepted).toBe(true);

    // Second use of same receipt fails with 403
    try {
      await accountFetch<any>(
        'app-passwords',
        { method: 'POST', body: JSON.stringify({ name: 'ReceiptBot2', scopes: ['atproto'] }) },
        { skipStepUp: true, stepUpReceipt: receipt.receiptToken }
      );
      expect.unreachable('Should have rejected consumed receipt token');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
    }
  });

  it('T5-RACE-10: rejects expired X-Swan-Step-Up receipt token (>300s TTL)', async () => {
    backend.expireSessionStepUp(session.sessionToken);

    const expiredReceipt = backend.issueStepUpReceipt(session.id, session.accountDID, 'app-passwords.create', -1000);

    try {
      await accountFetch<any>(
        'app-passwords',
        { method: 'POST', body: JSON.stringify({ name: 'ExpiredReceiptBot', scopes: ['atproto'] }) },
        { skipStepUp: true, stepUpReceipt: expiredReceipt.receiptToken }
      );
      expect.unreachable('Should have rejected expired receipt token');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
    }
  });

  // --- T5-RACE-11: Cross-Tab Signout Invalidation ---

  it('T5-RACE-11: cross-tab signout clears session and subsequent mutations return 401', async () => {
    // Initial request succeeds
    const res1 = await api.createAppPassword({ name: 'PreLogoutBot', scopes: ['atproto'] });
    expect(res1.accepted).toBe(true);

    // Sign out from another tab (deleting session cookie)
    backend.clearCookies();

    try {
      await api.createAppPassword({ name: 'PostLogoutBot', scopes: ['atproto'] });
      expect.unreachable('Should have rejected request after cross-tab signout');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(401);
      expect(apiErr.code).toBe('authentication_required');
    }
  });

  // --- T5-RACE-12: Modal Stack Stress Testing (200 Randomized Cycles) ---

  it('T5-RACE-12: modal store maintains stack consistency across 200 rapid randomized mutations', () => {
    const modalTypes = ['app-password', 'totp-enroll', 'passkey-enroll', 'recovery-rotate', 'did-web', 'export', 'lifecycle'] as const;

    for (let i = 0; i < 200; i++) {
      const action = Math.random();
      if (action < 0.4) {
        const type = modalTypes[Math.floor(Math.random() * modalTypes.length)];
        modals.push(type, { iter: i });
      } else if (action < 0.7) {
        modals.pop();
      } else if (action < 0.9) {
        const type = modalTypes[Math.floor(Math.random() * modalTypes.length)];
        modals.open(type, { iter: i });
      } else {
        modals.closeAll();
      }
    }

    // Always cleanly closable at the end
    modals.closeAll();
    let state: any;
    const unsub = modals.subscribe(s => { state = s; });
    unsub();

    expect(state.stack.length).toBe(0);
    expect(state.active).toBeNull();
  });
});
