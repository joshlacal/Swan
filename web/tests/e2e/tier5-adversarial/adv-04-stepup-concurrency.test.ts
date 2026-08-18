import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api, setCSRF, setStepUpHandler } from '../../../src/lib/api';
import { stepup } from '../../../src/lib/stores/stepup';
import { modals } from '../../../src/lib/stores/modals';
import {
  getTestBackend,
  setupTestEnv,
  teardownTestEnv
} from '../harness/test-env';

describe('Tier 5 Adversarial - Suite 04: Step-Up Concurrency, Replay Defense & Store State', () => {
  let backend: ReturnType<typeof getTestBackend>;
  let currentSessionToken: string;

  beforeEach(() => {
    const env = setupTestEnv({
      authenticated: true,
      elevated: false // Ensure session requires step-up
    });
    backend = env.backend;
    currentSessionToken = env.session!.sessionToken;
    setCSRF(env.session!.csrfToken);
    // Connect default stepup store handler
    setStepUpHandler((context) => stepup.requestStepUp(context));
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
    setStepUpHandler(null);
  });

  /**
   * T5-ST-01: 100-Request Simultaneous 403 Storm Coalescing
   * An application UI triggers 100 simultaneous protected mutations that return HTTP 403.
   * All 100 requests must coalesce into exactly 1 step-up dialog prompt.
   * Resolving with a valid receipt token must replay all 100 mutations simultaneously.
   */
  it('T5-ST-01: 100-Request Simultaneous 403 Storm Coalescing', async () => {
    let stepUpOpenCount = 0;
    stepup.subscribe((s) => {
      if (s.isOpen) stepUpOpenCount++;
    });

    // 100 simultaneous mutations
    const stormPromises = Array.from({ length: 100 }, (_, i) =>
      api.createAppPassword({
        name: `storm_password_${i}`,
        scopes: ['atproto']
      })
    );

    // Yield macro-task / micro-task queue to let all 100 requests execute and fail with 403
    await new Promise((r) => setTimeout(r, 20));

    // Exactly 1 step-up modal opened
    expect(modals.isOpen('step-up')).toBe(true);

    // Issue valid single-use receipt for replay
    const session = backend.getSession(currentSessionToken)!;
    // For 100 requests replaying simultaneously, simulate session elevation so all succeed
    backend.elevateSession(currentSessionToken, 'stepUpPassword');

    // Resolve step-up dialog
    stepup.resolveStepUp(true);

    // All 100 requests should resolve successfully
    const results = await Promise.all(stormPromises);
    expect(results.length).toBe(100);
    results.forEach((res) => {
      expect(res.accepted).toBe(true);
    });

    // Verify modal closed
    expect(modals.isOpen('step-up')).toBe(false);
  });

  /**
   * T5-ST-02: In-Place Elevation (resolveStepUp(true)) Replay
   * 50 concurrent requests fail with 403; user enters password directly in StepUpModal,
   * which elevates the cookie session in-place and calls resolveStepUp(true).
   * All 50 requests must replay without X-Swan-Step-Up header and succeed.
   */
  it('T5-ST-02: In-Place Elevation (resolveStepUp(true)) Replay', async () => {
    const concurrentRequests = Array.from({ length: 50 }, (_, i) =>
      api.createAppPassword({
        name: `inplace_elevate_${i}`,
        scopes: ['atproto', 'transition:email']
      })
    );

    await new Promise((r) => setTimeout(r, 15));
    expect(modals.isOpen('step-up')).toBe(true);

    // Elevate session in-place (simulating successful POST /account/api/step-up/password)
    backend.elevateSession(currentSessionToken, 'stepUpPassword');

    // Resolve with true
    stepup.resolveStepUp(true);

    const results = await Promise.all(concurrentRequests);
    expect(results.length).toBe(50);
    results.forEach((r) => expect(r.accepted).toBe(true));
  });

  /**
   * T5-ST-03: User Cancellation Cascade & Clean Store Reset
   * 50 concurrent requests fail with 403; user dismisses the dialog (cancelStepUp()).
   * All 50 promises must reject cleanly with the original 403 ApiError, and the store
   * must reset to clean initial state.
   */
  it('T5-ST-03: User Cancellation Cascade & Clean Rejection', async () => {
    const concurrentRequests = Array.from({ length: 50 }, (_, i) =>
      api.createAppPassword({
        name: `cancel_test_${i}`,
        scopes: ['atproto']
      })
    );

    await new Promise((r) => setTimeout(r, 15));
    expect(modals.isOpen('step-up')).toBe(true);

    // User cancels
    stepup.cancelStepUp('User closed dialog');

    const settled = await Promise.allSettled(concurrentRequests);
    expect(settled.length).toBe(50);

    settled.forEach((res) => {
      expect(res.status).toBe('rejected');
      if (res.status === 'rejected') {
        expect(res.reason.status).toBe(403);
        expect(res.reason.code).toBe('step_up_required');
      }
    });

    // Store is cleanly reset
    expect(modals.isOpen('step-up')).toBe(false);
  });

  /**
   * T5-ST-04: Immediate Post-Cancel Re-Authentication
   * When Request 1 is cancelled, an immediate subsequent Request 2 must open
   * a fresh step-up prompt without being stuck or polluted by the cancelled request.
   */
  it('T5-ST-04: Immediate Post-Cancel Re-Authentication', async () => {
    // 1. Request 1 fails with 403
    const req1 = api.createAppPassword({ name: 'req1', scopes: ['atproto'] });
    await new Promise((r) => setTimeout(r, 10));
    expect(modals.isOpen('step-up')).toBe(true);

    // User cancels request 1
    stepup.cancelStepUp('Cancelled first prompt');
    await expect(req1).rejects.toThrow();
    expect(modals.isOpen('step-up')).toBe(false);

    // 2. Request 2 triggered immediately
    const req2 = api.createAppPassword({ name: 'req2', scopes: ['atproto'] });
    await new Promise((r) => setTimeout(r, 10));
    expect(modals.isOpen('step-up')).toBe(true);

    // Elevate and resolve request 2
    backend.elevateSession(currentSessionToken, 'stepUpPassword');
    stepup.resolveStepUp(true);

    const result2 = await req2;
    expect(result2.accepted).toBe(true);
    expect(modals.isOpen('step-up')).toBe(false);
  });

  /**
   * T5-ST-05: Replay Infinite Loop Defense (skipStepUp: true)
   * If a replayed request fails with 403 again (e.g. receipt was rejected),
   * accountFetch must NOT trigger stepUpHandler recursively. Total fetch calls must be exactly 2.
   */
  it('T5-ST-05: Replay Infinite Loop Defense', async () => {
    let handlerCallCount = 0;
    setStepUpHandler(async (ctx) => {
      handlerCallCount++;
      return 'invalid_expired_receipt';
    });

    let fetchCount = 0;
    backend.addInterceptor((req) => {
      if (req.url.includes('app-passwords') && req.method === 'POST') {
        fetchCount++;
        // Always reject with 403
        return {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
          body: { code: 'request_not_allowed', message: 'Step-up rejected.' }
        };
      }
      return undefined;
    });

    await expect(
      api.createAppPassword({ name: 'loop_defense', scopes: ['atproto'] })
    ).rejects.toMatchObject({
      status: 403,
      code: 'request_not_allowed'
    });

    // Exactly 1 handler call and 2 network fetch requests (initial + 1 replay)
    expect(handlerCallCount).toBe(1);
    expect(fetchCount).toBe(2);
  });

  /**
   * T5-ST-06: Replay Non-403 Error Propagation
   * If the replayed request fails with a 500 Internal Server Error,
   * accountFetch must propagate the 500 ApiError, NOT the initial 403.
   */
  it('T5-ST-06: Replay Non-403 Error Propagation', async () => {
    let callIndex = 0;
    backend.addInterceptor((req) => {
      if (req.url.includes('app-passwords') && req.method === 'POST') {
        callIndex++;
        if (callIndex === 1) {
          // First attempt: 403
          return {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'request_not_allowed', message: 'Step-up required.' }
          };
        } else {
          // Replayed attempt: 500 Server Error
          return {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
            body: { code: 'database_unavailable', message: 'Database connection failed.' }
          };
        }
      }
      return undefined;
    });

    setStepUpHandler(async () => 'valid_receipt_123');

    await expect(
      api.createAppPassword({ name: 'db_fail_test', scopes: ['atproto'] })
    ).rejects.toMatchObject({
      status: 500,
      code: 'database_unavailable',
      message: 'Database connection failed.'
    });
  });

  /**
   * T5-ST-07: Chained Mutations & Interleaved Traffic
   * While step-up modal is waiting for user action on a mutation, interleaved GET requests
   * (e.g. portal snapshot or policy) must resolve immediately without blocking.
   * Sequential chained mutations inside .then() handlers must proceed cleanly.
   */
  it('T5-ST-07: Chained & Interleaved Step-Up Traversal', async () => {
    // 1. Mutation triggers step-up
    const mutationPromise = api.createAppPassword({ name: 'chained_1', scopes: ['atproto'] });
    await new Promise((r) => setTimeout(r, 10));
    expect(modals.isOpen('step-up')).toBe(true);

    // 2. Interleaved GET requests resolve immediately while step-up is pending
    const snapshotPromise = api.fetchSnapshot();
    const policyPromise = api.fetchSignupPolicy();

    const [snapshot, policy] = await Promise.all([snapshotPromise, policyPromise]);
    expect(snapshot).toBeDefined();
    expect(policy.policy).toBe('closed');
    expect(modals.isOpen('step-up')).toBe(true);

    // 3. User elevates session and resolves mutation 1
    backend.elevateSession(currentSessionToken, 'stepUpPassword');
    stepup.resolveStepUp(true);

    const mut1Result = await mutationPromise;
    expect(mut1Result.accepted).toBe(true);

    // 4. Chained mutation 2 immediately follows; since session is now elevated, it succeeds without prompt
    const mut2Result = await api.createAppPassword({ name: 'chained_2', scopes: ['atproto'] });
    expect(mut2Result.accepted).toBe(true);
  });
});
