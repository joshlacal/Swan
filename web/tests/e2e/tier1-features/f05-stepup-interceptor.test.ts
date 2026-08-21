import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  accountFetch,
  api,
  setCSRF,
  setStepUpHandler
} from '../../../src/lib/api';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';
import type { MockSwanBackend, MockSession } from '../harness/mock-backend';

describe('Tier 1 - F05: Step-Up Coordinator & Interceptor', () => {
  let backend: MockSwanBackend;
  let session: MockSession;

  beforeEach(() => {
    // Authenticated session without elevated step-up
    const env = setupTestEnv({ authenticated: true, elevated: false });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);
    setStepUpHandler(null);
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
    setStepUpHandler(null);
    vi.restoreAllMocks();
  });

  it('T1-F05-01: Automatically intercepts HTTP 403 step-up required and invokes stepUpHandler', async () => {
    let handlerInvoked = false;
    let operationContext = '';

    setStepUpHandler(async ({ operation, error }) => {
      handlerInvoked = true;
      operationContext = operation || '';
      expect(error.status).toBe(403);
      expect(error.code).toBe('step_up_required');

      // Issue a mock step-up receipt on the backend
      const receipt = backend.issueStepUpReceipt(session.id, session.accountDID, 'app-passwords.create');
      return receipt.receiptToken;
    });

    const result = await api.createAppPassword({ name: 'Automated Bot', scopes: ['atproto'] });

    expect(handlerInvoked).toBe(true);
    expect(operationContext).toBe('app-passwords');
    expect(result).toBeDefined();
    expect(result.password).toMatch(/^swan-app-/);
  });

  it('T1-F05-02: Replays mutation with X-Swan-Step-Up receipt header returned by handler', async () => {
    let receiptUsed = '';

    setStepUpHandler(async () => {
      const receipt = backend.issueStepUpReceipt(session.id, session.accountDID, 'app-passwords.create');
      receiptUsed = receipt.receiptToken;
      return receipt.receiptToken;
    });

    const result = await api.createAppPassword({ name: 'Receipt Replay App', scopes: ['atproto'] });

    expect(receiptUsed).toMatch(/^rcpt_/);
    expect(result.password).toBeDefined();
    expect(result.password).toMatch(/^swan-app-/);

    // Verify receipt was atomically consumed by the backend
    const receiptRecord = backend.getStepUpReceipt(receiptUsed);
    expect(receiptRecord?.consumed).toBe(true);
  });

  it('T1-F05-03: Replays mutation without receipt header when step-up handler returns true (in-place elevation)', async () => {
    setStepUpHandler(async () => {
      // Simulate user entering password in modal which calls stepUpPassword
      await api.stepUpPassword('correct-horse-battery-staple');
      return true; // in-place elevation
    });

    // Protected mutation (rotateRecoveryCodes requires elevated session)
    const result = await api.rotateRecoveryCodes();

    expect(result).toBeDefined();
    expect(result.recoveryCodes?.length).toBe(10);
    expect(session.strength).toBe('stepUpPassword');
  });

  it('T1-F05-04: User cancellation of step-up rejects the original mutation promise', async () => {
    setStepUpHandler(async () => {
      throw new Error('User closed step-up dialog');
    });

    await expect(
      api.createAppPassword({ name: 'Canceled Bot', scopes: ['atproto'] })
    ).rejects.toMatchObject({
      code: 'step_up_required',
      status: 403
    });
  });

  it('T1-F05-05: skipStepUp option bypasses the interceptor and throws 403 directly', async () => {
    const handler = vi.fn();
    setStepUpHandler(handler);

    await expect(
      accountFetch('app-passwords', {
        method: 'POST',
        body: JSON.stringify({ name: 'Bypass Bot', scopes: ['atproto'] })
      }, { skipStepUp: true })
    ).rejects.toMatchObject({
      code: 'step_up_required',
      status: 403
    });

    expect(handler).not.toHaveBeenCalled();
  });
});
