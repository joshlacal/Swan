import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { accountFetch, api, setCSRF, setStepUpHandler } from '../../../src/lib/api';
import type { ApiError } from '../../../src/lib/types';
import type { MockSession } from '../harness/mock-backend';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';

describe('Tier 2 Boundary: Step-Up Re-Authentication, Interceptor & Single-Use Receipts', () => {
  let backend: ReturnType<typeof setupTestEnv>['backend'];
  let session: MockSession;

  beforeEach(() => {
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
  });

  // --- Step-Up Interception & Replay Boundaries ---

  it('T2-STEP-01: intercepts 403 step_up_required on app password creation and calls stepUpHandler', async () => {
    let handlerCalled = false;
    setStepUpHandler(async ({ operation, error }) => {
      handlerCalled = true;
      expect(operation).toBe('app-passwords');
      expect(error.code).toBe('step_up_required');
      // Elevate session in place
      backend.elevateSession(session.sessionToken);
      return true;
    });

    const res = await api.createAppPassword({ name: 'My CLI Bot', scopes: ['atproto'] });
    expect(handlerCalled).toBe(true);
    expect(res.accepted).toBe(true);
    expect((res as any).password).toMatch(/^swan-app-/);
  });

  it('T2-STEP-02: intercepts 403 request_not_allowed on session revocation and calls stepUpHandler', async () => {
    const other = backend.createSession('did:plc:swan-test-user-12345', { label: 'Old Laptop', activeCookie: false });
    let handlerCalled = false;

    setStepUpHandler(async () => {
      handlerCalled = true;
      backend.elevateSession(session.sessionToken);
      return true;
    });

    const res = await api.revokeSession(other.id);
    expect(handlerCalled).toBe(true);
    expect(res.accepted).toBe(true);
    expect(backend.getSession(other.sessionToken)).toBeUndefined();
  });

  it('T2-STEP-03: seamlessly replays mutation with X-Swan-Step-Up header when handler returns receipt token', async () => {
    setStepUpHandler(async () => {
      const receipt = backend.issueStepUpReceipt(session.id, session.accountDID, 'app-passwords.create');
      return receipt.receiptToken;
    });

    const res = await api.createAppPassword({ name: 'Receipt App', scopes: ['atproto'] });
    expect(res.accepted).toBe(true);
    expect((res as any).password).toMatch(/^swan-app-/);
  });

  it('T2-STEP-04: throws original ApiError when stepUpHandler rejects (user aborts modal)', async () => {
    setStepUpHandler(async () => {
      throw new Error('User closed step-up dialog');
    });

    try {
      await api.createAppPassword({ name: 'Aborted App', scopes: ['atproto'] });
      expect.unreachable('Should have thrown error on step-up abort');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('step_up_required');
    }
  });

  it('T2-STEP-05: skips step-up and throws error directly when skipStepUp option is true', async () => {
    const handler = vi.fn();
    setStepUpHandler(handler);

    try {
      await accountFetch('app-passwords', {
        method: 'POST',
        body: JSON.stringify({ name: 'No Stepup', scopes: ['atproto'] })
      }, { skipStepUp: true });
      expect.unreachable('Should have thrown 403 directly');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(handler).not.toHaveBeenCalled();
    }
  });

  // --- Step-Up Receipt Token Lifecycle Boundaries ---

  it('T2-STEP-06: rejects expired step-up receipt token (>300s elapsed) with 403 request_not_allowed', async () => {
    // Issue receipt with negative TTL to simulate expiration
    const expiredReceipt = backend.issueStepUpReceipt(session.id, session.accountDID, 'app-passwords.create', -1000);

    try {
      await accountFetch('app-passwords', {
        method: 'POST',
        body: JSON.stringify({ name: 'Expired Receipt App', scopes: ['atproto'] })
      }, { stepUpReceipt: expiredReceipt.receiptToken, skipStepUp: true });
      expect.unreachable('Should have rejected expired receipt');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
      expect(apiErr.message).toContain('Invalid step-up receipt');
    }
  });

  it('T2-STEP-07: rejects replaying an already-consumed step-up receipt token with 403 request_not_allowed', async () => {
    const receipt = backend.issueStepUpReceipt(session.id, session.accountDID, 'app-passwords.create');

    // First use consumes the receipt
    const firstRes = await accountFetch<{ accepted: boolean }>('app-passwords', {
      method: 'POST',
      body: JSON.stringify({ name: 'First App', scopes: ['atproto'] })
    }, { stepUpReceipt: receipt.receiptToken, skipStepUp: true });
    expect(firstRes.accepted).toBe(true);
    expect(receipt.consumed).toBe(true);

    // Second use of same receipt fails
    try {
      await accountFetch('app-passwords', {
        method: 'POST',
        body: JSON.stringify({ name: 'Second App', scopes: ['atproto'] })
      }, { stepUpReceipt: receipt.receiptToken, skipStepUp: true });
      expect.unreachable('Should have rejected already-consumed receipt');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
      expect(apiErr.message).toContain('already consumed');
    }
  });

  it('T2-STEP-08: rejects receipt issued for a different account DID with 403 request_not_allowed', async () => {
    // Receipt issued for Bob
    const bobReceipt = backend.issueStepUpReceipt('sess_bob', 'did:plc:bob-other-user', 'app-passwords.create');

    try {
      await accountFetch('app-passwords', {
        method: 'POST',
        body: JSON.stringify({ name: 'Attacker App', scopes: ['atproto'] })
      }, { stepUpReceipt: bobReceipt.receiptToken, skipStepUp: true });
      expect.unreachable('Should have rejected wrong account receipt');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  it('T2-STEP-09: rejects receipt issued for a different operation with 403 request_not_allowed', async () => {
    // Receipt specifically bound to 'app-passwords.revoke'
    const revokeReceipt = backend.issueStepUpReceipt(session.id, session.accountDID, 'app-passwords.revoke');

    try {
      await accountFetch('app-passwords', {
        method: 'POST',
        body: JSON.stringify({ name: 'Create App', scopes: ['atproto'] })
      }, { stepUpReceipt: revokeReceipt.receiptToken, skipStepUp: true });
      expect.unreachable('Should have rejected operation mismatch receipt');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  it('T2-STEP-10: expires elevated session state after 600s requiring new step-up', async () => {
    backend.elevateSession(session.sessionToken);
    // Simulate 11 minutes having passed
    session.lastStepUpAt = Date.now() - 660_000;

    try {
      await accountFetch('app-passwords', {
        method: 'POST',
        body: JSON.stringify({ name: 'Stale Session App', scopes: ['atproto'] })
      }, { skipStepUp: true });
      expect.unreachable('Should have required fresh step-up');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('step_up_required');
    }
  });

  // --- Password, TOTP, Recovery Code & Passkey Step-Up Boundaries ---

  it('T2-STEP-11: password step-up rejects wrong password with 401 authentication_required', async () => {
    try {
      await api.stepUpPassword('incorrect-password');
      expect.unreachable('Should have rejected incorrect password');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(401);
      expect(apiErr.code).toBe('authentication_required');
      expect(apiErr.message).toBe('Password incorrect.');
    }
  });

  it('T2-STEP-12: password step-up rejects malformed JSON with 400 invalid_request', async () => {
    try {
      await accountFetch('step-up/password', {
        method: 'POST',
        body: 'invalid-non-json'
      });
      expect.unreachable('Should have rejected malformed JSON');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.code).toBe('invalid_request');
      expect(apiErr.message).toBe('Invalid JSON payload.');
    }
  });

  it('T2-STEP-13: TOTP step-up rejects non-6-digit code with 403 request_not_allowed', async () => {
    try {
      await api.stepUpTotp('totp_factor_1', '12345'); // 5 digits
      expect.unreachable('Should have rejected non-6-digit TOTP code');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
      expect(apiErr.message).toContain('Invalid TOTP');
    }
  });

  it('T2-STEP-14: TOTP step-up elevates session to stepUpMFA and issues factorToken', async () => {
    const res = await api.stepUpTotp('totp_factor_1', '654321');
    expect(res.accepted).toBe(true);
    expect((res as any).factorToken).toMatch(/^rcpt_/);
    expect(session.strength).toBe('stepUpMFA');
  });

  it('T2-STEP-15: Recovery code step-up consumes the backup code and prevents reuse', async () => {
    backend.setRecoveryCodes(session.accountDID, ['RCV-SAFE-1234']);

    // First use succeeds
    const firstRes = await api.stepUpRecoveryCode('RCV-SAFE-1234');
    expect(firstRes.accepted).toBe(true);
    expect((firstRes as any).factorToken).toBeDefined();
    expect(backend.getRecoveryCodes(session.accountDID)).not.toContain('RCV-SAFE-1234');

    // Replay attempt fails with 403
    try {
      await api.stepUpRecoveryCode('RCV-SAFE-1234');
      expect.unreachable('Should have rejected consumed recovery code');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
      expect(apiErr.message).toBe('Invalid recovery code.');
    }
  });

  it('T2-STEP-16: Recovery code step-up rejects invalid recovery code format/value', async () => {
    backend.setRecoveryCodes(session.accountDID, ['RCV-REAL-9999']);

    try {
      await api.stepUpRecoveryCode('RCV-FAKE-0000');
      expect.unreachable('Should have rejected invalid recovery code');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
    }
  });

  it('T2-STEP-17: Passkey step-up challenge creation and assertion handshake', async () => {
    const challengeRes = await api.requestPasskeyStepUpChallenge('pk_1');
    expect(challengeRes.accepted).toBe(true);
    const challenge = (challengeRes as any).challenge;
    expect(challenge).toBeDefined();

    // Assert with challenge
    const assertRes = await api.submitPasskeyAssertion({
      kind: 'passkey',
      factorID: 'pk_1',
      challenge,
      clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0',
      authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAA',
      credentialID: 'cred_123',
      signature: 'MEUCIQDx123'
    });

    expect(assertRes.accepted).toBe(true);
    expect((assertRes as any).factorToken).toBeDefined();
    expect(session.strength).toBe('stepUpMFA');
  });

  it('T2-STEP-18: Passkey step-up rejects invalid or expired challenge with 403 request_not_allowed', async () => {
    try {
      await api.submitPasskeyAssertion({
        kind: 'passkey',
        factorID: 'pk_1',
        challenge: 'non_existent_expired_challenge',
        clientDataJSON: 'test',
        authenticatorData: 'test',
        credentialID: 'cred_123',
        signature: 'sig_123'
      });
      expect.unreachable('Should have rejected invalid passkey challenge');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('request_not_allowed');
      expect(apiErr.message).toContain('Invalid or expired passkey challenge');
    }
  });

  // --- Concurrent Interceptions & Sensitive Action Boundaries ---

  it('T2-STEP-19: handles multiple concurrent 403 step-up requests smoothly without crash', async () => {
    let callCount = 0;
    setStepUpHandler(async () => {
      callCount++;
      backend.elevateSession(session.sessionToken);
      return true;
    });

    // Fire 3 simultaneous mutations needing step-up
    const results = await Promise.all([
      api.createAppPassword({ name: 'Concurrent 1', scopes: ['atproto'] }),
      api.createAppPassword({ name: 'Concurrent 2', scopes: ['atproto'] }),
      api.createAppPassword({ name: 'Concurrent 3', scopes: ['atproto'] })
    ]);

    expect(results.length).toBe(3);
    results.forEach(r => expect(r.accepted).toBe(true));
  });

  it('T2-STEP-20: recovery code rotation without elevated session returns 403 step_up_required', async () => {
    try {
      await accountFetch('factors/recovery-codes/rotate', {
        method: 'POST',
        body: '{}'
      }, { skipStepUp: true });
      expect.unreachable('Should have required step-up for recovery code rotation');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('step_up_required');
    }
  });

  it('T2-STEP-21: account deletion without elevated session returns 403 step_up_required', async () => {
    try {
      await accountFetch('lifecycle/delete', {
        method: 'POST',
        body: '{}'
      }, { skipStepUp: true });
      expect.unreachable('Should have required step-up for account deletion');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('step_up_required');
    }
  });

  it('T2-STEP-22: export request without elevated session returns 403 step_up_required', async () => {
    try {
      await accountFetch('export/request', {
        method: 'POST',
        body: '{}'
      }, { skipStepUp: true });
      expect.unreachable('Should have required step-up for export request');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('step_up_required');
    }
  });

  it('T2-STEP-23: single-use receipt is not reused across separate subsequent API calls', async () => {
    const receipt = backend.issueStepUpReceipt(session.id, session.accountDID, 'app-passwords.create');

    // First call with receipt
    const res1 = await api.createAppPassword({ name: 'Scoped App 1', scopes: ['atproto'] }, receipt.receiptToken);
    expect(res1.accepted).toBe(true);

    // Second call without receipt should trigger 403 step-up (session is still password-strength)
    try {
      await accountFetch('app-passwords', {
        method: 'POST',
        body: JSON.stringify({ name: 'Scoped App 2', scopes: ['atproto'] })
      }, { skipStepUp: true });
      expect.unreachable('Should have required fresh step-up');
    } catch (err: any) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('step_up_required');
    }
  });
});
