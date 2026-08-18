import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api, setCSRF } from '../../../src/lib/api';
import { setupTestEnv, teardownTestEnv } from '../harness/test-env';
import type { MockSwanBackend, MockSession } from '../harness/mock-backend';

describe('Tier 1 - F11: Recovery Code Rotation Modal', () => {
  let backend: MockSwanBackend;
  let session: MockSession;

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: true, elevated: true });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
  });

  it('T1-F11-01: rotateRecoveryCodes issues POST /account/api/factors/recovery-codes/rotate under elevated session', async () => {
    const result = await api.rotateRecoveryCodes();

    expect(result).toBeDefined();
    expect(result.accepted).toBe(true);
    expect(result.message).toBe('Recovery codes rotated');
    expect(Array.isArray(result.recoveryCodes)).toBe(true);
    expect(result.recoveryCodes!.length).toBe(10);
  });

  it('T1-F11-02: Rotation produces 10 structured single-use recovery codes matching RCV-XXXX-XXXX format', async () => {
    const result = await api.rotateRecoveryCodes();
    const codes = result.recoveryCodes!;

    expect(codes.length).toBe(10);
    for (const code of codes) {
      expect(code).toMatch(/^RCV-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    }

    const backendCodes = backend.getRecoveryCodes(session.accountDID);
    expect(backendCodes.length).toBe(10);
    expect(new Set(backendCodes).size).toBe(10); // All unique
  });

  it('T1-F11-03: Attempting rotation without elevated session demands step-up elevation', async () => {
    backend.expireSessionStepUp(session.sessionToken);

    await expect(api.rotateRecoveryCodes()).rejects.toMatchObject({
      status: 403,
      code: 'step_up_required'
    });
  });

  it('T1-F11-04: Emergency recovery code step-up consumes valid code and provides step-up receipt', async () => {
    const rotateResult = await api.rotateRecoveryCodes();
    const codeToUse = rotateResult.recoveryCodes![0];

    const stepUpResult = await api.stepUpRecoveryCode(codeToUse);

    expect(stepUpResult.accepted).toBe(true);
    expect(stepUpResult.factorToken).toMatch(/^rcpt_/);

    // Code is now consumed from backend store
    const remainingCodes = backend.getRecoveryCodes(session.accountDID);
    expect(remainingCodes.length).toBe(9);
    expect(remainingCodes).not.toContain(codeToUse);
  });

  it('T1-F11-05: Replaying or reusing a consumed recovery code is rejected', async () => {
    backend.setRecoveryCodes(session.accountDID, ['RCV-ONCE-ONLY']);

    // First use succeeds
    const firstUse = await api.stepUpRecoveryCode('RCV-ONCE-ONLY');
    expect(firstUse.accepted).toBe(true);

    // Second use is rejected
    await expect(api.stepUpRecoveryCode('RCV-ONCE-ONLY')).rejects.toMatchObject({
      status: 403,
      code: 'request_not_allowed'
    });
  });
});
