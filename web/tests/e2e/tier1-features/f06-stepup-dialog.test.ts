import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api, setCSRF } from '../../../src/lib/api';
import { performPasskeyAssertion } from '../../../src/lib/webauthn';
import type { WebAuthnStepUpChallenge } from '../../../src/lib/types';
import {
  createMockPublicKeyCredential,
  mockWebAuthnGet,
  setupTestEnv,
  teardownTestEnv
} from '../harness/test-env';
import type { MockSwanBackend, MockSession } from '../harness/mock-backend';

describe('Tier 1 - F06: Interactive Step-Up Dialog', () => {
  let backend: MockSwanBackend;
  let session: MockSession;

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: true, elevated: false });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
  });

  it('T1-F06-01: Password step-up flow elevates session strength and returns step-up receipt token', async () => {
    expect(session.strength).toBe('password');

    const result = await api.stepUpPassword('correct-horse-battery-staple');

    expect(result).toBeDefined();
    expect(result.accepted).toBe(true);
    expect(result.factorToken).toMatch(/^rcpt_/);
    expect(session.strength).toBe('stepUpPassword');
    expect(session.lastStepUpAt).toBeGreaterThan(0);
  });

  it('T1-F06-02: TOTP factor step-up verifies 6-digit code, elevates session to stepUpMFA, and returns receipt', async () => {
    const factor = backend.addFactor(session.accountDID, {
      kind: 'totp',
      label: 'Authenticator App',
      secret: 'JBSWY3DPEHPK3PXP',
      enabled: true
    });

    const result = await api.stepUpTotp(factor.id, '654321');

    expect(result).toBeDefined();
    expect(result.accepted).toBe(true);
    expect(result.factorToken).toMatch(/^rcpt_/);
    expect(session.strength).toBe('stepUpMFA');
  });

  it('T1-F06-03: WebAuthn passkey step-up challenge and assertion ceremony', async () => {
    const factor = backend.addFactor(session.accountDID, {
      kind: 'passkey',
      label: 'YubiKey 5C',
      publicKey: 'mock-pk',
      credentialID: 'cred_yubikey_123',
      enabled: true
    });

    // 1. Request step-up challenge from server
    const challengeResult = await api.requestPasskeyStepUpChallenge(factor.id);
    expect(challengeResult.challenge).toBeDefined();
    expect(challengeResult.factorID).toBe(factor.id);

    // 2. Perform WebAuthn assertion
    mockWebAuthnGet(async () => {
      return createMockPublicKeyCredential('get', {
        id: 'cred_yubikey_123',
        challenge: challengeResult.challenge
      });
    });

    const assertionPayload = await performPasskeyAssertion(
      {
        challenge: challengeResult.challenge!,
        factorID: factor.id
      },
      'cred_yubikey_123'
    );

    // 3. Submit assertion to server
    const assertionResult = await api.submitPasskeyAssertion(assertionPayload);
    expect(assertionResult.accepted).toBe(true);
    expect(assertionResult.factorToken).toMatch(/^rcpt_/);
    expect(session.strength).toBe('stepUpMFA');
  });

  it('T1-F06-04: Emergency recovery code step-up verifies and consumes a single-use backup code', async () => {
    backend.setRecoveryCodes(session.accountDID, ['RCV-SAFE-9999']);

    const result = await api.stepUpRecoveryCode('RCV-SAFE-9999', 'rec_factor');

    expect(result).toBeDefined();
    expect(result.accepted).toBe(true);
    expect(result.factorToken).toMatch(/^rcpt_/);

    // Code is now consumed
    expect(backend.getRecoveryCodes(session.accountDID)).not.toContain('RCV-SAFE-9999');
  });

  it('T1-F06-05: Step-up handles invalid credentials and returns granular error details', async () => {
    // 1. Wrong password
    await expect(api.stepUpPassword('wrong-horse-battery')).rejects.toMatchObject({
      status: 401,
      code: 'authentication_required'
    });

    // 2. Invalid TOTP code format (not 6 digits)
    await expect(api.stepUpTotp('totp_1', '12')).rejects.toMatchObject({
      status: 403,
      code: 'request_not_allowed'
    });

    // 3. Invalid recovery code
    backend.setRecoveryCodes(session.accountDID, ['VALID-CODE-1']);
    await expect(api.stepUpRecoveryCode('INVALID-CODE')).rejects.toMatchObject({
      status: 403,
      code: 'request_not_allowed'
    });
  });
});
