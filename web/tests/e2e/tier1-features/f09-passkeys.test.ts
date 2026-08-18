import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api, setCSRF } from '../../../src/lib/api';
import { formatWebAuthnError, performPasskeyRegistration } from '../../../src/lib/webauthn';
import {
  createMockPublicKeyCredential,
  mockWebAuthnCreate,
  mockWebAuthnError,
  setupTestEnv,
  teardownTestEnv
} from '../harness/test-env';
import type { MockSwanBackend, MockSession } from '../harness/mock-backend';

describe('Tier 1 - F09: Passkey WebAuthn Enrollment Modal', () => {
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

  it('T1-F09-01: requestPasskeyChallenge initiates WebAuthn challenge creation on backend', async () => {
    const result = await api.requestPasskeyChallenge('MacBook Pro TouchID');

    expect(result).toBeDefined();
    expect(result.accepted).toBe(true);
    expect(result.challenge).toBeDefined();
    expect(result.factorID).toBeDefined();
  });

  it('T1-F09-02: performPasskeyRegistration coordinates browser WebAuthn credential creation', async () => {
    const challengeResult = await api.requestPasskeyChallenge('Security Key');

    mockWebAuthnCreate(async () => {
      return createMockPublicKeyCredential('create', { challenge: challengeResult.challenge });
    });

    const attestation = await performPasskeyRegistration(
      {
        challenge: challengeResult.challenge!,
        factorID: challengeResult.factorID!,
        accountDID: session.accountDID
      },
      'Security Key',
      'alice'
    );

    expect(attestation).toBeDefined();
    expect(attestation.factorID).toBe(challengeResult.factorID);
    expect(attestation.clientDataJSON).toBeDefined();
    expect(attestation.authenticatorData).toBeDefined();
    expect(attestation.credentialID).toBeDefined();
  });

  it('T1-F09-03: registerPasskey submits attestation payload and registers active factor on backend', async () => {
    const challengeResult = await api.requestPasskeyChallenge('TouchID Factor');

    const attestation = await performPasskeyRegistration(
      {
        challenge: challengeResult.challenge!,
        factorID: challengeResult.factorID!,
        accountDID: session.accountDID
      },
      'TouchID Factor',
      'alice'
    );

    const enrollResult = await api.registerPasskey(attestation);

    expect(enrollResult).toBeDefined();
    expect(enrollResult.accepted).toBe(true);
    expect(enrollResult.message).toBe('Passkey enrolled');

    const factors = backend.getFactors(session.accountDID);
    const passkeyFactor = factors.find((f) => f.kind === 'passkey' && f.label === 'TouchID Factor');
    expect(passkeyFactor).toBeDefined();
    expect(passkeyFactor?.enabled).toBe(true);
  });

  it('T1-F09-04: revokePasskey sends HTTP DELETE to remove passkey factor', async () => {
    const factor = backend.addFactor(session.accountDID, {
      kind: 'passkey',
      label: 'Old Key',
      credentialID: 'cred_old_key',
      enabled: true
    });

    expect(backend.getFactors(session.accountDID).some((f) => f.id === factor.id)).toBe(true);

    const result = await api.revokePasskey(factor.id);

    expect(result.accepted).toBe(true);
    expect(result.message).toBe('Authentication factor revoked');
    expect(backend.getFactors(session.accountDID).some((f) => f.id === factor.id)).toBe(false);
  });

  it('T1-F09-05: formatWebAuthnError translates browser DOMExceptions into friendly messages', () => {
    const notAllowed = { name: 'NotAllowedError', message: 'User canceled' };
    expect(formatWebAuthnError(notAllowed)).toBe('Passkey prompt was cancelled or timed out.');

    const invalidState = { name: 'InvalidStateError', message: 'Already registered' };
    expect(formatWebAuthnError(invalidState)).toBe('This passkey is already registered.');

    const notSupported = { name: 'NotSupportedError', message: 'No authenticator' };
    expect(formatWebAuthnError(notSupported)).toBe('Passkeys are not supported on this device.');

    const abortError = { name: 'AbortError', message: 'Aborted' };
    expect(formatWebAuthnError(abortError)).toBe('Passkey authentication was aborted.');

    const genericError = new Error('Custom failure');
    expect(formatWebAuthnError(genericError)).toBe('Custom failure');
  });
});
