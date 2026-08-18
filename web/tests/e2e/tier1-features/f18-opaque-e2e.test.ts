import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api, setCSRF } from '../../../src/lib/api';
import { performPasskeyAssertion, performPasskeyRegistration } from '../../../src/lib/webauthn';
import {
  createMockPublicKeyCredential,
  mockWebAuthnCreate,
  mockWebAuthnGet,
  setupTestEnv,
  teardownTestEnv
} from '../harness/test-env';
import type { MockSwanBackend, MockSession } from '../harness/mock-backend';

describe('Tier 1 - F18: Opaque-Box E2E Verifications', () => {
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

  it('T1-F18-01: Opaque journey: login -> fetch snapshot -> create scoped app password -> revoke password', async () => {
    // 1. Fetch snapshot
    const snapshot = await api.fetchSnapshot();
    expect(snapshot.account.handle).toBe('alice.swan.place');

    // 2. Create app password
    const createResult = await api.createAppPassword({
      name: 'Skyfeed Bot',
      scopes: ['atproto', 'transition:chat.bsky']
    });
    expect(createResult.password).toMatch(/^swan-app-/);

    // 3. Verify snapshot contains new password
    const updatedSnap = await api.fetchSnapshot();
    expect(updatedSnap.passwords.some((p) => p.name === 'Skyfeed Bot')).toBe(true);

    // 4. Revoke app password
    const revokeResult = await api.revokeAppPassword('Skyfeed Bot');
    expect(revokeResult.accepted).toBe(true);

    // 5. Verify snapshot after revocation
    const finalSnap = await api.fetchSnapshot();
    expect(finalSnap.passwords.some((p) => p.name === 'Skyfeed Bot')).toBe(false);
  });

  it('T1-F18-02: Opaque journey: initiate TOTP -> verify 6-digit code -> step-up elevation -> rotate recovery codes', async () => {
    // 1. Initiate TOTP
    const init = await api.enrollTotp({
      label: 'Authenticator App',
      secret: 'JBSWY3DPEHPK3PXP'
    });
    expect(init.factorID).toBeDefined();

    // 2. Verify code
    const verify = await api.verifyTotpEnrollment(init.factorID!, '123456');
    expect(verify.accepted).toBe(true);

    // 3. Step-up with TOTP
    const stepUp = await api.stepUpTotp(init.factorID!, '654321');
    expect(stepUp.accepted).toBe(true);
    expect(stepUp.factorToken).toMatch(/^rcpt_/);

    // 4. Rotate recovery codes
    const rotate = await api.rotateRecoveryCodes();
    expect(rotate.recoveryCodes?.length).toBe(10);
  });

  it('T1-F18-03: Opaque journey: request passkey challenge -> create credential -> register factor -> step-up assertion', async () => {
    // 1. Challenge
    const chal = await api.requestPasskeyChallenge('MacBook TouchID');
    expect(chal.challenge).toBeDefined();

    // 2. Mock credential creation & registration
    mockWebAuthnCreate(async () => {
      return createMockPublicKeyCredential('create', { id: 'cred_mbp_passkey', challenge: chal.challenge });
    });
    const attestation = await performPasskeyRegistration(
      { challenge: chal.challenge!, factorID: chal.factorID!, accountDID: session.accountDID },
      'MacBook TouchID',
      'alice'
    );
    const regResult = await api.registerPasskey(attestation);
    expect(regResult.accepted).toBe(true);

    // 3. Step-up challenge & assertion
    const stepUpChal = await api.requestPasskeyStepUpChallenge(chal.factorID!);
    mockWebAuthnGet(async () => {
      return createMockPublicKeyCredential('get', { id: 'cred_mbp_passkey', challenge: stepUpChal.challenge });
    });
    const assertion = await performPasskeyAssertion(
      { challenge: stepUpChal.challenge!, factorID: chal.factorID! },
      'cred_mbp_passkey'
    );
    const assertResult = await api.submitPasskeyAssertion(assertion);
    expect(assertResult.accepted).toBe(true);
  });

  it('T1-F18-04: Opaque journey: reserve did:web -> verify public claim -> bind domain -> revert to PLC', async () => {
    // 1. Reserve
    const reserve = await api.reserveDidWeb({
      requestID: 'req_journey_didweb',
      targetDID: 'did:web:journey.alice.io',
      handle: 'journey.alice.io',
      expiresAt: new Date(Date.now() + 3600000).toISOString()
    });
    expect(reserve.nonce).toBeDefined();

    // 2. Claim
    const binding = await api.claimDidWeb({ requestID: reserve.requestID });
    expect(binding.state).toBe('active');
    expect(binding.handle).toBe('journey.alice.io');

    // 3. Remove / revert to PLC
    const revert = await api.removeDidWeb({ stepUpReceipt: 'receipt_revert' });
    expect(revert.state).toBe('removed');
  });

  it('T1-F18-05: Opaque journey: query active sessions -> revoke single remote session -> bulk revoke others', async () => {
    // Seed extra sessions
    const sess1 = backend.createSession(session.accountDID, { label: 'Remote iPhone', activeCookie: false });
    const sess2 = backend.createSession(session.accountDID, { label: 'Remote Chrome', activeCookie: false });

    // 1. Query sessions in snapshot
    const snap = await api.fetchSnapshot();
    expect(snap.sessions.length).toBe(3);

    // 2. Revoke single remote session with DELETE
    const del1 = await api.revokeSession(sess1.id);
    expect(del1.accepted).toBe(true);

    const snap2 = await api.fetchSnapshot();
    expect(snap2.sessions.some((s) => s.id === sess1.id)).toBe(false);

    // 3. Bulk revoke all others
    const bulkResult = await api.revokeOtherSessions();
    expect(bulkResult.accepted).toBe(true);

    const finalSnap = await api.fetchSnapshot();
    expect(finalSnap.sessions.length).toBe(1);
    expect(finalSnap.sessions[0].current).toBe(true);
  });
});
