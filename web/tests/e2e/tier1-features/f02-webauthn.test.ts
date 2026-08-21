import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  base64urlToUint8Array,
  formatWebAuthnError,
  isWebAuthnSupported,
  performPasskeyAssertion,
  performPasskeyRegistration,
  uint8ArrayToBase64URL
} from '../../../src/lib/webauthn';
import type { WebAuthnChallenge } from '../../../src/lib/types';
import {
  base64URLToBuffer,
  bufferToBase64URL,
  createMockPublicKeyCredential,
  mockWebAuthnCreate,
  mockWebAuthnError,
  mockWebAuthnGet,
  restoreWebAuthnMock,
  setupTestEnv,
  teardownTestEnv
} from '../harness/test-env';

describe('Tier 1 - F02: Base64URL & WebAuthn Helpers', () => {
  beforeEach(() => {
    setupTestEnv({ authenticated: false });
  });

  afterEach(() => {
    teardownTestEnv();
  });

  it('T1-F02-01: base64urlToUint8Array decodes Base64URL strings with hyphen and underscore correctly', () => {
    // '-_' in Base64URL corresponds to 0xFB, 0xFF, 0xBF in 3-byte groups
    const base64url = '-_-_';
    const decoded = base64urlToUint8Array(base64url);

    expect(decoded).toBeInstanceOf(Uint8Array);
    expect(decoded.length).toBe(3);
    expect(decoded[0]).toBe(0xfb);
    expect(decoded[1]).toBe(0xff);
    expect(decoded[2]).toBe(0xbf);

    // Empty string
    expect(base64urlToUint8Array('').length).toBe(0);

    // Known test vectors
    const helloBytes = base64urlToUint8Array('SGVsbG8gU3dhbg');
    expect(new TextDecoder().decode(helloBytes)).toBe('Hello Swan');
  });

  it('T1-F02-02: uint8ArrayToBase64URL encodes Uint8Array and ArrayBuffer without padding', () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0xbf]);
    const encoded = uint8ArrayToBase64URL(bytes);

    expect(encoded).toBe('-_-_');
    expect(encoded).not.toContain('=');
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');

    const textBytes = new TextEncoder().encode('Hello Swan');
    const textEncoded = uint8ArrayToBase64URL(textBytes);
    expect(textEncoded).toBe('SGVsbG8gU3dhbg');

    // ArrayBuffer input
    const buffer = bytes.buffer;
    expect(uint8ArrayToBase64URL(buffer)).toBe('-_-_');
  });

  it('T1-F02-03: performPasskeyRegistration transforms server challenge DTO into CredentialCreationOptions and calls navigator.credentials.create', async () => {
    let capturedOptions: any = null;
    mockWebAuthnCreate(async (options) => {
      capturedOptions = options;
      return createMockPublicKeyCredential('create', { challenge: 'server-challenge-xyz' });
    });

    const challengeData: WebAuthnChallenge = {
      challenge: 'server-challenge-xyz',
      factorID: 'factor_passkey_123',
      relyingPartyId: 'swan.place',
      accountDID: 'did:plc:test-account-did'
    };

    expect(isWebAuthnSupported()).toBe(true);

    const result = await performPasskeyRegistration(challengeData, 'My Hardware Key', 'alice');

    expect(capturedOptions).toBeDefined();
    expect(capturedOptions.publicKey).toBeDefined();
    expect(capturedOptions.publicKey.rp.name).toBe('Swan');
    expect(capturedOptions.publicKey.rp.id).toBe('swan.place');
    expect(capturedOptions.publicKey.pubKeyCredParams).toEqual([{ alg: -7, type: 'public-key' }]);

    expect(result).toBeDefined();
    expect(result.kind).toBe('passkey');
    expect(result.factorID).toBe('factor_passkey_123');
    expect(result.label).toBe('My Hardware Key');
    expect(result.clientDataJSON).toBeDefined();
    expect(result.authenticatorData).toBeDefined();
    expect(result.credentialID).toBeDefined();
  });

  it('T1-F02-04: performPasskeyRegistration formats credential result into WebAuthnAttestationPayload', async () => {
    const challengeData: WebAuthnChallenge = {
      challenge: 'chal_abc123',
      factorID: 'factor_macbook',
      accountDID: 'did:plc:alice'
    };

    const payload = await performPasskeyRegistration(challengeData, 'MacBook TouchID', 'alice');

    expect(payload.factorID).toBe('factor_macbook');
    expect(payload.label).toBe('MacBook TouchID');
    expect(payload.challenge).toBe('chal_abc123');
    expect(typeof payload.clientDataJSON).toBe('string');
    expect(typeof payload.authenticatorData).toBe('string');
    expect(typeof payload.credentialID).toBe('string');
    // Ensure Base64URL characters only
    expect(payload.clientDataJSON).not.toContain('=');
    expect(payload.authenticatorData).not.toContain('=');
  });

  it('T1-F02-05: performPasskeyAssertion formats assertion response for step-up verification', async () => {
    let capturedOptions: any = null;
    mockWebAuthnGet(async (options) => {
      capturedOptions = options;
      return createMockPublicKeyCredential('get', { challenge: 'stepup_challenge_999' });
    });

    const challengeData: WebAuthnChallenge = {
      challenge: 'stepup_challenge_999',
      factorID: 'factor_passkey_stepup',
      relyingPartyId: 'swan.place'
    };

    const assertion = await performPasskeyAssertion(challengeData, 'cred_id_123');

    expect(capturedOptions).toBeDefined();
    expect(capturedOptions.publicKey.allowCredentials).toBeDefined();
    expect(capturedOptions.publicKey.allowCredentials.length).toBe(1);

    expect(assertion).toBeDefined();
    expect(assertion.kind).toBe('passkey');
    expect(assertion.factorID).toBe('factor_passkey_stepup');
    expect(assertion.challenge).toBe('stepup_challenge_999');
    expect(assertion.signature).toBeDefined();
    expect(assertion.authenticatorData).toBeDefined();
    expect(assertion.credentialID).toBeDefined();
  });
});
