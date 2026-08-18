import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  base64urlToUint8Array,
  extractAuthDataFromAttestationObject,
  formatWebAuthnError,
  isPlatformAuthenticatorAvailable,
  isWebAuthnSupported,
  performPasskeyAssertion,
  performPasskeyRegistration,
  uint8ArrayToBase64URL
} from '../../../src/lib/webauthn';
import type { WebAuthnChallenge } from '../../../src/lib/types';
import {
  createMockPublicKeyCredential,
  mockWebAuthnCreate,
  mockWebAuthnGet,
  mockWebAuthnError,
  restoreWebAuthnMock,
  setupTestEnv,
  teardownTestEnv
} from '../harness/test-env';

describe('Tier 5 Adversarial - Suite 02: WebAuthn Authenticator Anomalies & CBOR Parsing', () => {
  beforeEach(() => {
    setupTestEnv({ authenticated: false });
  });

  afterEach(() => {
    teardownTestEnv();
  });

  /**
   * T5-WA-01: CBOR False-Positive Pattern Resilience
   * Tests the CBOR parser when the byte sequence 0x68 "authData" appears in dummy payloads
   * (e.g., an x5c certificate comment or extensions map) before the actual authData entry.
   * If the first match has an invalid header or out-of-bounds length, the parser must loop forward
   * to discover the real entry or throw a clean extraction error.
   */
  it('T5-WA-01: CBOR False-Positive Pattern Resilience in extractAuthDataFromAttestationObject', () => {
    const authDataPattern = [0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61]; // 0x68 + "authData"
    const realAuthData = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

    // Construct buffer:
    // [Header] -> [False positive "authData" with invalid type byte 0xFF] -> [Real "authData" with 0x58 0x08 ...]
    const falsePositive = [...authDataPattern, 0xff, 0x00];
    const realEntry = [...authDataPattern, 0x58, realAuthData.length, ...realAuthData];

    const combined = new Uint8Array([0xa2, ...falsePositive, ...realEntry]);
    const extracted = extractAuthDataFromAttestationObject(combined.buffer);

    expect(extracted).toBeInstanceOf(Uint8Array);
    expect(extracted).toEqual(realAuthData);

    // Test with 2-byte length header (0x59)
    const longAuthData = new Uint8Array(300).fill(0x77);
    const lenHigh = (longAuthData.length >> 8) & 0xff;
    const lenLow = longAuthData.length & 0xff;
    const entry59 = new Uint8Array([
      0xa1,
      ...authDataPattern,
      0x59,
      lenHigh,
      lenLow,
      ...longAuthData
    ]);

    const extracted59 = extractAuthDataFromAttestationObject(entry59.buffer);
    expect(extracted59.length).toBe(300);
    expect(extracted59).toEqual(longAuthData);

    // Test with direct major type 2 length (< 24 bytes, typeByte = 0x40 | len)
    const shortAuthData = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const directTypeByte = 0x40 | shortAuthData.length; // 0x44
    const entryDirect = new Uint8Array([
      0xa1,
      ...authDataPattern,
      directTypeByte,
      ...shortAuthData
    ]);
    const extractedDirect = extractAuthDataFromAttestationObject(entryDirect.buffer);
    expect(extractedDirect).toEqual(shortAuthData);
  });

  /**
   * T5-WA-02: Truncated CBOR Byte Length Header
   * An adversary sends a truncated attestation object where length headers indicate more bytes
   * than available in the buffer. Must throw 'Failed to extract authenticatorData from attestationObject.'
   */
  it('T5-WA-02: Truncated CBOR Byte Length Header & Out-of-Bounds Buffers', () => {
    const authDataPattern = [0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61];

    // 1. 0x59 header claiming 500 bytes on a 20-byte buffer
    const truncated59 = new Uint8Array([
      0xa1,
      ...authDataPattern,
      0x59,
      0x01,
      0xf4, // 500 in big-endian
      0x01,
      0x02,
      0x03
    ]);
    expect(() => extractAuthDataFromAttestationObject(truncated59.buffer)).toThrowError(
      'Failed to extract authenticatorData from attestationObject.'
    );

    // 2. 0x58 header claiming 100 bytes on a 5-byte buffer
    const truncated58 = new Uint8Array([
      0xa1,
      ...authDataPattern,
      0x58,
      0x64, // 100
      0x01,
      0x02
    ]);
    expect(() => extractAuthDataFromAttestationObject(truncated58.buffer)).toThrowError(
      'Failed to extract authenticatorData from attestationObject.'
    );

    // 3. authData pattern at very end of buffer with missing type/length byte
    const patternAtEnd = new Uint8Array([0xa1, ...authDataPattern]);
    expect(() => extractAuthDataFromAttestationObject(patternAtEnd.buffer)).toThrowError(
      'Failed to extract authenticatorData from attestationObject.'
    );

    // 4. Empty buffer
    expect(() => extractAuthDataFromAttestationObject(new ArrayBuffer(0))).toThrowError(
      'Failed to extract authenticatorData from attestationObject.'
    );

    // 5. Corrupted random noise buffer
    const noise = new Uint8Array([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    expect(() => extractAuthDataFromAttestationObject(noise.buffer)).toThrowError(
      'Failed to extract authenticatorData from attestationObject.'
    );
  });

  /**
   * T5-WA-03: Null & Undefined Authenticator Return
   * If navigator.credentials.create or get resolves with null/undefined (e.g. browser dialog
   * dismissed or dismissed without DOMException), helper must throw descriptive Error.
   */
  it('T5-WA-03: Null & Undefined Authenticator Return', async () => {
    const challenge: WebAuthnChallenge = {
      challenge: 'test-challenge-123',
      factorID: 'factor_1',
      accountDID: 'did:plc:test'
    };

    // 1. Registration returning null
    mockWebAuthnCreate(async () => null);
    await expect(performPasskeyRegistration(challenge)).rejects.toThrowError(
      'Passkey registration failed: no credential returned.'
    );

    // 2. Registration returning undefined
    mockWebAuthnCreate(async () => undefined as any);
    await expect(performPasskeyRegistration(challenge)).rejects.toThrowError(
      'Passkey registration failed: no credential returned.'
    );

    // 3. Assertion returning null
    mockWebAuthnGet(async () => null);
    await expect(performPasskeyAssertion(challenge)).rejects.toThrowError(
      'Passkey assertion failed: no credential returned.'
    );

    // 4. Assertion returning undefined
    mockWebAuthnGet(async () => undefined as any);
    await expect(performPasskeyAssertion(challenge)).rejects.toThrowError(
      'Passkey assertion failed: no credential returned.'
    );
  });

  /**
   * T5-WA-04: WebAuthn DOMException Error Formatter Coverage
   * Exercises all standard WebAuthn DOMException error names and ensures user-friendly strings.
   */
  it('T5-WA-04: WebAuthn DOMException Error Formatter Coverage', () => {
    // 1. NotAllowedError (user cancelled / timeout)
    const notAllowed = new DOMException('The operation was cancelled by the user.', 'NotAllowedError');
    expect(formatWebAuthnError(notAllowed)).toBe('Passkey prompt was cancelled or timed out.');

    // 2. InvalidStateError (passkey already registered)
    const invalidState = new DOMException('Authenticator has already registered this credential.', 'InvalidStateError');
    expect(formatWebAuthnError(invalidState)).toBe('This passkey is already registered.');

    // 3. NotSupportedError (no platform authenticator)
    const notSupported = new DOMException('Public key credential operations are not supported.', 'NotSupportedError');
    expect(formatWebAuthnError(notSupported)).toBe('Passkeys are not supported on this device.');

    // 4. AbortError (aborted via AbortSignal)
    const abortErr = new DOMException('The operation was aborted.', 'AbortError');
    expect(formatWebAuthnError(abortErr)).toBe('Passkey authentication was aborted.');

    // 5. SecurityError (origin or RP ID mismatch)
    const securityErr = new DOMException('Relying party ID is not a registrable domain suffix.', 'SecurityError');
    expect(formatWebAuthnError(securityErr)).toBe('Relying party ID is not a registrable domain suffix.');

    // 6. Generic Error instance
    const genericErr = new Error('Hardware connection lost.');
    expect(formatWebAuthnError(genericErr)).toBe('Hardware connection lost.');

    // 7. Non-Error objects
    expect(formatWebAuthnError({ message: 'Custom object message' })).toBe('Passkey operation failed.');
    expect(formatWebAuthnError({ name: 'OtherError', message: 'Other' })).toBe('Passkey operation failed.');

    // 8. Primitive values (null, undefined, strings, numbers)
    expect(formatWebAuthnError(null)).toBe('Passkey operation failed.');
    expect(formatWebAuthnError(undefined)).toBe('Passkey operation failed.');
    expect(formatWebAuthnError('String error message')).toBe('Passkey operation failed.');
    expect(formatWebAuthnError(500)).toBe('Passkey operation failed.');
  });

  /**
   * T5-WA-05: Missing Optional Response Fields
   * Verifies registration and assertion when optional fields (e.g. userHandle, transports, getTransports)
   * are omitted or null from the browser credential response.
   */
  it('T5-WA-05: Missing Optional Response Fields & Fallback Properties', async () => {
    const challenge: WebAuthnChallenge = {
      challenge: 'chal_optional_fields',
      factorID: 'factor_optional',
      relyingPartyId: 'swan.place'
    };

    // 1. Registration where response does not have getAuthenticatorData or getTransports functions
    mockWebAuthnCreate(async () => {
      const mock = createMockPublicKeyCredential('create');
      // Delete optional method helpers to test fallbacks
      delete (mock.response as any).getAuthenticatorData;
      delete (mock.response as any).getTransports;
      return mock;
    });

    const regResult = await performPasskeyRegistration(challenge, 'Key Without Transports');
    expect(regResult).toBeDefined();
    expect(regResult.transports).toEqual([]);
    expect(typeof regResult.authenticatorData).toBe('string');
    expect(regResult.authenticatorData.length).toBeGreaterThan(0);

    // 2. Assertion where userHandle is null / undefined
    mockWebAuthnGet(async () => {
      const mock = createMockPublicKeyCredential('get', { challenge: 'chal_optional_fields' });
      mock.response.userHandle = null;
      return mock;
    });

    const assertResult = await performPasskeyAssertion(challenge);
    expect(assertResult).toBeDefined();
    expect(assertResult.userHandle).toBeUndefined();
    expect(assertResult.signature).toBeDefined();

    // 3. Assertion where userHandle is present
    mockWebAuthnGet(async () => {
      const mock = createMockPublicKeyCredential('get', {
        challenge: 'chal_optional_fields',
        userHandle: 'user_alice_handle'
      });
      return mock;
    });

    const assertWithHandle = await performPasskeyAssertion(challenge);
    expect(assertWithHandle.userHandle).toBeDefined();
    const decodedHandle = new TextDecoder().decode(base64urlToUint8Array(assertWithHandle.userHandle!));
    expect(decodedHandle).toBe('user_alice_handle');
  });

  /**
   * T5-WA-06: Platform Authenticator Check Exception Handling
   * PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable can reject in iframe
   * or restricted environments. Helper must catch error and return false safely.
   */
  it('T5-WA-06: Platform Authenticator Check Exception Handling', async () => {
    expect(isWebAuthnSupported()).toBe(true);

    // 1. Mock rejection in isUserVerifyingPlatformAuthenticatorAvailable
    (globalThis as any).PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => {
      throw new DOMException('Not allowed in this context', 'SecurityError');
    };

    const isAvailable = await isPlatformAuthenticatorAvailable();
    expect(isAvailable).toBe(false);

    // 2. Mock missing isUserVerifyingPlatformAuthenticatorAvailable function
    (globalThis as any).PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = undefined;
    const isAvailable2 = await isPlatformAuthenticatorAvailable();
    expect(isAvailable2).toBe(false);

    // 3. Mock environment where PublicKeyCredential is not defined
    const originalPKC = (globalThis as any).PublicKeyCredential;
    delete (globalThis as any).PublicKeyCredential;
    expect(isWebAuthnSupported()).toBe(false);
    expect(await isPlatformAuthenticatorAvailable()).toBe(false);
    (globalThis as any).PublicKeyCredential = originalPKC;
  });

  /**
   * T5-WA-07: WebAuthn RP ID, Challenge & AccountDID Formatting
   * Verifies custom RP ID configuration, fallback to hostname, DID normalization, and URL-unsafe challenge bytes.
   */
  it('T5-WA-07: WebAuthn RP ID, Challenge & AccountDID Formatting', async () => {
    let capturedOptions: any = null;
    mockWebAuthnCreate(async (opts) => {
      capturedOptions = opts;
      return createMockPublicKeyCredential('create');
    });

    // URL-unsafe challenge with '-' and '_'
    const urlUnsafeChallenge = '-_-_1234abcdABCD';
    const challenge: WebAuthnChallenge = {
      challenge: urlUnsafeChallenge,
      factorID: 'factor_custom_rp',
      relyingPartyId: 'custom.swan.place',
      accountDID: 'did:web:swan.place%3Auser%3Aalice'
    };

    await performPasskeyRegistration(challenge, 'Custom Key', 'alice@swan.place');

    expect(capturedOptions).toBeDefined();
    expect(capturedOptions.publicKey.rp.id).toBe('custom.swan.place');

    // Challenge BufferSource should match decoded bytes of urlUnsafeChallenge
    const expectedChallengeBytes = base64urlToUint8Array(urlUnsafeChallenge);
    expect(new Uint8Array(capturedOptions.publicKey.challenge)).toEqual(expectedChallengeBytes);

    // User ID BufferSource should match encoded DID
    const expectedUserIdBytes = new TextEncoder().encode('did:web:swan.place%3Auser%3Aalice');
    expect(new Uint8Array(capturedOptions.publicKey.user.id)).toEqual(expectedUserIdBytes);
    expect(capturedOptions.publicKey.user.name).toBe('alice@swan.place');
  });
});
