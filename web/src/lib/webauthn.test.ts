import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import {
  base64urlToUint8Array,
  uint8ArrayToBase64URL,
  utf8ToUint8Array,
  uint8ArrayToUtf8,
  isWebAuthnSupported,
  isPlatformAuthenticatorAvailable,
  extractAuthDataFromAttestationObject,
  performPasskeyRegistration,
  performPasskeyAssertion,
  formatWebAuthnError
} from './webauthn';

describe('Base64URL Helpers', () => {
  it('encodes empty buffer to empty string', () => {
    expect(uint8ArrayToBase64URL(new Uint8Array(0))).toBe('');
    expect(base64urlToUint8Array('')).toEqual(new Uint8Array(0));
  });

  it('correctly encodes and decodes single, double, and triple byte arrays without padding', () => {
    const single = new Uint8Array([0x42]);
    const singleB64 = uint8ArrayToBase64URL(single);
    expect(singleB64).toBe('Qg');
    expect(base64urlToUint8Array(singleB64)).toEqual(single);

    const double = new Uint8Array([0x42, 0x13]);
    const doubleB64 = uint8ArrayToBase64URL(double);
    expect(doubleB64).toBe('QhM');
    expect(base64urlToUint8Array(doubleB64)).toEqual(double);

    const triple = new Uint8Array([0x42, 0x13, 0x37]);
    const tripleB64 = uint8ArrayToBase64URL(triple);
    expect(tripleB64).toBe('QhM3');
    expect(base64urlToUint8Array(tripleB64)).toEqual(triple);
  });

  it('safely handles characters requiring - and _ URL replacements', () => {
    // 0xFB, 0xFF, 0xFE in standard b64 is "+//+" -> in b64url is "-_-_" (or "-__-")
    const bytes = new Uint8Array([0xfb, 0xff, 0xfe]);
    const encoded = uint8ArrayToBase64URL(bytes);
    expect(encoded.includes('/')).toBe(false);
    expect(encoded.includes('+')).toBe(false);
    expect(base64urlToUint8Array(encoded)).toEqual(bytes);
  });

  it('roundtrips UTF-8 strings through Base64URL', () => {
    const text = 'Swan Account Management & Security \u2728';
    const bytes = utf8ToUint8Array(text);
    const b64url = uint8ArrayToBase64URL(bytes);
    const decodedBytes = base64urlToUint8Array(b64url);
    expect(uint8ArrayToUtf8(decodedBytes)).toBe(text);
  });

  it('decodes standard base64 strings containing + and /', () => {
    const standardB64 = 'QhM3+w==';
    const decoded = base64urlToUint8Array(standardB64);
    expect(decoded.length).toBe(4);
  });

  it('throws on invalid base64 characters', () => {
    expect(() => base64urlToUint8Array('Invalid!Char')).toThrow();
  });

  it('rejects malformed Base64URL strings with length modulo 4 === 1 per RFC 4648 §3.5', () => {
    expect(() => base64urlToUint8Array('Q')).toThrow(/Invalid Base64URL string length/);
    expect(() => base64urlToUint8Array('QQQQQ')).toThrow(/Invalid Base64URL string length/);
    expect(() => base64urlToUint8Array('123456789')).toThrow(/Invalid Base64URL string length/);
    expect(() => base64urlToUint8Array('  QQQQQ==  ')).toThrow(/Invalid Base64URL string length/);
  });

  it('decodes large buffers and high-bit byte sequences without integer overflow or upper-bit bleed', () => {
    for (const size of [1, 2, 3, 4, 7, 16, 64, 256, 1024, 4096]) {
      const bytes = new Uint8Array(size);
      for (let i = 0; i < size; i++) {
        bytes[i] = (i * 37 + 0x80) & 0xff;
      }
      const encoded = uint8ArrayToBase64URL(bytes);
      const decoded = base64urlToUint8Array(encoded);
      expect(decoded).toEqual(bytes);
    }
  });

  it('correctly handles all valid Base64URL string length classes (mod 4 == 0, 2, 3)', () => {
    // mod 4 == 2 -> 1 byte
    expect(base64urlToUint8Array('Qg')).toEqual(new Uint8Array([0x42]));
    // mod 4 == 3 -> 2 bytes
    expect(base64urlToUint8Array('QhM')).toEqual(new Uint8Array([0x42, 0x13]));
    // mod 4 == 0 -> 3 bytes
    expect(base64urlToUint8Array('QhM3')).toEqual(new Uint8Array([0x42, 0x13, 0x37]));
  });
});

describe('WebAuthn Feature Detection', () => {
  it('detects WebAuthn support correctly', () => {
    expect(typeof isWebAuthnSupported()).toBe('boolean');
  });

  it('checks platform authenticator availability', async () => {
    const originalPKC = (globalThis as any).PublicKeyCredential;
    const originalNavCreds = (globalThis as any).navigator?.credentials;

    (globalThis as any).PublicKeyCredential = {
      isUserVerifyingPlatformAuthenticatorAvailable: vi.fn().mockResolvedValue(true)
    };
    if (!globalThis.navigator) {
      (globalThis as any).navigator = {};
    }
    (globalThis.navigator as any).credentials = {};

    expect(await isPlatformAuthenticatorAvailable()).toBe(true);

    if (originalPKC !== undefined) {
      (globalThis as any).PublicKeyCredential = originalPKC;
    } else {
      delete (globalThis as any).PublicKeyCredential;
    }
    if (originalNavCreds !== undefined && globalThis.navigator) {
      (globalThis.navigator as any).credentials = originalNavCreds;
    } else if (globalThis.navigator) {
      delete (globalThis.navigator as any).credentials;
    }
  });
});

describe('CBOR / AuthenticatorData Extraction', () => {
  it('extracts authData bytes from simulated CBOR attestation object', () => {
    const authDataPayload = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    // Simulated CBOR map with "authData" key (0x68 'a' 'u' 't' 'h' 'D' 'a' 't' 'a' 0x58 len)
    const prefix = [0xa2, 0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, 0x58, authDataPayload.length];
    const cborBytes = new Uint8Array([...prefix, ...authDataPayload]);
    const extracted = extractAuthDataFromAttestationObject(cborBytes.buffer);
    expect(extracted).toEqual(authDataPayload);
  });

  it('throws error if authData is not found in invalid CBOR bytes', () => {
    const badBytes = new Uint8Array([0x01, 0x02, 0x03]);
    expect(() => extractAuthDataFromAttestationObject(badBytes.buffer)).toThrow();
  });
});

describe('Passkey Registration & Assertion Ceremonies', () => {
  let originalPKC: any;
  let originalNavCreds: any;

  beforeEach(() => {
    originalPKC = (globalThis as any).PublicKeyCredential;
    originalNavCreds = (globalThis as any).navigator?.credentials;
    vi.restoreAllMocks();
  });

  afterEach(() => {
    if (originalPKC !== undefined) {
      (globalThis as any).PublicKeyCredential = originalPKC;
    } else {
      delete (globalThis as any).PublicKeyCredential;
    }
    if (originalNavCreds !== undefined && globalThis.navigator) {
      (globalThis.navigator as any).credentials = originalNavCreds;
    } else if (globalThis.navigator) {
      delete (globalThis.navigator as any).credentials;
    }
    vi.restoreAllMocks();
  });

  it('formats registration options and returns valid attestation payload', async () => {
    const mockRawId = new Uint8Array([10, 20, 30]);
    const mockClientData = new Uint8Array([40, 50, 60]);
    const mockAuthData = new Uint8Array([70, 80, 90]);

    const createSpy = vi.fn().mockResolvedValue({
      rawId: mockRawId.buffer,
      response: {
        clientDataJSON: mockClientData.buffer,
        getAuthenticatorData: () => mockAuthData.buffer,
        getTransports: () => ['internal', 'hybrid']
      }
    });

    Object.defineProperty(globalThis, 'PublicKeyCredential', {
      value: function () {},
      configurable: true
    });

    Object.defineProperty(globalThis.navigator, 'credentials', {
      value: { create: createSpy },
      configurable: true
    });

    const payload = await performPasskeyRegistration(
      { challenge: 'dGVzdC1jaGFsbGVuZ2U', factorID: 'factor-123', accountDID: 'did:plc:test' },
      'My MacBook',
      'alice.swan.place'
    );

    expect(createSpy).toHaveBeenCalled();
    expect(payload).toEqual({
      kind: 'passkey',
      factorID: 'factor-123',
      label: 'My MacBook',
      challenge: 'dGVzdC1jaGFsbGVuZ2U',
      clientDataJSON: uint8ArrayToBase64URL(mockClientData),
      authenticatorData: uint8ArrayToBase64URL(mockAuthData),
      credentialID: uint8ArrayToBase64URL(mockRawId),
      transports: ['internal', 'hybrid']
    });
  });

  it('formats assertion options and returns valid assertion payload', async () => {
    const mockRawId = new Uint8Array([11, 22, 33]);
    const mockClientData = new Uint8Array([44, 55, 66]);
    const mockAuthData = new Uint8Array([77, 88, 99]);
    const mockSignature = new Uint8Array([1, 3, 5, 7]);

    const getSpy = vi.fn().mockResolvedValue({
      rawId: mockRawId.buffer,
      response: {
        clientDataJSON: mockClientData.buffer,
        authenticatorData: mockAuthData.buffer,
        signature: mockSignature.buffer,
        userHandle: new Uint8Array([100]).buffer
      }
    });

    Object.defineProperty(globalThis, 'PublicKeyCredential', {
      value: function () {},
      configurable: true
    });

    Object.defineProperty(globalThis.navigator, 'credentials', {
      value: { get: getSpy },
      configurable: true
    });

    const payload = await performPasskeyAssertion({
      challenge: 'dGVzdC1jaGFsbGVuZ2U',
      factorID: 'factor-456'
    });

    expect(getSpy).toHaveBeenCalled();
    expect(payload).toEqual({
      kind: 'passkey',
      factorID: 'factor-456',
      challenge: 'dGVzdC1jaGFsbGVuZ2U',
      clientDataJSON: uint8ArrayToBase64URL(mockClientData),
      authenticatorData: uint8ArrayToBase64URL(mockAuthData),
      credentialID: uint8ArrayToBase64URL(mockRawId),
      signature: uint8ArrayToBase64URL(mockSignature),
      userHandle: uint8ArrayToBase64URL(new Uint8Array([100]))
    });
  });
});

describe('WebAuthn Error Formatter', () => {
  it('formats known DOMExceptions to friendly strings', () => {
    expect(formatWebAuthnError({ name: 'NotAllowedError' })).toBe('Passkey prompt was cancelled or timed out.');
    expect(formatWebAuthnError({ name: 'InvalidStateError' })).toBe('This passkey is already registered.');
    expect(formatWebAuthnError({ name: 'NotSupportedError' })).toBe('Passkeys are not supported on this device.');
    expect(formatWebAuthnError({ name: 'AbortError' })).toBe('Passkey authentication was aborted.');
    expect(formatWebAuthnError(new Error('Custom error message'))).toBe('Custom error message');
    expect(formatWebAuthnError('unknown string')).toBe('Passkey operation failed.');
  });
});
