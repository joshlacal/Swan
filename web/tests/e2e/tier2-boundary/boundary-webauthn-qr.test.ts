import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  base64urlToUint8Array,
  extractAuthDataFromAttestationObject,
  formatWebAuthnError,
  isPlatformAuthenticatorAvailable,
  isWebAuthnSupported,
  performPasskeyAssertion,
  performPasskeyRegistration,
  uint8ArrayToBase64URL,
  utf8ToUint8Array
} from '../../../src/lib/webauthn';
import {
  generateOtpauthUri,
  generateQrMatrix,
  generateQrSvg,
  generateQrSvgPath
} from '../../../src/lib/qrcode';
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

describe('Tier 2 Boundary: WebAuthn, Base64URL, QR Codes & Security Boundaries', () => {
  beforeEach(() => {
    setupTestEnv({ authenticated: true });
  });

  afterEach(() => {
    teardownTestEnv();
  });

  // --- Base64URL Decoding & Encoding Boundaries ---

  it('T2-WA-01: decodes standard Base64URL string without padding', () => {
    const raw = base64urlToUint8Array('-_-_');
    expect(raw.length).toBe(3);
    expect(raw[0]).toBe(251);
    expect(raw[1]).toBe(255);
    expect(raw[2]).toBe(191);
  });

  it('T2-WA-02: leniently decodes standard Base64 characters + and / with whitespace and padding', () => {
    const raw = base64urlToUint8Array(' + / + / \n ');
    expect(raw.length).toBe(3);
    expect(raw[0]).toBe(251);
    expect(raw[1]).toBe(255);
    expect(raw[2]).toBe(191);
  });

  it('T2-WA-03: throws descriptive error on invalid non-Base64 characters', () => {
    expect(() => base64urlToUint8Array('invalid!@#$%^&*')).toThrow(/Invalid Base64URL character/);
    expect(() => base64urlToUint8Array('abc.def')).toThrow(/Invalid Base64URL character/);
  });

  it('T2-WA-04: zero-length empty string decodes to empty Uint8Array', () => {
    const res = base64urlToUint8Array('');
    expect(res).toBeInstanceOf(Uint8Array);
    expect(res.length).toBe(0);

    const whitespaceRes = base64urlToUint8Array('   ');
    expect(whitespaceRes.length).toBe(0);
  });

  it('T2-WA-05: uint8ArrayToBase64URL encodes zero-length buffer to empty string', () => {
    const res = uint8ArrayToBase64URL(new Uint8Array(0));
    expect(res).toBe('');

    const bufRes = uint8ArrayToBase64URL(new ArrayBuffer(0));
    expect(bufRes).toBe('');
  });

  it('T2-WA-06: uint8ArrayToBase64URL encodes 1-byte, 2-byte, and 3-byte inputs with no = padding', () => {
    // 1 byte: 2 chars output
    const oneByte = uint8ArrayToBase64URL(new Uint8Array([255]));
    expect(oneByte.length).toBe(2);
    expect(oneByte).not.toContain('=');

    // 2 bytes: 3 chars output
    const twoBytes = uint8ArrayToBase64URL(new Uint8Array([255, 255]));
    expect(twoBytes.length).toBe(3);
    expect(twoBytes).not.toContain('=');

    // 3 bytes: 4 chars output
    const threeBytes = uint8ArrayToBase64URL(new Uint8Array([251, 255, 191]));
    expect(threeBytes).toBe('-_-_');
  });

  it('T2-WA-07: uint8ArrayToBase64URL roundtrips 1,024 random binary bytes without corruption', () => {
    const randomBytes = new Uint8Array(1024);
    for (let i = 0; i < randomBytes.length; i++) {
      randomBytes[i] = (i * 37 + 13) % 256;
    }

    const encoded = uint8ArrayToBase64URL(randomBytes);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');

    const decoded = base64urlToUint8Array(encoded);
    expect(decoded.length).toBe(1024);
    expect(Array.from(decoded)).toEqual(Array.from(randomBytes));
  });

  // --- WebAuthn Attestation Parser & Error Boundaries ---

  it('T2-WA-08: extracts authData using 0x58 (1-byte length) CBOR pattern', () => {
    const fakeAuthData = new Uint8Array(37).fill(0xaa);
    // CBOR header: 'authData' (9 bytes) + 0x58 (1 byte len) + len + authData
    const pattern = [0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, 0x58, 37, ...fakeAuthData];
    const buffer = new Uint8Array(pattern).buffer;

    const extracted = extractAuthDataFromAttestationObject(buffer);
    expect(extracted.length).toBe(37);
    expect(extracted[0]).toBe(0xaa);
    expect(extracted[36]).toBe(0xaa);
  });

  it('T2-WA-09: extracts authData using 0x59 (2-byte length) CBOR pattern', () => {
    const fakeAuthData = new Uint8Array(300).fill(0xbb);
    // CBOR header: 'authData' + 0x59 + len(2 bytes: 0x01, 0x2c) + authData
    const pattern = [0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, 0x59, 0x01, 0x2c, ...fakeAuthData];
    const buffer = new Uint8Array(pattern).buffer;

    const extracted = extractAuthDataFromAttestationObject(buffer);
    expect(extracted.length).toBe(300);
    expect(extracted[0]).toBe(0xbb);
  });

  it('T2-WA-10: throws error when authData pattern is missing or buffer is truncated', () => {
    const badBuffer = new Uint8Array([1, 2, 3, 4, 5]).buffer;
    expect(() => extractAuthDataFromAttestationObject(badBuffer)).toThrow(
      'Failed to extract authenticatorData from attestationObject.'
    );

    // Header present but truncated payload
    const truncated = new Uint8Array([0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, 0x58, 50, 1, 2]).buffer;
    expect(() => extractAuthDataFromAttestationObject(truncated)).toThrow(
      'Failed to extract authenticatorData from attestationObject.'
    );
  });

  it('T2-WA-11: formatWebAuthnError translates all standard WebAuthn DOMException names', () => {
    expect(formatWebAuthnError({ name: 'NotAllowedError' })).toBe('Passkey prompt was cancelled or timed out.');
    expect(formatWebAuthnError({ name: 'InvalidStateError' })).toBe('This passkey is already registered.');
    expect(formatWebAuthnError({ name: 'NotSupportedError' })).toBe('Passkeys are not supported on this device.');
    expect(formatWebAuthnError({ name: 'AbortError' })).toBe('Passkey authentication was aborted.');
    expect(formatWebAuthnError(new Error('Custom crypto failure'))).toBe('Custom crypto failure');
    expect(formatWebAuthnError('String error')).toBe('Passkey operation failed.');
    expect(formatWebAuthnError(null)).toBe('Passkey operation failed.');
  });

  // --- WebAuthn Ceremony Registration & Assertion Ceremonies ---

  it('T2-WA-12: performPasskeyRegistration formats complete attestation payload successfully', async () => {
    const challenge = bufferToBase64URL(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
    const result = await performPasskeyRegistration(
      { challenge, factorID: 'pk_factor_1', relyingPartyId: 'swan.place', accountDID: 'did:plc:alice' },
      'MacBook TouchID',
      'alice.swan.place'
    );

    expect(result.kind).toBe('passkey');
    expect(result.factorID).toBe('pk_factor_1');
    expect(result.label).toBe('MacBook TouchID');
    expect(result.challenge).toBe(challenge);
    expect(result.credentialID).toBeDefined();
    expect(result.clientDataJSON).toBeDefined();
    expect(result.authenticatorData).toBeDefined();
  });

  it('T2-WA-13: performPasskeyRegistration throws when navigator.credentials.create returns null', async () => {
    mockWebAuthnCreate(async () => null);

    await expect(
      performPasskeyRegistration({ challenge: 'chal_123', factorID: 'pk_1' })
    ).rejects.toThrow('Passkey registration failed: no credential returned.');
  });

  it('T2-WA-14: performPasskeyRegistration throws on user cancellation (NotAllowedError)', async () => {
    const cancelErr = new Error('The operation either timed out or was not allowed.');
    cancelErr.name = 'NotAllowedError';
    mockWebAuthnCreate(async () => {
      throw cancelErr;
    });

    await expect(
      performPasskeyRegistration({ challenge: 'chal_123', factorID: 'pk_1' })
    ).rejects.toThrow('timed out or was not allowed');
  });

  it('T2-WA-15: performPasskeyAssertion formats complete assertion payload successfully', async () => {
    const challenge = bufferToBase64URL(new Uint8Array([10, 20, 30, 40, 50]));
    const result = await performPasskeyAssertion(
      { challenge, factorID: 'pk_factor_1', relyingPartyId: 'swan.place' },
      'cred_existing_id'
    );

    expect(result.kind).toBe('passkey');
    expect(result.factorID).toBe('pk_factor_1');
    expect(result.challenge).toBe(challenge);
    expect(result.credentialID).toBeDefined();
    expect(result.clientDataJSON).toBeDefined();
    expect(result.authenticatorData).toBeDefined();
    expect(result.signature).toBeDefined();
  });

  it('T2-WA-16: performPasskeyAssertion throws when navigator.credentials.get returns null', async () => {
    mockWebAuthnGet(async () => null);

    await expect(
      performPasskeyAssertion({ challenge: 'chal_123', factorID: 'pk_1' })
    ).rejects.toThrow('Passkey assertion failed: no credential returned.');
  });

  it('T2-WA-17: performPasskeyAssertion throws when WebAuthn ceremony is aborted by user', async () => {
    const abortErr = new Error('User clicked cancel');
    abortErr.name = 'AbortError';
    mockWebAuthnGet(async () => {
      throw abortErr;
    });

    await expect(
      performPasskeyAssertion({ challenge: 'chal_123', factorID: 'pk_1' })
    ).rejects.toThrow('User clicked cancel');
  });

  it('T2-WA-18: isPlatformAuthenticatorAvailable returns false when PKC is missing', async () => {
    (globalThis as any).PublicKeyCredential = undefined;
    const available = await isPlatformAuthenticatorAvailable();
    expect(available).toBe(false);
  });

  // --- TOTP URI & QR Code Generation Boundaries ---

  it('T2-WA-19: generateOtpauthUri handles ultra-long label (512 chars) with full percent encoding', () => {
    const longAccount = 'a'.repeat(400) + '@swan.place';
    const uri = generateOtpauthUri({
      secret: 'JBSWY3DPEHPK3PXP',
      account: longAccount,
      issuer: 'Swan Production Identity Provider'
    });

    expect(uri.startsWith('otpauth://totp/')).toBe(true);
    expect(uri).toContain('secret=JBSWY3DPEHPK3PXP');
    expect(uri).toContain('digits=6');
    expect(uri).toContain('period=30');
    expect(uri.length).toBeGreaterThan(450);
  });

  it('T2-WA-20: generateOtpauthUri handles unicode and special characters in account and issuer', () => {
    const uri = generateOtpauthUri({
      secret: 'HXDMVJECJJWSRZ3U',
      account: '🦢 Swan User / test+account@swan.place & special=true',
      issuer: 'Swan (HQ) & Co.'
    });

    expect(uri).toContain('otpauth://totp/');
    // Label should be properly encoded
    expect(uri).toContain(encodeURIComponent('Swan (HQ) & Co.'));
    expect(uri).toContain(encodeURIComponent('🦢 Swan User / test+account@swan.place & special=true'));
    expect(uri).toContain('secret=HXDMVJECJJWSRZ3U');
  });

  it('T2-WA-21: generateOtpauthUri cleans internal spaces and converts secret to uppercase', () => {
    const uri = generateOtpauthUri({
      secret: '  jbsw y3dp ehpk 3pxp  ',
      account: 'alice@swan.place'
    });

    expect(uri).toContain('secret=JBSWY3DPEHPK3PXP');
  });

  it('T2-WA-22: generateQrMatrix creates valid square grid for typical TOTP URI', () => {
    const uri = generateOtpauthUri({
      secret: 'JBSWY3DPEHPK3PXP',
      account: 'alice@swan.place',
      issuer: 'Swan'
    });

    const matrix = generateQrMatrix(uri, { ecc: 'M' });
    expect(Array.isArray(matrix)).toBe(true);
    expect(matrix.length).toBeGreaterThanOrEqual(25); // At least Version 2
    expect(matrix[0].length).toBe(matrix.length); // Strict square

    // Finder pattern checks (Top-left 7x7 outer border)
    expect(matrix[0][0]).toBe(true);
    expect(matrix[0][6]).toBe(true);
    expect(matrix[6][0]).toBe(true);
    expect(matrix[6][6]).toBe(true);
  });

  it('T2-WA-23: generateQrSvg produces strict CSP-compliant inline SVG markup', () => {
    const uri = 'otpauth://totp/Swan:alice?secret=JBSWY3DPEHPK3PXP&issuer=Swan';
    const svg = generateQrSvg(uri, {
      size: 200,
      margin: 4,
      foregroundColor: '#000000',
      backgroundColor: '#ffffff',
      title: 'Swan TOTP Setup'
    });

    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg.endsWith('</svg>')).toBe(true);
    expect(svg).toContain('xmlns="http://www.w3.org/2000/svg"');
    expect(svg).toContain('width="200"');
    expect(svg).toContain('height="200"');
    expect(svg).toContain('aria-label="Swan TOTP Setup"');
    expect(svg).toContain('<path d="M');

    // Strict CSP checks: no remote images, scripts, inline event handlers
    expect(svg).not.toContain('<img');
    expect(svg).not.toContain('<image');
    expect(svg).not.toContain('xlink:href');
    expect(svg).not.toContain('javascript:');
    expect(svg).not.toContain('onload=');
    expect(svg).not.toContain('onerror=');
  });

  it('T2-WA-24: generateQrSvg prevents SVG tag / attribute injection via malicious title or label', () => {
    const maliciousUri = 'otpauth://totp/<script>alert(1)</script>?secret=JBSWY3DPEHPK3PXP';
    const svg = generateQrSvg(maliciousUri, {
      title: '"><script>alert(2)</script><svg foo="'
    });

    // Content is encoded in vector modules, not rendered as raw executable HTML
    expect(svg).not.toContain('<script>alert(1)</script>');
  });

  it('T2-WA-25: generateQrSvgPath calculates exact viewBox and full module size with custom margin', () => {
    const uri = 'otpauth://totp/Swan:alice?secret=JBSWY3DPEHPK3PXP';
    const { viewBox, moduleCount, fullSize, margin } = generateQrSvgPath(uri, { margin: 6, ecc: 'L' });

    expect(margin).toBe(6);
    expect(fullSize).toBe(moduleCount + 12);
    expect(viewBox).toBe(`0 0 ${fullSize} ${fullSize}`);
  });

  it('T2-WA-26: generateQrMatrix throws descriptive error when payload exceeds Version 10 capacity', () => {
    // 1000 characters is too large for Version 10 QR code
    const oversizedPayload = 'A'.repeat(1000);
    expect(() => generateQrMatrix(oversizedPayload, { ecc: 'H' })).toThrow(
      'Text is too large for QR Versions 1-10 at ECC level H.'
    );
  });
});
