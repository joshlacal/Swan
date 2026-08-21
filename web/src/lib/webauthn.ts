/**
 * WebAuthn & Base64URL Utilities for Swan Account Portal
 * Strict CSP-compliant, zero external dependencies.
 */

import type {
  WebAuthnAssertionPayload,
  WebAuthnAttestationPayload,
  WebAuthnChallenge
} from './types';

// Base64URL character mapping
const B64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64_LOOKUP = new Int16Array(256).fill(-1);

for (let i = 0; i < B64URL_CHARS.length; i++) {
  B64_LOOKUP[B64URL_CHARS.charCodeAt(i)] = i;
}
// Support standard base64 characters '+' and '/' for lenient decoding
B64_LOOKUP['+'.charCodeAt(0)] = 62;
B64_LOOKUP['/'.charCodeAt(0)] = 63;

/**
 * Encodes a Uint8Array or ArrayBuffer to an unpadded Base64URL string.
 */
export function uint8ArrayToBase64URL(bytes: Uint8Array | ArrayBuffer): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let str = '';
  const len = arr.length;
  let i = 0;

  for (; i + 2 < len; i += 3) {
    const b0 = arr[i];
    const b1 = arr[i + 1];
    const b2 = arr[i + 2];
    str += B64URL_CHARS[b0 >> 2];
    str += B64URL_CHARS[((b0 & 3) << 4) | (b1 >> 4)];
    str += B64URL_CHARS[((b1 & 15) << 2) | (b2 >> 6)];
    str += B64URL_CHARS[b2 & 63];
  }

  if (i < len) {
    const b0 = arr[i];
    str += B64URL_CHARS[b0 >> 2];
    if (i + 1 < len) {
      const b1 = arr[i + 1];
      str += B64URL_CHARS[((b0 & 3) << 4) | (b1 >> 4)];
      str += B64URL_CHARS[(b1 & 15) << 2];
    } else {
      str += B64URL_CHARS[(b0 & 3) << 4];
    }
  }

  return str;
}

/**
 * Decodes a Base64URL (or standard Base64) string into a Uint8Array.
 */
export function base64urlToUint8Array(base64url: string): Uint8Array {
  // Strip whitespace and padding
  const clean = base64url.replace(/\s+/g, '').replace(/=+$/, '');
  if (clean.length === 0) return new Uint8Array(0);

  // RFC 4648 §3.5: Base64 data with length modulo 4 equal to 1 is malformed
  if (clean.length % 4 === 1) {
    throw new Error(`Invalid Base64URL string length: ${clean.length} (length modulo 4 cannot be 1).`);
  }

  const len = clean.length;
  const byteLen = Math.floor((len * 6) / 8);
  const out = new Uint8Array(byteLen);
  let outIdx = 0;
  let buffer = 0;
  let bits = 0;

  for (let i = 0; i < len; i++) {
    const code = clean.charCodeAt(i);
    const val = code < 256 ? B64_LOOKUP[code] : -1;
    if (val === -1) {
      throw new Error(`Invalid Base64URL character at index ${i}: ${clean[i]}`);
    }
    buffer = (buffer << 6) | val;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[outIdx++] = (buffer >> bits) & 0xff;
      buffer &= (1 << bits) - 1;
    }
  }

  return out.subarray(0, outIdx);
}

/**
 * Helper to encode UTF-8 string to Uint8Array.
 */
export function utf8ToUint8Array(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Helper to decode Uint8Array to UTF-8 string.
 */
export function uint8ArrayToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function getNavigator(): Navigator | undefined {
  if (typeof window !== 'undefined' && window.navigator) return window.navigator;
  if (typeof navigator !== 'undefined') return navigator;
  return undefined;
}

function getPublicKeyCredential(): any {
  if (typeof window !== 'undefined' && (window as any).PublicKeyCredential) {
    return (window as any).PublicKeyCredential;
  }
  if (typeof (globalThis as any).PublicKeyCredential !== 'undefined') {
    return (globalThis as any).PublicKeyCredential;
  }
  return undefined;
}

/**
 * Checks if WebAuthn is supported by the current environment.
 */
export function isWebAuthnSupported(): boolean {
  const nav = getNavigator();
  const pkc = getPublicKeyCredential();
  return (
    typeof nav !== 'undefined' &&
    typeof nav.credentials !== 'undefined' &&
    typeof pkc !== 'undefined'
  );
}

/**
 * Checks if a platform authenticator (e.g. Touch ID, Face ID, Windows Hello) is available.
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) return false;
  const pkc = getPublicKeyCredential();
  if (typeof pkc?.isUserVerifyingPlatformAuthenticatorAvailable !== 'function') {
    return false;
  }
  try {
    return await pkc.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

/**
 * Fallback CBOR parser to extract authData from attestationObject if
 * response.getAuthenticatorData() is not supported by the browser.
 */
export function extractAuthDataFromAttestationObject(attestationObject: ArrayBuffer): Uint8Array {
  const bytes = new Uint8Array(attestationObject);
  // Scan for key "authData" (ASCII: 0x68 0x61 0x75 0x74 0x68 0x44 0x61 0x74 0x61)
  const pattern = [0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61];
  for (let i = 0; i <= bytes.length - pattern.length - 3; i++) {
    let match = true;
    for (let p = 0; p < pattern.length; p++) {
      if (bytes[i + p] !== pattern[p]) {
        match = false;
        break;
      }
    }
    if (match) {
      let offset = i + pattern.length;
      const typeByte = bytes[offset++];
      let dataLen = 0;
      if (typeByte === 0x58) {
        dataLen = bytes[offset++];
      } else if (typeByte === 0x59) {
        dataLen = (bytes[offset] << 8) | bytes[offset + 1];
        offset += 2;
      } else if ((typeByte >> 5) === 2) {
        dataLen = typeByte & 0x1f;
      }
      if (dataLen > 0 && offset + dataLen <= bytes.length) {
        return bytes.slice(offset, offset + dataLen);
      }
    }
  }
  throw new Error('Failed to extract authenticatorData from attestationObject.');
}

/**
 * Initiates browser WebAuthn passkey registration ceremony.
 */
export async function performPasskeyRegistration(
  challengeData: WebAuthnChallenge,
  label: string = 'Passkey',
  userHandle: string = 'Swan User'
): Promise<WebAuthnAttestationPayload> {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn is not supported in this browser.');
  }

  const nav = getNavigator()!;
  const challengeBytes = base64urlToUint8Array(challengeData.challenge);
  const userIdBytes = utf8ToUint8Array(challengeData.accountDID || userHandle);
  const hostname = typeof window !== 'undefined' ? window.location?.hostname : 'localhost';
  const rpId = challengeData.relyingPartyId || hostname || 'localhost';

  const creationOptions: CredentialCreationOptions = {
    publicKey: {
      challenge: challengeBytes as BufferSource,
      rp: {
        name: 'Swan',
        id: rpId
      },
      user: {
        id: userIdBytes as BufferSource,
        name: userHandle,
        displayName: userHandle
      },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' } // ES256 (ECDSA P-256)
      ],
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred'
      },
      timeout: 60000,
      attestation: 'none'
    }
  };

  const credential = (await nav.credentials.create(creationOptions)) as PublicKeyCredential | null;
  if (!credential) {
    throw new Error('Passkey registration failed: no credential returned.');
  }

  const response = credential.response as AuthenticatorAttestationResponse;
  let authDataBytes: Uint8Array;

  if (typeof (response as any).getAuthenticatorData === 'function') {
    authDataBytes = new Uint8Array((response as any).getAuthenticatorData());
  } else {
    authDataBytes = extractAuthDataFromAttestationObject(response.attestationObject);
  }

  const transports = typeof (response as any).getTransports === 'function' ? (response as any).getTransports() : [];

  return {
    kind: 'passkey',
    factorID: challengeData.factorID,
    label,
    challenge: challengeData.challenge,
    clientDataJSON: uint8ArrayToBase64URL(new Uint8Array(response.clientDataJSON)),
    authenticatorData: uint8ArrayToBase64URL(authDataBytes),
    credentialID: uint8ArrayToBase64URL(new Uint8Array(credential.rawId)),
    transports
  };
}

/**
 * Initiates browser WebAuthn passkey assertion ceremony for step-up or login.
 */
export async function performPasskeyAssertion(
  challengeData: WebAuthnChallenge,
  credentialID?: string
): Promise<WebAuthnAssertionPayload> {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn is not supported in this browser.');
  }

  const nav = getNavigator()!;
  const challengeBytes = base64urlToUint8Array(challengeData.challenge);
  const hostname = typeof window !== 'undefined' ? window.location?.hostname : 'localhost';
  const rpId = challengeData.relyingPartyId || hostname || 'localhost';

  const requestOptions: CredentialRequestOptions = {
    publicKey: {
      challenge: challengeBytes as BufferSource,
      rpId,
      allowCredentials: credentialID
        ? [
            {
              id: base64urlToUint8Array(credentialID) as BufferSource,
              type: 'public-key'
            }
          ]
        : undefined,
      userVerification: 'preferred',
      timeout: 60000
    }
  };

  const credential = (await nav.credentials.get(requestOptions)) as PublicKeyCredential | null;
  if (!credential) {
    throw new Error('Passkey assertion failed: no credential returned.');
  }

  const response = credential.response as AuthenticatorAssertionResponse;

  return {
    kind: 'passkey',
    factorID: challengeData.factorID || '',
    challenge: challengeData.challenge,
    clientDataJSON: uint8ArrayToBase64URL(new Uint8Array(response.clientDataJSON)),
    authenticatorData: uint8ArrayToBase64URL(new Uint8Array(response.authenticatorData)),
    credentialID: uint8ArrayToBase64URL(new Uint8Array(credential.rawId)),
    signature: uint8ArrayToBase64URL(new Uint8Array(response.signature)),
    userHandle: response.userHandle ? uint8ArrayToBase64URL(new Uint8Array(response.userHandle)) : undefined
  };
}

/**
 * Translates WebAuthn errors into clear user-facing messages.
 */
export function formatWebAuthnError(error: unknown): string {
  if (error && typeof error === 'object' && 'name' in error) {
    const name = (error as { name: string }).name;
    if (name === 'NotAllowedError') {
      return 'Passkey prompt was cancelled or timed out.';
    }
    if (name === 'InvalidStateError') {
      return 'This passkey is already registered.';
    }
    if (name === 'NotSupportedError') {
      return 'Passkeys are not supported on this device.';
    }
    if (name === 'AbortError') {
      return 'Passkey authentication was aborted.';
    }
  }
  return error instanceof Error ? error.message : 'Passkey operation failed.';
}
