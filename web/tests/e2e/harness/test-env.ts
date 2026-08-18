/**
 * Test Environment Harness for Swan Portal Tests.
 *
 * Provides:
 * - Automatic `fetch` redirection to `MockSwanBackend` in Node/Vitest test suites.
 * - Complete mock implementations of `navigator.credentials.create` and `navigator.credentials.get` for WebAuthn.
 * - Helper utilities for session establishment, step-up elevation, and Base64URL encoding.
 */

import { MockSwanBackend, type MockAccount, type MockSession } from './mock-backend';
import { setCSRF, setStepUpHandler } from '../../../src/lib/api';
import { portal } from '../../../src/lib/stores/portal';
import { modals } from '../../../src/lib/stores/modals';
import { toasts } from '../../../src/lib/stores/toasts';

export interface TestEnvOptions {
  backend?: MockSwanBackend;
  authenticated?: boolean;
  userDid?: string;
  elevated?: boolean;
  stepUpKind?: 'stepUpPassword' | 'stepUpMFA';
  origin?: string;
}

let activeBackend: MockSwanBackend | null = null;
let originalFetch: typeof globalThis.fetch | null = null;
let originalCredentials: any = null;

let customWebAuthnCreateHandler: ((options?: any) => Promise<any>) | null = null;
let customWebAuthnGetHandler: ((options?: any) => Promise<any>) | null = null;

// --- Base64URL Utilities ---

export function bufferToBase64URL(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64url');
  }
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function base64URLToBuffer(base64url: string): ArrayBuffer {
  if (typeof Buffer !== 'undefined') {
    const buf = Buffer.from(base64url, 'base64url');
    const ab = new ArrayBuffer(buf.byteLength);
    new Uint8Array(ab).set(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
    return ab;
  }
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const mod4 = base64.length % 4;
  if (mod4 === 2) base64 += '==';
  else if (mod4 === 3) base64 += '=';
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function stringToBase64URL(str: string): string {
  const bytes = new TextEncoder().encode(str);
  return bufferToBase64URL(bytes);
}

export function base64URLToString(base64url: string): string {
  const buffer = base64URLToBuffer(base64url);
  return new TextDecoder().decode(buffer);
}

// --- WebAuthn Mock Helpers ---

function generateRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return bytes;
}

export function createMockPublicKeyCredential(
  kind: 'create' | 'get',
  options?: {
    id?: string;
    challenge?: string;
    origin?: string;
    rpId?: string;
    userHandle?: string;
  }
): any {
  const rawIdBytes = generateRandomBytes(16);
  const id = options?.id || bufferToBase64URL(rawIdBytes);
  const rawId = base64URLToBuffer(id);
  const origin = options?.origin || 'https://swan.place';
  const challenge = options?.challenge || bufferToBase64URL(generateRandomBytes(32));

  const clientData = {
    type: kind === 'create' ? 'webauthn.create' : 'webauthn.get',
    challenge,
    origin,
    crossOrigin: false
  };
  const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData)).buffer;

  // Mock authenticator data (37 bytes: 32 bytes rpIdHash, 1 byte flags, 4 bytes signCount)
  const authenticatorData = new Uint8Array(37);
  authenticatorData[32] = 0x05; // User present + User verified flags

  if (kind === 'create') {
    // Mock attestation object (CBOR-like mock)
    const attestationObject = new Uint8Array([0xa3, 0x63, 0x66, 0x6d, 0x74, 0x64, 0x6e, 0x6f, 0x6e, 0x65, 0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, 0xa0, 0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, 0x58, 0x25, ...authenticatorData]).buffer;
    const publicKey = new Uint8Array([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, ...new Uint8Array(64)]).buffer;

    return {
      id,
      rawId,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON,
        attestationObject,
        authenticatorData: authenticatorData.buffer,
        getTransports: () => ['internal', 'hybrid'],
        getPublicKey: () => publicKey,
        getPublicKeyAlgorithm: () => -7,
        getAuthenticatorData: () => authenticatorData.buffer
      },
      getClientExtensionResults: () => ({})
    };
  } else {
    // Mock signature (ECDSA P-256 signature)
    const signature = new Uint8Array([0x30, 0x44, 0x02, 0x20, ...new Uint8Array(32).fill(0xaa), 0x02, 0x20, ...new Uint8Array(32).fill(0xbb)]).buffer;
    const userHandle = options?.userHandle ? new TextEncoder().encode(options.userHandle).buffer : new Uint8Array([1, 2, 3, 4]).buffer;

    return {
      id,
      rawId,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON,
        authenticatorData: authenticatorData.buffer,
        signature,
        userHandle
      },
      getClientExtensionResults: () => ({})
    };
  }
}

let originalPublicKeyCredential: any = null;

export function setupWebAuthnMock(): void {
  if (typeof globalThis.navigator === 'undefined') {
    (globalThis as any).navigator = {};
  }

  originalCredentials = (globalThis.navigator as any).credentials;
  originalPublicKeyCredential = (globalThis as any).PublicKeyCredential;

  (globalThis as any).PublicKeyCredential = class PublicKeyCredential {
    static isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
  };

  (globalThis.navigator as any).credentials = {
    create: async (options?: any) => {
      if (customWebAuthnCreateHandler) {
        return customWebAuthnCreateHandler(options);
      }
      const challenge = options?.publicKey?.challenge
        ? (typeof options.publicKey.challenge === 'string'
            ? options.publicKey.challenge
            : bufferToBase64URL(options.publicKey.challenge))
        : undefined;
      return createMockPublicKeyCredential('create', { challenge });
    },
    get: async (options?: any) => {
      if (customWebAuthnGetHandler) {
        return customWebAuthnGetHandler(options);
      }
      const challenge = options?.publicKey?.challenge
        ? (typeof options.publicKey.challenge === 'string'
            ? options.publicKey.challenge
            : bufferToBase64URL(options.publicKey.challenge))
        : undefined;
      return createMockPublicKeyCredential('get', { challenge });
    }
  };
}

export function mockWebAuthnCreate(handler: (options?: any) => Promise<any>): void {
  customWebAuthnCreateHandler = handler;
}

export function mockWebAuthnGet(handler: (options?: any) => Promise<any>): void {
  customWebAuthnGetHandler = handler;
}

export function mockWebAuthnError(error: Error | string, method: 'create' | 'get' | 'both' = 'both'): void {
  const err = typeof error === 'string' ? new Error(error) : error;
  if (method === 'create' || method === 'both') {
    customWebAuthnCreateHandler = async () => { throw err; };
  }
  if (method === 'get' || method === 'both') {
    customWebAuthnGetHandler = async () => { throw err; };
  }
}

export function restoreWebAuthnMock(): void {
  customWebAuthnCreateHandler = null;
  customWebAuthnGetHandler = null;
  if (originalCredentials !== undefined && originalCredentials !== null && globalThis.navigator) {
    (globalThis.navigator as any).credentials = originalCredentials;
  }
  if (originalPublicKeyCredential !== undefined && originalPublicKeyCredential !== null) {
    (globalThis as any).PublicKeyCredential = originalPublicKeyCredential;
  }
}

// --- Test Environment Setup / Teardown ---

export function setupTestEnv(options: TestEnvOptions = {}): { backend: MockSwanBackend; session?: MockSession } {
  const backend = options.backend ?? new MockSwanBackend();
  if (options.origin) backend.origin = options.origin;
  activeBackend = backend;

  // Intercept globalThis.fetch
  if (!originalFetch) {
    originalFetch = globalThis.fetch;
  }

  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    let urlStr = '';
    if (typeof input === 'string') {
      urlStr = input;
    } else if (input instanceof URL) {
      urlStr = input.toString();
    } else if (input && typeof (input as any).url === 'string') {
      urlStr = (input as any).url;
    }

    // Intercept relative paths, backend origin, or localhost / 127.0.0.1
    if (
      urlStr.startsWith('/') ||
      urlStr.startsWith(backend.origin) ||
      urlStr.startsWith('http://localhost') ||
      urlStr.startsWith('https://127.0.0.1') ||
      urlStr.startsWith('http://127.0.0.1')
    ) {
      return backend.fetch(input, init);
    }

    if (originalFetch) {
      return originalFetch(input, init);
    }
    return backend.fetch(input, init);
  };

  // Setup WebAuthn
  setupWebAuthnMock();

  let session: MockSession | undefined;
  if (options.authenticated !== false) {
    const did = options.userDid || 'did:plc:swan-test-user-12345';
    session = backend.createSession(did, {
      strength: options.elevated ? (options.stepUpKind || 'stepUpPassword') : 'password',
      lastStepUpAt: options.elevated ? Date.now() : undefined
    });
  }

  return { backend, session };
}

export function teardownTestEnv(): void {
  if (originalFetch) {
    globalThis.fetch = originalFetch;
    originalFetch = null;
  }
  restoreWebAuthnMock();
  if (activeBackend) {
    activeBackend.reset();
    activeBackend = null;
  }
  setCSRF(undefined);
  setStepUpHandler(null);
  portal.reset();
  modals.closeAll();
  toasts.clear();
}

export function getTestBackend(): MockSwanBackend {
  if (!activeBackend) {
    activeBackend = new MockSwanBackend();
  }
  return activeBackend;
}

export function resetTestBackend(): void {
  if (activeBackend) {
    activeBackend.reset();
  }
  restoreWebAuthnMock();
}
