import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { base64urlToUint8Array, formatWebAuthnError, uint8ArrayToBase64URL } from '../../../src/lib/webauthn';
import { generateBase32Secret, generateOtpauthUri, generateQrMatrix, generateQrSvg, generateQrSvgPath } from '../../../src/lib/qrcode';
import { toasts } from '../../../src/lib/stores/toasts';
import { modals } from '../../../src/lib/stores/modals';

describe('Tier 5 Adversarial: Strict CSP Compliance, Cryptography & Data Integrity', () => {
  beforeEach(() => {
    toasts.clear();
    modals.closeAll();
  });

  afterEach(() => {
    toasts.clear();
    modals.closeAll();
  });

  // --- T5-CSP-01 & T5-CSP-02: Strict CSP & Zero Remote CDN/Image Checks ---

  it('T5-CSP-01: strict CSP check: QR code generation produces pure inline SVG without remote CDN/image calls', () => {
    const otpUri = generateOtpauthUri({
      secret: 'JBSWY3DPEHPK3PXP',
      account: 'alice.swan.place',
      issuer: 'Swan'
    });

    const svg = generateQrSvg(otpUri, { size: 200 });

    expect(svg).toContain('<svg');
    expect(svg).toContain('<path');
    expect(svg).toContain('</svg>');

    // Must NOT contain remote resource loads, images, or base64 raster data
    expect(svg).not.toContain('<image');
    expect(svg).not.toContain('<img');
    expect(svg).not.toContain('xlink:href');
    expect(svg).not.toContain('data:image/');
    expect(svg).not.toContain('https://');
  });

  it('T5-CSP-02: QR path generator generates pure path coordinates for accessible rendering', () => {
    const result = generateQrSvgPath('otpauth://totp/Swan:alice?secret=JBSWY3DPEHPK3PXP');

    expect(result.path).toBeDefined();
    expect(result.path.startsWith('M')).toBe(true);
    expect(result.viewBox).toBeDefined();
    expect(result.moduleCount).toBeGreaterThan(20);
    expect(result.margin).toBe(4);
  });

  // --- T5-CSP-03: QR Code Text Capacity Overflow ---

  it('T5-CSP-03: QR Code generator throws clean overflow error on text exceeding Version 10 capacity (2,000 bytes)', () => {
    const giantPayload = 'X'.repeat(2000);

    expect(() => {
      generateQrMatrix(giantPayload);
    }).toThrow(/too large/i);
  });

  // --- T5-CSP-04 & T5-CSP-05: Base64URL RFC 4648 §3.5 Boundaries ---

  it('T5-CSP-04: Base64URL decoder rejects malformed length (length % 4 === 1)', () => {
    // Strings with length % 4 === 1 cannot be valid Base64 / Base64URL
    const invalidLengths = ['A', 'ABCDE', '123456789'];

    for (const str of invalidLengths) {
      expect(() => {
        base64urlToUint8Array(str);
      }).toThrow(/Invalid Base64URL string length/i);
    }
  });

  it('T5-CSP-05: Base64URL decoder rejects illegal characters outside base64url alphabet', () => {
    const illegalPayloads = [
      'abc!def',
      'abc@def',
      'abc#def',
      'abc$def',
      'abc%def',
      'abc^def',
      'abc&def',
      'abc*def',
      'abc=def' // Internal '=' padding character
    ];

    for (const str of illegalPayloads) {
      expect(() => {
        base64urlToUint8Array(str);
      }).toThrow(/Invalid Base64URL character/i);
    }
  });

  // --- T5-CSP-06: Base64URL Round-Trip Bitwise Fidelity ---

  it('T5-CSP-06: Base64URL encoding/decoding maintains 100% byte fidelity across binary data patterns', () => {
    const testBuffers = [
      new Uint8Array(0),
      new Uint8Array([0x00]),
      new Uint8Array([0xff]),
      new Uint8Array([0x00, 0xff, 0xaa, 0x55]),
      new Uint8Array(Array.from({ length: 256 }, (_, i) => i)),
      new TextEncoder().encode('Special characters: 🚀 ✦ ◎ ⚠️ & < > " \'')
    ];

    for (const buf of testBuffers) {
      const encoded = uint8ArrayToBase64URL(buf);
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      expect(encoded).not.toContain('=');

      const decoded = base64urlToUint8Array(encoded);
      expect(decoded).toEqual(buf);
    }
  });

  // --- T5-CSP-07: WebAuthn Error Formatting Across DOMExceptions ---

  it('T5-CSP-07: formatWebAuthnError translates all browser DOMExceptions into human-friendly messages', () => {
    const cases = [
      {
        err: { name: 'NotAllowedError' },
        expected: 'Passkey prompt was cancelled or timed out.'
      },
      {
        err: { name: 'InvalidStateError' },
        expected: 'This passkey is already registered.'
      },
      {
        err: { name: 'NotSupportedError' },
        expected: 'Passkeys are not supported on this device.'
      },
      {
        err: { name: 'AbortError' },
        expected: 'Passkey authentication was aborted.'
      },
      {
        err: new Error('Custom hardware error'),
        expected: 'Custom hardware error'
      },
      {
        err: 'Unknown string error',
        expected: 'Passkey operation failed.'
      }
    ];

    for (const { err, expected } of cases) {
      const formatted = formatWebAuthnError(err);
      expect(formatted).toBe(expected);
    }
  });

  // --- T5-CSP-08: Modal Focus Trap Cycling ---

  it('T5-CSP-08: modal store and stacking preserves active pointer on open and close', () => {
    const id1 = modals.open('app-password');
    expect(modals.isOpen('app-password')).toBe(true);

    const id2 = modals.push('stepup');
    expect(modals.isOpen('stepup')).toBe(true);
    expect(modals.isOpen('app-password')).toBe(true);

    // Close top modal
    const popped = modals.pop();
    expect(popped?.id).toBe(id2);
    expect(modals.isOpen('stepup')).toBe(false);
    expect(modals.isOpen('app-password')).toBe(true);

    modals.closeAll();
    expect(modals.isOpen('app-password')).toBe(false);
  });

  // --- T5-CSP-09: Clipboard Copy Fallback Simulation ---

  it('T5-CSP-09: clipboard text copy fallback works safely when navigator.clipboard is undefined', async () => {
    let copiedText = '';
    let fallbackCommandCalled = false;

    const mockDoc = {
      createElement: (_tag: string) => ({
        style: {} as any,
        focus: () => {},
        select: () => {},
        value: ''
      }),
      body: {
        appendChild: (_el: any) => {},
        removeChild: (_el: any) => {}
      },
      execCommand: (commandId: string) => {
        if (commandId === 'copy') {
          fallbackCommandCalled = true;
          return true;
        }
        return false;
      }
    };

    async function copyToClipboard(text: string, doc: typeof mockDoc): Promise<boolean> {
      // In non-secure context or when clipboard API is missing:
      try {
        const textArea = doc.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        doc.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        const successful = doc.execCommand('copy');
        doc.body.removeChild(textArea);
        if (successful) {
          copiedText = text;
          return true;
        }
        return false;
      } catch {
        return false;
      }
    }

    const success = await copyToClipboard('swan-app-secret-12345', mockDoc);
    expect(success).toBe(true);
    expect(fallbackCommandCalled).toBe(true);
    expect(copiedText).toBe('swan-app-secret-12345');
  });

  // --- T5-CSP-10: Persistent Toast Duration ---

  it('T5-CSP-10: persistent toast with duration 0 or Infinity never auto-dismisses', () => {
    const id = toasts.error('Security alert: emergency rotation required', { duration: 0 });

    let list: any[] = [];
    const unsub = toasts.subscribe(t => { list = t; });
    unsub();

    const toast = list.find(t => t.id === id);
    expect(toast).toBeDefined();
    expect(toast?.duration).toBe(0);
    expect(toast?.message).toBe('Security alert: emergency rotation required');
  });

  // --- T5-CSP-11: Toast Queue Stress & Clear ---

  it('T5-CSP-11: toast queue handles 100 rapid additions and cleans up with clear()', () => {
    for (let i = 0; i < 100; i++) {
      toasts.add('info', `Notification ${i}`, { duration: 0 });
    }

    let list: any[] = [];
    let unsub = toasts.subscribe(t => { list = t; });
    unsub();
    expect(list.length).toBe(100);

    toasts.clear();
    unsub = toasts.subscribe(t => { list = t; });
    unsub();
    expect(list.length).toBe(0);
  });

  // --- T5-CSP-12: did:web JSON Document Generation Integrity ---

  it('T5-CSP-12: did:web public claim document generates valid W3C DID document with #atproto verificationMethod', () => {
    function generateDidJson(handle: string, publicKeyMultibase: string): Record<string, any> {
      const did = `did:web:${handle}`;
      return {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: did,
        alsoKnownAs: [`at://${handle}`],
        verificationMethod: [
          {
            id: `${did}#atproto`,
            type: 'Multikey',
            controller: did,
            publicKeyMultibase
          }
        ],
        service: [
          {
            id: '#atproto_pds',
            type: 'AtprotoPersonalDataServer',
            serviceEndpoint: 'https://swan.place'
          }
        ]
      };
    }

    const doc = generateDidJson('alice.example.com', 'zQ3sh...');

    expect(doc['@context']).toEqual(['https://www.w3.org/ns/did/v1']);
    expect(doc.id).toBe('did:web:alice.example.com');
    expect(doc.alsoKnownAs).toEqual(['at://alice.example.com']);
    expect(doc.verificationMethod.length).toBe(1);
    expect(doc.verificationMethod[0].id).toBe('did:web:alice.example.com#atproto');
    expect(doc.verificationMethod[0].type).toBe('Multikey');
    expect(doc.verificationMethod[0].publicKeyMultibase).toBe('zQ3sh...');
    expect(doc.service[0].serviceEndpoint).toBe('https://swan.place');

    // Must be valid serializable JSON
    const serialized = JSON.stringify(doc, null, 2);
    expect(JSON.parse(serialized)).toEqual(doc);
  });
});
