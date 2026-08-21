import { describe, expect, it } from 'vitest';
import {
  base64urlToUint8Array,
  uint8ArrayToBase64URL,
  utf8ToUint8Array,
  uint8ArrayToUtf8
} from '../../../src/lib/webauthn';

describe('Tier 5 Adversarial - Suite 01: Base64URL & Cryptographic Encoding', () => {
  /**
   * T5-B64-01: RFC 4648 §3.5 Modulo 4 === 1 Exhaustive Rejection
   * In Base64 encoding, 1 character represents 6 bits, which is strictly less than 1 full byte (8 bits).
   * Therefore, strings of length len % 4 === 1 are mathematically impossible to decode into whole bytes
   * and MUST be rejected immediately with an invalid length error.
   */
  it('T5-B64-01: RFC 4648 §3.5 Modulo 4 === 1 Exhaustive Rejection', () => {
    // Test various 1-mod-4 lengths (1, 5, 9, 13, 17, 33, 65, 129, 257)
    const singleChars = ['A', 'Z', 'a', 'z', '0', '9', '-', '_'];
    for (const char of singleChars) {
      expect(() => base64urlToUint8Array(char)).toThrowError(
        /Invalid Base64URL string length: 1 \(length modulo 4 cannot be 1\)\./
      );
    }

    const testLengths = [5, 9, 13, 17, 21, 33, 65, 129, 257];
    for (const len of testLengths) {
      const invalidStr = 'A'.repeat(len);
      expect(() => base64urlToUint8Array(invalidStr)).toThrowError(
        new RegExp(`Invalid Base64URL string length: ${len} \\(length modulo 4 cannot be 1\\)\\.`)
      );

      // Surrounding whitespace should be stripped before length checking
      const paddedWithSpace = `  \t\n${invalidStr}\r\n  `;
      expect(() => base64urlToUint8Array(paddedWithSpace)).toThrowError(
        new RegExp(`Invalid Base64URL string length: ${len} \\(length modulo 4 cannot be 1\\)\\.`)
      );

      // Trailing '=' padding should be stripped before length checking
      const trailingPadded = `${invalidStr}==`;
      expect(() => base64urlToUint8Array(trailingPadded)).toThrowError(
        new RegExp(`Invalid Base64URL string length: ${len} \\(length modulo 4 cannot be 1\\)\\.`)
      );
    }
  });

  /**
   * T5-B64-02: Hostile Non-Base64 & Unicode Character Injection
   * Any byte outside the RFC 4648 Base64 / Base64URL alphabet (A-Z, a-z, 0-9, -, _, +, /)
   * must trigger a descriptive error pinpointing the exact character and index.
   */
  it('T5-B64-02: Hostile Non-Base64 & Unicode Character Injection', () => {
    const hostileChars = [
      // Control chars
      '\x00', '\x01', '\x07', '\x08', '\x1b', '\x7f',
      // Punctuation outside base64 alphabet
      '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '~', '`', '[', ']', '{', '}', '|', '\\', ';', ':', '<', '>', ',', '.', '?',
      // Multi-byte Unicode characters / Emojis / Replacements
      '🔑', '🛡️', 'é', 'ñ', '日', '本', '\uFFFD', '\u200B'
    ];

    const valid3 = 'ABC'; // 3 chars
    const valid4 = 'ABCD'; // 4 chars

    for (const bad of hostileChars) {
      // 1) Test character validation when total length % 4 !== 1
      // e.g. 3 chars + 1 code unit = 4 code units
      const atStart4 = `${bad}${valid3}`;
      expect(() => base64urlToUint8Array(atStart4)).toThrow();

      const atMid4 = `A${bad}BC`;
      expect(() => base64urlToUint8Array(atMid4)).toThrow();

      const atEnd4 = `${valid3}${bad}`;
      expect(() => base64urlToUint8Array(atEnd4)).toThrow();

      // For ASCII non-base64 chars (1 code unit), verify exact character error message
      if (bad.length === 1 && bad.charCodeAt(0) < 256) {
        expect(() => base64urlToUint8Array(`A${bad}BC`)).toThrowError(
          `Invalid Base64URL character at index 1: ${bad}`
        );
      }
    }
  });

  /**
   * T5-B64-03: Internal & Malplaced Padding Injection
   * Trailing '=' padding is valid in standard Base64 and should be stripped.
   * However, '=' located internally or at the beginning of a payload is invalid.
   */
  it('T5-B64-03: Internal & Malplaced Padding Injection', () => {
    // Internal '=' characters in 4-char chunks (so length % 4 === 0)
    const internalPaddings4 = [
      'a=bc',
      'ab=c',
      '=abc',
      '==ab',
      'a=b=',
      'Q=M3',
      'S=v8'
    ];

    for (const str of internalPaddings4) {
      expect(() => base64urlToUint8Array(str)).toThrowError(
        /Invalid Base64URL character at index/
      );
    }

    // Malplaced padding in other lengths must throw error (character error or length error)
    const malplacedPaddings = [
      'abc=def',
      'a=b=c=d',
      'QhM=3',
      'SGVsbG8=A',
      '=QhM='
    ];
    for (const str of malplacedPaddings) {
      expect(() => base64urlToUint8Array(str)).toThrow();
    }

    // Pure padding strings should be stripped to empty string and return empty array
    const purePaddings = ['=', '==', '===', '====', '======'];
    for (const p of purePaddings) {
      const res = base64urlToUint8Array(p);
      expect(res).toBeInstanceOf(Uint8Array);
      expect(res.length).toBe(0);
    }
  });

  /**
   * T5-B64-04: High-Bit Pattern & Bitwise Shift Stress
   * Tests byte-for-byte roundtrip fidelity across all 256 individual byte values,
   * alternating bitmasks (0xAA, 0x55), all-zero and all-one blocks, and prime-length buffers.
   */
  it('T5-B64-04: High-Bit Pattern & Bitwise Shift Stress', () => {
    // 1. Test all 256 single-byte values
    for (let b = 0; b < 256; b++) {
      const single = new Uint8Array([b]);
      const encoded = uint8ArrayToBase64URL(single);
      const decoded = base64urlToUint8Array(encoded);
      expect(decoded.length).toBe(1);
      expect(decoded[0]).toBe(b);
    }

    // 2. Test 2-byte boundary combinations
    const twoBytePairs = [
      [0x00, 0x00],
      [0xff, 0xff],
      [0xaa, 0x55],
      [0x55, 0xaa],
      [0x80, 0x01],
      [0x01, 0x80],
      [0x7f, 0xfe],
      [0xfe, 0x7f]
    ];
    for (const pair of twoBytePairs) {
      const arr = new Uint8Array(pair);
      const enc = uint8ArrayToBase64URL(arr);
      const dec = base64urlToUint8Array(enc);
      expect(dec).toEqual(arr);
    }

    // 3. Test prime-length and large buffers (1, 2, 3, 5, 7, 13, 31, 61, 127, 257, 513, 1024, 4096 bytes)
    const testSizes = [1, 2, 3, 5, 7, 11, 13, 17, 31, 61, 127, 251, 509, 1021, 2048, 4096];
    for (const size of testSizes) {
      const buffer = new Uint8Array(size);
      for (let i = 0; i < size; i++) {
        buffer[i] = (i * 37 + 13) % 256; // Deterministic pseudo-random bytes
      }

      const b64url = uint8ArrayToBase64URL(buffer);
      // Ensure no standard base64 characters ('+', '/', '=') appear in base64url output
      expect(b64url).not.toMatch(/[+/=]/);

      const recovered = base64urlToUint8Array(b64url);
      expect(recovered.length).toBe(size);
      expect(recovered).toEqual(buffer);
    }
  });

  /**
   * T5-B64-05: Empty, Whitespace-Only, and Zero-Byte ArrayBuffers
   * Empty inputs, whitespace strings, and 0-length ArrayBuffers must resolve cleanly
   * to empty Uint8Array or empty string without throwing exceptions.
   */
  it('T5-B64-05: Empty, Whitespace-Only, and Zero-Byte ArrayBuffers', () => {
    // Decoding empty / whitespace inputs
    expect(base64urlToUint8Array('').length).toBe(0);
    expect(base64urlToUint8Array('   ').length).toBe(0);
    expect(base64urlToUint8Array('\t\r\n \n\t\r ').length).toBe(0);

    // Encoding empty buffers
    expect(uint8ArrayToBase64URL(new Uint8Array(0))).toBe('');
    expect(uint8ArrayToBase64URL(new ArrayBuffer(0))).toBe('');
    expect(uint8ArrayToBase64URL(new Uint8Array(new ArrayBuffer(16), 8, 0))).toBe('');

    // UTF8 helpers with empty inputs
    expect(utf8ToUint8Array('').length).toBe(0);
    expect(uint8ArrayToUtf8(new Uint8Array(0))).toBe('');
  });

  /**
   * T5-B64-06: Lenient Standard Base64 Conversion
   * The decoder accepts standard Base64 characters '+' (62) and '/' (63) and trailing '=' padding,
   * allowing seamless interop with standard base64 payloads.
   */
  it('T5-B64-06: Lenient Standard Base64 Conversion', () => {
    // '+/==' -> 2 chars '+' and '/' -> 12 bits -> 8-bit byte 0xFB
    const paddedStandard = '+/==';
    const decoded1 = base64urlToUint8Array(paddedStandard);
    expect(decoded1.length).toBe(1);
    expect(decoded1[0]).toBe(0xfb);

    // 'QhM3+w==' -> 6 chars 'QhM3+w' -> 4 bytes [0x42, 0x13, 0x37, 0xFB]
    const standardPayload = 'QhM3+w==';
    const decoded2 = base64urlToUint8Array(standardPayload);
    expect(decoded2).toEqual(new Uint8Array([0x42, 0x13, 0x37, 0xfb]));

    // '//++' -> 4 chars -> 3 bytes [0xFF, 0xFF, 0xBE]
    const allHigh = '//++';
    const decoded3 = base64urlToUint8Array(allHigh);
    expect(decoded3).toEqual(new Uint8Array([0xff, 0xff, 0xbe]));

    // Mixed Base64 and Base64URL characters in same string ('-' and '+', '_' and '/')
    const mixed = '-_+/';
    const decodedMixed = base64urlToUint8Array(mixed);
    expect(decodedMixed.length).toBe(3);
  });

  /**
   * T5-B64-07: Non-Zero Unused Bits Handling
   * In 2-character Base64URL strings (12 bits decoded -> 1 byte extracted, 4 bits unused)
   * or 3-character Base64URL strings (18 bits decoded -> 2 bytes extracted, 2 bits unused),
   * non-zero trailing bits must be safely ignored without out-of-bounds array operations.
   */
  it('T5-B64-07: Non-Zero Unused Bits Handling', () => {
    // 2-character strings:
    // 'Q' = 16 (010000), 'k' = 36 (100100) -> buffer = 010000_100100 (12 bits)
    // First byte = 01000010 (0x42), trailing 4 bits = 0100 (non-zero)
    const twoChar = 'Qk';
    const decodedTwo = base64urlToUint8Array(twoChar);
    expect(decodedTwo.length).toBe(1);
    expect(decodedTwo[0]).toBe(0x42);

    // 3-character strings:
    // '-_A' -> '-' = 62 (111110), '_' = 63 (111111), 'A' = 0 (000000) -> 18 bits
    // First byte = 11111011 (0xFB), Second byte = 11110000 (0xF0), trailing 2 bits = 00
    const threeChar = '-_A';
    const decodedThree = base64urlToUint8Array(threeChar);
    expect(decodedThree.length).toBe(2);
    expect(decodedThree[0]).toBe(0xfb);
    expect(decodedThree[1]).toBe(0xf0);

    // 'ZZ' -> 'Z' = 25 (011001), 'Z' = 25 (011001) -> 011001_011001
    // Byte = 01100101 (0x65), trailing 4 bits = 1001
    const zz = 'ZZ';
    const decodedZZ = base64urlToUint8Array(zz);
    expect(decodedZZ.length).toBe(1);
    expect(decodedZZ[0]).toBe(0x65);
  });
});
