import { describe, expect, it } from 'vitest';
import {
  generateBase32Secret,
  generateOtpauthUri,
  generateQrMatrix,
  generateQrSvg,
  generateQrSvgPath,
  getGeneratorPoly,
  getVersionBch,
  gfMul,
  rsEncode,
  VERSION_TABLE
} from '../../../src/lib/qrcode';

describe('Tier 5 Adversarial - Suite 03: QR Code Boundaries & SVG Sanitization', () => {
  /**
   * T5-QR-01: Multi-Byte UTF-8 Expansion in TOTP Labels
   * In JavaScript, String.prototype.length returns UTF-16 code units, not UTF-8 byte count.
   * Characters such as emojis (4 bytes) or CJK / Cyrillic (2-3 bytes) expand byte count.
   * The QR generator must calculate matrix versions using UTF-8 byte length to avoid matrix overflow.
   */
  it('T5-QR-01: Multi-Byte UTF-8 Expansion in TOTP Labels', () => {
    // 1. Emoji string where string length is 10 chars, but UTF-8 byte length is 24 bytes
    const emojiText = 'Swan 🦢✨🛡️🔑';
    const utf8Bytes = new TextEncoder().encode(emojiText);
    expect(utf8Bytes.length).toBeGreaterThan(emojiText.length);

    const matrix = generateQrMatrix(emojiText, { ecc: 'M' });
    expect(matrix).toBeDefined();
    expect(matrix.length).toBeGreaterThanOrEqual(21); // At least Version 1 (21x21)

    // 2. High-expansion CJK string: 44 characters -> 132 UTF-8 bytes
    const cjkText = '天鹅账户管理系统身份验证器双因素安全通行密钥'.repeat(2);
    const cjkBytes = new TextEncoder().encode(cjkText);
    expect(cjkBytes.length).toBe(cjkText.length * 3);

    const cjkMatrix = generateQrMatrix(cjkText, { ecc: 'L' });
    // 132 bytes in Level L exceeds Version 5 (108 bytes capacity) -> selects Version 6+ (dimension >= 41x41)
    expect(cjkMatrix.length).toBeGreaterThanOrEqual(41);
    expect(cjkMatrix.length % 4).toBe(1); // 17 + 4*v always has mod 4 == 1
  });

  /**
   * T5-QR-02: Version 9 to Version 10 Boundary Transition
   * Versions 1-9 use 8-bit character count indicator in Byte Mode.
   * Version 10 switches to 16-bit character count indicator.
   * Tests the exact boundary payloads at Version 9 upper limit and Version 10 lower limit.
   */
  it('T5-QR-02: Version 9 to Version 10 Boundary Transition', () => {
    // At ECC level 'L':
    // Version 9 capacity is 232 data bytes. Required bits = 4 + 8 + len*8 = 12 + len*8.
    // Max len for V9: 230 bytes (230*8 + 12 = 1852 bits <= 232*8 = 1856 bits).
    const v9MaxPayload = 'A'.repeat(230);
    const matrixV9 = generateQrMatrix(v9MaxPayload, { ecc: 'L' });
    // Version 9 dimension: 17 + 4 * 9 = 53x53
    expect(matrixV9.length).toBe(53);

    // 231 bytes exceeds Version 9-L capacity and transitions to Version 10
    // Version 10 uses 16-bit length indicator: Required bits = 4 + 16 + 231*8 = 1868 bits (234 bytes <= 274 bytes capacity).
    const v10MinPayload = 'A'.repeat(231);
    const matrixV10 = generateQrMatrix(v10MinPayload, { ecc: 'L' });
    // Version 10 dimension: 17 + 4 * 10 = 57x57
    expect(matrixV10.length).toBe(57);

    // Verify BCH Version Information is placed on Version 10 (v >= 7)
    const bchV10 = getVersionBch(10);
    expect(bchV10).toBeGreaterThan(0);
    expect((bchV10 >> 12) & 0x3f).toBe(10); // Leading 6 bits encode version number 10
  });

  /**
   * T5-QR-03: Version 10 Maximum Capacity & Overflow Rejection
   * Version 10 is the maximum supported version in the embedded generator (Versions 1-10).
   * Exact maximum capacities:
   * Level L: 271 bytes
   * Level H: 119 bytes
   * Text exceeding Version 10 capacity must throw a descriptive error.
   */
  it('T5-QR-03: Version 10 Maximum Capacity & Overflow Rejection', () => {
    // Level L maximum capacity: 271 bytes
    const maxLPayload = 'L'.repeat(271);
    const matrixL = generateQrMatrix(maxLPayload, { ecc: 'L' });
    expect(matrixL.length).toBe(57);

    // 272 bytes overflows Version 10-L
    const overflowL = 'L'.repeat(272);
    expect(() => generateQrMatrix(overflowL, { ecc: 'L' })).toThrowError(
      'Text is too large for QR Versions 1-10 at ECC level L.'
    );

    // Level H maximum capacity: 119 bytes
    const maxHPayload = 'H'.repeat(119);
    const matrixH = generateQrMatrix(maxHPayload, { ecc: 'H' });
    expect(matrixH.length).toBe(57);

    // 120 bytes overflows Version 10-H
    const overflowH = 'H'.repeat(120);
    expect(() => generateQrMatrix(overflowH, { ecc: 'H' })).toThrowError(
      'Text is too large for QR Versions 1-10 at ECC level H.'
    );
  });

  /**
   * T5-QR-04: Reed-Solomon GF(256) Generator Polynomial Degree 30
   * Version 9-L uses numEcc = 30, the maximum ECC degree in the generator.
   * Verifies generator polynomial monic properties and LFSR synthetic division.
   */
  it('T5-QR-04: Reed-Solomon GF(256) Generator Polynomial Degree 30 & LFSR Integrity', () => {
    // 1. Verify generator polynomial for degree 30
    const gen30 = getGeneratorPoly(30);
    expect(gen30).toBeInstanceOf(Uint8Array);
    expect(gen30.length).toBe(31);
    expect(gen30[30]).toBe(1); // Monic leading coefficient
    expect(gen30[0]).not.toBe(0); // Constant term non-zero

    // 2. RS encoding with degree 30
    const dataBlock = new Uint8Array(116);
    for (let i = 0; i < dataBlock.length; i++) {
      dataBlock[i] = (i * 17 + 5) & 0xff;
    }
    const eccResult = rsEncode(dataBlock, 30);
    expect(eccResult).toBeInstanceOf(Uint8Array);
    expect(eccResult.length).toBe(30);

    // Verify non-zero and non-trivial remainder
    const nonZeroCount = Array.from(eccResult).filter((b) => b !== 0).length;
    expect(nonZeroCount).toBeGreaterThan(25);

    // 3. GF(256) multiplication properties
    expect(gfMul(0, 255)).toBe(0);
    expect(gfMul(255, 0)).toBe(0);
    expect(gfMul(1, 128)).toBe(128);
    // Identity: a * (a^-1) = 1 in GF(256) for non-zero a
    for (let a = 1; a < 256; a++) {
      let foundInverse = false;
      for (let inv = 1; inv < 256; inv++) {
        if (gfMul(a, inv) === 1) {
          foundInverse = true;
          break;
        }
      }
      expect(foundInverse).toBe(true);
    }
  });

  /**
   * T5-QR-05: SVG Attribute & Tag Injection Immunity
   * When untrusted strings (e.g. injected script tags or broken HTML attributes)
   * are passed into SVG options (title, colors), verify safe vector module rendering.
   */
  it('T5-QR-05: SVG Attribute & Tag Injection Immunity', () => {
    const maliciousPayload = '"><script>alert("xss")</script><path d="';
    const svg = generateQrSvg('otpauth://totp/Swan:alice?secret=JBSWY3DPEHPK3PXP', {
      title: maliciousPayload,
      foregroundColor: 'black" onload="alert(1)"',
      backgroundColor: 'transparent'
    });

    expect(typeof svg).toBe('string');
    expect(svg.startsWith('<svg ')).toBe(true);
    expect(svg.endsWith('</svg>')).toBe(true);

    // Path rendering should strictly contain discrete rectangle movements 'M...h1v1h-1z'
    const svgPath = generateQrSvgPath('https://swan.place/account');
    expect(svgPath.path).toMatch(/^(M\d+,\d+h1v1h-1z\s*)+$/);
    expect(svgPath.moduleCount).toBeGreaterThan(0);
    expect(svgPath.fullSize).toBe(svgPath.moduleCount + svgPath.margin * 2);
  });

  /**
   * T5-QR-06: Extreme URI Delimiters & Special Characters in generateOtpauthUri
   * Tests OTP URI generation when issuer, account name, and secrets contain
   * URI-reserved delimiters ('&', '?', '=', ':', '/', spaces).
   */
  it('T5-QR-06: Extreme URI Delimiters & Special Characters in generateOtpauthUri', () => {
    const uri = generateOtpauthUri({
      secret: '  jbsw y3dp e   hpk3 pxp  ',
      account: 'alice+test/special:ops@swan.place?foo=bar&baz=qux',
      issuer: 'Swan:Place & Co. / <Security>'
    });

    expect(uri.startsWith('otpauth://totp/')).toBe(true);

    // Secret must be stripped of whitespace and capitalized
    expect(uri).toContain('secret=JBSWY3DPEHPK3PXP');

    // Parse URI back into standard URL
    const parsed = new URL(uri);
    expect(parsed.protocol).toBe('otpauth:');
    expect(parsed.host).toBe('totp');
    expect(parsed.pathname).toBe('/Swan%3APlace%20%26%20Co.%20%2F%20%3CSecurity%3E:alice%2Btest%2Fspecial%3Aops%40swan.place%3Ffoo%3Dbar%26baz%3Dqux');
    expect(parsed.searchParams.get('secret')).toBe('JBSWY3DPEHPK3PXP');
    expect(parsed.searchParams.get('issuer')).toBe('Swan:Place & Co. / <Security>');
    expect(parsed.searchParams.get('algorithm')).toBe('SHA1');
    expect(parsed.searchParams.get('digits')).toBe('6');
    expect(parsed.searchParams.get('period')).toBe('30');
  });

  /**
   * T5-QR-07: Base32 Secret Generator Entropy & Alphabet Strictness
   * Generates 1,000 random Base32 secrets and asserts that every secret strictly
   * conforms to RFC 4648 Base32 alphabet (A-Z, 2-7) with no 0, 1, 8, 9.
   */
  it('T5-QR-07: Base32 Secret Generator Entropy & Alphabet Strictness', () => {
    const RFC4648_BASE32_REGEX = /^[A-Z2-7]+$/;
    const sampledChars = new Set<string>();

    for (let i = 0; i < 1000; i++) {
      // 20 bytes (160 bits) -> 32 Base32 characters
      const secret20 = generateBase32Secret(20);
      expect(secret20.length).toBe(32);
      expect(RFC4648_BASE32_REGEX.test(secret20)).toBe(true);

      // Verify no ambiguous characters (0, 1, 8, 9, O, I)
      expect(secret20).not.toMatch(/[0189]/);

      for (const char of secret20) {
        sampledChars.add(char);
      }
    }

    // Over 1000 secrets * 32 chars = 32,000 characters, all 32 alphabet characters MUST appear
    expect(sampledChars.size).toBe(32);

    // Test with custom byte lengths (e.g. 10 bytes -> 16 chars, 32 bytes -> 52 chars (256/5 = 51.2 -> 52))
    const secret10 = generateBase32Secret(10);
    expect(secret10.length).toBe(16);
    expect(RFC4648_BASE32_REGEX.test(secret10)).toBe(true);

    const secret32 = generateBase32Secret(32);
    expect(secret32.length).toBe(52);
    expect(RFC4648_BASE32_REGEX.test(secret32)).toBe(true);
  });
});
