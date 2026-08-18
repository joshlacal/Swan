import { describe, expect, it } from 'vitest';
import {
  generateOtpauthUri,
  generateQrMatrix,
  generateQrSvg,
  generateQrSvgPath
} from '../../../src/lib/qrcode';

describe('Tier 1 - F03: Inline SVG QR Generator', () => {
  const sampleUri = 'otpauth://totp/Swan:alice.swan.place?secret=JBSWY3DPEHPK3PXP&issuer=Swan&algorithm=SHA1&digits=6&period=30';

  it('T1-F03-01: generateQrMatrix produces a valid 2D boolean bit matrix from an otpauth URI', () => {
    const matrix = generateQrMatrix(sampleUri);

    expect(Array.isArray(matrix)).toBe(true);
    expect(matrix.length).toBeGreaterThan(20);
    // Square matrix
    expect(matrix[0].length).toBe(matrix.length);

    // Modules are strictly boolean
    for (let r = 0; r < matrix.length; r++) {
      for (let c = 0; c < matrix[r].length; c++) {
        expect(typeof matrix[r][c]).toBe('boolean');
      }
    }

    // Top-left finder pattern center (row 3, col 3) is true
    expect(matrix[3][3]).toBe(true);
    // Top-left finder pattern inner ring (row 1, col 1) is false
    expect(matrix[1][1]).toBe(false);
  });

  it('T1-F03-02: generateQrSvg produces strict CSP-compliant inline SVG markup with no remote references', () => {
    const svg = generateQrSvg(sampleUri, { size: 200, foregroundColor: '#173f3e', title: 'TOTP Secret' });

    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg.endsWith('</svg>')).toBe(true);
    expect(svg).toContain('xmlns="http://www.w3.org/2000/svg"');
    expect(svg).toContain('viewBox=');
    expect(svg).toContain('width="200"');
    expect(svg).toContain('height="200"');
    expect(svg).toContain('role="img"');
    expect(svg).toContain('aria-label="TOTP Secret"');

    // Strict CSP compliance assertions: no inline javascript or external resource URLs
    expect(svg).not.toContain('<script');
    expect(svg).not.toContain('javascript:');
    expect(svg).not.toContain('https://');
    expect(svg).not.toContain('<image');
    expect(svg).not.toContain('href=');
    expect(svg).not.toContain('src=');
  });

  it('T1-F03-03: QR code error correction levels (L, M, Q, H) are supported and properly adjust matrix version/capacity', () => {
    const matrixL = generateQrMatrix(sampleUri, { ecc: 'L' });
    const matrixH = generateQrMatrix(sampleUri, { ecc: 'H' });

    expect(matrixL.length).toBeGreaterThanOrEqual(21);
    expect(matrixH.length).toBeGreaterThanOrEqual(matrixL.length);

    // Both produce valid square matrices
    expect(matrixL[0].length).toBe(matrixL.length);
    expect(matrixH[0].length).toBe(matrixH.length);
  });

  it('T1-F03-04: generateQrSvgPath outputs a valid scalable SVG path and matching viewBox', () => {
    const margin = 4;
    const result = generateQrSvgPath(sampleUri, { margin, ecc: 'M' });

    expect(result).toBeDefined();
    expect(typeof result.path).toBe('string');
    expect(result.path.length).toBeGreaterThan(0);
    // Path uses 'M', 'h1', 'v1', 'h-1z' commands for crisp pixel rendering
    expect(result.path).toContain('h1v1h-1z');

    expect(result.moduleCount).toBeGreaterThan(0);
    expect(result.fullSize).toBe(result.moduleCount + margin * 2);
    expect(result.viewBox).toBe(`0 0 ${result.fullSize} ${result.fullSize}`);
  });

  it('T1-F03-05: generateOtpauthUri formats RFC 6238 compliant TOTP URI with custom parameters', () => {
    const uri = generateOtpauthUri({
      account: 'alice@swan.place',
      secret: 'jbsw y3dp ehpk 3pxp', // with spaces and lowercase
      issuer: 'Swan Secure',
      digits: 6,
      period: 30,
      algorithm: 'SHA1'
    });

    expect(uri.startsWith('otpauth://totp/')).toBe(true);
    expect(uri).toContain('secret=JBSWY3DPEHPK3PXP'); // cleaned secret
    expect(uri).toContain('issuer=Swan+Secure');
    expect(uri).toContain('digits=6');
    expect(uri).toContain('period=30');
    expect(uri).toContain('algorithm=SHA1');
  });
});
