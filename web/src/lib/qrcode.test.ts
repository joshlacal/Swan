import { describe, expect, it } from 'vitest';
import {
  generateQrMatrix,
  generateQrSvg,
  generateQrSvgPath,
  generateOtpauthUri,
  rsEncode,
  getGeneratorPoly,
  getVersionBch,
  gfMul,
  GF_EXP,
  VERSION_TABLE,
  type QrEccLevel
} from './qrcode';

describe('Reed-Solomon Error Correction Codec (ISO/IEC 18004)', () => {
  // ISO/IEC 18004 GF(256) Reed-Solomon Syndrome Calculator
  function calculateSyndromes(codeword: Uint8Array, numEcc: number): number[] {
    const syndromes: number[] = [];
    for (let r = 0; r < numEcc; r++) {
      const root = GF_EXP[r];
      let syn = 0;
      for (let i = 0; i < codeword.length; i++) {
        syn = gfMul(syn, root) ^ codeword[i];
      }
      syndromes.push(syn);
    }
    return syndromes;
  }

  it('produces generator polynomials with monic leading term and correct degree', () => {
    for (const numEcc of [7, 10, 13, 15, 16, 17, 18, 20, 22, 24, 26, 28, 30]) {
      const gen = getGeneratorPoly(numEcc);
      expect(gen.length).toBe(numEcc + 1);
      // Leading term (coefficient of x^numEcc) must be 1
      expect(gen[numEcc]).toBe(1);
      // Constant term g_0 must be non-zero
      expect(gen[0]).toBeGreaterThan(0);
    }
  });

  it('generates zero syndromes for all supported ECC lengths on synthetic data', () => {
    const eccLengths = [7, 10, 13, 15, 16, 17, 18, 20, 22, 24, 26, 28, 30];
    for (const numEcc of eccLengths) {
      for (let dataLen = 1; dataLen <= 60; dataLen += 5) {
        const data = new Uint8Array(dataLen);
        for (let i = 0; i < dataLen; i++) {
          data[i] = (i * 37 + 13) & 0xff;
        }
        const parity = rsEncode(data, numEcc);
        expect(parity.length).toBe(numEcc);

        const codeword = new Uint8Array([...data, ...parity]);
        const syndromes = calculateSyndromes(codeword, numEcc);

        // Every syndrome S_0..S_(numEcc-1) must be identically 0
        const allZero = syndromes.every((s) => s === 0);
        expect(allZero).toBe(true);
      }
    }
  });

  it('produces non-zero syndromes when codeword is corrupted', () => {
    const data = new Uint8Array([0x10, 0x20, 0x30, 0x40, 0x50]);
    const numEcc = 10;
    const parity = rsEncode(data, numEcc);
    const codeword = new Uint8Array([...data, ...parity]);

    // Corrupt one data byte
    codeword[2] ^= 0x01;
    const corruptedSyndromes = calculateSyndromes(codeword, numEcc);
    const hasNonZero = corruptedSyndromes.some((s) => s !== 0);
    expect(hasNonZero).toBe(true);
  });
});

describe('BCH Version Information (ISO/IEC 18004 Table D.1)', () => {
  it('computes correct 18-bit BCH codes for Versions 7-10', () => {
    // Standard ISO/IEC 18004 reference values:
    expect(getVersionBch(7)).toBe(0x07c94);  // 000111 110010010100
    expect(getVersionBch(8)).toBe(0x085bc);  // 001000 010110111100
    expect(getVersionBch(9)).toBe(0x09a99);  // 001001 101010011001
    expect(getVersionBch(10)).toBe(0x0a4d3); // 001010 010011010011
  });
});

describe('Full QR Matrix ISO/IEC 18004 Syndrome Verification (All 40 Combinations)', () => {
  const ALIGNMENT_COORDS = [
    [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
    [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]
  ];

  const MASK_CONDITIONS = [
    (r: number, c: number) => (r + c) % 2 === 0,
    (r: number) => r % 2 === 0,
    (_: number, c: number) => c % 3 === 0,
    (r: number, c: number) => (r + c) % 3 === 0,
    (r: number, c: number) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
    (r: number, c: number) => ((r * c) % 2) + ((r * c) % 3) === 0,
    (r: number, c: number) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
    (r: number, c: number) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0
  ];

  function decodeAndVerifyMatrixSyndromes(matrix: boolean[][], expectedEcc: QrEccLevel, expectedVersion: number) {
    const N = matrix.length;
    const v = (N - 17) / 4;
    expect(v).toBe(expectedVersion);

    // 1. Read format info from top-left
    const topCoords = [
      [8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8],
      [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]
    ];
    let rawFormat = 0;
    for (let i = 0; i < 15; i++) {
      if (matrix[topCoords[i][0]][topCoords[i][1]]) rawFormat |= (1 << i);
    }
    const format = rawFormat ^ 0x5412;
    const formatData = format >> 10;
    const mask = formatData & 7;
    const eccBits = (formatData >> 3) & 3;
    const eccMap: Record<number, QrEccLevel> = { 0: 'M', 1: 'L', 2: 'H', 3: 'Q' };
    const detectedEcc = eccMap[eccBits];
    expect(detectedEcc).toBe(expectedEcc);

    // 2. Build isFunction map matching ISO/IEC 18004
    const isFunction: boolean[][] = Array.from({ length: N }, () => Array(N).fill(false));
    const markFinder = (sr: number, sc: number) => {
      for (let r = -1; r <= 7; r++) {
        for (let c = -1; c <= 7; c++) {
          const nr = sr + r, nc = sc + c;
          if (nr >= 0 && nr < N && nc >= 0 && nc < N) isFunction[nr][nc] = true;
        }
      }
    };
    markFinder(0, 0); markFinder(0, N - 7); markFinder(N - 7, 0);

    for (let i = 8; i < N - 8; i++) {
      isFunction[6][i] = true;
      isFunction[i][6] = true;
    }

    if (v >= 2) {
      const coords = ALIGNMENT_COORDS[v - 1];
      for (const r of coords) {
        for (const c of coords) {
          if ((r <= 8 && c <= 8) || (r <= 8 && c >= N - 9) || (r >= N - 9 && c <= 8)) continue;
          for (let dr = -2; dr <= 2; dr++) {
            for (let dc = -2; dc <= 2; dc++) isFunction[r + dr][c + dc] = true;
          }
        }
      }
    }

    isFunction[4 * v + 9][8] = true; // dark module
    for (let i = 0; i <= 8; i++) { isFunction[8][i] = true; isFunction[i][8] = true; }
    for (let i = 0; i < 8; i++) isFunction[8][N - 1 - i] = true;
    for (let i = 0; i < 7; i++) isFunction[N - 1 - i][8] = true;

    if (v >= 7) {
      for (let r = 0; r < 6; r++) {
        for (let c = 0; c < 3; c++) {
          isFunction[r][N - 11 + c] = true;
          isFunction[N - 11 + c][r] = true;
        }
      }
    }

    // 3. Extract unmasked data bits
    const bits: number[] = [];
    let goingUp = true;
    for (let c = N - 1; c > 0; c -= 2) {
      if (c === 6) c--;
      const rows = goingUp
        ? Array.from({ length: N }, (_, i) => N - 1 - i)
        : Array.from({ length: N }, (_, i) => i);
      for (const r of rows) {
        for (const col of [c, c - 1]) {
          if (!isFunction[r][col]) {
            const masked = matrix[r][col];
            const unmasked = masked !== MASK_CONDITIONS[mask](r, col);
            bits.push(unmasked ? 1 : 0);
          }
        }
      }
      goingUp = !goingUp;
    }

    const entry = VERSION_TABLE[detectedEcc][v - 1];
    const totalCodewords = entry.totalCodewords;
    const codewords = new Uint8Array(totalCodewords);
    for (let i = 0; i < totalCodewords; i++) {
      let val = 0;
      for (let b = 0; b < 8; b++) val = (val << 1) | bits[i * 8 + b];
      codewords[i] = val;
    }

    // 4. De-interleave data and ECC blocks
    const numBlocks = entry.g1Blocks + entry.g2Blocks;
    const dataBlocks: number[][] = Array.from({ length: numBlocks }, () => []);
    const eccBlocks: number[][] = Array.from({ length: numBlocks }, () => []);

    let cwIdx = 0;
    const maxData = Math.max(entry.g1Data, entry.g2Data);
    for (let i = 0; i < maxData; i++) {
      for (let b = 0; b < numBlocks; b++) {
        const blockDataLen = b < entry.g1Blocks ? entry.g1Data : entry.g2Data;
        if (i < blockDataLen) {
          dataBlocks[b].push(codewords[cwIdx++]);
        }
      }
    }

    for (let i = 0; i < entry.eccPerBlock; i++) {
      for (let b = 0; b < numBlocks; b++) {
        eccBlocks[b].push(codewords[cwIdx++]);
      }
    }

    // 5. Check Reed-Solomon syndromes on all blocks
    for (let b = 0; b < numBlocks; b++) {
      const fullBlock = new Uint8Array([...dataBlocks[b], ...eccBlocks[b]]);
      for (let r = 0; r < entry.eccPerBlock; r++) {
        const root = GF_EXP[r];
        let syn = 0;
        for (let i = 0; i < fullBlock.length; i++) {
          syn = gfMul(syn, root) ^ fullBlock[i];
        }
        expect(syn, `Syndrome root ${r} failed in V${v}-${detectedEcc} block ${b}`).toBe(0);
      }
    }
  }

  const eccLevels: QrEccLevel[] = ['L', 'M', 'Q', 'H'];

  for (const ecc of eccLevels) {
    for (let v = 1; v <= 10; v++) {
      it(`verifies zero syndromes for Version ${v} with ECC level ${ecc}`, () => {
        let prevCapacity = 0;
        if (v > 1) {
          const prevEntry = VERSION_TABLE[ecc][v - 2];
          const prevTotalData = prevEntry.g1Blocks * prevEntry.g1Data + prevEntry.g2Blocks * prevEntry.g2Data;
          const prevLengthBits = (v - 1) < 10 ? 8 : 16;
          prevCapacity = Math.floor((prevTotalData * 8 - 4 - prevLengthBits) / 8);
        }
        const payloadLen = Math.max(1, prevCapacity + 1);
        const text = 'S'.repeat(payloadLen);

        const matrix = generateQrMatrix(text, { minVersion: v, ecc });
        decodeAndVerifyMatrixSyndromes(matrix, ecc, v);
      });
    }
  }
});

describe('QR Code Matrix Generator (Structural Features)', () => {
  it('generates a 21x21 matrix for Version 1 QR code', () => {
    const matrix = generateQrMatrix('Swan', { minVersion: 1 });
    expect(matrix.length).toBe(21);
    expect(matrix[0].length).toBe(21);
  });

  it('creates exact 7x7 finder patterns at the three corners', () => {
    const matrix = generateQrMatrix('https://swan.place');
    const N = matrix.length;

    const checkFinder = (startR: number, startC: number) => {
      for (let c = 0; c < 7; c++) {
        expect(matrix[startR][startC + c]).toBe(true);
        expect(matrix[startR + 6][startC + c]).toBe(true);
      }
      for (let r = 0; r < 7; r++) {
        expect(matrix[startR + r][startC]).toBe(true);
        expect(matrix[startR + r][startC + 6]).toBe(true);
      }
      for (let r = 2; r <= 4; r++) {
        for (let c = 2; c <= 4; c++) {
          expect(matrix[startR + r][startC + c]).toBe(true);
        }
      }
      for (let r = 1; r <= 5; r++) {
        if (r === 1 || r === 5) {
          for (let c = 1; c <= 5; c++) {
            expect(matrix[startR + r][startC + c]).toBe(false);
          }
        } else {
          expect(matrix[startR + r][startC + 1]).toBe(false);
          expect(matrix[startR + r][startC + 5]).toBe(false);
        }
      }
    };

    checkFinder(0, 0);
    checkFinder(0, N - 7);
    checkFinder(N - 7, 0);
  });

  it('places alternating timing patterns on row 6 and column 6', () => {
    const matrix = generateQrMatrix('TOTP Secret');
    const N = matrix.length;
    for (let i = 8; i < N - 8; i++) {
      const expected = i % 2 === 0;
      expect(matrix[6][i]).toBe(expected);
      expect(matrix[i][6]).toBe(expected);
    }
  });

  it('places Version Information blocks for Version 7 and above', () => {
    const matrix = generateQrMatrix('A'.repeat(120), { minVersion: 7, ecc: 'M' });
    const N = matrix.length;
    expect(N).toBe(45); // Version 7 is 45x45

    const vInfo = getVersionBch(7);
    // Top-right 6x3 block
    for (let r = 0; r < 6; r++) {
      for (let c = 0; c < 3; c++) {
        const expectedBit = ((vInfo >> (r * 3 + c)) & 1) === 1;
        expect(matrix[r][N - 11 + c]).toBe(expectedBit);
      }
    }
    // Bottom-left 3x6 block
    for (let r = 0; r < 6; r++) {
      for (let c = 0; c < 3; c++) {
        const expectedBit = ((vInfo >> (r * 3 + c)) & 1) === 1;
        expect(matrix[N - 11 + c][r]).toBe(expectedBit);
      }
    }
  });

  it('automatically scales version for long TOTP URIs', () => {
    const longUri =
      'otpauth://totp/Swan:joshua.swan.place?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Swan&algorithm=SHA1&digits=6&period=30';
    const matrix = generateQrMatrix(longUri, { ecc: 'M' });
    expect(matrix.length).toBeGreaterThanOrEqual(29); // Version 3+ (29x29+)
  });

  it('throws error if payload exceeds Version 10 capacity', () => {
    const hugePayload = 'A'.repeat(500);
    expect(() => generateQrMatrix(hugePayload, { ecc: 'H' })).toThrow();
  });
});

describe('QR Code SVG Path & Full SVG Generator', () => {
  it('generates valid SVG path commands', () => {
    const result = generateQrSvgPath('TEST', { margin: 4 });
    expect(result.path.startsWith('M')).toBe(true);
    expect(result.viewBox).toBe(`0 0 ${result.fullSize} ${result.fullSize}`);
    expect(result.moduleCount).toBe(21);
    expect(result.fullSize).toBe(29);
  });

  it('generates valid SVG markup with path commands', () => {
    const svg = generateQrSvg('TEST', { size: 200, margin: 4 });
    expect(svg).toContain('<svg xmlns="http://www.w3.org/2000/svg"');
    expect(svg).toContain('width="200" height="200"');
    expect(svg).toContain('<path d="M');
    expect(svg).toContain('fill="currentColor"');
    expect(svg).toContain('</svg>');
  });

  it('supports background color and custom foreground color', () => {
    const svg = generateQrSvg('TEST', {
      foregroundColor: '#0055ff',
      backgroundColor: '#ffffff'
    });
    expect(svg).toContain('<rect width="100%" height="100%" fill="#ffffff" />');
    expect(svg).toContain('fill="#0055ff"');
  });
});

describe('OTPAuth URI Helper', () => {
  it('builds a canonical otpauth URL', () => {
    const uri = generateOtpauthUri({
      secret: 'JBSWY3DPEHPK3PXP',
      account: 'alice@swan.place',
      issuer: 'Swan'
    });
    expect(uri).toBe(
      'otpauth://totp/Swan:alice%40swan.place?secret=JBSWY3DPEHPK3PXP&issuer=Swan&algorithm=SHA1&digits=6&period=30'
    );
  });

  it('handles custom algorithms, digits, and periods', () => {
    const uri = generateOtpauthUri({
      secret: 'HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ',
      account: 'bob',
      issuer: 'CustomSwan',
      algorithm: 'SHA256',
      digits: 8,
      period: 60
    });
    expect(uri).toContain('algorithm=SHA256');
    expect(uri).toContain('digits=8');
    expect(uri).toContain('period=60');
    expect(uri).toContain('issuer=CustomSwan');
  });
});
