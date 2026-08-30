/**
 * Zero-dependency, pure TypeScript QR Code generator.
 * Produces crisp, strict CSP-compliant inline SVGs for TOTP setup URIs.
 * Standard: ISO/IEC 18004 (Byte Mode, GF(256) Reed-Solomon ECC, Versions 1-10).
 */

export type QrEccLevel = 'L' | 'M' | 'Q' | 'H';

export interface QrOptions {
  ecc?: QrEccLevel;
  minVersion?: number;
}

export interface QrSvgPathResult {
  path: string;
  viewBox: string;
  moduleCount: number;
  fullSize: number;
  margin: number;
}

export interface QrSvgOptions extends QrOptions {
  size?: number;             // Output width/height in px (default: 256)
  margin?: number;           // Quiet zone in modules (default: 4)
  foregroundColor?: string;  // Dark module color (default: 'currentColor')
  backgroundColor?: string;  // Background color (default: 'transparent')
  title?: string;            // Accessible SVG title (default: 'QR Code')
}

// Galois Field GF(2^8) Tables with primitive polynomial 0x11D (285 = x^8 + x^4 + x^3 + x^2 + 1)
export const GF_EXP = new Uint8Array(512);
export const GF_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_EXP[i + 255] = x;
    GF_LOG[x] = i;
    x = x << 1;
    if (x >= 256) x ^= 0x11d;
  }
})();

export function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

/**
 * Calculates the Reed-Solomon generator polynomial for a given number of ECC codewords:
 * G(x) = (x - alpha^0)(x - alpha^1)...(x - alpha^(numEcc-1))
 * Returned array gen has length numEcc + 1, where gen[k] is the coefficient of x^k:
 * gen[0] is constant term g_0, gen[numEcc-1] is g_(numEcc-1), and gen[numEcc] = 1 (monic leading term).
 */
export function getGeneratorPoly(numEcc: number): Uint8Array {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < numEcc; i++) {
    const next = new Uint8Array(poly.length + 1);
    const root = GF_EXP[i];
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= gfMul(poly[j], root);
      next[j + 1] ^= poly[j];
    }
    poly = next;
  }
  return poly;
}

/**
 * Computes Reed-Solomon error correction codewords for a data block using synthetic division (LFSR).
 * Systematic remainder R(x) = (D(x) * x^numEcc) mod G(x).
 * Indexing: gen[numEcc - 1 - j] is the coefficient of x^(numEcc - 1 - j), and gen[0] is constant g_0.
 */
export function rsEncode(data: Uint8Array, numEcc: number): Uint8Array {
  const gen = getGeneratorPoly(numEcc);
  const remainder = new Uint8Array(numEcc);
  for (let i = 0; i < data.length; i++) {
    const factor = data[i] ^ remainder[0];
    for (let j = 0; j < numEcc - 1; j++) {
      remainder[j] = remainder[j + 1] ^ gfMul(gen[numEcc - 1 - j], factor);
    }
    remainder[numEcc - 1] = gfMul(gen[0], factor);
  }
  return remainder;
}

// Version information BCH (18, 6) generator polynomial 0x1F25 (7973)
const VERSION_BCH_POLY = 0x1f25;

/**
 * Computes the 18-bit BCH Version Information string for Versions 7-10.
 */
export function getVersionBch(version: number): number {
  let rem = version << 12;
  for (let i = 17; i >= 12; i--) {
    if ((rem >> i) & 1) {
      rem ^= VERSION_BCH_POLY << (i - 12);
    }
  }
  return (version << 12) | rem;
}

// Alignment pattern coordinate centers for Versions 1-10
const ALIGNMENT_COORDS: number[][] = [
  [], // V1
  [6, 18], // V2
  [6, 22], // V3
  [6, 26], // V4
  [6, 30], // V5
  [6, 34], // V6
  [6, 22, 38], // V7
  [6, 24, 42], // V8
  [6, 26, 46], // V9
  [6, 28, 50]  // V10
];

export interface VersionTableEntry {
  version: number;
  totalCodewords: number;
  eccPerBlock: number;
  g1Blocks: number;
  g1Data: number;
  g2Blocks: number;
  g2Data: number;
}

// Table for Versions 1-10 across L, M, Q, H (ISO/IEC 18004 Table 9)
export const VERSION_TABLE: Record<QrEccLevel, VersionTableEntry[]> = {
  L: [
    { version: 1, totalCodewords: 26, eccPerBlock: 7, g1Blocks: 1, g1Data: 19, g2Blocks: 0, g2Data: 0 },
    { version: 2, totalCodewords: 44, eccPerBlock: 10, g1Blocks: 1, g1Data: 34, g2Blocks: 0, g2Data: 0 },
    { version: 3, totalCodewords: 70, eccPerBlock: 15, g1Blocks: 1, g1Data: 55, g2Blocks: 0, g2Data: 0 },
    { version: 4, totalCodewords: 100, eccPerBlock: 20, g1Blocks: 1, g1Data: 80, g2Blocks: 0, g2Data: 0 },
    { version: 5, totalCodewords: 134, eccPerBlock: 26, g1Blocks: 1, g1Data: 108, g2Blocks: 0, g2Data: 0 },
    { version: 6, totalCodewords: 172, eccPerBlock: 18, g1Blocks: 2, g1Data: 68, g2Blocks: 0, g2Data: 0 },
    { version: 7, totalCodewords: 196, eccPerBlock: 20, g1Blocks: 2, g1Data: 78, g2Blocks: 0, g2Data: 0 },
    { version: 8, totalCodewords: 242, eccPerBlock: 24, g1Blocks: 2, g1Data: 97, g2Blocks: 0, g2Data: 0 },
    { version: 9, totalCodewords: 292, eccPerBlock: 30, g1Blocks: 2, g1Data: 116, g2Blocks: 0, g2Data: 0 },
    { version: 10, totalCodewords: 346, eccPerBlock: 18, g1Blocks: 2, g1Data: 68, g2Blocks: 2, g2Data: 69 }
  ],
  M: [
    { version: 1, totalCodewords: 26, eccPerBlock: 10, g1Blocks: 1, g1Data: 16, g2Blocks: 0, g2Data: 0 },
    { version: 2, totalCodewords: 44, eccPerBlock: 16, g1Blocks: 1, g1Data: 28, g2Blocks: 0, g2Data: 0 },
    { version: 3, totalCodewords: 70, eccPerBlock: 26, g1Blocks: 1, g1Data: 44, g2Blocks: 0, g2Data: 0 },
    { version: 4, totalCodewords: 100, eccPerBlock: 18, g1Blocks: 2, g1Data: 32, g2Blocks: 0, g2Data: 0 },
    { version: 5, totalCodewords: 134, eccPerBlock: 24, g1Blocks: 2, g1Data: 43, g2Blocks: 0, g2Data: 0 },
    { version: 6, totalCodewords: 172, eccPerBlock: 16, g1Blocks: 4, g1Data: 27, g2Blocks: 0, g2Data: 0 },
    { version: 7, totalCodewords: 196, eccPerBlock: 18, g1Blocks: 4, g1Data: 31, g2Blocks: 0, g2Data: 0 },
    { version: 8, totalCodewords: 242, eccPerBlock: 22, g1Blocks: 2, g1Data: 38, g2Blocks: 2, g2Data: 39 },
    { version: 9, totalCodewords: 292, eccPerBlock: 22, g1Blocks: 3, g1Data: 36, g2Blocks: 2, g2Data: 37 },
    { version: 10, totalCodewords: 346, eccPerBlock: 26, g1Blocks: 4, g1Data: 43, g2Blocks: 1, g2Data: 44 }
  ],
  Q: [
    { version: 1, totalCodewords: 26, eccPerBlock: 13, g1Blocks: 1, g1Data: 13, g2Blocks: 0, g2Data: 0 },
    { version: 2, totalCodewords: 44, eccPerBlock: 22, g1Blocks: 1, g1Data: 22, g2Blocks: 0, g2Data: 0 },
    { version: 3, totalCodewords: 70, eccPerBlock: 18, g1Blocks: 2, g1Data: 17, g2Blocks: 0, g2Data: 0 },
    { version: 4, totalCodewords: 100, eccPerBlock: 26, g1Blocks: 2, g1Data: 24, g2Blocks: 0, g2Data: 0 },
    { version: 5, totalCodewords: 134, eccPerBlock: 18, g1Blocks: 2, g1Data: 15, g2Blocks: 2, g2Data: 16 },
    { version: 6, totalCodewords: 172, eccPerBlock: 24, g1Blocks: 4, g1Data: 19, g2Blocks: 0, g2Data: 0 },
    { version: 7, totalCodewords: 196, eccPerBlock: 18, g1Blocks: 2, g1Data: 14, g2Blocks: 4, g2Data: 15 },
    { version: 8, totalCodewords: 242, eccPerBlock: 22, g1Blocks: 4, g1Data: 18, g2Blocks: 2, g2Data: 19 },
    { version: 9, totalCodewords: 292, eccPerBlock: 20, g1Blocks: 4, g1Data: 16, g2Blocks: 4, g2Data: 17 },
    { version: 10, totalCodewords: 346, eccPerBlock: 24, g1Blocks: 6, g1Data: 19, g2Blocks: 2, g2Data: 20 }
  ],
  H: [
    { version: 1, totalCodewords: 26, eccPerBlock: 17, g1Blocks: 1, g1Data: 9, g2Blocks: 0, g2Data: 0 },
    { version: 2, totalCodewords: 44, eccPerBlock: 28, g1Blocks: 1, g1Data: 16, g2Blocks: 0, g2Data: 0 },
    { version: 3, totalCodewords: 70, eccPerBlock: 22, g1Blocks: 2, g1Data: 13, g2Blocks: 0, g2Data: 0 },
    { version: 4, totalCodewords: 100, eccPerBlock: 16, g1Blocks: 4, g1Data: 9, g2Blocks: 0, g2Data: 0 },
    { version: 5, totalCodewords: 134, eccPerBlock: 22, g1Blocks: 2, g1Data: 11, g2Blocks: 2, g2Data: 12 },
    { version: 6, totalCodewords: 172, eccPerBlock: 28, g1Blocks: 4, g1Data: 15, g2Blocks: 0, g2Data: 0 },
    { version: 7, totalCodewords: 196, eccPerBlock: 26, g1Blocks: 4, g1Data: 13, g2Blocks: 1, g2Data: 14 },
    { version: 8, totalCodewords: 242, eccPerBlock: 26, g1Blocks: 4, g1Data: 14, g2Blocks: 2, g2Data: 15 },
    { version: 9, totalCodewords: 292, eccPerBlock: 24, g1Blocks: 4, g1Data: 12, g2Blocks: 4, g2Data: 13 },
    { version: 10, totalCodewords: 346, eccPerBlock: 28, g1Blocks: 6, g1Data: 15, g2Blocks: 2, g2Data: 16 }
  ]
};

export const ECC_FORMAT_BITS: Record<QrEccLevel, number> = {
  M: 0,
  L: 1,
  H: 2,
  Q: 3
};

/**
 * Calculates the QR bit matrix (2D boolean array) for a given text.
 */
export function generateQrMatrix(text: string, options: QrOptions = {}): boolean[][] {
  const ecc = options.ecc ?? 'M';
  const minVersion = options.minVersion ?? 1;
  const utf8Bytes = new TextEncoder().encode(text);
  const dataLen = utf8Bytes.length;

  const entries = VERSION_TABLE[ecc];
  let selectedEntry: VersionTableEntry | null = null;

  for (const entry of entries) {
    if (entry.version < minVersion) continue;
    const capacity = entry.g1Blocks * entry.g1Data + entry.g2Blocks * entry.g2Data;
    // 4 bits mode + 8/16 bits length (v1-9: 8, v10: 16) + dataLen * 8
    const lengthBits = entry.version < 10 ? 8 : 16;
    const requiredBits = 4 + lengthBits + dataLen * 8;
    if (Math.ceil(requiredBits / 8) <= capacity) {
      selectedEntry = entry;
      break;
    }
  }

  if (!selectedEntry) {
    throw new Error(`Text is too large for QR Versions 1-10 at ECC level ${ecc}.`);
  }

  const v = selectedEntry.version;
  const totalDataBytes = selectedEntry.g1Blocks * selectedEntry.g1Data + selectedEntry.g2Blocks * selectedEntry.g2Data;

  // 1. Bitstream encoding (Byte Mode)
  const bitStream: number[] = [];
  const pushBits = (val: number, count: number) => {
    for (let i = count - 1; i >= 0; i--) {
      bitStream.push((val >> i) & 1);
    }
  };

  // Byte mode indicator: 0100 (4)
  pushBits(4, 4);
  // Character count indicator
  pushBits(dataLen, v < 10 ? 8 : 16);
  // Data bytes
  for (let i = 0; i < dataLen; i++) {
    pushBits(utf8Bytes[i], 8);
  }
  // Terminator bits (up to 4)
  const maxDataBits = totalDataBytes * 8;
  const termCount = Math.min(4, maxDataBits - bitStream.length);
  pushBits(0, termCount);
  // Pad to byte boundary
  while (bitStream.length % 8 !== 0) {
    bitStream.push(0);
  }
  // Pad bytes: alternating 0xEC (236) and 0x11 (17)
  const padBytes = [0xec, 0x11];
  let padIdx = 0;
  while (bitStream.length < maxDataBits) {
    pushBits(padBytes[padIdx % 2], 8);
    padIdx++;
  }

  // Convert bitstream to data codewords
  const dataCodewords = new Uint8Array(totalDataBytes);
  for (let i = 0; i < totalDataBytes; i++) {
    let byteVal = 0;
    for (let b = 0; b < 8; b++) {
      byteVal = (byteVal << 1) | bitStream[i * 8 + b];
    }
    dataCodewords[i] = byteVal;
  }

  // 2. Reed-Solomon Block Splitting & Interleaving
  const blocks: Uint8Array[] = [];
  const eccBlocks: Uint8Array[] = [];
  let offset = 0;

  for (let i = 0; i < selectedEntry.g1Blocks; i++) {
    const slice = dataCodewords.slice(offset, offset + selectedEntry.g1Data);
    blocks.push(slice);
    eccBlocks.push(rsEncode(slice, selectedEntry.eccPerBlock));
    offset += selectedEntry.g1Data;
  }
  for (let i = 0; i < selectedEntry.g2Blocks; i++) {
    const slice = dataCodewords.slice(offset, offset + selectedEntry.g2Data);
    blocks.push(slice);
    eccBlocks.push(rsEncode(slice, selectedEntry.eccPerBlock));
    offset += selectedEntry.g2Data;
  }

  // Interleave data codewords
  const finalSequence: number[] = [];
  const maxBlockDataLen = Math.max(selectedEntry.g1Data, selectedEntry.g2Data);
  for (let i = 0; i < maxBlockDataLen; i++) {
    for (let b = 0; b < blocks.length; b++) {
      if (i < blocks[b].length) {
        finalSequence.push(blocks[b][i]);
      }
    }
  }
  // Interleave ECC codewords
  for (let i = 0; i < selectedEntry.eccPerBlock; i++) {
    for (let b = 0; b < eccBlocks.length; b++) {
      finalSequence.push(eccBlocks[b][i]);
    }
  }

  // 3. Matrix Construction
  const N = 17 + 4 * v;
  const matrix: (boolean | null)[][] = Array.from({ length: N }, () => Array(N).fill(null));
  const isFunction: boolean[][] = Array.from({ length: N }, () => Array(N).fill(false));

  const setModule = (r: number, c: number, val: boolean, isFunc = true) => {
    matrix[r][c] = val;
    if (isFunc) isFunction[r][c] = true;
  };

  // Place Finder Patterns & 1-module separators
  const placeFinder = (startR: number, startC: number) => {
    for (let r = 0; r < 7; r++) {
      for (let c = 0; c < 7; c++) {
        const isOuter = r === 0 || r === 6 || c === 0 || c === 6;
        const isInner = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        setModule(startR + r, startC + c, isOuter || isInner);
      }
    }
    // Place 1-module white separator
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        if (r >= 0 && r <= 6 && c >= 0 && c <= 6) continue;
        const nr = startR + r;
        const nc = startC + c;
        if (nr >= 0 && nr < N && nc >= 0 && nc < N) {
          setModule(nr, nc, false);
        }
      }
    }
  };

  placeFinder(0, 0);
  placeFinder(0, N - 7);
  placeFinder(N - 7, 0);

  // Timing patterns
  for (let i = 8; i < N - 8; i++) {
    const val = i % 2 === 0;
    if (matrix[6][i] === null) setModule(6, i, val);
    if (matrix[i][6] === null) setModule(i, 6, val);
  }

  // Alignment patterns
  if (v >= 2) {
    const coords = ALIGNMENT_COORDS[v - 1];
    for (const r of coords) {
      for (const c of coords) {
        // Skip if overlaps with finders
        if (
          (r <= 8 && c <= 8) ||
          (r <= 8 && c >= N - 9) ||
          (r >= N - 9 && c <= 8)
        ) {
          continue;
        }
        for (let dr = -2; dr <= 2; dr++) {
          for (let dc = -2; dc <= 2; dc++) {
            const isBorder = Math.abs(dr) === 2 || Math.abs(dc) === 2;
            const isCenter = dr === 0 && dc === 0;
            setModule(r + dr, c + dc, isBorder || isCenter);
          }
        }
      }
    }
  }

  // Dark module
  setModule(4 * v + 9, 8, true);

  // Reserve format information areas
  // Top-left: row 8 cols 0-8, col 8 rows 0-8
  for (let i = 0; i <= 8; i++) {
    if (matrix[8][i] === null) isFunction[8][i] = true;
    if (matrix[i][8] === null) isFunction[i][8] = true;
  }
  // Top-right: row 8 cols (N-8) to (N-1) -> 8 modules
  for (let i = 0; i < 8; i++) {
    if (matrix[8][N - 1 - i] === null) isFunction[8][N - 1 - i] = true;
  }
  // Bottom-left: col 8 rows (N-7) to (N-1) -> 7 modules (row N-8 is dark module)
  for (let i = 0; i < 7; i++) {
    if (matrix[N - 1 - i][8] === null) isFunction[N - 1 - i][8] = true;
  }

  // Place Version Information for Version 7+ (two 3x6 blocks)
  if (v >= 7) {
    const vInfo = getVersionBch(v);
    for (let r = 0; r < 6; r++) {
      for (let c = 0; c < 3; c++) {
        const bit = ((vInfo >> (r * 3 + c)) & 1) === 1;
        setModule(r, N - 11 + c, bit);
        setModule(N - 11 + c, r, bit);
      }
    }
  }

  // 4. Place Data Bits
  const finalBits: number[] = [];
  for (const byte of finalSequence) {
    for (let b = 7; b >= 0; b--) {
      finalBits.push((byte >> b) & 1);
    }
  }

  let bitIdx = 0;
  let goingUp = true;
  for (let c = N - 1; c > 0; c -= 2) {
    if (c === 6) c--; // Skip vertical timing column
    const rows = goingUp
      ? Array.from({ length: N }, (_, i) => N - 1 - i)
      : Array.from({ length: N }, (_, i) => i);

    for (const r of rows) {
      for (const col of [c, c - 1]) {
        if (!isFunction[r][col]) {
          const bit = bitIdx < finalBits.length ? finalBits[bitIdx++] : 0;
          matrix[r][col] = bit === 1;
        }
      }
    }
    goingUp = !goingUp;
  }

  // 5. Mask Evaluation & Selection
  const MASK_CONDITIONS: ((r: number, c: number) => boolean)[] = [
    (r, c) => (r + c) % 2 === 0,
    (r) => r % 2 === 0,
    (_, c) => c % 3 === 0,
    (r, c) => (r + c) % 3 === 0,
    (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
    (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
    (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
    (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0
  ];

  let minPenalty = Infinity;
  let bestGrid: boolean[][] = [];

  for (let mask = 0; mask < 8; mask++) {
    const grid: boolean[][] = matrix.map((row, r) =>
      row.map((cell, c) => {
        if (isFunction[r][c]) return !!cell;
        return (cell ?? false) !== MASK_CONDITIONS[mask](r, c);
      })
    );

    // Apply format info for this mask
    applyFormatInfo(grid, ecc, mask, N);

    // Penalty scoring
    const penalty = calculatePenalty(grid, N);
    if (penalty < minPenalty) {
      minPenalty = penalty;
      bestGrid = grid;
    }
  }

  return bestGrid;
}

function applyFormatInfo(grid: boolean[][], ecc: QrEccLevel, mask: number, N: number) {
  const eccBits = ECC_FORMAT_BITS[ecc];
  const formatData = (eccBits << 3) | mask;

  // Calculate 10 BCH error correction bits with polynomial 0x537
  let rem = formatData << 10;
  for (let i = 14; i >= 10; i--) {
    if ((rem >> i) & 1) {
      rem ^= 0x537 << (i - 10);
    }
  }
  const formatString = ((formatData << 10) | rem) ^ 0x5412;

  // Write top-left & bottom-left / top-right format bits
  const topCoords = [
    [8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8],
    [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]
  ];
  const otherCoords = [
    [N - 1, 8], [N - 2, 8], [N - 3, 8], [N - 4, 8], [N - 5, 8], [N - 6, 8], [N - 7, 8],
    [8, N - 8], [8, N - 7], [8, N - 6], [8, N - 5], [8, N - 4], [8, N - 3], [8, N - 2], [8, N - 1]
  ];

  for (let i = 0; i < 15; i++) {
    const bit = ((formatString >> i) & 1) === 1;
    grid[topCoords[i][0]][topCoords[i][1]] = bit;
    grid[otherCoords[i][0]][otherCoords[i][1]] = bit;
  }
}

function calculatePenalty(grid: boolean[][], N: number): number {
  let penalty = 0;

  // N1: 5+ consecutive same color modules
  for (let r = 0; r < N; r++) {
    let count = 1;
    for (let c = 1; c < N; c++) {
      if (grid[r][c] === grid[r][c - 1]) {
        count++;
      } else {
        if (count >= 5) penalty += 3 + (count - 5);
        count = 1;
      }
    }
    if (count >= 5) penalty += 3 + (count - 5);
  }

  for (let c = 0; c < N; c++) {
    let count = 1;
    for (let r = 1; r < N; r++) {
      if (grid[r][c] === grid[r - 1][c]) {
        count++;
      } else {
        if (count >= 5) penalty += 3 + (count - 5);
        count = 1;
      }
    }
    if (count >= 5) penalty += 3 + (count - 5);
  }

  // N2: 2x2 same color blocks
  for (let r = 0; r < N - 1; r++) {
    for (let c = 0; c < N - 1; c++) {
      const val = grid[r][c];
      if (grid[r + 1][c] === val && grid[r][c + 1] === val && grid[r + 1][c + 1] === val) {
        penalty += 3;
      }
    }
  }

  // N3: 1:1:3:1:1 patterns
  const pattern = [true, false, true, true, true, false, true];
  for (let r = 0; r < N; r++) {
    for (let c = 0; c <= N - 11; c++) {
      let match = true;
      for (let i = 0; i < 7; i++) {
        if (grid[r][c + 4 + i] !== pattern[i]) {
          match = false;
          break;
        }
      }
      if (match) {
        const pre4 = !grid[r][c] && !grid[r][c + 1] && !grid[r][c + 2] && !grid[r][c + 3];
        const post4 = c + 11 + 4 <= N && !grid[r][c + 11] && !grid[r][c + 12] && !grid[r][c + 13] && !grid[r][c + 14];
        if (pre4 || post4) penalty += 40;
      }
    }
  }

  // N4: Dark module ratio
  let darkCount = 0;
  for (let r = 0; r < N; r++) {
    for (let c = 0; c < N; c++) {
      if (grid[r][c]) darkCount++;
    }
  }
  const ratio = (darkCount / (N * N)) * 100;
  const dev = Math.abs(ratio - 50);
  penalty += Math.floor(dev / 5) * 10;

  return penalty;
}

/**
 * Generates an SVG path string from the QR matrix for pure vector rendering.
 */
export function generateQrSvgPath(text: string, options: { margin?: number; ecc?: QrEccLevel } = {}): QrSvgPathResult {
  const margin = options.margin ?? 4;
  const matrix = generateQrMatrix(text, { ecc: options.ecc });
  const moduleCount = matrix.length;
  const fullSize = moduleCount + margin * 2;

  let path = '';
  for (let r = 0; r < moduleCount; r++) {
    for (let c = 0; c < moduleCount; c++) {
      if (matrix[r][c]) {
        path += `M${c + margin},${r + margin}h1v1h-1z `;
      }
    }
  }

  return {
    path: path.trim(),
    viewBox: `0 0 ${fullSize} ${fullSize}`,
    moduleCount,
    fullSize,
    margin
  };
}

/**
 * Generates an SVG string representation of the QR code.
 */
export function generateQrSvg(text: string, options: QrSvgOptions = {}): string {
  const margin = options.margin ?? 4;
  const size = options.size ?? 256;
  const foregroundColor = options.foregroundColor ?? 'currentColor';
  const backgroundColor = options.backgroundColor ?? 'transparent';
  const title = options.title ?? 'QR Code';
  const { path, fullSize } = generateQrSvgPath(text, { margin, ecc: options.ecc });

  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${fullSize} ${fullSize}" width="${size}" height="${size}" role="img" aria-label="${title}">` +
    (backgroundColor !== 'transparent' ? `<rect width="100%" height="100%" fill="${backgroundColor}" />` : '') +
    `<path d="${path}" fill="${foregroundColor}" />` +
    `</svg>`
  );
}

/**
 * Helper to build standard otpauth:// URI for TOTP authenticators.
 */
export function generateOtpauthUri(options: {
  secret: string;
  account: string;
  issuer?: string;
  algorithm?: 'SHA1' | 'SHA256' | 'SHA512';
  digits?: number;
  period?: number;
}): string {
  const issuer = options.issuer ?? 'Swan';
  const algorithm = options.algorithm ?? 'SHA1';
  const digits = options.digits ?? 6;
  const period = options.period ?? 30;
  const cleanSecret = options.secret.replace(/\s+/g, '').toUpperCase();

  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(options.account)}`;
  const params = new URLSearchParams({
    secret: cleanSecret,
    issuer,
    algorithm,
    digits: String(digits),
    period: String(period)
  });

  return `otpauth://totp/${label}?${params.toString()}`;
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Generates a cryptographically secure random Base32 secret for TOTP (default 20 bytes = 32 Base32 chars / 160 bits).
 */
export function generateBase32Secret(byteLength = 20): string {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('Web Crypto (crypto.getRandomValues) is required for secure TOTP generation.');
  }
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

