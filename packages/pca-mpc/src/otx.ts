/**
 * Typed-array kernels for the OT-extension hot path (no per-bit BigInt, no per-bit objects).
 *
 *  - `prgColumn`: AES-128-CTR keystream PRG for the column expansion (one cipher call per column per round).
 *  - `transposeCols`: 32x32 bit-block transpose from `KAPPA` bit-columns to row words.
 *  - `gf128*Words`: GF(2^128) as four little-endian u32 words (add = XOR, multiply-by-x, row accumulation).
 *  - `tmmoCrh`: batched tweakable correlation-robust hash H(x, t) = pi(pi(x) ^ t) ^ pi(x) with a fixed-key AES-128
 *    (the TMMO construction of Guo-Katz-Wang-Yu, ePrint 2019/074 section 7, secure in the ideal-cipher model),
 *    one ECB call over the whole batch, truncated to 64 bits.
 *  - `bigToBytes` / `bytesToBig`: boundary conversions (hex based) between the BigInt wire form and bytes.
 *
 * Every kernel has a naive reference in `otx.test.ts` and is compared on random and edge inputs.
 */

import { createCipheriv, createHash } from 'node:crypto';

/** Number of bit columns of the IKNP matrix (the security parameter kappa). */
export const COLS = 128;

const TAG_PRG_KEY = new TextEncoder().encode('atlas-pca-mpc/ot-prg-aes');
const TAG_CRH_KEY = new TextEncoder().encode('atlas-pca-mpc/ot-crh-aes-fixed-key');

/** Little-endian bytes of a non-negative bigint, exactly `len` bytes (caller range-checked). */
export function bigToBytes(v: bigint, len: number): Uint8Array {
  const hex = v.toString(16).padStart(len * 2, '0').slice(-len * 2); // low len bytes
  return Uint8Array.from(Buffer.from(hex, 'hex').reverse());
}

/** The bigint with the given little-endian bytes. */
export function bytesToBig(b: Uint8Array): bigint {
  if (b.length === 0) return 0n;
  const hex = Buffer.from(b).reverse().toString('hex'); // Buffer.from(Uint8Array) copies, so the input is not reversed in place
  return BigInt('0x' + hex);
}

const keyCache = new WeakMap<Uint8Array, Buffer>();

/** The AES key for a seed (cached per seed object). */
function prgKey(seed: Uint8Array): Buffer {
  let k = keyCache.get(seed);
  if (!k) {
    k = createHash('sha256').update(TAG_PRG_KEY).update(seed).digest().subarray(0, 16);
    keyCache.set(seed, k);
  }
  return k;
}

/**
 * `nwords` u32 words of the PRG stream of `seed` starting at AES block `startBlock` (16-byte blocks). The unused high bits
 * of the last word are NOT masked here.
 */
export function prgColumn(seed: Uint8Array, startBlock: number, nwords: number): Uint32Array {
  const iv = Buffer.alloc(16);
  iv.writeBigUInt64BE(BigInt(startBlock), 8);
  const c = createCipheriv('aes-128-ctr', prgKey(seed), iv);
  const zeros = Buffer.alloc(nwords * 4);
  const ks = c.update(zeros);
  const out = new Uint32Array(nwords);
  for (let i = 0; i < nwords; i++) out[i] = ks.readUInt32LE(i * 4);
  return out;
}

/** Clear the bits at positions >= nbits in a little-endian word column. */
export function maskTail(col: Uint32Array, nbits: number): void {
  const full = nbits >>> 5;
  const rem = nbits & 31;
  if (rem !== 0) col[full] = (col[full]! & ((1 << rem) - 1)) >>> 0;
  for (let i = rem !== 0 ? full + 1 : full; i < col.length; i++) col[i] = 0;
}

/** In-place transpose of a 32x32 bit matrix stored as 32 u32 words (bit c of word r <-> bit r of word c). */
export function transpose32(a: Uint32Array, off = 0): void {
  let m = 0x0000ffff;
  for (let j = 16; j !== 0; j >>>= 1, m = (m ^ (m << j)) >>> 0) {
    for (let k = 0; k < 32; k = (k + j + 1) & ~j) {
      const t = (((a[off + k]! >>> j) ^ a[off + k + j]!) & m) >>> 0;
      a[off + k] = (a[off + k]! ^ (t << j)) >>> 0;
      a[off + k + j] = (a[off + k + j]! ^ t) >>> 0;
    }
  }
}

/**
 * Transpose COLS = 128 bit-columns (each `W` words, concatenated) into `rows` rows of 128 bits (4 words each):
 * bit `i` of row `j` is bit `j` of column `i`. Only the first `rows` rows are produced.
 */
export function transposeCols(cols: Uint32Array, W: number, rows: number): Uint32Array {
  const out = new Uint32Array(rows * 4);
  const tmp = new Uint32Array(32);
  const blocks = (rows + 31) >>> 5;
  for (let rb = 0; rb < blocks; rb++) {
    for (let cb = 0; cb < 4; cb++) {
      for (let c = 0; c < 32; c++) tmp[c] = cols[(cb * 32 + c) * W + rb]!;
      transpose32(tmp);
      const lim = Math.min(32, rows - rb * 32);
      for (let r = 0; r < lim; r++) out[(rb * 32 + r) * 4 + cb] = tmp[r]!;
    }
  }
  return out;
}

// ---------------------------------------------------------------- GF(2^128) on u32 words

/** acc ^= v for the 4-word element at `v[vo..]`. */
export function gfXorInto(acc: Uint32Array, v: Uint32Array, vo: number): void {
  acc[0] = (acc[0]! ^ v[vo]!) >>> 0;
  acc[1] = (acc[1]! ^ v[vo + 1]!) >>> 0;
  acc[2] = (acc[2]! ^ v[vo + 2]!) >>> 0;
  acc[3] = (acc[3]! ^ v[vo + 3]!) >>> 0;
}

/** acc <- acc * x in GF(2^128) with x^128 = x^7 + x^2 + x + 1. */
export function gfMulX(acc: Uint32Array): void {
  const carry = acc[3]! >>> 31;
  acc[3] = ((acc[3]! << 1) | (acc[2]! >>> 31)) >>> 0;
  acc[2] = ((acc[2]! << 1) | (acc[1]! >>> 31)) >>> 0;
  acc[1] = ((acc[1]! << 1) | (acc[0]! >>> 31)) >>> 0;
  acc[0] = ((acc[0]! << 1) ^ (carry ? 0x87 : 0)) >>> 0;
}

/** XOR into `acc` the element `chi[j]` (4 words) for every set bit j of the word column `col`. */
export function accumColumn(col: Uint32Array, chi: Uint32Array, acc: Uint32Array): void {
  for (let w = 0; w < col.length; w++) {
    let x = col[w]!;
    const base = w << 5;
    while (x !== 0) {
      const lsb = x & -x;
      const j = base + (31 - Math.clz32(lsb));
      const o = j << 2;
      acc[0] = (acc[0]! ^ chi[o]!) >>> 0;
      acc[1] = (acc[1]! ^ chi[o + 1]!) >>> 0;
      acc[2] = (acc[2]! ^ chi[o + 2]!) >>> 0;
      acc[3] = (acc[3]! ^ chi[o + 3]!) >>> 0;
      x = (x ^ lsb) >>> 0;
    }
  }
}

/**
 * sum_i x^i * (sum_{j in col_i} chi_j) by Horner over the columns (127 multiplications by x in total), the KOS
 * combination used by both roles. `cols` holds COLS columns of W words.
 */
export function kosCombine(cols: Uint32Array, W: number, chi: Uint32Array): Uint32Array {
  const acc = new Uint32Array(4);
  const part = new Uint32Array(4);
  for (let i = COLS - 1; i >= 0; i--) {
    gfMulX(acc);
    part.fill(0);
    accumColumn(cols.subarray(i * W, (i + 1) * W), chi, part);
    gfXorInto(acc, part, 0);
  }
  return acc;
}

/** The 4-word little-endian form of a 128-bit bigint, and back. */
export function gfFromBig(v: bigint): Uint32Array {
  const out = new Uint32Array(4);
  for (let i = 0; i < 4; i++) out[i] = Number((v >> BigInt(32 * i)) & 0xffffffffn);
  return out;
}
export function gfToBig(w: Uint32Array): bigint {
  let v = 0n;
  for (let i = 3; i >= 0; i--) v = (v << 32n) | BigInt(w[i]!);
  return v;
}

// ---------------------------------------------------------------- correlation-robust hash

let crhKeyBuf: Buffer | undefined;
function crhKey(): Buffer {
  crhKeyBuf ??= createHash('sha256').update(TAG_CRH_KEY).digest().subarray(0, 16);
  return crhKeyBuf;
}

function aesEcb(buf: Uint8Array): Uint8Array {
  const c = createCipheriv('aes-128-ecb', crhKey(), null);
  c.setAutoPadding(false);
  const out = c.update(Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength));
  return new Uint8Array(out.buffer, out.byteOffset, out.byteLength);
}

/**
 * The 128-bit tweak of an OT-extension hash call, as two parts: a 64-bit GLOBAL row index (`offset` + position within the
 * call) in words 0..1 and a 64-bit session DOMAIN in words 2..3. `offset` is the number of rows the channel hashed in
 * all earlier rounds, so no two hash calls of one channel share a tweak; `domain` (`otTweakDomain`) separates channels
 * (sessions, directions, party pairs) that use the same fixed AES key. The default (offset 0, domain 0) is the legacy
 * tweak (position within the call, XORed into the low word).
 */
export interface OtTweak {
  /** Rows hashed by this channel before this call (non-negative safe integer). */
  offset: number;
  /** 2 u32 words; see `otTweakDomain`. */
  domain: Uint32Array;
}

const TAG_TWEAK_DOMAIN = new TextEncoder().encode('atlas-pca-mpc/ot-crh-tweak-domain/v2');
const ZERO_DOMAIN = new Uint32Array(2);

/** The 64-bit session domain of a channel: SHA-256(tag, binding)[0..8], where `binding` is the channel's session binding bytes. */
export function otTweakDomain(binding: Uint8Array): Uint32Array {
  const d = createHash('sha256').update(TAG_TWEAK_DOMAIN).update(binding).digest();
  return new Uint32Array([d.readUInt32LE(0), d.readUInt32LE(4)]);
}

/**
 * H(tweak, row_j) for `n` rows of 128 bits (4 words each in `rows`): returns 2 u32 words (64 bits) per row, TMMO:
 * H(x, t) = pi(pi(x) ^ t) ^ pi(x), pi = AES-128 under one fixed public key, truncated to the low 64 bits.
 *
 * TWEAK (R4-12): t_j = (domain[1] || domain[0] || hi || lo) where (hi || lo) = `tweak.offset + j` is the channel-global
 * row index (64 bits, XORed into words 0..1) and the 64-bit session domain fills words 2..3. Hence every hash call of a
 * channel, in every round, has a distinct tweak, and channels have disjoint tweaks except with probability 2^-64 per
 * pair. (Before R4-12 the tweak was only the position j within the call, restarting at 0 each round; that was safe
 * because the hashed rows are fresh PRG output, see docs/pca/security/pca-mpc-spdz-soundness.md section 8, but it left
 * distinctness to the inputs alone.) Sender and receiver derive the same tweak from the same round counter.
 */
export function tmmoCrh(rows: Uint32Array, n: number, tweak?: OtTweak): Uint32Array {
  const offset = tweak?.offset ?? 0;
  const dom = tweak?.domain ?? ZERO_DOMAIN;
  if (!Number.isSafeInteger(offset) || offset < 0) throw new RangeError('tmmoCrh: tweak offset must be a non-negative safe integer');
  if (dom.length !== 2) throw new RangeError('tmmoCrh: tweak domain must be 2 words');
  const offHi = Math.floor(offset / 4294967296);
  const offLo = offset % 4294967296;
  const a = aesEcb(new Uint8Array(rows.buffer, rows.byteOffset, n * 16));
  const aw = new Uint32Array(a.buffer.slice(a.byteOffset, a.byteOffset + n * 16));
  const b = new Uint32Array(n * 4);
  for (let j = 0; j < n; j++) {
    const o = j * 4;
    const v = offLo + j;
    b[o] = (aw[o]! ^ v) >>> 0;
    b[o + 1] = (aw[o + 1]! ^ (offHi + Math.floor(v / 4294967296))) >>> 0;
    b[o + 2] = (aw[o + 2]! ^ dom[0]!) >>> 0;
    b[o + 3] = (aw[o + 3]! ^ dom[1]!) >>> 0;
  }
  const c = aesEcb(new Uint8Array(b.buffer, 0, n * 16));
  const cw = new Uint32Array(c.buffer.slice(c.byteOffset, c.byteOffset + n * 16));
  const out = new Uint32Array(n * 2);
  for (let j = 0; j < n; j++) {
    out[2 * j] = (cw[4 * j]! ^ aw[4 * j]!) >>> 0;
    out[2 * j + 1] = (cw[4 * j + 1]! ^ aw[4 * j + 1]!) >>> 0;
  }
  return out;
}

/** The 64-bit value of the two words at index j of a `tmmoCrh` output. */
export function word64(h: Uint32Array, j: number): bigint {
  return (BigInt(h[2 * j + 1]!) << 32n) | BigInt(h[2 * j]!);
}
