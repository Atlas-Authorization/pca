/** Differential tests: the typed-array OT-extension kernels against naive BigInt / per-bit references. */
import { describe, expect, it } from 'vitest';
import { createCipheriv, createHash, randomBytes } from 'node:crypto';
import { gf128Add, gf128Mul, gf128MulByXi, gf128MulX } from './gf128';
import {
  accumColumn,
  bigToBytes,
  bytesToBig,
  COLS,
  gfFromBig,
  gfMulX,
  gfToBig,
  kosCombine,
  maskTail,
  prgColumn,
  otTweakDomain,
  tmmoCrh,
  transpose32,
  transposeCols,
  word64,
} from './otx';

const rnd32 = (n: number): Uint32Array => new Uint32Array(randomBytes(n * 4).buffer.slice(0, n * 4) as ArrayBuffer);

describe('otx kernels vs references', () => {
  it('bigToBytes / bytesToBig round-trip on random and edge values', () => {
    for (const len of [1, 2, 7, 16, 33, 1000]) {
      for (const v of [0n, 1n, (1n << BigInt(8 * len)) - 1n, 1n << BigInt(8 * len - 1), bytesToBig(randomBytes(len))]) {
        expect(bytesToBig(bigToBytes(v, len))).toBe(v);
      }
    }
  });

  it('transpose32 equals the naive bit transpose (random and edge matrices)', () => {
    const cases: Uint32Array[] = [new Uint32Array(32), new Uint32Array(32).fill(0xffffffff)];
    const diag = new Uint32Array(32);
    for (let i = 0; i < 32; i++) diag[i] = (1 << i) >>> 0;
    cases.push(diag);
    for (let k = 0; k < 2000; k++) cases.push(rnd32(32));
    for (const a of cases) {
      const b = Uint32Array.from(a);
      transpose32(b);
      for (let r = 0; r < 32; r++) for (let c = 0; c < 32; c++) expect((b[r]! >>> c) & 1).toBe((a[c]! >>> r) & 1);
    }
  });

  it('transposeCols equals the naive column-to-row gather for assorted sizes', () => {
    for (const mExt of [1, 31, 32, 33, 100, 257, 509, 1000]) {
      const W = (mExt + 31) >>> 5;
      const cols = rnd32(COLS * W);
      for (let i = 0; i < COLS; i++) maskTail(cols.subarray(i * W, (i + 1) * W), mExt);
      const rows = transposeCols(cols, W, mExt);
      for (let j = 0; j < mExt; j++) {
        for (let i = 0; i < COLS; i++) {
          const want = (cols[i * W + (j >>> 5)]! >>> (j & 31)) & 1;
          const got = (rows[j * 4 + (i >>> 5)]! >>> (i & 31)) & 1;
          if (want !== got) throw new Error(`mismatch at row ${j} col ${i} (mExt ${mExt})`);
        }
      }
    }
  });

  it('gfMulX equals gf128MulX and gfFromBig/gfToBig round-trip (random, many cases)', () => {
    for (let k = 0; k < 20000; k++) {
      const v = bytesToBig(randomBytes(16));
      const w = gfFromBig(v);
      expect(gfToBig(w)).toBe(v);
      gfMulX(w);
      expect(gfToBig(w)).toBe(gf128MulX(v));
    }
    for (const v of [0n, 1n, 1n << 127n, (1n << 128n) - 1n]) {
      const w = gfFromBig(v);
      gfMulX(w);
      expect(gfToBig(w)).toBe(gf128MulX(v));
    }
  });

  it('kosCombine equals sum_i x^i * (sum over set bits of chi) computed with the BigInt reference', () => {
    for (const mExt of [40, 200, 509]) {
      const W = (mExt + 31) >>> 5;
      const cols = rnd32(COLS * W);
      for (let i = 0; i < COLS; i++) maskTail(cols.subarray(i * W, (i + 1) * W), mExt);
      const chi = rnd32(mExt * 4);
      let want = 0n;
      for (let i = 0; i < COLS; i++) {
        let part = 0n;
        for (let j = 0; j < mExt; j++) if ((cols[i * W + (j >>> 5)]! >>> (j & 31)) & 1) part = gf128Add(part, gfToBig(chi.subarray(4 * j, 4 * j + 4)));
        want = gf128Add(want, gf128MulByXi(part, i));
      }
      expect(gfToBig(kosCombine(cols, W, chi))).toBe(want);
      // single-column accumulation agrees too
      const acc = new Uint32Array(4);
      accumColumn(cols.subarray(0, W), chi, acc);
      let p0 = 0n;
      for (let j = 0; j < mExt; j++) if ((cols[j >>> 5]! >>> (j & 31)) & 1) p0 ^= gfToBig(chi.subarray(4 * j, 4 * j + 4));
      expect(gfToBig(acc)).toBe(p0);
    }
    expect(gf128Mul(3n, 1n)).toBe(3n);
  });

  it('tmmoCrh equals the per-row AES reference H(j,x) = pi(pi(x) ^ j) ^ pi(x), low 64 bits', () => {
    const key = createHash('sha256').update(new TextEncoder().encode('atlas-pca-mpc/ot-crh-aes-fixed-key')).digest().subarray(0, 16);
    const pi = (b: Buffer): Buffer => {
      const c = createCipheriv('aes-128-ecb', key, null);
      c.setAutoPadding(false);
      return c.update(b);
    };
    const n = 300;
    const rows = rnd32(n * 4);
    const h = tmmoCrh(rows, n);
    for (let j = 0; j < n; j++) {
      const x = Buffer.from(new Uint8Array(rows.buffer, j * 16, 16));
      const px = pi(x);
      const t = Buffer.from(px);
      t.writeUInt32LE((t.readUInt32LE(0) ^ j) >>> 0, 0);
      const out = Buffer.from(pi(t));
      for (let i = 0; i < 16; i++) out[i] = out[i]! ^ px[i]!;
      expect(word64(h, j)).toBe(out.readBigUInt64LE(0));
    }
  });

  it('tmmoCrh with a global tweak equals the per-row reference pi(pi(x) ^ t) ^ pi(x), t = domain || 64-bit row index', () => {
    const key = createHash('sha256').update(new TextEncoder().encode('atlas-pca-mpc/ot-crh-aes-fixed-key')).digest().subarray(0, 16);
    const pi = (b: Buffer): Buffer => {
      const c = createCipheriv('aes-128-ecb', key, null);
      c.setAutoPadding(false);
      return c.update(b);
    };
    const domain = otTweakDomain(new TextEncoder().encode('binding'));
    for (const offset of [0, 1, 4294967290, 2 ** 40 + 5]) {
      const n = 20;
      const rows = rnd32(n * 4);
      const h = tmmoCrh(rows, n, { offset, domain });
      for (let j = 0; j < n; j++) {
        const px = pi(Buffer.from(new Uint8Array(rows.buffer, j * 16, 16)));
        const t = Buffer.from(px);
        const idx = BigInt(offset + j);
        t.writeBigUInt64LE(t.readBigUInt64LE(0) ^ idx, 0);
        t.writeUInt32LE((t.readUInt32LE(8) ^ domain[0]!) >>> 0, 8);
        t.writeUInt32LE((t.readUInt32LE(12) ^ domain[1]!) >>> 0, 12);
        const out = Buffer.from(pi(t));
        for (let i = 0; i < 16; i++) out[i] = out[i]! ^ px[i]!;
        expect(word64(h, j)).toBe(out.readBigUInt64LE(0));
      }
    }
  });

  it('tmmoCrh: the same row hashes differently under a different offset or session domain; domain is binding-separated', () => {
    const rows = rnd32(4);
    const d1 = otTweakDomain(new TextEncoder().encode('a'));
    const d2 = otTweakDomain(new TextEncoder().encode('b'));
    expect(d1).not.toEqual(d2);
    const h = (o: number, d: Uint32Array): bigint => word64(tmmoCrh(rows, 1, { offset: o, domain: d }), 0);
    expect(h(0, d1)).not.toBe(h(1, d1));
    expect(h(0, d1)).not.toBe(h(0, d2));
    expect(h(7, d1)).toBe(h(7, d1));
    expect(() => tmmoCrh(rows, 1, { offset: -1, domain: d1 })).toThrow(RangeError);
  });

  it('prgColumn is deterministic, block-aligned across calls, and seed/offset separated', () => {
    const seed = randomBytes(16);
    const a = prgColumn(seed, 0, 64);
    expect(Array.from(prgColumn(seed, 0, 64))).toEqual(Array.from(a));
    expect(Array.from(prgColumn(seed, 4, 48))).toEqual(Array.from(a.subarray(16)));
    expect(Array.from(prgColumn(randomBytes(16), 0, 64))).not.toEqual(Array.from(a));
  });
});
