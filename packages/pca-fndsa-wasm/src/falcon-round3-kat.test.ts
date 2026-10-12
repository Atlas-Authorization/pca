/**
 * NIST PQC round-3 Falcon KATs (the ORIGINAL Falcon submission, not FN-DSA / FIPS 206).
 *
 * These are official NIST-archive files, but they are NOT FIPS 206 vectors: FN-DSA changes the message
 * hashing, the signature container and the key-generation procedure. This file therefore uses them only
 * for the parts that are algorithmically identical, and pins down precisely where compatibility ends:
 *
 *  1. SAME key material, DIFFERENT encodings. Original Falcon packs the coefficients of f, g, F (secret key)
 *     and h (public key) most-significant-bit first, and its public key is h in coefficient form. The FN-DSA
 *     draft implemented by the backend packs least-significant-bit first, stores the public key as h in the
 *     NTT domain (h evaluated at the 2n-th roots of unity, in the implementation's fixed order), and an
 *     FN-DSA signing key also carries a 64-byte SHAKE256 hash of the public key. The test transcodes each
 *     official key pair (repacking, plus evaluating h at the roots; the root order is calibrated from a
 *     key the backend itself generated, and a wrong order could only make verification fail), signs through
 *     the wasm backend, and verifies under the transcoded ORIGINAL public key.
 *     That succeeds for every entry, which requires the backend's secret-key decoding, recomputation of G,
 *     FFT sampler, NTT and public-key handling to agree with the original Falcon arithmetic on official keys.
 *     The raw (untranscoded) round-3 keys are shown to be rejected.
 *  2. NOT compatible: the round-3 signatures. They hash (nonce || message) to a point and use a variable
 *     length compressed container; FN-DSA hashes (nonce || H(vk) || context || message) and pads. A round-3
 *     signature is therefore (correctly) rejected by FN-DSA verification. The test asserts the container
 *     facts and the rejection so the incompatibility is demonstrated rather than assumed.
 *  3. NOT tested: deriving the KAT key pairs from the NIST DRBG seeds. Round-3 key generation consumes the
 *     submission's own RNG stream, while the FN-DSA backend takes a 32-byte seed through a different
 *     procedure, so equality of generated keys is not expected and no such test was attempted.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { type FnDsaVariant, keygen, sign, sizes, verify } from './index';

const DIR = join(__dirname, '..', 'test-vectors', 'falcon-round3');
const prov = JSON.parse(readFileSync(join(DIR, 'PROVENANCE.json'), 'utf8')) as {
  files: Array<{ file: string; sha256: string; entries: number }>;
};

interface Kat { count: number; seed: string; msg: Uint8Array; pk: Uint8Array; sk: Uint8Array; sm: Uint8Array }

function load(file: string): Kat[] {
  const txt = readFileSync(join(DIR, file), 'utf8');
  const out: Kat[] = [];
  for (const block of txt.split(/\n\n+/)) {
    const f: Record<string, string> = {};
    for (const line of block.split('\n')) {
      const m = /^(\w+) = (.*)$/.exec(line.trim());
      if (m) f[m[1] as string] = m[2] as string;
    }
    if (f.count === undefined) continue;
    const b = (k: string): Uint8Array => new Uint8Array(Buffer.from(f[k] as string, 'hex'));
    const mlen = Number(f.mlen);
    const msg = b('msg');
    if (msg.length !== mlen) throw new Error(`KAT ${f.count}: mlen mismatch`);
    out.push({ count: Number(f.count), seed: f.seed as string, msg, pk: b('pk'), sk: b('sk'), sm: b('sm') });
  }
  return out;
}

/** Original Falcon packing: `bits` per value, most significant bit first. */
function unpackMsb(d: Uint8Array, count: number, bits: number, signed: boolean): number[] {
  const out: number[] = [];
  let acc = 0;
  let accLen = 0;
  const mask = (1 << bits) - 1;
  for (const byte of d) {
    acc = (acc << 8) | byte;
    accLen += 8;
    while (accLen >= bits && out.length < count) {
      accLen -= bits;
      let v = (acc >> accLen) & mask;
      if (signed && v >= 1 << (bits - 1)) v -= 1 << bits;
      out.push(v);
    }
    acc &= (1 << accLen) - 1;
  }
  if (out.length !== count) throw new Error('unpackMsb: short input');
  return out;
}
/** FN-DSA draft packing: `bits` per value, least significant bit first. */
function packLsb(vals: number[], bits: number): Uint8Array {
  const out: number[] = [];
  let acc = 0;
  let accLen = 0;
  const mask = (1 << bits) - 1;
  for (const v of vals) {
    acc |= (v & mask) << accLen;
    accLen += bits;
    while (accLen >= 8) { out.push(acc & 0xff); acc >>= 8; accLen -= 8; }
  }
  if (accLen !== 0) throw new Error('packLsb: not byte aligned');
  return Uint8Array.from(out);
}
const shake64 = (x: Uint8Array): Uint8Array => new Uint8Array(createHash('shake256', { outputLength: 64 }).update(x).digest());
const seedFor = (label: string): Uint8Array => new Uint8Array(createHash('shake256', { outputLength: 32 }).update(label).digest());

const Q = 12289;
const mulmod = (a: number, b: number): number => (a * b) % Q; // operands < 2^14, product < 2^28: exact in a double
function powmod(b: number, e: number): number {
  let r = 1;
  let x = b % Q;
  for (let k = e; k > 0; k = Math.floor(k / 2)) {
    if (k % 2 === 1) r = mulmod(r, x);
    x = mulmod(x, x);
  }
  return r;
}
const norm = (c: number): number => ((c % Q) + Q) % Q;
/** p(r) mod q by Horner. */
function evalPoly(p: number[], r: number): number {
  let acc = 0;
  for (let i = p.length - 1; i >= 0; i--) acc = (mulmod(acc, r) + norm(p[i] as number)) % Q;
  return acc;
}
function unpackLsb(d: Uint8Array, count: number, bits: number, signed: boolean): number[] {
  const out: number[] = [];
  let acc = 0;
  let accLen = 0;
  const mask = (1 << bits) - 1;
  for (const byte of d) {
    acc |= byte << accLen;
    accLen += 8;
    while (accLen >= bits && out.length < count) {
      let v = acc & mask;
      if (signed && v >= 1 << (bits - 1)) v -= 1 << bits;
      out.push(v);
      acc >>= bits;
      accLen -= bits;
    }
  }
  return out;
}
/** 11 is a primitive root mod 12289; zeta is a primitive 2n-th root of unity. */
const zetaPow = (logn: number, k: number): number => powmod(powmod(11, (Q - 1) / (2 << logn)), k);

const orderCache = new Map<number, number[]>();
/**
 * The exponent k_i such that the backend's public key coefficient i equals h(zeta^k_i). Calibrated from a key pair
 * the backend generated itself (vk_i = g(r)/f(r) for exactly one root r), so it is the implementation's own order.
 */
function rootOrder(variant: FnDsaVariant, logn: number): number[] {
  const hit = orderCache.get(logn);
  if (hit !== undefined) return hit;
  const n = 1 << logn;
  const fgBits = logn === 9 ? 6 : 5;
  const fgBytes = (n * fgBits) >> 3;
  // Values g(r)/f(r) can collide between roots within one key (birthday effect), so intersect over several keys.
  let candidates: Array<Set<number>> | undefined;
  for (let t = 0; t < 4; t++) {
    const { verifyingKey, signingKey } = keygen(variant, seedFor(`calibrate:${variant}:${t}`));
    const f = unpackLsb(signingKey.subarray(1, 1 + fgBytes), n, fgBits, true);
    const g = unpackLsb(signingKey.subarray(1 + fgBytes, 1 + 2 * fgBytes), n, fgBits, true);
    const h = unpackLsb(verifyingKey.subarray(1), n, 14, false);
    const byValue = new Map<number, number[]>();
    for (let k = 1; k < 2 * n; k += 2) {
      const r = zetaPow(logn, k);
      const v = mulmod(evalPoly(g, r), powmod(evalPoly(f, r), Q - 2));
      byValue.set(v, [...(byValue.get(v) ?? []), k]);
    }
    const here = h.map((x) => new Set(byValue.get(x) ?? []));
    candidates = candidates === undefined ? here : candidates.map((c, i) => new Set([...c].filter((k) => (here[i] as Set<number>).has(k))));
  }
  const order = (candidates as Array<Set<number>>).map((c) => {
    if (c.size !== 1) throw new Error('calibration failed: backend public key is not h at a unique 2n-th root of unity');
    return [...c][0] as number;
  });
  if (new Set(order).size !== n) throw new Error('calibration failed: root order is not a permutation');
  orderCache.set(logn, order);
  return order;
}

function toFnDsaVk(pk: Uint8Array, logn: number, variant: FnDsaVariant): Uint8Array {
  const n = 1 << logn;
  const h = unpackMsb(pk.subarray(1), n, 14, false); // original Falcon: coefficient form, MSB-first
  const ntt = rootOrder(variant, logn).map((k) => evalPoly(h, zetaPow(logn, k)));
  return new Uint8Array([pk[0] as number, ...packLsb(ntt, 14)]);
}
function toFnDsaSk(sk: Uint8Array, fnVk: Uint8Array, logn: number): Uint8Array {
  const n = 1 << logn;
  const fgBits = logn === 9 ? 6 : 5;
  const fgBytes = (n * fgBits) >> 3;
  const f = unpackMsb(sk.subarray(1, 1 + fgBytes), n, fgBits, true);
  const g = unpackMsb(sk.subarray(1 + fgBytes, 1 + 2 * fgBytes), n, fgBits, true);
  const F = unpackMsb(sk.subarray(1 + 2 * fgBytes), n, 8, true);
  return new Uint8Array([sk[0] as number, ...packLsb(f, fgBits), ...packLsb(g, fgBits), ...packLsb(F, 8), ...shake64(fnVk)]);
}

const CASES: Array<{ variant: FnDsaVariant; file: string; logn: number; roundThreeSk: number; roundThreeSig: number; step: number }> = [
  { variant: 'fn-dsa-512', file: 'falcon512-KAT.rsp', logn: 9, roundThreeSk: 1281, roundThreeSig: 690, step: 1 },
  { variant: 'fn-dsa-1024', file: 'falcon1024-KAT.rsp', logn: 10, roundThreeSk: 2305, roundThreeSig: 1330, step: 1 },
];

describe('Falcon round-3 KAT files are the pinned NIST archive contents', () => {
  for (const c of CASES) {
    it(`${c.file}: sha256 matches the archive and holds 100 entries`, () => {
      const meta = prov.files.find((f) => f.file === c.file);
      expect(meta).toBeDefined();
      const raw = readFileSync(join(DIR, c.file));
      expect(createHash('sha256').update(raw).digest('hex')).toBe(meta?.sha256);
      expect(load(c.file)).toHaveLength(meta?.entries ?? -1);
    });
  }
});

for (const c of CASES) {
  const kats = load(c.file);
  const sz = sizes(c.variant);

  describe(`${c.variant}: official Falcon round-3 keys through the FN-DSA backend`, () => {
    it('key sizes and headers line up: round-3 pk == FN-DSA vk size, round-3 sk + 64 B vk hash == FN-DSA sk size', () => {
      for (const k of kats) {
        expect(k.pk.length).toBe(sz.verifyingKey);
        expect(k.pk[0]).toBe(c.logn); // header 0x00 + logn
        expect(k.sk.length).toBe(c.roundThreeSk);
        expect(k.sk[0]).toBe(0x50 + c.logn);
        expect(k.sk.length + 64).toBe(sz.signingKey);
      }
    });

    it(`all ${kats.length} official key pairs: sign with the transcoded secret key, verify under the transcoded ORIGINAL public key`, () => {
      let n = 0;
      for (const k of kats) {
        const vk = toFnDsaVk(k.pk, c.logn, c.variant);
        const fnSk = toFnDsaSk(k.sk, vk, c.logn);
        const msg = k.msg;
        const sig = sign(c.variant, fnSk, msg, seedFor(`${c.variant}:r3:${k.count}`));
        expect(sig.length).toBe(sz.signature);
        expect(verify(c.variant, vk, msg, sig), `count ${k.count}`).toBe(true);
        n++;
      }
      expect(n).toBe(kats.length);
    }, 600_000);

    it('the raw (untranscoded) round-3 encodings are NOT interchangeable: the secret key is refused and the public key does not verify', () => {
      for (const k of kats.slice(0, 10)) {
        const vk = toFnDsaVk(k.pk, c.logn, c.variant);
        const rawSk = new Uint8Array([...k.sk, ...shake64(vk)]);
        expect(() => sign(c.variant, rawSk, k.msg, seedFor('raw'))).toThrow();
        const sig = sign(c.variant, toFnDsaSk(k.sk, vk, c.logn), k.msg, seedFor('raw2'));
        expect(Buffer.from(k.pk).equals(Buffer.from(vk))).toBe(false);
        expect(verify(c.variant, k.pk, k.msg, sig)).toBe(false);
      }
    });

    it('negative: the same signature fails under another official public key, with a modified message, and with a flipped signature bit', () => {
      for (let i = 0; i < 5; i++) {
        const k = kats[i] as Kat;
        const other = kats[i + 1] as Kat;
        const vk = toFnDsaVk(k.pk, c.logn, c.variant);
        const sig = sign(c.variant, toFnDsaSk(k.sk, vk, c.logn), k.msg, seedFor(`${c.variant}:r3neg:${k.count}`));
        expect(verify(c.variant, toFnDsaVk(other.pk, c.logn, c.variant), k.msg, sig)).toBe(false);
        expect(verify(c.variant, vk, new Uint8Array([...k.msg, 0]), sig)).toBe(false);
        const bad = Uint8Array.from(sig);
        bad[sig.length >> 1] = (bad[sig.length >> 1] ?? 0) ^ 0x01;
        expect(verify(c.variant, vk, k.msg, bad)).toBe(false);
      }
    });

    it('a secret key whose appended hash is for a different public key never verifies under the real one', () => {
      const k = kats[0] as Kat;
      const vk = toFnDsaVk(k.pk, c.logn, c.variant);
      const wrong = toFnDsaSk(k.sk, toFnDsaVk((kats[1] as Kat).pk, c.logn, c.variant), c.logn);
      let signed: Uint8Array | undefined;
      try { signed = sign(c.variant, wrong, k.msg, seedFor('wrong-hash')); } catch { signed = undefined; }
      if (signed !== undefined) expect(verify(c.variant, vk, k.msg, signed)).toBe(false);
    });
  });

  describe(`${c.variant}: official Falcon round-3 SIGNATURES are not FN-DSA signatures (documented incompatibility)`, () => {
    it('sm container: 2-byte length, 40-byte nonce, message, then a variable-length compressed signature with the 0x2<logn> header', () => {
      const lens = new Set<number>();
      for (const k of kats) {
        const sigLen = ((k.sm[0] as number) << 8) | (k.sm[1] as number);
        expect(k.sm.length).toBe(2 + 40 + k.msg.length + sigLen);
        expect(Buffer.from(k.sm.subarray(42, 42 + k.msg.length)).equals(Buffer.from(k.msg))).toBe(true);
        const sigStart = 42 + k.msg.length;
        expect(k.sm[sigStart]).toBe(0x20 + c.logn); // original-Falcon "compressed" header; FN-DSA padded signatures use another
        lens.add(sigLen);
      }
      expect(lens.size).toBeGreaterThan(1); // variable length; FN-DSA's signature is fixed at sizes().signature
    });

    it('re-containerised (header + nonce + zero-padded to the FN-DSA length) round-3 signatures are rejected by FN-DSA verify', () => {
      let rejected = 0;
      for (const k of kats.slice(0, 20)) {
        const sigLen = ((k.sm[0] as number) << 8) | (k.sm[1] as number);
        const nonce = k.sm.subarray(2, 42);
        const comp = k.sm.subarray(42 + k.msg.length + 1, 42 + k.msg.length + sigLen);
        const padded = new Uint8Array(sz.signature);
        padded[0] = 0x30 + c.logn;
        padded.set(nonce, 1);
        padded.set(comp, 41);
        if (!verify(c.variant, toFnDsaVk(k.pk, c.logn, c.variant), k.msg, padded)) rejected++;
      }
      // Hash-to-point differs (no vk hash / context in the original), so none can verify.
      expect(rejected).toBe(20);
    });
  });
}
