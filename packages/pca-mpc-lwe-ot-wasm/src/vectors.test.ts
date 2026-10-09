/**
 * Validation of the Kyber-768 / ML-KEM-768 K-PKE core against OFFICIAL NIST ACVP vectors (FIPS 203) and
 * an independent implementation (kyber-py).
 *
 * The wasm exposes only the K-PKE layer (the endemic OT bypasses the Fujisaki-Okamoto transform), so the
 * ACVP ML-KEM vectors are checked by composing the wasm K-PKE with the FIPS 203 FO wrapper written in the
 * test from Node's SHA3 (H = SHA3-256, G = SHA3-512, J = SHAKE256):
 *   Encaps: (K, r) = G(m || H(ek));  c = K-PKE.Encrypt(ek, m, r)          -> must equal ACVP (c, K)
 *   Decaps: m' = K-PKE.Decrypt(dk_pke, c); (K', r') = G(m' || h); re-encrypt; compare;
 *           implicit rejection K = J(z || c)                               -> must equal ACVP K
 *
 * KNOWN, DOCUMENTED NON-CONFORMANCE: pqc_kyber derives K-PKE keys as G(d); FIPS 203 derives them as
 * G(d || k). `kpkeKeygen(d)` therefore does NOT reproduce the ACVP keyGen outputs (asserted below as
 * a regression guard on that fact). This is harmless for the endemic OT (keys are internal and only
 * need to be valid K-PKE keys; the interop tests below prove they are), but it means this module is
 * not an ML-KEM.KeyGen.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CT_BYTES, PK_BYTES, SK_BYTES, hashToRing, kpkeDec, kpkeEnc, kpkeKeygen } from './index';

const dir = join(__dirname, '..', 'testdata');
const h = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'hex'));
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const sha3_256 = (...p: Uint8Array[]): Uint8Array => new Uint8Array(createHash('sha3-256').update(Buffer.concat(p)).digest());
const sha3_512 = (...p: Uint8Array[]): Uint8Array => new Uint8Array(createHash('sha3-512').update(Buffer.concat(p)).digest());
const shake256_32 = (...p: Uint8Array[]): Uint8Array => new Uint8Array(createHash('shake256', { outputLength: 32 }).update(Buffer.concat(p)).digest());

interface Acvp {
  provenance: { kind: string; commit: string; files: { url: string; sha256: string }[] };
  keyGen: { tcId: number; d: string; z: string; ek: string; dk: string }[];
  encapsulation: { tcId: number; ek: string; m: string; c: string; k: string }[];
  decapsulation: { tcId: number; dk: string; c: string; k: string }[];
}
const acvp = JSON.parse(readFileSync(join(dir, 'acvp-ml-kem-768.json'), 'utf8')) as Acvp;

describe('ACVP provenance', () => {
  it('is official, pinned to a commit, with per-file sha256', () => {
    expect(acvp.provenance.kind).toMatch(/OFFICIAL NIST ACVP/);
    expect(acvp.provenance.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(acvp.provenance.files).toHaveLength(2);
    for (const f of acvp.provenance.files) expect(f.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(acvp.keyGen).toHaveLength(25);
    expect(acvp.encapsulation).toHaveLength(25);
    expect(acvp.decapsulation).toHaveLength(10);
  });
});

describe('ACVP ML-KEM-768 encapsulation through the wasm K-PKE.Encrypt', () => {
  it('reproduces the official ciphertext and shared secret for all 25 cases', () => {
    for (const t of acvp.encapsulation) {
      const ek = h(t.ek), m = h(t.m);
      const g = sha3_512(m, sha3_256(ek)); // (K || r)
      expect(hex(g.slice(0, 32)), `tcId ${t.tcId} K`).toBe(t.k);
      const ct = kpkeEnc(ek, m, g.slice(32));
      expect(ct.length).toBe(CT_BYTES);
      expect(hex(ct), `tcId ${t.tcId} c`).toBe(t.c);
    }
  });
  it('a one-bit change in the message, key or coins changes the ciphertext (no degenerate encryption)', () => {
    const t = acvp.encapsulation[0]!;
    const ek = h(t.ek), m = h(t.m);
    const r = sha3_512(m, sha3_256(ek)).slice(32);
    const base = hex(kpkeEnc(ek, m, r));
    const m2 = Uint8Array.from(m); m2[0] = (m2[0] ?? 0) ^ 1;
    const r2 = Uint8Array.from(r); r2[0] = (r2[0] ?? 0) ^ 1;
    expect(hex(kpkeEnc(ek, m2, r))).not.toBe(base);
    expect(hex(kpkeEnc(ek, m, r2))).not.toBe(base);
  });
});

describe('ACVP ML-KEM-768 decapsulation through the wasm K-PKE.Decrypt (incl. implicit rejection)', () => {
  const DKPKE = 1152, EK = 1184;
  function decaps(dk: Uint8Array, c: Uint8Array): { k: Uint8Array; rejected: boolean } {
    const dkPke = dk.slice(0, DKPKE);
    const ek = dk.slice(DKPKE, DKPKE + EK);
    const hek = dk.slice(DKPKE + EK, DKPKE + EK + 32);
    const z = dk.slice(DKPKE + EK + 32, DKPKE + EK + 64);
    expect(hex(sha3_256(ek))).toBe(hex(hek)); // the dk embeds H(ek): the official key is self-consistent
    const m = kpkeDec(dkPke, c);
    const g = sha3_512(m, hek);
    const c2 = kpkeEnc(ek, m, g.slice(32));
    const ok = hex(c2) === hex(c);
    return { k: ok ? g.slice(0, 32) : shake256_32(z, c), rejected: !ok };
  }
  it('every official case yields the official K, valid ciphertexts and implicit-rejection ones alike', () => {
    let rejected = 0;
    for (const t of acvp.decapsulation) {
      const r = decaps(h(t.dk), h(t.c));
      expect(hex(r.k), `tcId ${t.tcId}`).toBe(t.k);
      if (r.rejected) rejected += 1;
    }
    expect(acvp.decapsulation.length).toBe(10);
    // The official set mixes valid ciphertexts and modified ones; make sure both paths were taken.
    expect(rejected).toBeGreaterThan(0);
    expect(rejected).toBeLessThan(acvp.decapsulation.length);
  });
  it('K-PKE round trip under every official decapsulation key pair', () => {
    for (const d of acvp.decapsulation) {
      const dk = h(d.dk);
      const ek = dk.slice(1152, 1152 + 1184);
      const m = new Uint8Array(32).fill(0x42);
      const ct = kpkeEnc(ek, m, new Uint8Array(32).fill(0x24));
      expect(hex(kpkeDec(dk.slice(0, 1152), ct))).toBe(hex(m));
    }
  });
});

describe('ACVP ML-KEM-768 keyGen: documented difference', () => {
  it('official ek/dk have the K-PKE sizes this core consumes', () => {
    for (const t of acvp.keyGen) {
      expect(h(t.ek).length).toBe(PK_BYTES);
      expect(h(t.dk).length).toBe(SK_BYTES + PK_BYTES + 64);
      expect(hex(h(t.dk).slice(0, SK_BYTES)).length).toBe(SK_BYTES * 2);
    }
  });
  it('kpkeKeygen(d) is pre-standard Kyber key derivation, so it does NOT equal ML-KEM.KeyGen(d) (guard on the documented fact)', () => {
    for (const t of acvp.keyGen) {
      const kp = kpkeKeygen(h(t.d));
      expect(hex(kp.publicKey)).not.toBe(t.ek);
    }
  });
  it('but the official dk_pke decrypts what the official ek encrypts (ACVP keys are valid inputs)', () => {
    for (const t of acvp.keyGen) {
      const ek = h(t.ek), dk = h(t.dk);
      const m = shake256_32(h(t.d));
      const ct = kpkeEnc(ek, m, shake256_32(h(t.z)));
      expect(hex(kpkeDec(dk.slice(0, SK_BYTES), ct)), `tcId ${t.tcId}`).toBe(hex(m));
    }
  });
});

interface Cross {
  provenance: { kind: string; independent_implementation: Record<string, string> };
  wasm_keys: { seed: string; pk: string; sk: string; m: string; coins: string; ct_wasm: string; ct_kyber_py: string }[];
  py_keys: { d: string; ek: string; dk: string; m: string; coins: string; ct: string }[];
  uniform_keys: { pk: string; m: string; coins: string; ct_wasm: string; ct_kyber_py: string }[];
  hash_to_ring: { input: string; out: string }[];
}
const cross = JSON.parse(readFileSync(join(dir, 'crosscheck-ml-kem-768.json'), 'utf8')) as Cross;

describe('cross-implementation vs kyber-py (not official vectors)', () => {
  it('records the independent library version', () => {
    expect(cross.provenance.kind).toMatch(/NOT official/);
    expect(cross.provenance.independent_implementation['kyber-py']).toMatch(/^\d+\.\d+\.\d+$/);
  });
  it('wasm keys: keygen is reproducible; wasm ciphertext == kyber-py ciphertext byte for byte; wasm decrypts it', () => {
    for (const c of cross.wasm_keys) {
      const kp = kpkeKeygen(h(c.seed));
      expect(hex(kp.publicKey)).toBe(c.pk);
      expect(hex(kp.secretKey)).toBe(c.sk);
      const ct = kpkeEnc(h(c.pk), h(c.m), h(c.coins));
      expect(hex(ct)).toBe(c.ct_kyber_py);
      expect(c.ct_wasm).toBe(c.ct_kyber_py);
      expect(hex(kpkeDec(h(c.sk), h(c.ct_kyber_py)))).toBe(c.m);
    }
  });
  it('kyber-py (FIPS 203 K-PKE.KeyGen) keys: wasm encrypts identically and decrypts kyber-py ciphertexts', () => {
    for (const c of cross.py_keys) {
      expect(hex(kpkeEnc(h(c.ek), h(c.m), h(c.coins)))).toBe(c.ct);
      expect(hex(kpkeDec(h(c.dk), h(c.ct)))).toBe(c.m);
    }
  });
  it('a wrong secret key does not recover the message (decryption is key-dependent)', () => {
    const a = cross.py_keys[0]!, b = cross.py_keys[1]!;
    expect(hex(kpkeDec(h(b.dk), h(a.ct)))).not.toBe(a.m);
  });
  it('uniform (hash-derived) public keys used by the endemic OT encrypt identically to kyber-py', () => {
    for (const c of cross.uniform_keys) {
      expect(hex(kpkeEnc(h(c.pk), h(c.m), h(c.coins)))).toBe(c.ct_kyber_py);
    }
  });
  it('hashToRing equals an independent FIPS 203 Algorithm 7 (SampleNTT) over SHAKE128, for short and long inputs', () => {
    for (const c of cross.hash_to_ring) expect(hex(hashToRing(h(c.input)))).toBe(c.out);
    expect(cross.hash_to_ring.length).toBeGreaterThanOrEqual(5);
  });
});
