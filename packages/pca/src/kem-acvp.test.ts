import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { ml_kem1024, ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { describe, expect, it } from 'vitest';
import {
  XWING_LABEL,
  hybridDecapsulate,
  hybridDecapsulate1024,
  hybridEncapsulate,
  hybridEncapsulate1024,
  mlKemDecapsulationKeyCheck,
  mlKemEncapsulationKeyCheck,
  xwingEncapsulateDerand,
} from './kem';

// NIST ACVP ML-KEM (FIPS 203) vectors for ML-KEM-768 and ML-KEM-1024, from the public ACVP-Server repository
// (source commit and file digests are recorded in the fixture). They are NIST's expected answers, independent of this code.
type Hex = string;
interface ParamSet {
  keyGen: { tcId: number; d: Hex; z: Hex; ek: Hex; dk: Hex }[];
  encap: { tcId: number; ek: Hex; m: Hex; c: Hex; k: Hex; dk?: Hex }[];
  decap: { tcId: number; dk: Hex; c: Hex; k: Hex; reason: string }[];
  dkCheck: { tcId: number; dk: Hex; passed: boolean; reason: string }[];
  ekCheck: { tcId: number; ek: Hex; passed: boolean; reason: string }[];
}
const fx = JSON.parse(readFileSync(resolve(__dirname, '../testdata/kem-kat/mlkem-acvp.json'), 'utf8')) as {
  source: { repository: string; commit: string; files_sha256: Record<string, string> };
  sets: Record<'ML-KEM-768' | 'ML-KEM-1024', ParamSet>;
};
const hex = (s: string) => Uint8Array.from(Buffer.from(s, 'hex'));
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const cat = (...p: Uint8Array[]) => Uint8Array.from(p.flatMap((x) => [...x]));
const eq = (a: Uint8Array, b: string) => toHex(a) === b.toLowerCase();

const XPRIV = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const XPUB = x25519.getPublicKey(XPRIV);
const EPH = Uint8Array.from({ length: 32 }, (_, i) => 0x80 + i);
const EPHPUB = x25519.getPublicKey(EPH);
const ssX = x25519.getSharedSecret(EPH, XPUB);

// the two hybrid combiners, restated from their wire definitions (domain-separated HKDF over ss_mlkem || ss_x25519 || ct_x || pk_x)
const combine = (domain: string, ssM: Uint8Array) =>
  toHex(hkdf(sha256, cat(ssM, ssX, EPHPUB, XPUB), undefined, new TextEncoder().encode(domain), 32));

const levels = [
  { name: 'ML-KEM-768' as const, n: 768 as const, ml: ml_kem768, domain: 'atlas-pca/kem/x25519-ml-kem-768/v1\0', dec: hybridDecapsulate, enc: hybridEncapsulate },
  { name: 'ML-KEM-1024' as const, n: 1024 as const, ml: ml_kem1024, domain: 'atlas-pca/kem/x25519-ml-kem-1024/v1\0', dec: hybridDecapsulate1024, enc: hybridEncapsulate1024 },
];

describe('ACVP fixture provenance', () => {
  it('names the NIST repository, a 40-hex commit and the digests of the full source files', () => {
    expect(fx.source.repository).toBe('usnistgov/ACVP-Server');
    expect(fx.source.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(Object.keys(fx.source.files_sha256)).toHaveLength(2);
    for (const d of Object.values(fx.source.files_sha256)) expect(d).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe.each(levels)('ACVP $name', ({ name, n, ml, domain, dec, enc }) => {
  const set = fx.sets[name];

  it('key generation: (d, z) reproduces the NIST encapsulation and decapsulation keys byte for byte', () => {
    expect(set.keyGen).toHaveLength(10);
    for (const t of set.keyGen) {
      const k = ml.keygen(hex(t.d + t.z));
      expect(eq(k.publicKey, t.ek), `tcId ${t.tcId} ek`).toBe(true);
      expect(eq(k.secretKey, t.dk), `tcId ${t.tcId} dk`).toBe(true);
    }
  });

  it('encapsulation: the primitive PCA wraps returns the NIST ciphertext and shared secret for the NIST message', () => {
    for (const t of set.encap) {
      const r = ml.encapsulate(hex(t.ek), hex(t.m));
      expect(eq(r.cipherText, t.c), `tcId ${t.tcId} c`).toBe(true);
      expect(eq(r.sharedSecret, t.k), `tcId ${t.tcId} k`).toBe(true);
    }
  });

  it('the hybrid encapsulate / decapsulate path round-trips under NIST-generated keys', () => {
    for (const t of set.encap.filter((x) => x.dk)) {
      const e = enc(cat(XPUB, hex(t.ek)));
      expect(toHex(dec(e.ciphertext, cat(XPRIV, hex(t.dk!))))).toBe(toHex(e.sharedSecret));
    }
  });

  it('hybrid decapsulation: a valid NIST ciphertext yields the NIST secret; a modified one yields the NIST implicit-rejection secret (exact)', () => {
    expect(set.decap.some((t) => t.reason === 'valid decapsulation')).toBe(true);
    expect(set.decap.some((t) => t.reason === 'modified ciphertext')).toBe(true);
    for (const t of set.decap) {
      const out = dec(cat(EPHPUB, hex(t.c)), cat(XPRIV, hex(t.dk)));
      expect(toHex(out), `tcId ${t.tcId} (${t.reason})`).toBe(combine(domain, hex(t.k)));
    }
  });

  it('the implicit-rejection secret differs from the valid one: a modified ciphertext never returns the real secret', () => {
    const t = set.encap.find((x) => x.dk)!;
    const good = dec(cat(EPHPUB, hex(t.c)), cat(XPRIV, hex(t.dk!)));
    const bad = hex(t.c);
    bad[5] = bad[5]! ^ 1;
    const out = dec(cat(EPHPUB, bad), cat(XPRIV, hex(t.dk!)));
    expect(out).toHaveLength(32);
    expect(toHex(out)).not.toBe(toHex(good));
  });

  it('decapsulation-key check (FIPS 203 §7.3): accepts every NIST valid key and rejects every key with a modified H(ek)', () => {
    expect(set.dkCheck.filter((t) => t.passed)).toHaveLength(5);
    expect(set.dkCheck.filter((t) => !t.passed)).toHaveLength(5);
    for (const t of set.dkCheck) expect(mlKemDecapsulationKeyCheck(n, hex(t.dk)), `tcId ${t.tcId} (${t.reason})`).toBe(t.passed);
  });

  it('encapsulation-key check (FIPS 203 §7.2): accepts every NIST valid key and rejects every non-reduced one; encapsulation refuses the same keys', () => {
    expect(set.ekCheck.filter((t) => !t.passed)).toHaveLength(5);
    for (const t of set.ekCheck) {
      expect(mlKemEncapsulationKeyCheck(n, hex(t.ek)), `tcId ${t.tcId} (${t.reason})`).toBe(t.passed);
      if (!t.passed) expect(() => enc(cat(XPUB, hex(t.ek))), `tcId ${t.tcId}`).toThrow(/modulus/);
    }
  });

  it('the key checks reject wrong lengths and non-byte input and never throw', () => {
    const t = set.keyGen[0]!;
    for (const len of [0, 1, hex(t.ek).length - 1, hex(t.ek).length + 1]) expect(mlKemEncapsulationKeyCheck(n, new Uint8Array(len))).toBe(false);
    for (const len of [0, 1, hex(t.dk).length - 1, hex(t.dk).length + 1]) expect(mlKemDecapsulationKeyCheck(n, new Uint8Array(len))).toBe(false);
    expect(mlKemEncapsulationKeyCheck(n, 'x' as never)).toBe(false);
    expect(mlKemDecapsulationKeyCheck(n, null as never)).toBe(false);
    // a flipped bit inside the embedded ek breaks H(ek)
    const dk = hex(t.dk);
    dk[(n === 768 ? 3 : 4) * 384 + 7] ^= 1;
    expect(mlKemDecapsulationKeyCheck(n, dk)).toBe(false);
    // the untouched generated key passes both
    expect(mlKemEncapsulationKeyCheck(n, hex(t.ek))).toBe(true);
    expect(mlKemDecapsulationKeyCheck(n, hex(t.dk))).toBe(true);
  });
});

describe('ACVP ML-KEM-768 through X-Wing (the standard hybrid built on it)', () => {
  const set = fx.sets['ML-KEM-768'];
  it('the derandomized X-Wing encapsulation carries the NIST ML-KEM ciphertext and combines the NIST shared secret', () => {
    for (const t of set.encap) {
      const ekX = Uint8Array.from({ length: 32 }, (_, i) => 0x40 + i);
      const r = xwingEncapsulateDerand(cat(hex(t.ek), XPUB), cat(hex(t.m), ekX));
      const ctX = x25519.getPublicKey(ekX);
      expect(eq(r.ciphertext.subarray(0, r.ciphertext.length - 32), t.c), `tcId ${t.tcId} ct`).toBe(true);
      expect(toHex(r.ciphertext.subarray(r.ciphertext.length - 32))).toBe(toHex(ctX));
      const want = sha3_256(cat(hex(t.k), x25519.getSharedSecret(ekX, XPUB), ctX, XPUB, XWING_LABEL));
      expect(toHex(r.sharedSecret), `tcId ${t.tcId} ss`).toBe(toHex(want));
    }
  });

  it('X-Wing encapsulation refuses a NIST non-reduced encapsulation key', () => {
    const bad = set.ekCheck.find((t) => !t.passed)!;
    expect(() => xwingEncapsulateDerand(cat(hex(bad.ek), XPUB), new Uint8Array(64))).toThrow(/modulus/);
  });
});
