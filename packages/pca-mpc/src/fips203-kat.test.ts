import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { kpkeDec, kpkeEnc, kpkeKeygenFips203, PK_BYTES, SK_BYTES } from './endemic-ot';

// Official NIST ACVP ML-KEM-768 keyGen vectors (FIPS 203), shipped with the lattice core package.
interface KeyGenCase { tcId: number; d: string; z: string; ek: string; dk: string }
const acvp = JSON.parse(
  readFileSync(join(__dirname, '..', '..', 'pca-mpc-lwe-ot-wasm', 'testdata', 'acvp-ml-kem-768.json'), 'utf8'),
) as { keyGen: KeyGenCase[] };
const h = (x: string): Uint8Array => Uint8Array.from(Buffer.from(x, 'hex'));

describe('kpkeKeygenFips203 is FIPS 203 K-PKE.KeyGen', () => {
  it('reproduces the official ek and dk_pke for every ACVP keyGen case', () => {
    expect(acvp.keyGen.length).toBeGreaterThanOrEqual(25);
    for (const t of acvp.keyGen) {
      const kp = kpkeKeygenFips203(h(t.d));
      expect(Buffer.from(kp.publicKey).toString('hex'), `tcId ${t.tcId} ek`).toBe(t.ek);
      expect(Buffer.from(kp.secretKey).toString('hex'), `tcId ${t.tcId} dk_pke`).toBe(t.dk.slice(0, SK_BYTES * 2));
      expect(kp.publicKey.length).toBe(PK_BYTES);
    }
  });
  it('a key it produces round-trips through the wasm K-PKE encrypt/decrypt', () => {
    const kp = kpkeKeygenFips203(new Uint8Array(32).fill(7));
    const m = new Uint8Array(32).fill(0x5a);
    expect(kpkeDec(kp.secretKey, kpkeEnc(kp.publicKey, m, new Uint8Array(32).fill(1)))).toEqual(m);
  });
  it('fails closed on a seed of the wrong length or type', () => {
    for (const bad of [new Uint8Array(0), new Uint8Array(31), new Uint8Array(33), 'x' as unknown as Uint8Array]) {
      expect(() => kpkeKeygenFips203(bad)).toThrow(/exactly 32 bytes/);
    }
  });
});
