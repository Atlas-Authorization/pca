/** Round-2 SECURITY: noble's G1/G2 parsers accept non-reduced coordinates (x + p). Each BBS element must have exactly one encoding. */
import { bls12_381 } from '@noble/curves/bls12-381';
import { describe, expect, it } from 'vitest';
import { generateKeyPair, proofGen, proofVerify, sign, skToPk, verify } from './bbs';

const P = bls12_381.fields.Fp.ORDER;
const num = (b: Uint8Array): bigint => { let n = 0n; for (const x of b) n = (n << 8n) | BigInt(x); return n; };
const be48 = (v: bigint): Uint8Array => { const b = new Uint8Array(48); for (let i = 47; i >= 0; i--, v >>= 8n) b[i] = Number(v & 0xffn); return b; };
const enc = (s: string) => new TextEncoder().encode(s);

/** x + p for a compressed G1 point (flags kept), or null when it would not fit in 381 bits. */
function aliasG1(pt: Uint8Array): Uint8Array | null {
  const x = num(Uint8Array.from([pt[0]! & 0x1f, ...pt.subarray(1)])) + P;
  if (x >> 381n !== 0n) return null;
  const a = be48(x);
  a[0]! |= pt[0]! & 0xe0;
  return a;
}

describe('r2: BBS elements have exactly one encoding', () => {
  const msgs = [enc('a'), enc('b'), enc('c')];
  it('a signature whose A is encoded as x + p is refused', () => {
    const kp = generateKeyPair();
    for (let n = 0; n < 60; n++) {
      const h = enc('h' + n);
      const sig = sign(kp.sk, kp.pk, h, msgs);
      expect(verify(kp.pk, sig, h, msgs)).toBe(true);
      const alias = aliasG1(sig.subarray(0, 48));
      if (alias === null) continue;
      const bad = Uint8Array.from(sig); bad.set(alias, 0);
      expect(verify(kp.pk, bad, h, msgs)).toBe(false);
      return;
    }
    throw new Error('no aliasable signature found');
  });
  it('a proof whose points are encoded as x + p is refused', () => {
    const kp = generateKeyPair();
    const sig = sign(kp.sk, kp.pk, enc('h'), msgs);
    let done = 0;
    for (let n = 0; n < 80 && done < 3; n++) {
      const proof = proofGen(kp.pk, sig, enc('h'), enc('ph'), msgs, [0]);
      expect(proofVerify(kp.pk, proof, enc('h'), enc('ph'), [msgs[0]!], [0])).toBe(true);
      for (const o of [0, 48, 96]) {
        const alias = aliasG1(proof.subarray(o, o + 48));
        if (alias === null) continue;
        const bad = Uint8Array.from(proof); bad.set(alias, o);
        expect(proofVerify(kp.pk, bad, enc('h'), enc('ph'), [msgs[0]!], [0])).toBe(false);
        done++;
      }
    }
    expect(done).toBeGreaterThan(0);
  });
  it('a public key whose G2 x.c0 is encoded as c0 + p is refused (a second identity for one issuer)', () => {
    const kp = generateKeyPair();
    const alias = Uint8Array.from(kp.pk);
    alias.set(be48(num(kp.pk.subarray(48)) + P), 48);
    expect(skToPk(kp.sk)).toEqual(kp.pk);
    const h = enc('h');
    // the issuer signs bound to the aliased key bytes (the domain hashes the key octets)
    let sig: Uint8Array | undefined;
    try { sig = sign(kp.sk, alias, h, msgs); } catch { /* refusing at sign time is fine too */ }
    if (sig !== undefined) expect(verify(alias, sig, h, msgs)).toBe(false);
  });
});
