import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { checkStatement, signStatement, verifyStatement } from './index';

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/** The (r, n-s) twin of an ES256 COSE_Sign1: the signature is the final 64 bytes of the statement. */
function flipS(statement: Uint8Array): Uint8Array {
  const out = statement.slice();
  const s = BigInt(`0x${Buffer.from(out.subarray(out.length - 32)).toString('hex')}`);
  out.set(Buffer.from((N - s).toString(16).padStart(64, '0'), 'hex'), out.length - 32);
  return out;
}

describe('ES256 statements are low-S canonical (no second leaf from signature malleation)', () => {
  it('signStatement always emits low-S; the (r, n-s) twin is rejected with a typed reason', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    for (let i = 0; i < 40; i++) {
      const st = signStatement({ i }, { alg: 'ES256', key: privateKey, issuer: 'agent://es' });
      expect(checkStatement(st, publicKey)).toEqual({ ok: true });
      const twin = flipS(st);
      expect(Buffer.from(twin).equals(Buffer.from(st))).toBe(false);
      expect(checkStatement(twin, publicKey)).toEqual({ ok: false, reason: 'non-canonical signature (high-S)' });
      expect(verifyStatement(twin, publicKey)).toBe(false);
      // The explicit legacy opt-in still verifies the twin (it IS a valid ECDSA signature).
      expect(verifyStatement(twin, publicKey, { allowHighS: true })).toBe(true);
    }
  });
  it('a corrupted signature is still just "bad signature"', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const st = signStatement({ a: 1 }, { alg: 'ES256', key: privateKey, issuer: 'agent://es' });
    const bad = st.slice();
    bad[bad.length - 1] = (bad[bad.length - 1] ?? 0) ^ 1;
    expect(checkStatement(bad, publicKey)).toEqual({ ok: false, reason: 'bad signature' });
  });
});
