/**
 * Site kills for the per-site ledger migration:
 *  - chain.ts:186 (the wellTyped loop) refuses a null hop with its reason instead of throwing;
 *  - chain.ts:200 (the per-hop loop) is what fills the key/message lists: the honest chain verifies, and a broken
 *    parent link is refused with its own reason;
 *  - core.ts:172 / :190 (the KeyValidate loops) refuse an x + p aliased public key that noble itself would accept.
 */
import { bls12_381 } from '@noble/curves/bls12-381';
import { describe, expect, it } from 'vitest';
import { KeyRegistry, keyGen, popProve } from './bls';
import { aggregateVerify, fastAggregateVerify, keyValidate, sign } from './core';
import { aggregateChainSignatures, blsDelegate, blsPublicKey, mintBlsRoot, verifyAggregatedChain } from './chain';

const P = bls12_381.fields.Fp.ORDER;
const be48 = (v: bigint): Uint8Array => { const b = new Uint8Array(48); for (let i = 47; i >= 0; i--, v >>= 8n) b[i] = Number(v & 0xffn); return b; };
const num = (b: Uint8Array): bigint => { let n = 0n; for (const x of b) n = (n << 8n) | BigInt(x); return n; };
function aliasedKey(): { sk: Uint8Array; pk: Uint8Array; alias: Uint8Array } {
  for (let n = 0; n < 400; n++) {
    const k = keyGen();
    const flags = k.publicKey[0]! & 0xe0;
    const xx = num(Uint8Array.from([k.publicKey[0]! & 0x1f, ...k.publicKey.subarray(1)])) + P;
    if (xx >> 381n !== 0n) continue;
    const alias = be48(xx);
    alias[0]! |= flags;
    return { sk: k.secretKey, pk: k.publicKey, alias };
  }
  throw new Error('no aliasable key found');
}

describe('aggregated chain loops', () => {
  const k0 = keyGen(), k1 = keyGen(), k2 = keyGen();
  const reg = new KeyRegistry();
  for (const k of [k0, k1, k2]) reg.register(k.publicKey, popProve(k.secretKey));
  const pub = (k: { secretKey: Uint8Array }) => blsPublicKey(k.secretKey);
  const root = mintBlsRoot({ principalSecret: k0.secretKey, principalPublic: pub(k0), holder: pub(k1), caveats: [{ type: 'a' }] });
  const c1 = blsDelegate(root, pub(k2), [{ type: 'b' }], k1.secretKey);
  const agg = aggregateChainSignatures([root, c1]);
  it('a null hop is refused by the wellTyped loop (no TypeError escapes)', () => {
    expect(verifyAggregatedChain([null] as never, agg, reg)).toEqual({ ok: false, reason: 'hop 0: malformed capability' });
    expect(verifyAggregatedChain([root, null] as never, agg, reg)).toEqual({ ok: false, reason: 'hop 1: malformed capability' });
  });
  it('the per-hop loop: honest chain verifies; a broken parent link has its own reason', () => {
    expect(verifyAggregatedChain([root, c1], agg, reg)).toEqual({ ok: true });
    const other = mintBlsRoot({ principalSecret: k0.secretKey, principalPublic: pub(k0), holder: pub(k1), caveats: [{ type: 'z' }] });
    const orphan = blsDelegate(other, pub(k2), [], k1.secretKey);
    expect(verifyAggregatedChain([root, orphan], aggregateChainSignatures([root, orphan]), reg)).toEqual({ ok: false, reason: 'hop 1: broken parent link' });
  });
});

describe('raw AggregateVerify / FastAggregateVerify KeyValidate every key', () => {
  it('an x + p aliased key with a valid signature is refused by both', () => {
    const { sk, pk, alias } = aliasedKey();
    const msg = new TextEncoder().encode('m');
    const sig = sign(sk, msg);
    expect(keyValidate(alias)).toBe(false);
    // noble itself accepts the alias: only the KeyValidate loop stands in the way
    expect(bls12_381.verify(sig, msg, alias, { DST: 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_' })).toBe(true);
    expect(aggregateVerify([pk], [msg], sig)).toBe(true);
    expect(aggregateVerify([alias], [msg], sig)).toBe(false);
    expect(fastAggregateVerify([pk], msg, sig)).toBe(true);
    expect(fastAggregateVerify([alias], msg, sig)).toBe(false);
  });
});
