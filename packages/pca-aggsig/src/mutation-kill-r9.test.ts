/** 0.4.2 mutation kills (Stryker run 39706550807): chain.ts wellTyped accepts plain objects only; a function that carries every field is not a capability. */
import { describe, expect, it } from 'vitest';
import { KeyRegistry, keyGen, popProve } from './bls';
import { aggregateChainSignatures, blsPublicKey, mintBlsRoot, verifyAggregatedChain } from './chain';

describe('wellTyped: only objects', () => {
  const k0 = keyGen(), k1 = keyGen();
  const reg = new KeyRegistry();
  for (const k of [k0, k1]) reg.register(k.publicKey, popProve(k.secretKey));
  const root = mintBlsRoot({ principalSecret: k0.secretKey, principalPublic: blsPublicKey(k0.secretKey), holder: blsPublicKey(k1.secretKey), caveats: [{ type: 'a' }] });
  const agg = aggregateChainSignatures([root]);
  it('the honest single-hop chain verifies', () => {
    expect(verifyAggregatedChain([root], agg, reg)).toMatchObject({ ok: true });
  });
  it('a function carrying every capability field is refused as malformed, like any other non-object', () => {
    const fn = Object.assign(() => undefined, root);
    expect(verifyAggregatedChain([fn] as never, agg, reg)).toEqual({ ok: false, reason: 'hop 0: malformed capability' });
    for (const prim of [5, 'str', true, 7n]) expect(verifyAggregatedChain([prim] as never, agg, reg)).toEqual({ ok: false, reason: 'hop 0: malformed capability' });
  });
});
