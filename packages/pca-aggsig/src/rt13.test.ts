import { describe, expect, it } from 'vitest';
import { KeyRegistry, aggregate, fastAggregateVerify, keyGen, popProve, registerKey, sign } from './bls';
import { aggregateChainSignatures, blsDelegate, blsPublicKey, capHash, mintBlsRoot, verifyAggregatedChain } from './chain';

describe('RT-13 hop sig field', () => {
  const P = keyGen();
  const H = keyGen();
  const reg = new KeyRegistry();
  reg.register(P.publicKey, popProve(P.secretKey));
  const root = mintBlsRoot({ principalSecret: P.secretKey, principalPublic: blsPublicKey(P.secretKey), holder: blsPublicKey(H.secretKey), caveats: [{ type: 'scope', value: 'x' }] });
  const agg = aggregateChainSignatures([root]);

  it('honest chain verifies', () => {
    expect(verifyAggregatedChain([root], agg, reg).ok).toBe(true);
  });
  it('a junk / empty / non-base64 leaf sig is rejected (previously accepted)', () => {
    for (const junk of ['AAAA', 'not-even-base64!!', '']) {
      expect(verifyAggregatedChain([{ ...root, sig: junk }], agg, reg).ok).toBe(false);
    }
  });
  it('a different valid-looking sig that does not sum to the aggregate is rejected', () => {
    const other = mintBlsRoot({ principalSecret: P.secretKey, principalPublic: blsPublicKey(P.secretKey), holder: blsPublicKey(H.secretKey), caveats: [{ type: 'scope', value: 'y' }] });
    expect(verifyAggregatedChain([{ ...root, sig: other.sig }], agg, reg).ok).toBe(false);
  });
  it('capHash does not depend on sig, so sig cannot mint identities', () => {
    expect(capHash({ ...root, sig: 'AAAA' })).toBe(capHash(root));
  });
  it('a delegated chain still verifies and links by the sig-free hash', () => {
    const reg2 = new KeyRegistry();
    reg2.register(P.publicKey, popProve(P.secretKey));
    reg2.register(H.publicKey, popProve(H.secretKey));
    const child = blsDelegate(root, blsPublicKey(keyGen().secretKey), [{ type: 'scope', value: 'z' }], H.secretKey);
    const chain = [root, child];
    expect(verifyAggregatedChain(chain, aggregateChainSignatures(chain), reg2).ok).toBe(true);
  });
});

describe('RT-13 duplicate keys', () => {
  it('fastAggregateVerify refuses one registered key repeated', () => {
    const W = keyGen();
    const rk = registerKey(W.publicKey, popProve(W.secretKey));
    if (!rk.ok) throw new Error('reg');
    const msg = new TextEncoder().encode('sth');
    const s = sign(W.secretKey, msg);
    expect(fastAggregateVerify([rk.key], msg, s)).toBe(true);
    expect(fastAggregateVerify([rk.key, rk.key, rk.key], msg, aggregate([s, s, s]))).toBe(false);
  });
});
