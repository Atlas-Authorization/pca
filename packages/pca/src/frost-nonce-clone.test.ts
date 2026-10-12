import { describe, expect, it } from 'vitest';
import { frostCommit, frostSign, frostTrustedDealerKeygen } from './frost';
import { utf8 } from './hash';

// RT-14: the nonce one-shot guard must track the nonce by CONTENT, not by array identity.
describe('FROST nonce single-use is content-based', () => {
  const kg = frostTrustedDealerKeygen(2, 3);
  const s1 = kg.participantShares[0]!;
  const s2 = kg.participantShares[1]!;

  it('a byte-clone of spent nonces is refused for a second message', () => {
    const c1 = frostCommit(s1);
    const c2 = frostCommit(s2);
    const commits = [c1.commitment, c2.commitment];
    const clone = { hiding: Uint8Array.from(c1.hidingNonce), binding: Uint8Array.from(c1.bindingNonce) };
    frostSign(s1.identifier, s1.share, kg.groupPublicKey, { hiding: c1.hidingNonce, binding: c1.bindingNonce }, utf8('transfer 1'), commits);
    expect(() => frostSign(s1.identifier, s1.share, kg.groupPublicKey, clone, utf8('transfer 999999'), commits)).toThrow(/already used/);
  });
  it('a clone taken before the first signing is also refused after the original signs', () => {
    const c1 = frostCommit(s1);
    const c2 = frostCommit(s2);
    const commits = [c1.commitment, c2.commitment];
    const persisted = structuredClone({ hiding: c1.hidingNonce, binding: c1.bindingNonce });
    frostSign(s1.identifier, s1.share, kg.groupPublicKey, { hiding: c1.hidingNonce, binding: c1.bindingNonce }, utf8('a'), commits);
    expect(() => frostSign(s1.identifier, s1.share, kg.groupPublicKey, persisted, utf8('b'), commits)).toThrow(/already used/);
  });
  it('fresh nonces still sign', () => {
    const c1 = frostCommit(s1);
    const c2 = frostCommit(s2);
    expect(() => frostSign(s1.identifier, s1.share, kg.groupPublicKey, { hiding: c1.hidingNonce, binding: c1.bindingNonce }, utf8('c'), [c1.commitment, c2.commitment])).not.toThrow();
  });
});
