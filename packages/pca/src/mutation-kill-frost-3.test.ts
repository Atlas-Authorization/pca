/**
 * Mutation-kill test for frost.ts mulPoint's zero-scalar branch (`v === 0n ? ZERO : multiply(v)`), which only fires when a
 * hash-derived scalar (the challenge c, or a binding factor) is exactly 0 (probability 2^-252 with a real SHA-512). The hash
 * is replaced by an all-zero digest so c = 0 and the binding factor = 0 deterministically; noble's multiply(0) THROWS, so a
 * mulPoint that does not map 0 to the identity makes the verifier wrongly reject a share that satisfies z*B == hiding.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { describe, expect, it, vi } from 'vitest';

const zero = vi.hoisted(() => ({ on: false }));
vi.mock('@noble/hashes/sha512', async (orig) => {
  const m = await orig<typeof import('@noble/hashes/sha512')>();
  const wrapped = ((data: Uint8Array) => (zero.on ? new Uint8Array(64) : m.sha512(data))) as typeof m.sha512;
  return { ...m, sha512: Object.assign(wrapped, m.sha512) };
});

import { frostCommit, frostTrustedDealerKeygen, frostVerifySigShare, scalarToBytes } from './frost';

describe('mulPoint maps the zero scalar to the identity', () => {
  it('frostVerifySigShare accepts z*B == hiding when c = 0 and binding factor = 0 (all-zero hash)', () => {
    const k = frostTrustedDealerKeygen(1, 1);
    const p = k.participantShares[0]!;
    const c = frostCommit(p);
    const h = BigInt('0x' + Array.from(c.hidingNonce.slice().reverse(), (x) => x.toString(16).padStart(2, '0')).join(''));
    zero.on = true;
    try {
      const ok = frostVerifySigShare({
        identifier: p.identifier, publicKey: p.publicKey, commitment: c.commitment,
        sigShare: { identifier: p.identifier, sigShare: scalarToBytes(h) },
        signingCommitments: [c.commitment], groupPublicKey: k.groupPublicKey, message: new Uint8Array([1]),
      });
      expect(ok).toBe(true);
    } finally { zero.on = false; }
    expect(ed25519.ExtendedPoint.BASE.multiply(h).toRawBytes()).toEqual(c.commitment.hiding);
  });
});
