// R6-ALIAS-07: frostAggregate must verify EVERY signature share against its verification share before aggregating.
// Without verificationShares a share z_i + L (a second encoding of the same scalar) was reduced and aggregated, and an
// invalid share was only noticed (unattributed) by the final group-signature check.
import { describe, expect, it } from 'vitest';
import { utf8 } from './hash';
import { verify } from './keys';
import {
  frostAggregate,
  frostCommit,
  frostSign,
  frostTrustedDealerKeygen,
  type FrostCommitment,
  type FrostSignatureShare,
} from './frost';

const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const le = (x: bigint) => {
  const o = new Uint8Array(32);
  for (let i = 0; i < 32; i++) o[i] = Number((x >> BigInt(8 * i)) & 0xffn);
  return o;
};
const fromLe = (b: Uint8Array) => b.reduceRight((acc, v) => (acc << 8n) | BigInt(v), 0n);

function round(signerIds: number[]) {
  const kg = frostTrustedDealerKeygen(2, 3);
  const msg = utf8('r6 frost alias');
  const shares = new Map(kg.participantShares.map((s) => [s.identifier, s]));
  const commits = signerIds.map((id) => frostCommit(shares.get(id)!));
  const commitments: FrostCommitment[] = commits.map((c) => c.commitment);
  const sigShares: FrostSignatureShare[] = signerIds.map((id, i) =>
    frostSign(id, shares.get(id)!.share, kg.groupPublicKey, { hiding: commits[i]!.hidingNonce, binding: commits[i]!.bindingNonce }, msg, commitments),
  );
  const vss = kg.participantShares.map((p) => ({ identifier: p.identifier, publicKey: p.publicKey }));
  return { kg, msg, commitments, sigShares, vss };
}

describe('R6-ALIAS-07 frostAggregate verifies every share', () => {
  it('verificationShares are required', () => {
    const r = round([1, 3]);
    expect(() => (frostAggregate as (...a: unknown[]) => Uint8Array)(r.msg, r.commitments, r.sigShares, r.kg.groupPublicKey)).toThrow(/verificationShares are required/);
    expect(() => frostAggregate(r.msg, r.commitments, r.sigShares, r.kg.groupPublicKey, { threshold: 2 } as never)).toThrow(/verificationShares are required/);
  });
  it('a share re-encoded as z + L is refused and the participant is named', () => {
    const r = round([1, 3]);
    const z = fromLe(r.sigShares[1]!.sigShare);
    expect(z + L < 2n ** 256n).toBe(true);
    const aliased = [r.sigShares[0]!, { identifier: r.sigShares[1]!.identifier, sigShare: le(z + L) }];
    expect(() => frostAggregate(r.msg, r.commitments, aliased, r.kg.groupPublicKey, { verificationShares: r.vss })).toThrow(/participant 3/);
  });
  it('the honest round still aggregates to a valid group signature', () => {
    const r = round([1, 3]);
    const sig = frostAggregate(r.msg, r.commitments, r.sigShares, r.kg.groupPublicKey, { verificationShares: r.vss });
    expect(verify(r.kg.groupPublicKey, r.msg, sig)).toBe(true);
  });
});
