// 0.4.2 mutation kill (Stryker run 39706550807): a share whose pq_pk is not the one its role registers is refused with the reason
// `pq-pk-mismatch` (and the share index), distinct from `invalid-sig`; it never counts.
import { describe, expect, it } from 'vitest';
import { decideThreshold } from '../src/threshold';

describe('decideThreshold reasons', () => {
  const signers = [
    { role: 'agent' as const, keyOk: true, pqOk: true, key: 'A' },
    { role: 'guardian' as const, keyOk: true, pqOk: true, key: 'G' },
  ];
  const sh = (key: string, over: Record<string, unknown> = {}) => ({ wellFormed: true, role: key === 'A' ? ('agent' as const) : ('guardian' as const), key, algKnown: true, pqPkOk: true, sigOk: () => true, ...over });
  it('pqPkOk=false: pq-pk-mismatch at that share, nothing counted', () => {
    const r = decideThreshold(signers, [sh('A', { pqPkOk: false })], 1);
    expect(r).toMatchObject({ ok: false, count: 0, roles: [], reason: { kind: 'pq-pk-mismatch', share: 0 } });
  });
  it('the mismatch is reported for the share that has it, and it is not confused with a bad signature', () => {
    expect(decideThreshold(signers, [sh('A'), sh('G', { pqPkOk: false })], 2)).toMatchObject({ ok: false, count: 1, reason: { kind: 'pq-pk-mismatch', share: 1 } });
    expect(decideThreshold(signers, [sh('A'), sh('G', { sigOk: () => false })], 2)).toMatchObject({ ok: false, count: 1, reason: { kind: 'invalid-sig', share: 1 } });
  });
});
