import { describe, expect, it } from 'vitest';
import * as pq from '../../pca/src/pq';
import { holderPqCommitment } from '../../pca/src/capability';
import { pqResolve } from '../src';

/** Literal transcription of the R3-01 choke point's decision structure (pq.ts: resolvePqVerifyKey) over booleans. */
function reference(f: { trusted: boolean; artifactKeyOk: boolean; pinPresent: boolean; pinEquals: boolean; commitPresent: boolean; commitMatches: boolean; allowUnbound: boolean }) {
  if (f.trusted) return 'trusted';
  if (!f.artifactKeyOk) return 'refused';
  if (f.pinPresent) return f.pinEquals ? 'pinned' : 'refused';
  if (f.commitPresent && f.commitMatches) return 'committed';
  if (f.allowUnbound) return 'unbound';
  return 'refused';
}

describe('PQ key authority decision (R2-01 / R3-01)', () => {
  it('matches the reference on the full 2^7 truth table', () => {
    for (let m = 0; m < 128; m++) {
      const f = { trusted: !!(m & 1), artifactKeyOk: !!(m & 2), pinPresent: !!(m & 4), pinEquals: !!(m & 8), commitPresent: !!(m & 16), commitMatches: !!(m & 32), allowUnbound: !!(m & 64) };
      expect(pqResolve(f)).toBe(reference(f));
    }
  });

  // The real choke point (R3-01) agrees on every input combination.
  const real = (pq as unknown as { resolvePqVerifyKey: (id: string, pk: unknown, src?: Record<string, unknown>) => unknown }).resolvePqVerifyKey;
  it('agrees with the real resolvePqVerifyKey on realised inputs', () => {
    const PK = 'AAAA-artifact-key';
    for (let m = 0; m < 128; m++) {
      const f = { trusted: !!(m & 1), artifactKeyOk: !!(m & 2), pinPresent: !!(m & 4), pinEquals: !!(m & 8), commitPresent: !!(m & 16), commitMatches: !!(m & 32), allowUnbound: !!(m & 64) };
      const src: Record<string, unknown> = { allowUnboundPq: f.allowUnbound };
      if (f.trusted) src.trustedPk = 'TRUSTED';
      if (f.pinPresent) src.pqPins = { ident: f.pinEquals ? PK : 'OTHER' };
      if (f.commitPresent) src.holderPq = f.commitMatches ? holderPqCommitment(PK) : 'WRONG';
      const got = real('ident', f.artifactKeyOk ? PK : undefined, src);
      // an unusable combination (pin equal but no artifact key) is a refusal in both
      expect(got !== null, JSON.stringify(f)).toBe(pqResolve(f) !== 'refused');
    }
  });
});
