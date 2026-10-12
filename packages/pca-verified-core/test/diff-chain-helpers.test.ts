import { describe, expect, it } from 'vitest';
import { holderPqCommitment, pqBindingError } from '../../pca/src/capability';
import { pqBindingError as pqBindingErrorLegacy } from './support/legacy/capability';

// pqBindingError (F-2 binding rule) is now decided by the verified `pqBinding`; the frozen pre-wiring copy is the oracle.
describe('differential: pqBindingError (production, verified core) vs legacy (frozen TS)', () => {
  const algs: unknown[] = [undefined, 'ed25519', 'ml-dsa-65', 'hybrid', 'ml-dsa-87', 'slh-dsa-sha2-128f', 'slh-dsa-sha2-256s', 'bogus', 5, null];
  const pks: unknown[] = [undefined, 'AAAA', 'BBBB', 7, null];
  const committed: Array<string | undefined> = [undefined, holderPqCommitment('AAAA'), holderPqCommitment('CCCC'), ''];
  const policies = [undefined, {}, { allowUnboundPq: true }, { allowUnboundPq: false }];
  it('agrees on the full alg x pq_pk x commitment x policy grid', () => {
    let n = 0;
    let errs = 0;
    for (const alg of algs) for (const pk of pks) for (const c of committed) for (const pol of policies) {
      const a = pqBindingError(alg, pk, c, 'hop 1', pol);
      expect(a).toBe(pqBindingErrorLegacy(alg, pk, c, 'hop 1', pol));
      n++;
      if (a !== undefined) errs++;
    }
    expect(n).toBe(800);
    expect(errs).toBeGreaterThan(50);
  });
});
