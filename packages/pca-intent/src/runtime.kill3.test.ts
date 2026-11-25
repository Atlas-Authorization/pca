import { describe, expect, it } from 'vitest';
import { hashCanonical } from '@atlasauth/pca';
import type { NumDim, VerbSpace } from './omega';
import { pcactnActionOf } from './runtime';

const AMT = 'action.params.amount';
const dim: NumDim = { kind: 'num', path: AMT, lo: 0, hi: 100, cuts: [], dist: 'uniform' };
const vs: VerbSpace = { verb: 'r.v', reversibility: 'rate_limited', weight: 1, dims: [dim] };

describe('pcactnActionOf', () => {
  it('commits the verb, resource, canonical params digest and reversibility class', () => {
    expect(pcactnActionOf(vs, { verb: 'r.v', values: { [AMT]: 5, 'action.resource': 'acct/1' } })).toEqual({
      verb: 'r.v',
      resource: 'acct/1',
      params_digest: hashCanonical({ amount: 5 }),
      reversibility_class: 'rate_limited',
    });
  });
  it('an outcome without parameters commits the digest of the empty object', () => {
    expect(pcactnActionOf(vs, { verb: 'r.v', values: {} }).params_digest).toBe(hashCanonical({}));
  });
});
