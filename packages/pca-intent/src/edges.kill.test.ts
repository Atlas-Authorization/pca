import { describe, expect, it } from 'vitest';
import { certifyBracket } from './clopper';
import { ceilingAdmitters, commitIntentMap, createLearner, emitIntentMap, type Omega, type PolicyInput } from './index';

describe('certifyBracket never walks past the top of the grid', () => {
  it('an upper walk that would overshoot is capped at 2^52', () => {
    const A = 1n << 52n;
    expect(certifyBracket(A - 1n, (a) => a < A)).toEqual({ hi: A, lo: A - (1n << 8n) });
  });
});

describe('ceilingAdmitters refuses a primitive ceiling', () => {
  it('a string or a number is malformed, with the ceiling named', () => {
    expect(() => ceilingAdmitters({ org: 'x' as unknown as PolicyInput })).toThrow('ceilingAdmitters: the org ceiling is malformed (null or not an object)');
    expect(() => ceilingAdmitters({ site: 7 as unknown as PolicyInput })).toThrow('ceilingAdmitters: the site ceiling is malformed (null or not an object)');
  });
});

describe('commitIntentMap counts single-value numeric cells', () => {
  it('a cut right above lo and a last cell of one value give three cells', () => {
    const omega: Omega = { v: 1, approximate: [], verbs: [{ verb: 'v', reversibility: 'reversible', weight: 1, dims: [{ kind: 'num', path: 'action.params.a', lo: 0, hi: 2, cuts: [1], dist: 'uniform' }] }] };
    const m = emitIntentMap(createLearner(omega, { eta: 0, tau: 1 }));
    expect(m.cells.map((c) => c.cell)).toEqual([[0], [1], [2]]);
    const headers = commitIntentMap(m, new Uint8Array(32).fill(7)).leaves.filter((x) => x.kind === 'header');
    expect(headers.map((h) => h.leaf)).toEqual([{ verb: 'v', first: 1, cells: 3, dims: [{ kind: 'num', path: 'action.params.a', lo: 0, hi: 2, cuts: [1] }] }]);
  });
});
