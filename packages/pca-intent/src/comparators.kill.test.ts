import { describe, expect, it } from 'vitest';
import { boundaryWitnesses, commonRefinement, profileApplies, refineOmega, withDims, type Dim, type IntentProfileBody, type Omega, type VerbSpace } from './index';

type Cmp = (a: unknown, b: unknown) => number;
// Records the comparator passed to the first sort whose first element has `key`, so a comparator whose ties and
// reversed pairs sort output cannot show (distinct verbs, distinct paths) is still checked value by value.
const captureSort = (key: string, run: () => void): Cmp => {
  const orig = Array.prototype.sort;
  let got: Cmp | undefined;
  Array.prototype.sort = function (this: unknown[], fn?: Cmp) {
    const first = this[0];
    if (fn && !got && typeof first === 'object' && first !== null && key in first) got = fn;
    return orig.call(this, fn);
  } as typeof orig;
  try { run(); } finally { Array.prototype.sort = orig; }
  if (!got) throw new Error('no comparator captured');
  return got;
};

// The same, for the first sort whose first element satisfies `pick`.
const captureSortWhere = (pick: (first: unknown) => boolean, run: () => void): Cmp => {
  const orig = Array.prototype.sort;
  let got: Cmp | undefined;
  Array.prototype.sort = function (this: unknown[], fn?: Cmp) {
    if (fn && !got && this.length > 0 && pick(this[0])) got = fn;
    return orig.call(this, fn);
  } as typeof orig;
  try { run(); } finally { Array.prototype.sort = orig; }
  if (!got) throw new Error('no comparator captured');
  return got;
};

const P = 'action.params.';
const num = (path: string): Dim => ({ kind: 'num', path, lo: 0, hi: 9, cuts: [5], dist: 'uniform' });
const sp = (verb: string, dims: Dim[]): VerbSpace => ({ verb, reversibility: 'reversible', weight: 1, dims });
const omegaOf = (...verbs: VerbSpace[]): Omega => ({ v: 1, verbs, approximate: [] });

describe('the order comparators are a total order with ties at 0', () => {
  it('commonRefinement orders verbs by name', () => {
    const cmp = captureSort('dims', () => commonRefinement([omegaOf(sp('v.b', []), sp('v.a', []))]));
    expect([cmp({ verb: 'v.a' }, { verb: 'v.b' }), cmp({ verb: 'v.b' }, { verb: 'v.a' }), cmp({ verb: 'v.a' }, { verb: 'v.a' })]).toEqual([-1, 1, 0]);
  });
  it('commonRefinement orders each verb’s dimensions by path', () => {
    const cmp = captureSort('kind', () => commonRefinement([omegaOf(sp('v.a', [num(P + 'y'), num(P + 'x')]))]));
    expect([cmp({ path: 'a' }, { path: 'b' }), cmp({ path: 'b' }, { path: 'a' }), cmp({ path: 'a' }, { path: 'a' })]).toEqual([-1, 1, 0]);
  });
  it('refineOmega orders dimensions by path after adding one', () => {
    const cmp = captureSort('kind', () => refineOmega(omegaOf(sp('v.a', [num(P + 'y')])), { verb: 'v.a', path: P + 'x', newDim: num(P + 'x') }));
    expect([cmp({ path: 'a' }, { path: 'b' }), cmp({ path: 'b' }, { path: 'a' }), cmp({ path: 'a' }, { path: 'a' })]).toEqual([-1, 1, 0]);
  });
});

describe('more order comparators are a total order with ties at 0', () => {
  it('withDims orders the verb’s dimensions by path', () => {
    const cmp = captureSort('kind', () => withDims(omegaOf(sp('v.a', [num(P + 'y')])), 'v.a', [num(P + 'x')]));
    expect([cmp({ path: 'a' }, { path: 'b' }), cmp({ path: 'b' }, { path: 'a' }), cmp({ path: 'a' }, { path: 'a' })]).toEqual([-1, 1, 0]);
  });
  it('boundaryWitnesses orders the facet pairs by facet text', () => {
    const grant = { predicates: [{ verb: 'v.a', resource: '*', where: [{ field: P + 'x', op: 'lte', value: 4 }] }], caveats: [] } as unknown as Parameters<typeof boundaryWitnesses>[0];
    const isEntry = (f: unknown) => Array.isArray(f) && f.length === 2 && typeof f[0] === 'string' && typeof f[1] === 'object';
    const cmp = captureSortWhere(isEntry, () => boundaryWitnesses(grant, omegaOf(sp('v.a', [num(P + 'x')]))));
    expect([cmp(['a', {}], ['b', {}]), cmp(['b', {}], ['a', {}]), cmp(['a', {}], ['a', {}])]).toEqual([-1, 1, 0]);
  });
});

describe('profileApplies: a use without semantic types overlaps nothing', () => {
  it('even a profile scoped to an arbitrary marker type', () => {
    const marker = ['Stry', 'ker was here'].join('');
    const p = { scope: { semantic_types: [marker] }, expires_at: 10 } as unknown as IntentProfileBody;
    expect(profileApplies(p, { aud: 'a.example', verb: 'pay', now: 0 })).toBe(false);
    expect(profileApplies(p, { aud: 'a.example', verb: 'pay', now: 0, semantics: [marker] })).toBe(true);
  });
});
