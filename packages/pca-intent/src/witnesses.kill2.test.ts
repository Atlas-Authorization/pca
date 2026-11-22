import { describe, expect, it } from 'vitest';
import type { Predicate } from '@atlasauth/pca';
import { OTHER, boundaryWitnesses, cellRep, checkWitnesses, renderQuestion, type CatDim, type NumDim, type Omega, type VerbSpace, type Witness } from './index';

const R = 'stripe.refund';
const num = (path: string, lo: number, hi: number, cuts: number[]): NumDim => ({ kind: 'num', path, lo, hi, cuts, dist: 'uniform' });
const cat = (path: string, vals: string[]): CatDim => ({ kind: 'cat', path, values: [...vals.map((value) => ({ kind: 'exact' as const, value })), { kind: 'other' as const, value: OTHER }] });
const space = (verb: string, dims: VerbSpace['dims']): VerbSpace => ({ verb, reversibility: 'reversible', weight: 1, dims });
const omegaOf = (...verbs: VerbSpace[]): Omega => ({ v: 1, verbs, approximate: [] });
type Where = { field: string; op: string; value: unknown };
const grant = (...wheres: Where[][]) => ({ predicates: wheres.map((where) => ({ verb: R, resource: '*', where })) as unknown as Predicate[], caveats: [] });
const wit = (vs: VerbSpace, kind: Witness['kind'], cell: number[], allows: boolean, facet: string, outcomeValues: Record<string, number | string>): Witness => ({
  kind,
  side: allows ? 'inside' : 'outside',
  verb: vs.verb,
  cell,
  outcome: { verb: vs.verb, values: outcomeValues },
  grantAllows: allows,
  facet,
  question: renderQuestion(vs, cell),
});

const AMT = 'action.params.amount';
const REG = 'action.params.region';

describe('boundaryWitnesses: exact witness lists on small spaces', () => {
  it('emits the verb witness, then each facet pair sorted by facet, deduplicating shared cells', () => {
    const vs = space(R, [num(AMT, 0, 9, [3, 6]), cat(REG, ['eu', 'us'])]);
    const g = grant([
      { field: AMT, op: 'gte', value: 3 },
      { field: AMT, op: 'lte', value: 5 },
      { field: REG, op: 'eq', value: 'eu' },
    ]);
    expect(boundaryWitnesses(g, omegaOf(vs))).toEqual([
      wit(vs, 'verb', [2, 0], true, `${R}|verb`, { [AMT]: 4, [REG]: 'eu' }),
      wit(vs, 'boundary', [1, 0], true, `${R}|${AMT}|0~1`, { [AMT]: 3, [REG]: 'eu' }),
      wit(vs, 'boundary', [0, 0], false, `${R}|${AMT}|0~1`, { [AMT]: 2, [REG]: 'eu' }),
      wit(vs, 'boundary', [3, 0], false, `${R}|${AMT}|2~3`, { [AMT]: 6, [REG]: 'eu' }),
      wit(vs, 'boundary', [2, 1], false, `${R}|${REG}|1`, { [AMT]: 4, [REG]: 'us' }),
      wit(vs, 'boundary', [2, 2], false, `${R}|${REG}|2`, { [AMT]: 4, [REG]: 'other' }),
    ]);
  });

  it('a verb the grant denies gets one outside witness at its most typical cell (first of equals)', () => {
    const a = space('stripe.charge', [cat('action.params.k', ['a', 'b'])]);
    const b = space('stripe.payout', [num(AMT, 0, 9, [2, 3])]);
    expect(boundaryWitnesses(grant([{ field: AMT, op: 'lte', value: 1 }]), omegaOf(a, b))).toEqual([
      wit(a, 'verb', [0], false, 'stripe.charge|verb', { 'action.params.k': 'a' }),
      wit(b, 'verb', [3], false, 'stripe.payout|verb', { [AMT]: 4 }),
    ]);
  });

  it('a denied verb whose cells all have zero mass is witnessed at its first cell', () => {
    const a: VerbSpace = { ...space('stripe.charge', [cat('action.params.k', ['a', 'b'])]), weight: 0 };
    expect(boundaryWitnesses(grant([{ field: AMT, op: 'lte', value: 1 }]), omegaOf(a))).toEqual([
      wit(a, 'verb', [0], false, 'stripe.charge|verb', { 'action.params.k': 'a' }),
    ]);
  });

  it('an unconstrained categorical dimension is witnessed at its other cell, wherever that cell sits', () => {
    const K = 'action.params.k';
    const vs = space(R, [{ kind: 'cat', path: K, values: [{ kind: 'other', value: OTHER }, { kind: 'exact', value: 'a' }] }]);
    const out = boundaryWitnesses({ predicates: [{ verb: R, resource: '*' }] as unknown as Predicate[], caveats: [] }, omegaOf(vs));
    // the other cell is [0]: it is either the typical action itself or the unconstrained witness, never cell [1]
    expect(out.map((w) => w.cell)).toContainEqual([0]);
    expect(out.filter((w) => w.kind === 'unconstrained').map((w) => w.cell)).not.toContainEqual([1]);
  });

  it('the first of equally typical admitted cells is the base, and the first of equal-score pairs wins', () => {
    const vs = space(R, [cat('action.params.k', ['a', 'b'])]);
    const g = grant([{ field: 'action.params.k', op: 'in', value: ['a', 'b'] }]);
    expect(boundaryWitnesses(g, omegaOf(vs))).toEqual([
      wit(vs, 'verb', [0], true, `${R}|verb`, { 'action.params.k': 'a' }),
      wit(vs, 'boundary', [2], false, `${R}|action.params.k|2`, { 'action.params.k': 'other' }),
    ]);
  });

  it('prefers the pair that shares the typical action\'s other coordinates over a heavier pair that does not', () => {
    const O = 'action.params.o';
    const K = 'action.params.k';
    const vs = space(R, [num(O, 0, 3, [0]), num(K, 0, 99, [24])]);
    const g = grant(
      [{ field: O, op: 'eq', value: 0 }, { field: K, op: 'gte', value: 25 }],
      [{ field: O, op: 'eq', value: 0 }, { field: K, op: 'lte', value: 23 }],
      [{ field: O, op: 'gte', value: 1 }, { field: K, op: 'lte', value: 23 }],
    );
    const ws = boundaryWitnesses(g, omegaOf(vs)).filter((w) => w.facet === `${R}|${K}|0~1`);
    expect(ws.map((w) => [w.cell, w.grantAllows])).toEqual([
      [[0, 0], true],
      [[0, 1], false],
    ]);
  });

  it('shared coordinates are counted on the other dimensions only', () => {
    const O = 'action.params.o';
    const K = 'action.params.k';
    const vs = space(R, [num(O, 0, 9, [5]), cat(K, ['a', 'b'])]);
    const g = grant(
      [{ field: O, op: 'eq', value: 4 }, { field: K, op: 'in', value: ['a', 'other'] }],
      [{ field: O, op: 'eq', value: 5 }, { field: K, op: 'eq', value: 'a' }],
      [{ field: O, op: 'eq', value: 6 }, { field: K, op: 'eq', value: 'b' }],
    );
    const ws = boundaryWitnesses(g, omegaOf(vs)).filter((w) => w.facet === `${R}|${K}|2`);
    // the inside cell [2, 1] is the typical action, already listed under the verb facet
    expect(ws.map((w) => [w.cell, w.grantAllows])).toEqual([[[2, 2], false]]);
  });

  it('a dimension the grant ignores gets an unconstrained witness at its most extreme cell', () => {
    const NOTE = 'action.params.note';
    const vs = space(R, [num(AMT, 0, 9, [5]), cat(NOTE, ['n1']), num('env.hour', 0, 23, [12])]);
    const g = grant([{ field: AMT, op: 'lte', value: 4 }]);
    expect(boundaryWitnesses(g, omegaOf(vs))).toEqual([
      wit(vs, 'verb', [0, 0, 0], true, `${R}|verb`, { [AMT]: 4, [NOTE]: 'n1', 'env.hour': 11 }),
      wit(vs, 'boundary', [1, 0, 0], false, `${R}|${AMT}|0~1`, { [AMT]: 5, [NOTE]: 'n1', 'env.hour': 11 }),
      wit(vs, 'unconstrained', [0, 1, 0], true, `${R}|${NOTE}|unconstrained`, { [AMT]: 4, [NOTE]: 'other', 'env.hour': 11 }),
      wit(vs, 'unconstrained', [0, 0, 2], true, `${R}|env.hour|unconstrained`, { [AMT]: 4, [NOTE]: 'n1', 'env.hour': 13 }),
    ]);
  });

  it('cell keys keep their separator: [11,1] and [1,11] are different witnesses', () => {
    const P = 'action.params.p';
    const Q = 'action.params.q';
    const names = (x: string) => Array.from({ length: 12 }, (_, i) => `${x}${i}`);
    const vs = space(R, [cat(P, names('p')), cat(Q, names('q'))]);
    const g = grant([{ field: P, op: 'eq', value: 'p1' }, { field: Q, op: 'eq', value: 'q1' }]);
    const ws = boundaryWitnesses(g, omegaOf(vs));
    expect(ws.length).toBe(25);
    const cells = ws.map((w) => w.cell.join(','));
    expect(new Set(cells).size).toBe(25);
    expect(cells).toContain('11,1');
    expect(cells).toContain('1,11');
  });

  it('orders more than a few facets lexicographically by facet string', () => {
    const P = 'action.params.p';
    const vs = space(R, [cat(P, Array.from({ length: 40 }, (_, i) => `p${i}`))]);
    const ws = boundaryWitnesses(grant([{ field: P, op: 'eq', value: 'p0' }]), omegaOf(vs));
    const facets = ws.filter((w) => w.kind === 'boundary').map((w) => w.facet);
    expect(facets.length).toBe(40);
    expect(facets).toEqual([...facets].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)));
    expect(facets[0]).toBe(`${R}|${P}|1`);
    expect(facets[1]).toBe(`${R}|${P}|10`);
  });

  it('every witness outcome is the representative of its cell', () => {
    const vs = space(R, [num(AMT, 0, 9, [3, 6]), cat(REG, ['eu', 'us'])]);
    const ws = boundaryWitnesses(grant([{ field: AMT, op: 'lte', value: 5 }]), omegaOf(vs));
    for (const w of ws) expect(w.outcome).toEqual(cellRep(vs, w.cell));
  });
});

describe('checkWitnesses', () => {
  it('counts the questions and returns exactly the witnesses the oracle disagrees with', () => {
    const vs = space(R, [num(AMT, 0, 9, [3, 6])]);
    const ws = boundaryWitnesses(grant([{ field: AMT, op: 'lte', value: 5 }]), omegaOf(vs));
    const r = checkWitnesses(ws, (w) => w.grantAllows);
    expect(r).toEqual({ questions: ws.length, mismatches: [] });
    const flipped = checkWitnesses(ws, (w) => !w.grantAllows);
    expect(flipped.mismatches).toEqual(ws);
  });
});
