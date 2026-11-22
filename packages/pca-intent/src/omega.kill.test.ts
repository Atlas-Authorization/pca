import { describe, expect, it } from 'vitest';
import { buildCatalog, defineAction } from '@atlasauth/pca/ext/research';
import {
  catCellOf,
  catRep,
  cellCount,
  cellOfValue,
  cellStats,
  DEFAULT_HARM,
  deriveOmega,
  dimCellStats,
  harmMax,
  intervalWeight,
  numCells,
  OTHER,
  rng,
  sampleOutcome,
  verbSpace,
  type CatDim,
  type CatValue,
  type DeriveOmegaOptions,
  type Dim,
  type HarmModel,
  type NumDim,
  type NumDist,
  type Omega,
  type PolicyInput,
  type VerbSpace,
} from './index';

const P = 'action.params.';
const AM = P + 'amount';
const num = (path: string, lo: number, hi: number, cuts: number[], dist: NumDist = 'uniform'): NumDim => ({ kind: 'num', path, lo, hi, cuts, dist });
const catv = (path: string, vals: [CatValue['kind'], string][]): CatDim => ({ kind: 'cat', path, values: vals.map(([kind, value]) => ({ kind, value })) });
const VS = (verb: string, weight: number, dims: Dim[], reversibility: VerbSpace['reversibility'] = 'reversible'): VerbSpace => ({ verb, reversibility, weight, dims });
const omegaOf = (...verbs: VerbSpace[]): Omega => ({ v: 1, verbs, approximate: [] });
// a scripted random source: returns the given draws in order, cycling
const seq = (xs: number[]) => {
  let i = 0;
  return () => xs[i++ % xs.length]!;
};

describe('cells of a dimension', () => {
  const d1 = num(P + 'n', 2, 5, [1, 3, 7]);
  it('cuts outside the domain are ignored, and the cell list is cached', () => {
    expect(numCells(d1)).toEqual([
      { lo: 2, hi: 2 },
      { lo: 3, hi: 3 },
      { lo: 4, hi: 5 },
    ]);
    expect(numCells(d1)).toBe(numCells(d1));
  });

  it('catCellOf: exact beats prefix whatever the order, the longest prefix wins, the first of equal prefixes wins, a prefix at index 0 counts', () => {
    expect(catCellOf(catv(P + 'k', [['prefix', 'ab'], ['exact', 'ab'], ['other', OTHER]]), 'ab')).toBe(1);
    expect(catCellOf(catv(P + 'k', [['prefix', 'ab'], ['prefix', 'a'], ['other', OTHER]]), 'abc')).toBe(0);
    expect(catCellOf(catv(P + 'k', [['prefix', 'a'], ['prefix', 'a'], ['other', OTHER]]), 'ab')).toBe(0);
    expect(catCellOf(catv(P + 'k', [['prefix', 'a'], ['other', OTHER]]), 'ab')).toBe(0);
    expect(catCellOf(catv(P + 'k', [['prefix', 'a'], ['other', OTHER]]), 'b')).toBe(1);
  });

  it('cellOfValue: -1 for a value outside the domain or of the wrong type', () => {
    expect(cellOfValue(num(P + 'n', 0, Infinity, []), Infinity)).toBe(-1);
    for (const x of ['3', 'x', NaN, 1]) expect(cellOfValue(d1, x)).toBe(-1);
    expect(cellOfValue(d1, 4)).toBe(2);
    expect(cellOfValue(catv(P + 'k', [['exact', 'a'], ['other', OTHER]]), 5)).toBe(-1);
  });

  it('catRep: a prefix gets an x; the OTHER search tries up to 63 suffixes, then falls back to the base', () => {
    expect(catRep(catv(P + 'k', [['prefix', 'ab'], ['other', OTHER]]), 0)).toBe('abx');
    const many = catv(P + 'k', [...Array.from({ length: 64 }, (_, k): [CatValue['kind'], string] => ['exact', 'other' + (k === 0 ? '' : String(k))]), ['other', OTHER]]);
    expect(catRep(many, 64)).toBe('other');
    expect(catRep(catv(P + 'k', [['exact', 'other'], ['other', OTHER]]), 1)).toBe('other1');
  });
});

describe('the default harm model', () => {
  const H = DEFAULT_HARM;
  it('verb factors', () => {
    expect([H.verb(VS('v', 1, [], 'rate_limited')), H.verb(VS('v', 1, [], 'irreversible')), H.verb(VS('v', 1, []))]).toEqual([3, 10, 1]);
  });

  it('only a numeric dimension whose path is or ends in .amount scales, and only for a number', () => {
    expect(H.dim(num(AM, 0, 100, []), 50)).toBe(1.5);
    expect(H.dim(num('amount', 0, 100, []), 50)).toBe(1.5);
    expect(H.dim(catv(AM, [['other', OTHER]]), 50)).toBe(1);
    expect(H.dim(num(P + 'amount_x', 0, 100, []), 50)).toBe(1);
    expect(H.dim(num(AM, 0, 100, []), '5')).toBe(1);
    expect(H.dim(num(P + 'n', 0, 100, []), 50)).toBe(1);
  });

  it('closed-form cell means (uniform, loguniform, a negative loguniform domain treated as uniform, an empty and a negative interval)', () => {
    expect(H.dimMean!(num(AM, 0, 100, []), 2, 6)).toBe(1.04);
    expect(H.dimMean!(num(AM, -3, 10, [], 'loguniform'), 0, 10)).toBe(1.05);
    expect(H.dimMean!(num(AM, 0, 100, []), 5, 3)).toBe(1);
    expect(H.dimMean!(num(AM, 0, 100, [], 'loguniform'), 2, 6)).toBe(1.0357516339869282);
    expect(H.dimMean!(num(AM, 0, 10000, [], 'loguniform'), 1, 9000)).toBe(11.355842634875291);
    expect(H.dimMean!(num(AM, -10, 10, []), -5, -1)).toBe(1);
    expect(H.dimMean!(num(AM, -10, 10, []), -10, -5)).toBe(1);
  });

  it('harmMax takes the largest categorical factor and the rate-limited verb factor', () => {
    const hc: HarmModel = { verb: () => 1, dim: (d, x) => (d.kind === 'cat' ? (x === 'a' ? 3 : 2) : 1) };
    expect(harmMax(omegaOf(VS('v', 1, [catv(P + 'k', [['exact', 'a'], ['other', OTHER]])])), hc)).toBe(3);
    expect(harmMax(omegaOf(VS('v', 1, [num(AM, 0, 300, [])], 'rate_limited')))).toBe(12);
  });
});

describe('interval weights', () => {
  const lg = num(P + 'n', 0, 100000, [], 'loguniform');
  const un = num(P + 'n', 0, 100000, []);
  const ln = num(P + 'n', -2, 100, [], 'loguniform');
  it('empty intervals, a negative loguniform domain, and exact versus asymptotic harmonic sums around 4096 values', () => {
    expect(intervalWeight(un, 5, 3)).toBe(0);
    expect(intervalWeight(un, 5, 4)).toBe(0);
    expect(intervalWeight(ln, 0, 3)).toBe(4);
    expect(intervalWeight(un, 3, 9000)).toBe(8998);
    expect(intervalWeight(lg, 0, 3)).toBe(2.083333333333333);
    expect(intervalWeight(lg, 1, 5000)).toBe(8.094708812992437);
    expect(intervalWeight(lg, 0, 4095)).toBe(8.895103896966317);
    expect(intervalWeight(lg, 1, 4096)).toBe(7.8953479780012215);
    expect(intervalWeight(lg, 1, 4097)).toBe(7.895591999475117);
    expect(intervalWeight(lg, 1, 4098)).toBe(7.895835961417054);
    expect(intervalWeight(lg, 4096, 9000)).toBe(0.7872582775471262);
    expect(intervalWeight(lg, 0, 99999)).toBe(12.09014612986343);
    expect(intervalWeight(lg, 50, 60000)).toBe(7.080135167475426);
  });
});

describe('cell statistics', () => {
  // a harm without a closed form: exact weighted sums on short cells, the 1024-piece quadrature on long ones
  const hq: HarmModel = { verb: () => 1, dim: (_d, x) => 1 + (x as number) };
  const ds = [
    num(P + 'n', 0, 9, [3], 'loguniform'),
    num(P + 'n', -2, 5, [1], 'loguniform'),
    num(P + 'n', 0, 9, [3]),
    num(P + 'n', 0, 20000, [4096, 8193], 'loguniform'),
    num(P + 'n', 0, 20000, [4096, 8193]),
    num(P + 'n', 5, 4101, [4100]),
    num(P + 'n', 5, 4101, [4101], 'loguniform'),
    num(P + 'n', 0, 5000, [7], 'loguniform'),
  ];
  it('exact mass and harm of every cell, with a custom harm and with the default one', () => {
    expect(ds.map((d) => Array.from({ length: cellCount(d) }, (_, i) => [dimCellStats(d, i, hq), dimCellStats(d, i)]))).toEqual([[[{"mass":0.6259314456035767,"harm":1.6363636363636365},{"mass":0.6259314456035767,"harm":1}],[{"mass":0.08535428803685138,"harm":4},{"mass":0.08535428803685138,"harm":1}],[{"mass":0.2887142663595719,"harm":7.0952604411074605},{"mass":0.2887142663595719,"harm":1}]],[[{"mass":0.375,"harm":0},{"mass":0.375,"harm":1}],[{"mass":0.125,"harm":2},{"mass":0.125,"harm":1}],[{"mass":0.5,"harm":4.5},{"mass":0.5,"harm":1}]],[[{"mass":0.3,"harm":2},{"mass":0.3,"harm":1}],[{"mass":0.1,"harm":4},{"mass":0.1,"harm":1}],[{"mass":0.6,"harm":7.5},{"mass":0.6,"harm":1}]],[[{"mass":0.8487064333128751,"harm":460.4780390926006},{"mass":0.8487064333128751,"harm":1}],[{"mass":0.000023288445753060773,"harm":4097},{"mass":0.000023288445753060773,"harm":1}],[{"mass":0.06611762116417698,"harm":5910.839913716254},{"mass":0.06611762116417698,"harm":1}],[{"mass":0.000011644222876530386,"harm":8194},{"mass":0.000011644222876530386,"harm":1}],[{"mass":0.08514101285431755,"harm":13231.719897642379},{"mass":0.08514101285431755,"harm":1}]],[[{"mass":0.2047897605119744,"harm":2048.5},{"mass":0.2047897605119744,"harm":1}],[{"mass":0.00004999750012499375,"harm":4097},{"mass":0.00004999750012499375,"harm":1}],[{"mass":0.2047897605119744,"harm":6145.5},{"mass":0.2047897605119744,"harm":1}],[{"mass":0.00004999750012499375,"harm":8194},{"mass":0.00004999750012499375,"harm":1}],[{"mass":0.5903204839758012,"harm":14098.27593800288},{"mass":0.5903204839758012,"harm":1}]],[[{"mass":0.9995118379301928,"harm":2053},{"mass":0.9995118379301928,"harm":1}],[{"mass":0.000244081034903588,"harm":4101},{"mass":0.000244081034903588,"harm":1}],[{"mass":0.000244081034903588,"harm":4102},{"mass":0.000244081034903588,"harm":1}]],[[{"mass":0.9999631370197318,"harm":619.3869594036107},{"mass":0.9999631370197318,"harm":1}],[{"mass":0.00003686298026748265,"harm":4102},{"mass":0.00003686298026748265,"harm":1}]],[[{"mass":0.2850951246677697,"harm":2.6997245179063363},{"mass":0.2850951246677697,"harm":1}],[{"mass":0.013744255321448955,"harm":8},{"mass":0.013744255321448955,"harm":1}],[{"mass":0.7011606200107814,"harm":783.0907259290698},{"mass":0.7011606200107814,"harm":1}]]]);
  });

  it('a whole cell multiplies the verb weight, the verb factor and every dimension', () => {
    expect(cellStats(VS('v', 0.5, [num(AM, 0, 9, [3]), catv(P + 'k', [['exact', 'a'], ['other', OTHER]])], 'rate_limited'), [1, 0])).toEqual({"mass":0.025,"harm":3.09});
  });
});

describe('rng', () => {
  it('exact first draws', () => {
    expect([1, 0xffffffff, 12345].map((s) => {
      const r = rng(s);
      return [r(), r(), r()];
    })).toEqual([
      [0.6270739405881613, 0.002735721180215478, 0.5274470399599522],
      [0.8964226141106337, 0.189478256739676, 0.7156526781618595],
      [0.9797282677609473, 0.3067522644996643, 0.484205421525985],
    ]);
  });
});

describe('sampleOutcome', () => {
  const draw = (om: Omega, xs: number[]) => sampleOutcome(om, seq(xs));
  it('verb choice by cumulative weight; a draw past the total weight lands on the last verb', () => {
    const om = omegaOf(VS('a', 0.25, []), VS('b', 0.25, []), VS('c', 0.25, []));
    expect([0, 0.2, 0.25, 0.5, 0.74, 0.75, 0.9].map((u) => draw(om, [u]).o.verb)).toEqual(['a', 'a', 'b', 'c', 'c', 'c', 'c']);
  });

  it('categorical values are uniform, and a draw of exactly 1 still lands on the last value', () => {
    const om = omegaOf(VS('a', 1, [catv(P + 'k', [['exact', 'x'], ['prefix', 'p'], ['other', OTHER]])]));
    expect([0, 0.3, 0.34, 0.5, 0.7, 0.9, 1].map((u) => draw(om, [0, u]).o.values[P + 'k'])).toEqual(['x', 'x', 'px', 'px', 'other', 'other', 'other']);
  });

  it('numeric quantiles: short and long cells, uniform and loguniform, exactly at each cell boundary and at 1', () => {
    const ds = [
      num(P + 'n', 0, 9, [5]),
      num(P + 'n', 0, 9, [5], 'loguniform'),
      num(P + 'n', -3, 9, [2], 'loguniform'),
      num(P + 'n', 0, 20000, [4096, 8193]),
      num(P + 'n', 0, 20000, [4096, 8193], 'loguniform'),
      num(P + 'n', 0, 100000, [10], 'loguniform'),
    ];
    const us = [0, 0.1, 0.25, 0.3, 0.5, 0.55, 0.7, 0.9, 0.97, 0.999, 1];
    const got = ds.map((d) => {
      const om = omegaOf(VS('a', 1, [d]));
      const tot = intervalWeight(d, d.lo, d.hi);
      const bounds: number[] = [];
      for (const c of numCells(d)) bounds.push((bounds.length ? bounds[bounds.length - 1]! : 0) + intervalWeight(d, c.lo, c.hi));
      return [...us, ...bounds.map((b) => b / tot)].map((u) => draw(om, [0, u]).o.values[P + 'n']);
    });
    expect(got).toEqual([[0,1,2,3,5,5,7,9,9,9,9,5,6,9],[0,0,0,0,1,2,3,7,9,9,9,5,6,9],[-3,-2,0,0,3,4,6,8,9,9,9,2,3,9],[0,2000,5000,6000,10000,11000,14000,18000,19400,19980,20000,4096,4097,8193,8194,20000],[0,1,7,12,105,178,861,7012,14605,19793,20000,4096,4097,8193,8194,20000],[0,1,11,21,246,451,2773,31136,72581,100000,100000,10,11,100000]]);
  });

  it('dense draws inside a cell of exactly 4096 values (exact inverse), of 4097 values (continuous inverse) and in a long negative loguniform cell (uniform)', () => {
    const band = (d: NumDim, c: number) => {
      const om = omegaOf(VS('a', 1, [d]));
      const tot = intervalWeight(d, d.lo, d.hi);
      const cs = numCells(d);
      let acc = 0;
      for (let i = 0; i < c; i++) acc += intervalWeight(d, cs[i]!.lo, cs[i]!.hi);
      const w = intervalWeight(d, cs[c]!.lo, cs[c]!.hi);
      return Array.from({ length: 40 }, (_, j) => draw(om, [0, (acc + (w * (j + 0.5)) / 40) / tot]).o.values[P + 'n']);
    };
    expect([band(num(P + 'n', 0, 20000, [4096, 8193], 'loguniform'), 2), band(num(P + 'n', 0, 30000, [5000, 9098], 'loguniform'), 2), band(num(P + 'n', -5, 10000, [], 'loguniform'), 0)]).toEqual([[4132,4204,4278,4353,4429,4506,4585,4665,4747,4830,4914,5000,5087,5176,5267,5359,5452,5548,5645,5743,5844,5946,6050,6155,6263,6372,6484,6597,6712,6830,6949,7071,7194,7320,7448,7578,7710,7845,7982,8122],[5038,5114,5191,5269,5349,5429,5511,5594,5679,5764,5851,5939,6029,6120,6212,6306,6401,6497,6595,6695,6796,6898,7002,7108,7215,7324,7434,7546,7660,7775,7892,8011,8132,8255,8379,8506,8634,8764,8896,9030],[120,370,620,870,1120,1370,1620,1871,2121,2371,2621,2871,3121,3372,3622,3872,4122,4372,4622,4872,5123,5373,5623,5873,6123,6373,6623,6874,7124,7374,7624,7874,8124,8375,8625,8875,9125,9375,9625,9875]]);
  });
});

describe('deriveOmega', () => {
  const catalog = buildCatalog([
    defineAction({ connector: 'c1', action: 'a', reversibility: 'reversible', blastRadius: 0.1, description: 'x' }),
    defineAction({ connector: 'c2', action: 'b', reversibility: 'rate_limited', blastRadius: 0.1, description: 'x' }),
  ]);
  const D = (opts: Omit<DeriveOmegaOptions, 'catalog'>) => deriveOmega({ catalog, ...opts });
  const pol = (...predicates: unknown[]) => ({ predicates }) as unknown as PolicyInput;
  const other = { kind: 'other', value: OTHER };
  const ex = (value: string) => ({ kind: 'exact', value });
  const pre = (value: string) => ({ kind: 'prefix', value });

  it('resource matchers: re: is approximate, a trailing * is a prefix, anything else exact; a non-string resource is ignored', () => {
    const o = D({ policies: [pol({ verb: 'c1.a', resource: 're:^x' }, { verb: 'c1.a', resource: 'files/*' }, { verb: 'c1.a', resource: 'exact1' }, { verb: 'c1.a', resource: ['arr'] }, { verb: 'c1.a', resource: 'abre:' })] });
    expect(o).toEqual({
      v: 1,
      verbs: [{ verb: 'c1.a', reversibility: 'reversible', weight: 1, dims: [{ kind: 'cat', path: 'action.resource', values: [ex('abre:'), ex('exact1'), pre('files/'), other] }] }],
      approximate: ['re: resource matcher'],
    });
  });

  it('verbs: string lists drop non-strings, a missing verb adds none, an unknown verb is irreversible, a wildcard expands to its connectors or the whole catalog', () => {
    expect(D({ policies: [pol({ verb: ['c1.a', 5], resource: '*' }, { resource: '*' }, { verb: 'zz.q', resource: '*' })] }).verbs.map((v) => [v.verb, v.reversibility, v.weight])).toEqual([
      ['c1.a', 'reversible', 0.5],
      ['zz.q', 'irreversible', 0.5],
    ]);
    expect(D({ policies: [pol({ verb: '*', resource: '*' })] }).verbs.map((v) => v.verb)).toEqual(['c1.a', 'c2.b']);
    expect(D({ policies: [pol({ verb: ['x', '*'], resource: '*' })] }).verbs.map((v) => v.verb)).toEqual(['c1.a', 'c2.b']);
  });

  it('a wildcard predicate shapes every verb, a named one only its own', () => {
    const o = D({
      policies: [pol({ verb: '*', resource: '*', where: [{ field: P + 'w', op: 'lte', value: 4 }] }, { verb: 'c2.b', resource: '*', where: [{ field: P + 'o', op: 'lte', value: 9 }] })],
      slots: { verbs: ['c1.a'], constraints: [] },
    });
    expect(o.verbs.map((v) => [v.verb, v.dims.map((d) => d.path)])).toEqual([
      ['c1.a', [P + 'w']],
      ['c2.b', [P + 'o', P + 'w']],
    ]);
  });

  it('slot constraints: max, min, a verb filter, oneOf/noneOf exacts and prefixes', () => {
    const o = D({
      policies: [],
      slots: { verbs: ['c1.a', 'c2.b'], constraints: [{ path: P + 'z', max: 50 }, { path: P + 'y', min: 3 }, { path: P + 'x', verb: 'c2.b', max: 9 }, { path: P + 'k', oneOf: ['q'], noneOf: ['p'] }, { path: P + 'j', prefixOneOf: ['t/'] }] },
    });
    const j = { kind: 'cat', path: P + 'j', values: [pre('t/'), other] };
    const k = { kind: 'cat', path: P + 'k', values: [ex('p'), ex('q'), other] };
    const y = num(P + 'y', 0, 13, [3], 'loguniform');
    const z = num(P + 'z', 0, 100, [50], 'loguniform');
    expect(o).toEqual({
      v: 1,
      verbs: [
        { verb: 'c1.a', reversibility: 'reversible', weight: 0.5, dims: [j, k, y, z] },
        { verb: 'c2.b', reversibility: 'rate_limited', weight: 0.5, dims: [j, k, num(P + 'x', 0, 19, [9], 'loguniform'), y, z] },
      ],
      approximate: [],
    });
  });

  it('numeric domains: built-in, derived (negative cuts make it uniform), overridden with out-of-range cuts dropped; a prefix or an exact on a built-in numeric path makes it categorical', () => {
    const o = D({
      policies: [pol({ verb: 'c1.a', resource: '*', where: [{ field: P + 'v', op: 'in', value: [-2, 5, 10, 12] }, { field: AM, op: 'lte', value: 7 }, { field: P + 'u', op: 'gte', value: -3 }, { field: P + 't', op: 'lte', value: 7 }, { field: 'env.hour', op: 'prefix', value: '1' }, { field: P + 'count', op: 'eq', value: '9' }] })],
      domains: { [P + 'v']: { lo: 0, hi: 10 } },
    });
    expect(o.verbs[0]!.dims).toEqual([
      num(AM, 0, 100000, [7], 'loguniform'),
      { kind: 'cat', path: P + 'count', values: [ex('9'), other] },
      num(P + 't', 0, 17, [7], 'loguniform'),
      num(P + 'u', -4, 10, [-3]),
      num(P + 'v', 0, 10, [5, 10], 'loguniform'),
      { kind: 'cat', path: 'env.hour', values: [pre('1'), other] },
    ]);
  });

  it('conditions: groups, non-conditions, exists, non-finite and fractional numbers, booleans, refs and approximate operators', () => {
    const o = D({
      policies: [
        pol({
          verb: 'c1.a',
          resource: '*',
          where: [
            null,
            5,
            {},
            { all_of: 'x' },
            { any_of: 'x' },
            { all_of: [{ field: P + 'g', op: 'lte', value: 2.5 }, { field: P + 'q', op: 'lte', value: Infinity }] },
            { any_of: [{ field: P + 's', op: 'eq', value: 'b' }, { field: P + 's', op: 'eq', value: 'a' }, { field: P + 's', op: 'prefix', value: 'zz' }, { field: P + 's', op: 'prefix', value: 'yy' }] },
            { not: { field: P + 'm', op: 'gte', value: -3 } },
            { field: P + 'e', op: 'exists', value: 5 },
            { field: P + 'e2', op: 'exists' },
            { field: 'env.hour', op: 'exists' },
            { field: P + 'b', op: 'eq', value: true },
            { field: P + 'r', op: 'eq', value: 1, ref: P + 'g' },
            { field: P + 'l1', op: 'like', value: 'x%' },
            { field: P + 'l2', op: 'matches', value: 'x' },
            { field: P + 'l3', op: 'is_a', value: 'x' },
            { field: P + 'l4', op: 'member_of', value: 'x' },
            { field: P + 'c', op: 'in', value: [7, 'w'] },
          ],
        }),
      ],
    });
    expect(o).toEqual({"v":1,"verbs":[{"verb":"c1.a","reversibility":"reversible","weight":1,"dims":[{"kind":"cat","path":"action.params.b","values":[{"kind":"other","value":"⊥"}]},{"kind":"num","path":"action.params.c","lo":0,"hi":17,"cuts":[7],"dist":"loguniform"},{"kind":"cat","path":"action.params.e","values":[{"kind":"other","value":"⊥"}]},{"kind":"cat","path":"action.params.e2","values":[{"kind":"other","value":"⊥"}]},{"kind":"num","path":"action.params.g","lo":0,"hi":13,"cuts":[2,3],"dist":"loguniform"},{"kind":"cat","path":"action.params.l1","values":[{"kind":"exact","value":"x%"},{"kind":"other","value":"⊥"}]},{"kind":"cat","path":"action.params.l2","values":[{"kind":"exact","value":"x"},{"kind":"other","value":"⊥"}]},{"kind":"cat","path":"action.params.l3","values":[{"kind":"exact","value":"x"},{"kind":"other","value":"⊥"}]},{"kind":"cat","path":"action.params.l4","values":[{"kind":"exact","value":"x"},{"kind":"other","value":"⊥"}]},{"kind":"num","path":"action.params.m","lo":-4,"hi":10,"cuts":[-3],"dist":"uniform"},{"kind":"cat","path":"action.params.q","values":[{"kind":"other","value":"⊥"}]},{"kind":"num","path":"action.params.r","lo":0,"hi":11,"cuts":[1],"dist":"loguniform"},{"kind":"cat","path":"action.params.s","values":[{"kind":"exact","value":"a"},{"kind":"exact","value":"b"},{"kind":"prefix","value":"yy"},{"kind":"prefix","value":"zz"},{"kind":"other","value":"⊥"}]},{"kind":"num","path":"env.hour","lo":0,"hi":23,"cuts":[],"dist":"uniform"}]}],"approximate":["cross-field ref on action.params.r","is_a on action.params.l3","like on action.params.l1","matches on action.params.l2","member_of on action.params.l4"]});
  });

  it('verbSpace finds a verb or nothing', () => {
    const o = D({ policies: [], slots: { verbs: ['c1.a', 'c2.b'], constraints: [] } });
    expect(verbSpace(o, 'c2.b')).toBe(o.verbs[1]);
    expect(verbSpace(o, 'c1.a')).toBe(o.verbs[0]);
    expect(verbSpace(o, 'zz')).toBeUndefined();
  });
});
