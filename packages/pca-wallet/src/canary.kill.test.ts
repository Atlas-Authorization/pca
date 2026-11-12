import { describe, expect, it } from 'vitest';
import { cellCount, type Omega } from '@atlasauth/pca-intent';
import { SHOP } from './fixtures.test-util';
import {
  betaQuantile,
  boundaryNeighbours,
  cellKey,
  clopperPearsonUpper,
  EMPTY_NOISE,
  estimateNoise,
  pickCanary,
  type CanaryContext,
  type NoiseCounts,
} from './index';

const seq = (...vals: number[]) => {
  let i = 0;
  return () => vals[i++] ?? 0.99;
};

describe('estimateNoise', () => {
  const n: NoiseCounts = { falseYes: 1, correctNo: 2, falseNo: 3, correctYes: 4 };
  it('rejects a confidence level outside the open interval (0, 1) with the exact message', () => {
    for (const d of [0, 1, -0.1, 1.5, Number.NaN]) expect(() => estimateNoise(n, d)).toThrow('estimateNoise: deltaC must be in (0, 1)');
    expect(() => estimateNoise(n, 0.5)).not.toThrow();
    expect(() => estimateNoise(n, 0.001)).not.toThrow();
    expect(() => estimateNoise(n, 0.999)).not.toThrow();
  });
  it('computes every member from the counts', () => {
    const d = 0.1;
    const e = estimateNoise(n, d);
    expect(e.etaPos).toBe(2 / 13);
    expect(e.etaNeg).toBe(4 / 17);
    expect(e.etaPosUpper).toBe(betaQuantile(1 - d, 2, 11));
    expect(e.etaNegUpper).toBe(betaQuantile(1 - d, 4, 13));
    expect(e.etaPosCP).toBe(clopperPearsonUpper(1, 3, d));
    expect(e.etaNegCP).toBe(clopperPearsonUpper(3, 7, d));
    expect(e.asked).toBe(10);
  });
  it('the Clopper-Pearson bounds are 1 only when there are no canaries of that kind', () => {
    const empty = estimateNoise(EMPTY_NOISE);
    expect(empty).toMatchObject({ etaPosCP: 1, etaNegCP: 1, asked: 0 });
    const onlyNo = estimateNoise({ ...EMPTY_NOISE, correctNo: 5 });
    expect(onlyNo.etaPosCP).toBe(clopperPearsonUpper(0, 5, 0.05));
    expect(onlyNo.etaPosCP).toBeLessThan(1);
    expect(onlyNo.etaNegCP).toBe(1);
    expect(onlyNo.asked).toBe(5);
    const onlyYes = estimateNoise({ ...EMPTY_NOISE, correctYes: 6 });
    expect(onlyYes.etaNegCP).toBe(clopperPearsonUpper(0, 6, 0.05));
    expect(onlyYes.etaNegCP).toBeLessThan(1);
    expect(onlyYes.etaPosCP).toBe(1);
    expect(onlyYes.asked).toBe(6);
  });
});

describe('cellKey and boundaryNeighbours', () => {
  const add = SHOP.verbs[0]!;
  const buy = SHOP.verbs[1]!;
  it('keys join the index with commas', () => {
    expect(cellKey('v', [1, 2])).toBe('v|1,2');
    expect(cellKey('v', [7])).toBe('v|7');
  });
  it('a middle cell has both numeric neighbours', () => {
    expect(boundaryNeighbours(SHOP, [{ verb: 'cart.add', idx: [4] }])).toEqual([
      { verb: 'cart.add', idx: [3] },
      { verb: 'cart.add', idx: [5] },
    ]);
  });
  it('the first and last cells have one neighbour each (range edges)', () => {
    const n = cellCount(add.dims[0]!);
    expect(boundaryNeighbours(SHOP, [{ verb: 'cart.add', idx: [0] }])).toEqual([{ verb: 'cart.add', idx: [1] }]);
    expect(boundaryNeighbours(SHOP, [{ verb: 'cart.add', idx: [n - 1] }])).toEqual([{ verb: 'cart.add', idx: [n - 2] }]);
    expect(boundaryNeighbours(SHOP, [{ verb: 'cart.add', idx: [1] }])).toEqual([
      { verb: 'cart.add', idx: [0] },
      { verb: 'cart.add', idx: [2] },
    ]);
  });
  it('uses the dimensions of the confirmed cell own verb', () => {
    const n = cellCount(buy.dims[0]!);
    expect(n).toBeLessThan(cellCount(add.dims[0]!));
    expect(boundaryNeighbours(SHOP, [{ verb: 'cart.buy', idx: [n - 1] }])).toEqual([{ verb: 'cart.buy', idx: [n - 2] }]);
  });
  it('skips a confirmed cell of an unknown verb', () => {
    expect(boundaryNeighbours(SHOP, [{ verb: 'nope', idx: [1] }, { verb: 'cart.add', idx: [4] }])).toEqual([
      { verb: 'cart.add', idx: [3] },
      { verb: 'cart.add', idx: [5] },
    ]);
  });
  it('excludes cells already inside the confirmed region', () => {
    expect(boundaryNeighbours(SHOP, [{ verb: 'cart.add', idx: [3] }, { verb: 'cart.add', idx: [4] }])).toEqual([
      { verb: 'cart.add', idx: [2] },
      { verb: 'cart.add', idx: [5] },
    ]);
  });
  it('a categorical dimension offers every other value; output is sorted by key', () => {
    const om: Omega = {
      v: 1,
      approximate: [],
      verbs: [
        {
          verb: 'v',
          reversibility: 'reversible',
          weight: 1,
          dims: [
            { kind: 'cat', path: 'action.params.c', values: [{ kind: 'exact', value: 'a' }, { kind: 'exact', value: 'b' }, { kind: 'exact', value: 'c' }] },
            add.dims[0]!,
          ],
        },
      ],
    };
    expect(boundaryNeighbours(om, [{ verb: 'v', idx: [1, 2] }]).map((c) => cellKey(c.verb, c.idx))).toEqual(['v|0,2', 'v|1,1', 'v|1,3', 'v|2,2']);
  });
  it('sorts descending insertion order into ascending key order', () => {
    const got = boundaryNeighbours(SHOP, [{ verb: 'cart.add', idx: [7] }, { verb: 'cart.add', idx: [2] }]);
    expect(got.map((c) => c.idx[0])).toEqual([1, 3, 6, 8]);
  });
});

describe('pickCanary', () => {
  const base = (over: Partial<CanaryContext> = {}): CanaryContext => ({
    omega: SHOP,
    confirmed: [{ verb: 'cart.add', idx: [4] }],
    knownNo: () => 'ceiling',
    knownYes: [],
    exclude: new Set<string>(),
    rand: seq(0, 0),
    rho: 0.5,
    lowHarmSession: false,
    canariesSoFar: 0,
    ...over,
  });
  it('rejects rho outside [0, 1] with the exact message and accepts the endpoints', () => {
    for (const rho of [-0.1, 1.1]) expect(() => pickCanary(base({ rho }))).toThrow('pickCanary: rho must be in [0, 1]');
    expect(pickCanary(base({ rho: 0 }))).toBeNull();
    expect(pickCanary(base({ rho: 1, rand: seq(0.999, 0) }))).not.toBeNull();
  });
  it('inserts only when rand is strictly below rho (default 0.1)', () => {
    expect(pickCanary(base({ rho: undefined, rand: seq(0.1, 0) }))).toBeNull();
    expect(pickCanary(base({ rho: undefined, rand: seq(0.05, 0) }))).not.toBeNull();
    expect(pickCanary(base({ rho: 0.5, rand: seq(0.5, 0) }))).toBeNull();
    expect(pickCanary(base({ rho: 0.5, rand: seq(0.49, 0) }))).not.toBeNull();
  });
  it('known-no choices come from non-excluded boundary cells and carry the reason', () => {
    expect(pickCanary(base())).toEqual({ verb: 'cart.add', idx: [3], expected: 0, source: 'ceiling' });
    expect(pickCanary(base({ exclude: new Set([cellKey('cart.add', [3])]) }))).toEqual({ verb: 'cart.add', idx: [5], expected: 0, source: 'ceiling' });
    expect(pickCanary(base({ knownNo: (_v, idx) => (idx[0] === 5 ? 'veto' : null) }))).toEqual({ verb: 'cart.add', idx: [5], expected: 0, source: 'veto' });
  });
  it('picks within a single pool by the second draw (clamped to the last element)', () => {
    expect(pickCanary(base({ rand: seq(0, 0) }))!.idx).toEqual([3]);
    expect(pickCanary(base({ rand: seq(0, 0.9) }))!.idx).toEqual([5]);
    expect(pickCanary(base({ rand: seq(0, 1) }))!.idx).toEqual([5]);
    const yes = [{ verb: 'cart.add', idx: [2] }, { verb: 'cart.add', idx: [6] }, { verb: 'cart.add', idx: [7] }];
    const only = (r: number) => pickCanary(base({ knownNo: () => null, knownYes: yes, rand: seq(0, r) }))!;
    expect(only(0).idx).toEqual([2]);
    expect(only(0.5).idx).toEqual([6]);
    expect(only(0.99).idx).toEqual([7]);
    expect(only(1).idx).toEqual([7]);
  });
  it('known-yes choices are copies, filtered by exclude, with expected 1', () => {
    const yes = [{ verb: 'cart.add', idx: [2] }, { verb: 'cart.add', idx: [6] }];
    const ctx = base({ knownNo: () => null, knownYes: yes, exclude: new Set([cellKey('cart.add', [2])]) });
    expect(pickCanary(ctx)).toEqual({ verb: 'cart.add', idx: [6], expected: 1, source: 'confirmed-yes' });
    expect(pickCanary(base({ knownNo: () => null, knownYes: yes, rand: seq(0, 0) }))).toEqual({ verb: 'cart.add', idx: [2], expected: 1, source: 'confirmed-yes' });
  });
  it('returns null when neither pool has a cell; a yes-only pool still yields a canary', () => {
    expect(pickCanary(base({ knownNo: () => null }))).toBeNull();
    expect(pickCanary(base({ knownNo: () => null, knownYes: [{ verb: 'cart.add', idx: [2] }] }))).not.toBeNull();
    expect(pickCanary(base({ knownYes: [{ verb: 'cart.add', idx: [2] }], exclude: new Set([cellKey('cart.add', [3]), cellKey('cart.add', [5]), cellKey('cart.add', [2])]) }))).toBeNull();
  });
  it('with both pools, a draw below 0.5 picks a known no and otherwise a known yes', () => {
    const yes = [{ verb: 'cart.add', idx: [7] }];
    const pick = (d: number) => pickCanary(base({ knownYes: yes, rand: seq(0, d, 0) }))!;
    expect(pick(0.4)).toMatchObject({ expected: 0, idx: [3] });
    expect(pick(0.5)).toMatchObject({ expected: 1, idx: [7] });
    expect(pick(0.6)).toMatchObject({ expected: 1, idx: [7] });
  });
});
