import { describe, expect, it } from 'vitest';
import type { Predicate } from '@atlasauth/pca';
import {
  admitter,
  auditRound,
  boxesToPredicates,
  cellRep,
  cellStats,
  decodeCell,
  DEFAULT_HARM,
  elicit,
  encodeCell,
  hypothesisCellSets,
  hypothesisClassName,
  IntentLearner,
  numCells,
  OTHER,
  rng,
  verbCellCount,
  type CatDim,
  type Dim,
  type HarmModel,
  type HypothesisClassSpec,
  type LearnerOptions,
  type NumDim,
  type Omega,
  type Outcome,
  type Question,
  type Region,
  type VerbSpace,
} from './index';

const P = 'action.params.';
const AMT = 'action.params.amount';

const num = (path: string, lo: number, hi: number, cuts: number[]): NumDim => ({ kind: 'num', path, lo, hi, cuts, dist: 'uniform' });
/** n single-value cells 0..n-1. */
const numN = (path: string, n: number): NumDim => num(path, 0, n - 1, Array.from({ length: n - 1 }, (_, i) => i + 1));
const cat = (path: string, exacts: string[] = [], prefixes: string[] = []): CatDim => ({
  kind: 'cat',
  path,
  values: [
    ...exacts.map((value) => ({ kind: 'exact' as const, value })),
    ...prefixes.map((value) => ({ kind: 'prefix' as const, value })),
    { kind: 'other' as const, value: OTHER },
  ],
});
const vspace = (verb: string, dims: Dim[], reversibility: VerbSpace['reversibility'] = 'reversible', weight = 1): VerbSpace => ({ verb, reversibility, weight, dims });
const omegaOf = (...verbs: VerbSpace[]): Omega => ({ v: 1, verbs, approximate: [] });
const range = (n: number): number[] => Array.from({ length: n }, (_, i) => i);
const nCellsOf = (vs: VerbSpace): number => verbCellCount(vs);

const V3 = vspace('v.a', [numN(P + 'a', 3)]);
const VU = vspace('v.u', [numN(P + 'a', 3), cat(P + 'k', ['a'])]);
const VK1 = vspace('v.k1', [numN(P + 'a', 3), cat(P + 'k')]);
const VA4 = vspace('v.a4', [numN(P + 'a', 4)]);
const VN5 = vspace('v.n5', [numN(P + 'a', 5)]);
const VC3 = vspace('v.c3', [cat(P + 'k', ['a', 'b'])]);
const V1 = vspace('v.1', [num(P + 'a', 0, 5, [])]);
const VR = vspace('v.r', [num(P + 'a', 0, 10, [3, 6])]);
const VMX = vspace('v.mx', [num(AMT, 0, 10, [3, 6])]);

// ---- independent references ---------------------------------------------------------------------------------

function choices(d: Dim): number[][] {
  const n = d.kind === 'num' ? numCells(d).length : d.values.length;
  const out: number[][] = [];
  if (d.kind === 'num') {
    for (let i = 0; i < n; i++) for (let j = i; j < n; j++) out.push(range(j - i + 1).map((x) => i + x));
  } else {
    for (let mask = 1; mask < 1 << n; mask++) out.push(range(n).filter((x) => (mask >> x) & 1));
  }
  return out;
}

/** Every box of a verb as a sorted list of flat cells. */
function boxCellSets(vs: VerbSpace): number[][] {
  const per = vs.dims.map(choices);
  const N = nCellsOf(vs);
  const out: number[][] = [];
  const rec = (k: number, pick: number[][]): void => {
    if (k === per.length) {
      out.push(range(N).filter((c) => decodeCell(vs, c).every((x, i) => pick[i]!.includes(x))));
      return;
    }
    for (const ch of per[k]!) rec(k + 1, [...pick, ch]);
  };
  rec(0, []);
  return out;
}

const keyOfCells = (cells: readonly number[], N: number): string => range(N).map((c) => (cells.includes(c) ? '1' : '0')).join('');
const keyOfMask = (m: Uint8Array): string => Array.from(m).join('');
const cmpEntry = (a: readonly [string, number], b: readonly [string, number]): number => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);

function canon(r: { sets: Uint8Array[]; complexity: number[] }): [string, number][] {
  expect(r.complexity.length).toBe(r.sets.length);
  return r.sets.map((s, i) => [keyOfMask(s), r.complexity[i]!] as [string, number]).sort(cmpEntry);
}

function bruteUnions(vs: VerbSpace, k: number): [string, number][] {
  const N = nCellsOf(vs);
  const boxes = boxCellSets(vs).map((b) => new Set(b));
  const levels: Map<string, Set<number>>[] = [new Map()];
  for (const b of boxes) levels[0]!.set(keyOfCells([...b], N), b);
  for (let j = 2; j <= k; j++) {
    const next = new Map<string, Set<number>>();
    for (const s of levels[j - 2]!.values()) for (const b of boxes) {
      const u = new Set([...s, ...b]);
      next.set(keyOfCells([...u], N), u);
    }
    levels.push(next);
  }
  const best = new Map<string, number>();
  levels.forEach((lv, i) => {
    for (const key of lv.keys()) if (!best.has(key)) best.set(key, i + 1);
  });
  return [...best].sort(cmpEntry);
}

/** Atomic one-dimensional tests as lists of flat cells. */
function atomicCells(vs: VerbSpace): number[][] {
  const N = nCellsOf(vs);
  const tests: number[][] = [];
  vs.dims.forEach((d, k) => {
    const n = d.kind === 'num' ? numCells(d).length : d.values.length;
    const add = (pred: (x: number) => boolean): void => {
      const cells = range(N).filter((c) => pred(decodeCell(vs, c)[k]!));
      if (cells.length > 0 && cells.length < N) tests.push(cells);
    };
    if (d.kind === 'num') {
      for (let i = 0; i < n - 1; i++) add((x) => x <= i);
      for (let i = 1; i < n; i++) add((x) => x >= i);
      if (n > 2) for (let i = 1; i < n - 1; i++) add((x) => x === i);
    } else for (let i = 0; i < n; i++) add((x) => x === i);
  });
  return tests;
}

function bruteLists(tests: number[][], N: number, L: number): [string, number][] {
  const best = new Map<string, number>();
  const rec = (rules: { t: Set<number>; label: 0 | 1 }[]): void => {
    for (const def of [0, 1]) {
      const bits = range(N).map((c) => {
        const r = rules.find((x) => x.t.has(c));
        return r ? r.label : def;
      });
      if (bits.some((b) => b === 1)) {
        const key = bits.join('');
        const cx = Math.max(1, rules.length);
        const prev = best.get(key);
        if (prev === undefined || cx < prev) best.set(key, cx);
      }
    }
    if (rules.length < L) for (const t of tests) for (const label of [0, 1] as const) rec([...rules, { t: new Set(t), label }]);
  };
  rec([]);
  return [...best].sort(cmpEntry);
}

/** The number of (state, test, label) steps the decision-list enumeration performs. */
function dlWork(tests: number[][], N: number, L: number): number {
  let frontier = [{ decided: new Array<number>(N).fill(0), acc: new Array<number>(N).fill(0) }];
  let work = 0;
  for (let depth = 1; depth <= L; depth++) {
    const states = new Map<string, { decided: number[]; acc: number[] }>();
    for (const st of frontier) {
      for (const t of tests) {
        for (const label of [0, 1]) {
          work++;
          const decided = [...st.decided];
          const acc = [...st.acc];
          let fresh = false;
          for (let c = 0; c < N; c++) {
            if (!st.decided[c] && t.includes(c)) {
              decided[c] = 1;
              acc[c] = label;
              fresh = true;
            }
          }
          if (!fresh) continue;
          states.set(decided.join('') + '|' + acc.join(''), { decided, acc });
        }
      }
    }
    frontier = [...states.values()];
  }
  return work;
}

interface Hyp {
  cells: Set<number>;
  w: number;
}
const norm = (hs: Hyp[]): Hyp[] => {
  const s = hs.reduce((a, h) => a + h.w, 0);
  if (s > 0) hs.forEach((h) => (h.w /= s));
  return hs;
};
function refPrior(sets: number[][], nm = 0.2, raw: number[] = sets.map(() => 1)): Hyp[] {
  const z = raw.reduce((a, b) => a + b, 0);
  return norm([{ cells: new Set<number>(), w: nm }, ...sets.map((s, i) => ({ cells: new Set(s), w: ((1 - nm) * raw[i]!) / z }))]);
}
const refP = (hs: Hyp[], c: number): number => hs.reduce((a, h) => a + (h.cells.has(c) ? h.w : 0), 0);
function refObserve(hs: Hyp[], cells: number[], y: 0 | 1, etaPos = 0, etaNeg = 0): void {
  const prev = hs.map((h) => h.w);
  for (const h of hs) {
    const inH = cells.every((c) => h.cells.has(c));
    h.w *= inH ? (y === 1 ? 1 - etaNeg : etaNeg) : y === 1 ? etaPos : 1 - etaPos;
  }
  if (hs.reduce((a, h) => a + h.w, 0) === 0) hs.forEach((h, i) => (h.w = prev[i]!));
  else norm(hs);
}
function expectPosterior(l: IntentLearner, vs: VerbSpace, hs: Hyp[], digits = 10): void {
  for (const c of range(nCellsOf(vs))) expect(l.acceptance(cellRep(vs, decodeCell(vs, c)))).toBeCloseTo(refP(hs, c), digits);
}
const rep = (vs: VerbSpace, ...idx: number[]): Outcome => cellRep(vs, idx);
const flatOf = (vs: VerbSpace, ...idx: number[]): number => encodeCell(vs, idx);

const binEnt = (p: number): number => (p <= 0 || p >= 1 ? 0 : -(p * Math.log2(p) + (1 - p) * Math.log2(1 - p)));

// ---- names, defaults, validation ----------------------------------------------------------------------------

describe('learner: class names, defaults and option validation', () => {
  it('names every hypothesis class', () => {
    expect(hypothesisClassName({ kind: 'box' })).toBe('per-verb-box/v1');
    expect(hypothesisClassName({ kind: 'union', k: 2 })).toBe('per-verb-union/v1');
    expect(hypothesisClassName({ kind: 'decision-list', maxRules: 2 })).toBe('per-verb-decision-list/v2');
    expect(hypothesisClassName({ kind: 'decision-list', maxRules: 2, conditions: 'box' })).toBe('per-verb-decision-list/v2');
    expect(hypothesisClassName({ kind: 'decision-list', maxRules: 2, conditions: 'atomic' })).toBe('per-verb-decision-list/v1');
  });

  it('defaults', () => {
    const l = new IntentLearner(omegaOf(V3));
    expect(l.hypothesisClass).toEqual({ kind: 'box' });
    expect(l.strategy).toBe('disagreement');
    expect(l.harm).toBe(DEFAULT_HARM);
    expect(l.eta).toBe(0);
    expect(l.etaPos).toBe(0);
    expect(l.etaNeg).toBe(0);
    expect(l.tau).toBe(1);
    expect(l.metrics().log2VersionSpace).not.toBeNull();
    const custom: HarmModel = { verb: () => 2, dim: () => 1 };
    expect(new IntentLearner(omegaOf(V3), { harm: custom }).harm).toBe(custom);
    expect(new IntentLearner(omegaOf(V3), { strategy: 'risk' }).strategy).toBe('risk');
  });

  it('rejects eta outside [0, 0.5)', () => {
    for (const eta of [-0.1, 0.5, 0.7]) expect(() => new IntentLearner(omegaOf(V3), { eta })).toThrow('pca-intent: eta must be in [0, 0.5)');
    expect(() => new IntentLearner(omegaOf(V3), { eta: 0 })).not.toThrow();
    expect(() => new IntentLearner(omegaOf(V3), { eta: 0.49 })).not.toThrow();
  });

  it('rejects etaPos / etaNeg outside [0, 0.5)', () => {
    const m = 'pca-intent: etaPos and etaNeg must be in [0, 0.5)';
    for (const o of [{ etaPos: -0.1 }, { etaPos: 0.5 }, { etaPos: 0.7 }, { etaNeg: -0.1 }, { etaNeg: 0.5 }, { etaNeg: 0.7 }]) {
      expect(() => new IntentLearner(omegaOf(V3), o)).toThrow(m);
    }
    expect(() => new IntentLearner(omegaOf(V3), { etaPos: 0, etaNeg: 0.49 })).not.toThrow();
  });

  it('either asymmetric rate alone makes the learner noisy', () => {
    const a = new IntentLearner(omegaOf(V3), { etaNeg: 0.1 });
    expect(a.tau).toBe(0.95);
    expect(a.etaPos).toBe(0);
    expect(a.etaNeg).toBe(0.1);
    expect(a.metrics().log2VersionSpace).toBeNull();
    const b = new IntentLearner(omegaOf(V3), { etaPos: 0.1 });
    expect(b.tau).toBe(0.95);
    expect(b.metrics().log2VersionSpace).toBeNull();
    const c = new IntentLearner(omegaOf(V3), { eta: 0.2, etaPos: 0.1 });
    expect([c.etaPos, c.etaNeg]).toEqual([0.1, 0.2]);
  });

  it('validates the agnostic slack', () => {
    const m = 'pca-intent: agnosticSlack must be a non-negative integer';
    for (const agnosticSlack of [-1, 1.5]) expect(() => new IntentLearner(omegaOf(V3), { agnosticSlack })).toThrow(m);
    expect(() => new IntentLearner(omegaOf(V3), { agnosticSlack: 0 })).not.toThrow();
    expect(() => new IntentLearner(omegaOf(V3), { agnosticSlack: 2 })).not.toThrow();
    expect(() => new IntentLearner(omegaOf(V3), { agnosticSlack: 1, eta: 0.1 })).toThrow('pca-intent: agnostic selection replaces the noise model; use eta = 0');
  });

  it('validates the decay of the richer classes', () => {
    for (const decay of [0, -1, 1.5]) {
      expect(() => new IntentLearner(omegaOf(V3), { hypothesisClass: { kind: 'union', k: 2, decay } })).toThrow('pca-intent: decay must be in (0, 1]');
    }
    expect(() => new IntentLearner(omegaOf(V3), { hypothesisClass: { kind: 'union', k: 2, decay: 1 } })).not.toThrow();
  });

  it('validates the null mass', () => {
    for (const nullMass of [-0.1, 1.5]) expect(() => new IntentLearner(omegaOf(V3), { nullMass })).toThrow('pca-intent: nullMass must be in [0, 1]');
    expect(() => new IntentLearner(omegaOf(V3), { nullMass: () => 2 })).toThrow('pca-intent: nullMass must be in [0, 1]');
    expect(() => new IntentLearner(omegaOf(V3), { nullMass: 0 })).not.toThrow();
    expect(() => new IntentLearner(omegaOf(V3), { nullMass: 1 })).not.toThrow();
  });

  it('validates the union and decision-list parameters', () => {
    for (const k of [0, -1, 1.5]) expect(() => hypothesisCellSets(V3, { kind: 'union', k })).toThrow('pca-intent: union class needs an integer k ≥ 1');
    expect(() => hypothesisCellSets(V3, { kind: 'union', k: 1 })).not.toThrow();
    for (const maxRules of [0, -1, 1.5]) {
      expect(() => hypothesisCellSets(V3, { kind: 'decision-list', maxRules })).toThrow('pca-intent: decision-list class needs an integer maxRules ≥ 1');
    }
    expect(() => hypothesisCellSets(V3, { kind: 'decision-list', maxRules: 1 })).not.toThrow();
  });

  it('asks the cost model once per cell when the verb model is built', () => {
    let calls = 0;
    const harm: HarmModel = {
      verb: (vs) => {
        calls++;
        return DEFAULT_HARM.verb(vs);
      },
      dim: DEFAULT_HARM.dim,
    };
    new IntentLearner(omegaOf(V3, VU), { harm });
    expect(calls).toBe(nCellsOf(V3) + nCellsOf(VU));
  });
});

// ---- enumeration of the hypothesis classes -------------------------------------------------------------------

describe('learner: hypothesis enumeration', () => {
  it('the box class is every contiguous range / non-empty subset product', () => {
    for (const vs of [VU, VC3, VN5, VK1]) {
      const N = nCellsOf(vs);
      const expected = boxCellSets(vs)
        .map((b) => [keyOfCells(b, N), 1] as [string, number])
        .sort(cmpEntry);
      expect(canon(hypothesisCellSets(vs))).toEqual(expected);
    }
  });

  it('a categorical dimension of 20 values is enumerated, 21 is refused', () => {
    const wide = (n: number): VerbSpace => vspace('v.w', [cat(P + 'k', range(n - 1).map((i) => 'v' + String(i).padStart(2, '0')))]);
    expect(() => new IntentLearner(omegaOf(wide(21)))).toThrow('pca-intent: categorical dimension action.params.k has 21 values (max 20 for exact enumeration)');
    expect(() => new IntentLearner(omegaOf(wide(20)))).toThrow('pca-intent: |Θ_v.w| = 1048576 exceeds maxHypotheses 400000; coarsen the cuts');
  });

  it('the box class respects maxHypotheses exactly', () => {
    const B = boxCellSets(VU).length;
    expect(() => hypothesisCellSets(VU, { kind: 'box' }, { maxHypotheses: B + 1 })).not.toThrow();
    expect(() => hypothesisCellSets(VU, { kind: 'box' }, { maxHypotheses: B })).toThrow(`pca-intent: |Θ_v.u| = ${B + 1} exceeds maxHypotheses ${B}; coarsen the cuts`);
  });

  it('unions of at most k boxes, with the fewest-boxes complexity', () => {
    for (const [vs, k] of [[VU, 1], [VU, 2], [VK1, 2], [VC3, 2], [VN5, 3]] as [VerbSpace, number][]) {
      expect(canon(hypothesisCellSets(vs, { kind: 'union', k }))).toEqual(bruteUnions(vs, k));
    }
    // a 3-box union exists only at k = 3
    const n3 = bruteUnions(VN5, 3).filter(([, cx]) => cx === 3);
    expect(n3.length).toBeGreaterThan(0);
  });

  it('the union class respects the set cap and the enumeration cap exactly', () => {
    const B = boxCellSets(VU).length;
    const N = bruteUnions(VU, 2).length;
    expect(() => hypothesisCellSets(VU, { kind: 'union', k: 2 }, { maxHypotheses: N + 1 })).not.toThrow();
    expect(() => hypothesisCellSets(VU, { kind: 'union', k: 2 }, { maxHypotheses: N })).toThrow(`pca-intent: |Θ_v.u| = ${N + 1} exceeds maxHypotheses ${N}; coarsen the cuts`);
    expect(() => hypothesisCellSets(VU, { kind: 'union', k: 1 }, { maxEnumeration: B })).not.toThrow();
    expect(() => hypothesisCellSets(VU, { kind: 'union', k: 1 }, { maxEnumeration: B - 1 })).toThrow(`pca-intent: ${B} boxes for v.u exceed the enumeration cap; coarsen the cuts`);
    expect(() => hypothesisCellSets(VU, { kind: 'union', k: 2 }, { maxEnumeration: B * B })).not.toThrow();
    expect(() => hypothesisCellSets(VU, { kind: 'union', k: 2 }, { maxEnumeration: B * B - 1 })).toThrow(
      'pca-intent: the union-of-2-boxes class for v.u exceeds the enumeration cap; coarsen the cuts or lower k',
    );
  });

  it('atomic decision lists equal every first-match list over the one-dimensional tests', () => {
    for (const [vs, L] of [[VU, 1], [VU, 2], [VK1, 2], [VA4, 3]] as [VerbSpace, number][]) {
      const spec: HypothesisClassSpec = { kind: 'decision-list', maxRules: L, conditions: 'atomic' };
      expect(canon(hypothesisCellSets(vs, spec))).toEqual(bruteLists(atomicCells(vs), nCellsOf(vs), L));
    }
  });

  it('box-condition decision lists equal every first-match list over the boxes', () => {
    for (const [vs, L] of [[VU, 1], [VU, 2], [VA4, 2]] as [VerbSpace, number][]) {
      const spec: HypothesisClassSpec = { kind: 'decision-list', maxRules: L };
      expect(canon(hypothesisCellSets(vs, spec))).toEqual(bruteLists(boxCellSets(vs), nCellsOf(vs), L));
    }
  });

  it('the first decision list is "accept everything", at complexity 1', () => {
    for (const conditions of ['atomic', 'box'] as const) {
      const r = hypothesisCellSets(VU, { kind: 'decision-list', maxRules: 2, conditions });
      expect(Array.from(r.sets[0]!)).toEqual(new Array(nCellsOf(VU)).fill(1));
      expect(r.complexity[0]).toBe(1);
      for (const s of r.sets) expect(Array.from(s).some((x) => x === 1)).toBe(true);
    }
  });

  it('the decision-list class respects the set cap', () => {
    const spec: HypothesisClassSpec = { kind: 'decision-list', maxRules: 2, conditions: 'atomic' };
    const N = bruteLists(atomicCells(VU), nCellsOf(VU), 2).length;
    expect(() => hypothesisCellSets(VU, spec, { maxHypotheses: N + 1 })).not.toThrow();
    expect(() => hypothesisCellSets(VU, spec, { maxHypotheses: N })).toThrow(`pca-intent: |Θ_v.u| = ${N + 1} exceeds maxHypotheses ${N}; coarsen the cuts`);
  });

  it('the decision-list work cap is exactly the number of steps taken', () => {
    const T = atomicCells(VU).length;
    const one: HypothesisClassSpec = { kind: 'decision-list', maxRules: 1, conditions: 'atomic' };
    expect(() => hypothesisCellSets(VU, one, { maxEnumeration: 2 * T })).not.toThrow();
    expect(() => hypothesisCellSets(VU, one, { maxEnumeration: 2 * T - 1 })).toThrow('pca-intent: the decision-list class (≤ 1 rules) for v.u exceeds the enumeration cap');

    const three: HypothesisClassSpec = { kind: 'decision-list', maxRules: 3, conditions: 'atomic' };
    const W3 = dlWork(atomicCells(VA4), nCellsOf(VA4), 3);
    expect(() => hypothesisCellSets(VA4, three, { maxEnumeration: W3 })).not.toThrow();
    expect(() => hypothesisCellSets(VA4, three, { maxEnumeration: W3 - 1 })).toThrow('pca-intent: the decision-list class (≤ 3 rules) for v.a4 exceeds the enumeration cap');

    const boxTwo: HypothesisClassSpec = { kind: 'decision-list', maxRules: 2 };
    const W2 = dlWork(boxCellSets(VA4), nCellsOf(VA4), 2);
    expect(() => hypothesisCellSets(VA4, boxTwo, { maxEnumeration: W2 })).not.toThrow();
    expect(() => hypothesisCellSets(VA4, boxTwo, { maxEnumeration: W2 - 1 })).toThrow('exceeds the enumeration cap');
    const B = boxCellSets(VA4).length;
    expect(() => hypothesisCellSets(VA4, { kind: 'decision-list', maxRules: 1 }, { maxEnumeration: B - 1 })).toThrow(`pca-intent: ${B} boxes for v.a4 exceed the enumeration cap; coarsen the cuts`);
  });
});

// ---- the prior ----------------------------------------------------------------------------------------------

describe('learner: the prior', () => {
  it('null mass 0.2 by default, the rest uniform over the boxes', () => {
    const l = new IntentLearner(omegaOf(V3));
    expectPosterior(l, V3, refPrior(boxCellSets(V3), 0.2), 12);
  });

  it('a numeric or per-verb null mass', () => {
    expectPosterior(new IntentLearner(omegaOf(V3), { nullMass: 0.5 }), V3, refPrior(boxCellSets(V3), 0.5), 12);
    expectPosterior(new IntentLearner(omegaOf(V3), { nullMass: 0 }), V3, refPrior(boxCellSets(V3), 0), 12);
    const l = new IntentLearner(omegaOf(V3, VR), { nullMass: (vs) => (vs.verb === 'v.a' ? 0.5 : 0.1) });
    expectPosterior(l, V3, refPrior(boxCellSets(V3), 0.5), 12);
    expectPosterior(l, VR, refPrior(boxCellSets(VR), 0.1), 12);
    const all = new IntentLearner(omegaOf(V3), { nullMass: 1 });
    for (const c of range(3)) expect(all.acceptance(rep(V3, c))).toBe(0);
    expect(all.admitsOutcome(rep(V3, 0))).toBe(false);
  });

  it('counts the live hypotheses and the entropy of the prior', () => {
    const l = new IntentLearner(omegaOf(V3), { nullMass: 0 });
    const m = l.metrics();
    expect(m.log2VersionSpace).toBeCloseTo(Math.log2(6), 12);
    expect(m.entropyBits).toBeCloseTo(Math.log2(6), 12);
    const l2 = new IntentLearner(omegaOf(V3));
    const hs = refPrior(boxCellSets(V3), 0.2);
    expect(l2.metrics().entropyBits).toBeCloseTo(-hs.reduce((a, h) => a + h.w * Math.log2(h.w), 0), 12);
    expect(l2.metrics().log2VersionSpace).toBeCloseTo(Math.log2(7), 12);
  });

  it('the Occam decay of a union class', () => {
    const sets = bruteUnions(V3, 2);
    const cellsOf = (key: string): number[] => range(3).filter((c) => key[c] === '1');
    for (const decay of [undefined, 0.5, 1]) {
      const spec: HypothesisClassSpec = decay === undefined ? { kind: 'union', k: 2 } : { kind: 'union', k: 2, decay };
      const d = decay ?? 0.25;
      const hs = refPrior(
        sets.map(([k]) => cellsOf(k)),
        0.2,
        sets.map(([, cx]) => Math.pow(d, cx - 1)),
      );
      expectPosterior(new IntentLearner(omegaOf(V3), { hypothesisClass: spec }), V3, hs, 12);
    }
  });
});

describe('learner: anchored priors', () => {
  const VW = vspace('v.a', [numN(P + 'a', 3)], 'reversible', 0.5);
  const pol = (...where: { field: string; op: string; value: unknown }[][]) => ({
    predicates: where.map((w) => ({ verb: 'v.a', resource: '*', where: w })) as unknown as Predicate[],
    caveats: [],
  });
  const lte1 = pol([{ field: P + 'a', op: 'lte', value: 1 }]);
  const gte1 = pol([{ field: P + 'a', op: 'gte', value: 1 }]);
  const accOf = (policy: ReturnType<typeof pol>): number[] => {
    const adm = admitter(policy);
    return range(3).map((c) => (adm.admits(VW, rep(VW, c)) ? 1 : 0));
  };
  function refAnchor(hs: Hyp[], anchors: { acc: number[]; lambda: number }[]): void {
    const mass = range(3).map((c) => cellStats(VW, [c]).mass);
    const tot = mass.reduce((a, b) => a + b, 0);
    for (const h of hs) {
      let mix = 0;
      for (const a of anchors) {
        const dist = range(3).reduce((s, c) => s + ((h.cells.has(c) ? 1 : 0) !== a.acc[c]! ? mass[c]! : 0), 0);
        mix += Math.exp((-a.lambda * dist) / tot);
      }
      h.w *= mix / anchors.length;
    }
    norm(hs);
  }

  it('w ∝ exp(−λ·d(θ, anchor)) with d the μ-mass of the symmetric difference, normalised by the verb mass', () => {
    expect(accOf(lte1)).toEqual([1, 1, 0]);
    expect(accOf(gte1)).toEqual([0, 1, 1]);
    const hs = refPrior(boxCellSets(VW), 0.2);
    refAnchor(hs, [{ acc: [1, 1, 0], lambda: 2 }]);
    expectPosterior(new IntentLearner(omegaOf(VW), { anchor: { policy: lte1, lambda: 2 } }), VW, hs, 10);
  });

  it('a mixture of anchors is the mean of the per-anchor factors; anchor and anchors combine', () => {
    const hs = refPrior(boxCellSets(VW), 0.2);
    refAnchor(hs, [
      { acc: [1, 1, 0], lambda: 1 },
      { acc: [0, 1, 1], lambda: 3 },
    ]);
    const a = new IntentLearner(omegaOf(VW), { anchors: [{ policy: lte1, lambda: 1 }, { policy: gte1, lambda: 3 }] });
    expectPosterior(a, VW, hs, 10);
    const b = new IntentLearner(omegaOf(VW), { anchor: { policy: lte1, lambda: 1 }, anchors: [{ policy: gte1, lambda: 3 }] });
    expectPosterior(b, VW, hs, 10);
  });

  it('an anchor with a non-positive weight is ignored', () => {
    const hs = refPrior(boxCellSets(VW), 0.2);
    refAnchor(hs, [{ acc: [1, 1, 0], lambda: 2 }]);
    const l = new IntentLearner(omegaOf(VW), {
      anchors: [
        { policy: lte1, lambda: 2 },
        { policy: gte1, lambda: 0 },
        { policy: gte1, lambda: -3 },
      ],
    });
    expectPosterior(l, VW, hs, 10);
  });

  it('a zero-mass verb keeps its prior (the distance is normalised by max(mass, 1))', () => {
    const V0 = vspace('v.a', [numN(P + 'a', 3)], 'reversible', 0);
    const l = new IntentLearner(omegaOf(V0), { anchor: { policy: lte1, lambda: 5 } });
    expectPosterior(l, V0, refPrior(boxCellSets(V0), 0.2), 10);
  });

  it('a prior with no live hypothesis admits nothing (and never NaN)', () => {
    const two = pol([{ field: P + 'a', op: 'lte', value: 0 }], [{ field: P + 'a', op: 'gte', value: 2 }]);
    expect(accOf(two)).toEqual([1, 0, 1]);
    const l = new IntentLearner(omegaOf(V3), { anchor: { policy: two, lambda: 1e6 } });
    for (const c of range(3)) {
      expect(l.acceptance(rep(V3, c))).toBe(0);
      expect(l.admitsOutcome(rep(V3, c))).toBe(false);
    }
    expect(l.cells().every((v) => v.p === 0 && !v.inGrant)).toBe(true);
    const m = l.metrics();
    expect(m.entropyBits).toBe(0);
    expect(m.log2VersionSpace).toBe(0);
    expect(m.disagreementMass).toBe(0);
    expect(l.nextQuestion()).toBeNull();
    expect(l.synthesize()).toEqual({ predicates: [], caveats: [] });
  });
});

describe('learner: monotone prior', () => {
  const VM = vspace('v.m', [numN(P + 'x', 2), numN(P + 'a', 3), cat(P + 'k', ['k1'])]);
  const N = nCellsOf(VM);
  const isMono = (set: Set<number>, ks: number[]): boolean => {
    for (const c of set) {
      const idx = decodeCell(VM, c);
      for (const k of ks) {
        if (idx[k]! > 0) {
          const lower = [...idx];
          lower[k] = lower[k]! - 1;
          if (!set.has(encodeCell(VM, lower))) return false;
        }
      }
    }
    return true;
  };
  const ref = (ks: number[], off: number): Hyp[] => {
    const hs = refPrior(boxCellSets(VM), 0.2);
    for (const h of hs.slice(1)) if (!isMono(h.cells, ks)) h.w *= off;
    return norm(hs);
  };

  it('scales every non-downward-closed hypothesis by offMass', () => {
    const cases: [string[], number[]][] = [
      [[P + 'a'], [1]],
      [[P + 'a', P + 'x'], [0, 1]],
      [[P + 'a', P + 'k'], [1]], // a categorical path is never monotone-checked
      [['no.such.path'], []],
    ];
    for (const [paths, ks] of cases) {
      for (const off of [0, 0.5, 1, undefined]) {
        const l = new IntentLearner(omegaOf(VM), { monotone: off === undefined ? { paths } : { paths, offMass: off } });
        const hs = ref(ks, off ?? 0);
        for (const c of range(N)) expect(l.acceptance(rep(VM, ...decodeCell(VM, c)))).toBeCloseTo(refP(hs, c), 10);
      }
    }
  });

  it('rejects an offMass outside [0, 1]', () => {
    for (const offMass of [-0.1, 1.5]) {
      expect(() => new IntentLearner(omegaOf(VM), { monotone: { paths: [P + 'a'], offMass } })).toThrow('pca-intent: monotone.offMass must be in [0, 1]');
    }
    expect(() => new IntentLearner(omegaOf(VM), { monotone: { paths: [P + 'a'], offMass: 1 } })).not.toThrow();
    expect(() => new IntentLearner(omegaOf(VM), { monotone: { paths: [P + 'a'], offMass: 0 } })).not.toThrow();
  });
});

// ---- observing -----------------------------------------------------------------------------------------------

describe('learner: observe and the guards around it', () => {
  const unknown: Outcome = { verb: 'no.such', values: {} };
  const outside: Outcome = { verb: 'v.r', values: { [P + 'a']: 999 } };

  it('an outcome outside Ω is conservative everywhere', () => {
    const l = new IntentLearner(omegaOf(VR));
    l.observe(rep(VR, 1), 0, 'runtime');
    for (const o of [unknown, outside]) {
      expect(l.acceptance(o)).toBe(0);
      expect(l.admitsOutcome(o)).toBe(false);
      expect(l.isVetoed(o)).toBe(false);
      expect(l.observe(o, 1)).toBeNull();
    }
    expect(l.observations.length).toBe(1);
  });

  it('records the outcome, its cell, the answer and the default source', () => {
    const l = new IntentLearner(omegaOf(VR));
    const o = rep(VR, 2);
    const obs = l.observe(o, 1)!;
    expect(obs).toEqual({ verb: 'v.r', values: o.values, cell: [2], y: 1, source: 'elicitation' });
    expect('region' in obs).toBe(false);
    expect(obs.values).not.toBe(o.values);
  });

  const region: Region = { verb: 'v.r', dims: { [P + 'a']: { kind: 'num', lo: 2, hi: 4 } } };

  it('a "yes" about a region claims the cells wholly inside it', () => {
    const l = new IntentLearner(omegaOf(VR));
    const hs = refPrior(boxCellSets(VR), 0.2);
    refObserve(hs, [1], 1);
    const obs = l.observe(rep(VR, 1), 1, 'elicitation', region)!;
    expect(obs.region).toEqual(region);
    expect(obs.cell).toEqual([1]);
    expectPosterior(l, VR, hs);
    expect(l.acceptance(rep(VR, 1))).toBe(1);
    expect(l.acceptance(rep(VR, 0))).toBeLessThan(1);
  });

  it('a "no" about a region rules out hypotheses containing every cell that meets it', () => {
    const l = new IntentLearner(omegaOf(VR));
    const hs = refPrior(boxCellSets(VR), 0.2);
    refObserve(hs, [0, 1, 2], 0);
    l.observe(rep(VR, 1), 0, 'elicitation', region);
    expectPosterior(l, VR, hs);
  });

  it('a region that covers no cell is not an observation', () => {
    const l = new IntentLearner(omegaOf(VR));
    const hs = refPrior(boxCellSets(VR), 0.2);
    const tiny: Region = { verb: 'v.r', dims: { [P + 'a']: { kind: 'num', lo: 1, hi: 2 } } };
    expect(l.observe(rep(VR, 1), 1, 'elicitation', tiny)).toBeNull();
    expect(l.observations.length).toBe(0);
    expectPosterior(l, VR, hs);
  });

  it('a runtime "no" vetoes the cell for good; a runtime "yes" and an elicited "no" do not', () => {
    const V2 = vspace('v.b', [numN(P + 'a', 2)]);
    const l = new IntentLearner(omegaOf(V3, V2));
    expect(l.vetoedCells()).toEqual([]);
    l.observe(rep(V3, 1), 0, 'runtime');
    l.observe(rep(V2, 1), 0, 'runtime');
    l.observe(rep(V3, 2), 1, 'runtime');
    l.observe(rep(V3, 0), 0, 'elicitation');
    expect(l.vetoedCells()).toEqual(['v.a|1', 'v.b|1']);
    expect(l.isVetoed(rep(V3, 1))).toBe(true);
    expect(l.isVetoed(rep(V3, 2))).toBe(false);
    expect(l.isVetoed(rep(V3, 0))).toBe(false);
    const view = l.cells().filter((v) => v.vetoed).map((v) => `${v.verb}|${flatOf(V3.verb === v.verb ? V3 : V2, ...v.cell)}`);
    expect(view).toEqual(['v.a|1', 'v.b|1']);
    expect(l.cells().filter((v) => v.vetoed).every((v) => !v.inGrant)).toBe(true);
  });

  it('exact Bayesian updates under asymmetric and symmetric noise', () => {
    const seq: [number, 0 | 1][] = [[0, 1], [1, 0], [0, 1], [2, 1], [1, 0]];
    for (const [opts, ep, en] of [
      [{ etaPos: 0.1, etaNeg: 0.3 }, 0.1, 0.3],
      [{ eta: 0.2, etaPos: 0.1 }, 0.1, 0.2],
      [{ eta: 0.2 }, 0.2, 0.2],
    ] as [LearnerOptions, number, number][]) {
      const l = new IntentLearner(omegaOf(V3), opts);
      const hs = refPrior(boxCellSets(V3), 0.2);
      for (const [c, y] of seq) {
        l.observe(rep(V3, c), y);
        refObserve(hs, [c], y, ep, en);
        expectPosterior(l, V3, hs, 10);
      }
    }
  });

  it('a contradicted posterior is kept, flagged as a conflict, and a "no" is honoured by veto', () => {
    const l = new IntentLearner(omegaOf(V3));
    const hs = refPrior(boxCellSets(V3), 0.2);
    l.observe(rep(V3, 1), 1);
    refObserve(hs, [1], 1);
    const o = l.observe(rep(V3, 1), 0)!;
    expect(o.conflict).toBe(true);
    expect(l.isVetoed(rep(V3, 1))).toBe(true);
    expectPosterior(l, V3, hs);
    expect(l.metrics().conflicts).toBe(1);
  });

  it('a conflict under one-sided noise: restored posterior, veto only for a "no"', () => {
    // η⁺ = 0: a "yes" rules out the deny hypothesis; with all the mass on it the answer is unexplainable
    const a = new IntentLearner(omegaOf(V1), { etaPos: 0, etaNeg: 0.1, nullMass: 1 });
    const oa = a.observe(rep(V1, 0), 1)!;
    expect(oa.conflict).toBe(true);
    expect(a.isVetoed(rep(V1, 0))).toBe(false);
    expect(a.acceptance(rep(V1, 0))).toBe(0);
    // η⁻ = 0: a "no" rules out the only hypothesis that accepts; the posterior is restored
    const b = new IntentLearner(omegaOf(V1), { etaPos: 0.1, etaNeg: 0, nullMass: 0 });
    const ob = b.observe(rep(V1, 0), 0)!;
    expect(ob.conflict).toBe(true);
    expect(b.isVetoed(rep(V1, 0))).toBe(true);
    expect(b.acceptance(rep(V1, 0))).toBe(1);
  });

  it('replay reproduces the learner, regions and sources included', () => {
    const region: Region = { verb: 'v.r', dims: { [P + 'a']: { kind: 'num', lo: 2, hi: 4 } } };
    const opts: LearnerOptions = { eta: 0.1 };
    const l = new IntentLearner(omegaOf(VR), opts);
    l.observe(rep(VR, 1), 1, 'elicitation', region);
    l.observe(rep(VR, 4), 0, 'runtime');
    l.observe(rep(VR, 3), 1, 'witness');
    const r = IntentLearner.replay(omegaOf(VR), opts, l.observations);
    expect(r.cells()).toEqual(l.cells());
    expect(r.observations).toEqual(l.observations);
    expect(r.vetoedCells()).toEqual(l.vetoedCells());
    expect(r.vetoedCells().length).toBe(1);
  });
});

describe('learner: agnostic selection', () => {
  it('keeps the minimum-mistake hypotheses even when only the deny hypothesis is consistent', () => {
    const l = new IntentLearner(omegaOf(V3), { agnosticSlack: 0, nullMass: 0 });
    for (const c of range(3)) l.observe(rep(V3, c), 0);
    for (const c of range(3)) expect(l.acceptance(rep(V3, c))).toBeCloseTo(1 / 3, 12);
  });

  it('keeps every hypothesis within the slack of the fewest mistakes', () => {
    const answers: [number, 0 | 1][] = [[0, 1], [1, 0], [2, 1]];
    for (const slack of [0, 1, 2]) {
      const l = new IntentLearner(omegaOf(V3), { agnosticSlack: slack, nullMass: 0.1 });
      const prior = refPrior(boxCellSets(V3), 0.1);
      const err = prior.map(() => 0);
      for (const [c, y] of answers) {
        l.observe(rep(V3, c), y);
        prior.forEach((h, i) => {
          const inH = h.cells.has(c) ? 1 : 0;
          if (inH !== y) err[i] = err[i]! + 1;
        });
      }
      const minErr = Math.min(...err);
      const hs = prior.map((h, i) => ({ cells: h.cells, w: err[i]! <= minErr + slack ? h.w : 0 }));
      norm(hs);
      expectPosterior(l, V3, hs, 10);
    }
  });

  it('flags an answer that contradicts every live hypothesis', () => {
    const a = new IntentLearner(omegaOf(V3), { agnosticSlack: 0 });
    expect(a.observe(rep(V3, 1), 1)!.conflict).toBeUndefined();
    const no = a.observe(rep(V3, 1), 0)!;
    expect(no.conflict).toBe(true);
    expect(a.isVetoed(rep(V3, 1))).toBe(true);

    const b = new IntentLearner(omegaOf(V3), { agnosticSlack: 0 });
    const first = b.observe(rep(V3, 1), 0)!;
    expect(first.conflict).toBeUndefined();
    expect(b.isVetoed(rep(V3, 1))).toBe(false);
    const yes = b.observe(rep(V3, 1), 1)!;
    expect(yes.conflict).toBe(true);
    expect(b.isVetoed(rep(V3, 1))).toBe(false);
  });
});

// ---- cells, metrics, questions -------------------------------------------------------------------------------

describe('learner: inGrant boundary', () => {
  it('p = τ is in the grant', () => {
    const tau = 0.5 + 1e-12;
    expect(tau - 1e-12).toBe(0.5);
    const l = new IntentLearner(omegaOf(V1), { nullMass: 0.5, tau });
    expect(l.acceptance(rep(V1, 0))).toBe(0.5);
    expect(l.admitsOutcome(rep(V1, 0))).toBe(true);
    expect(l.cells()[0]!.inGrant).toBe(true);
  });
});

describe('learner: metrics', () => {
  it('are the closed forms of the per-cell posterior', () => {
    const l = new IntentLearner(omegaOf(VMX), { tau: 0.4 });
    const hs = refPrior(boxCellSets(VMX), 0.2);
    const steps: [number, 0 | 1, 'elicitation' | 'runtime' | 'witness'][] = [[4, 0, 'elicitation'], [2, 1, 'runtime'], [3, 1, 'witness'], [2, 0, 'elicitation']];
    for (const [c, y, s] of steps) {
      l.observe(rep(VMX, c), y, s);
      refObserve(hs, [c], y);
    }
    const m = l.metrics();
    let R = 0;
    let B = 0;
    let U = 0;
    let dis = 0;
    let meanHarm = 0;
    for (const v of l.cells()) {
      meanHarm += v.mass * v.harm;
      if (v.inGrant) R += v.mass * (1 - v.p) * v.harm;
      else B += v.mass * v.p;
      U += v.mass * Math.min(v.p, 1 - v.p);
      if (v.p > 1e-12 && v.p < 1 - 1e-12) dis += v.mass;
    }
    expect(R).toBeGreaterThan(0);
    expect(B).toBeGreaterThan(0);
    expect(m.residualRisk).toBeCloseTo(R, 12);
    expect(m.burden).toBeCloseTo(B, 12);
    expect(m.uncertainty).toBeCloseTo(U, 12);
    expect(m.disagreementMass).toBeCloseTo(dis, 12);
    expect(m.meanHarm).toBeCloseTo(meanHarm, 12);
    const live = hs.filter((h) => h.w > 0);
    expect(live.length).toBe(3);
    expect(m.entropyBits).toBeCloseTo(-live.reduce((a, h) => a + h.w * Math.log2(h.w), 0), 12);
    expect(m.log2VersionSpace).toBeCloseTo(Math.log2(live.length), 12);
    expect(m.questions).toBe(2);
    expect(m.conflicts).toBe(1);
    expect(l.isVetoed(rep(VMX, 2))).toBe(true);
  });

  it('sum entropy and version-space size over verbs; no hard version space under noise', () => {
    const l = new IntentLearner(omegaOf(V3, VR), { nullMass: 0 });
    expect(l.metrics().log2VersionSpace).toBeCloseTo(Math.log2(6) + Math.log2(15), 12);
    expect(l.metrics().entropyBits).toBeCloseTo(Math.log2(6) + Math.log2(15), 12);
    expect(new IntentLearner(omegaOf(V3), { eta: 0.1 }).metrics().log2VersionSpace).toBeNull();
  });

  it('a cell whose probability sits on the 1e-12 / 1 − 1e-12 boundary is settled, not in dispute', () => {
    const low = new IntentLearner(omegaOf(V1), {
      nullMass: 1,
      priorMix: { beta: 1e-12, weight: (_vs, contains) => (contains(0) ? 1 : 0) },
    });
    expect(low.acceptance(rep(V1, 0))).toBe(1e-12);
    expect(low.metrics().disagreementMass).toBe(0);
    const high = new IntentLearner(omegaOf(V1), { nullMass: 1e-12 });
    expect(high.acceptance(rep(V1, 0))).toBe(1 - 1e-12);
    expect(high.metrics().disagreementMass).toBe(0);
    const mid = new IntentLearner(omegaOf(V1), { nullMass: 0.5 });
    expect(mid.metrics().disagreementMass).toBeCloseTo(1, 12);
  });
});

describe('learner: the next question', () => {
  function expectedNext(l: IntentLearner, strategy: 'disagreement' | 'risk') {
    let best: { cell: number[]; p: number; score: number } | null = null;
    for (const v of l.cells()) {
      if (v.vetoed) continue;
      if (v.p <= 1e-9 || v.p >= 1 - 1e-9) continue;
      const pe = v.p * (1 - l.etaNeg) + (1 - v.p) * l.etaPos;
      let score = binEnt(pe) - (l.etaPos === l.etaNeg ? binEnt(l.etaPos) : v.p * binEnt(l.etaNeg) + (1 - v.p) * binEnt(l.etaPos));
      if (strategy === 'risk') score *= v.mass * v.harm;
      if (score <= 1e-15) continue;
      if (!best || score > best.score + 1e-12) best = { cell: v.cell, p: v.p, score };
    }
    return best;
  }

  it('is the argmax expected information, in every noise and strategy configuration', () => {
    const cfgs: [LearnerOptions, 'disagreement' | 'risk'][] = [
      [{}, 'disagreement'],
      [{ eta: 0.1 }, 'disagreement'],
      [{ etaPos: 0.05, etaNeg: 0.3 }, 'disagreement'],
      [{ eta: 0.1, strategy: 'risk' }, 'risk'],
      [{ strategy: 'risk' }, 'risk'],
      [{ etaPos: 0.05, etaNeg: 0.3, strategy: 'risk' }, 'risk'],
    ];
    for (const [opts, strategy] of cfgs) {
      const l = new IntentLearner(omegaOf(VMX, VR), opts);
      for (const step of [0, 1]) {
        const q = l.nextQuestion()!;
        const e = expectedNext(l, strategy)!;
        expect(q.cell).toEqual(e.cell);
        expect(q.p).toBe(e.p);
        expect(q.score).toBeCloseTo(e.score, 12);
        expect(q.outcome).toEqual(rep(l.omega.verbs.find((v) => v.verb === q.verb)!, ...q.cell));
        if (step === 0) l.observe(q.outcome, 1);
      }
    }
  });

  it('the risk strategy weights the information by μ·h', () => {
    const d = new IntentLearner(omegaOf(VMX));
    const r = new IntentLearner(omegaOf(VMX), { strategy: 'risk' });
    const qd = d.nextQuestion()!;
    const qr = r.nextQuestion()!;
    const cv = r.cells().find((v) => v.cell[0] === qr.cell[0])!;
    expect(qr.score).toBeCloseTo(binEnt(qr.p) * cv.mass * cv.harm, 12);
    expect(qd.score).toBeCloseTo(binEnt(qd.p), 12);
  });

  it('the first of two equally informative cells wins', () => {
    const l = new IntentLearner(omegaOf(vspace('v.t', [numN(P + 'a', 2)])), { nullMass: 0.25 });
    expect(l.nextQuestion()!.cell).toEqual([0]);
  });

  it('a vetoed cell is not asked about, even if the noise leaves it uncertain', () => {
    const l = new IntentLearner(omegaOf(V1), { eta: 0.2 });
    expect(l.nextQuestion()).not.toBeNull();
    l.observe(rep(V1, 0), 0, 'runtime');
    expect(l.acceptance(rep(V1, 0))).toBeGreaterThan(1e-9);
    expect(l.nextQuestion()).toBeNull();
  });

  it('a cell that is 1e-9 from certain is not worth a question', () => {
    const near0 = new IntentLearner(omegaOf(V1), { nullMass: 1, priorMix: { beta: 1e-9, weight: (_vs, contains) => (contains(0) ? 1 : 0) } });
    expect(near0.acceptance(rep(V1, 0))).toBe(1e-9);
    expect(near0.nextQuestion()).toBeNull();
    const near1 = new IntentLearner(omegaOf(V1), { nullMass: 1e-9 });
    expect(near1.acceptance(rep(V1, 0))).toBe(1 - 1e-9);
    expect(near1.nextQuestion()).toBeNull();
    expect(new IntentLearner(omegaOf(V1), { nullMass: 0.5 }).nextQuestion()).not.toBeNull();
  });

  it('a question carrying no information is not asked', () => {
    const l = new IntentLearner(omegaOf(V1), { eta: 0.4999999999, nullMass: 0.5 });
    expect(l.acceptance(rep(V1, 0))).toBe(0.5);
    expect(l.nextQuestion()).toBeNull();
  });
});

describe('learner: inferred cells and the synthesised grant', () => {
  it('lists the grant cells never asked about, most consequential first', () => {
    const l = new IntentLearner(omegaOf(VMX));
    l.observe(rep(VMX, 0), 1);
    l.observe(rep(VMX, 4), 1);
    const u = l.unconfirmedGrantCells();
    expect(u.map((x) => x.cell)).toEqual(expect.arrayContaining([[1], [2], [3]]));
    expect(u.length).toBe(3);
    const w = (c: number): number => {
      const s = cellStats(VMX, [c]);
      return s.mass * s.harm;
    };
    const expected = [1, 2, 3].sort((a, b) => w(b) - w(a));
    expect(u.map((x) => x.cell[0])).toEqual(expected);
    u.forEach((x) => expect(x.weight).toBeCloseTo(w(x.cell[0]!), 12));
    // the unsorted order (1, 2, 3) is not already descending, so the sort did the work
    expect(w(1) < w(2) || w(2) < w(3)).toBe(true);
  });

  it('is available straight after an observation', () => {
    const l = new IntentLearner(omegaOf(V3));
    l.observe(rep(V3, 0), 1);
    l.observe(rep(V3, 2), 1);
    const u = l.unconfirmedGrantCells();
    expect(u.length).toBe(1);
    expect(u[0]!.verb).toBe('v.a');
    expect(u[0]!.cell).toEqual([1]);
    const s = cellStats(V3, [1]);
    expect(u[0]!.weight).toBeCloseTo(s.mass * s.harm, 12);
  });

  const vI = vspace('v.i', [numN(P + 'a', 2)], 'irreversible');
  const vL = vspace('v.l', [numN(P + 'a', 2)], 'rate_limited');
  const vR = vspace('v.r2', [numN(P + 'a', 2)], 'reversible');
  const allow = (vs: VerbSpace) => ({ verb: vs.verb, resource: '*', where: [{ field: P + 'a', op: 'gte', value: 0 }, { field: P + 'a', op: 'lte', value: 1 }] });
  const grant = (l: IntentLearner, ...vss: VerbSpace[]) => {
    for (const vs of vss) for (const c of [0, 1]) l.observe(rep(vs, c), 1);
  };

  it('the caveat is the worst reversibility class that received any grant', () => {
    const o = omegaOf(vI, vL, vR);
    const a = new IntentLearner(o);
    grant(a, vR);
    expect(a.synthesize()).toEqual({ predicates: [allow(vR)], caveats: [{ type: 'reversibility_max', class: 'reversible' }] });
    const b = new IntentLearner(o);
    grant(b, vL, vR);
    expect(b.synthesize()).toEqual({ predicates: [allow(vL), allow(vR)], caveats: [{ type: 'reversibility_max', class: 'rate_limited' }] });
    const c = new IntentLearner(o);
    grant(c, vI, vL, vR);
    expect(c.synthesize()).toEqual({ predicates: [allow(vI), allow(vL), allow(vR)], caveats: [{ type: 'reversibility_max', class: 'irreversible' }] });
    const d = new IntentLearner(o);
    expect(d.synthesize()).toEqual({ predicates: [], caveats: [] });
  });
});

// ---- the prior mixture ---------------------------------------------------------------------------------------

describe('learner: priorMix', () => {
  const sizeWeight = (_vs: VerbSpace, contains: (c: number) => boolean): number => range(3).filter((c) => contains(c)).length;

  it('w ← (1 − β)·w + β·weight/Σ weight', () => {
    const beta = 0.3;
    const l = new IntentLearner(omegaOf(V3), { priorMix: { beta, weight: sizeWeight } });
    const sets = boxCellSets(V3);
    const hs = refPrior(sets, 0.2);
    const pop = [0, ...sets.map((s) => s.length)];
    const z = pop.reduce((a, b) => a + b, 0);
    hs.forEach((h, i) => (h.w = (1 - beta) * h.w + (beta * pop[i]!) / z));
    expectPosterior(l, V3, hs, 12);
  });

  it('β = 0 leaves the base prior', () => {
    expectPosterior(new IntentLearner(omegaOf(V3), { priorMix: { beta: 0, weight: sizeWeight } }), V3, refPrior(boxCellSets(V3), 0.2), 12);
  });

  it('an all-zero mixture carries no information', () => {
    expectPosterior(new IntentLearner(omegaOf(V3), { priorMix: { beta: 0.5, weight: () => 0 } }), V3, refPrior(boxCellSets(V3), 0.2), 12);
    expect(() => new IntentLearner(omegaOf(V3), { priorMix: { beta: 0.5, weight: (_vs, contains) => (contains(0) ? 1 : 0) } })).not.toThrow();
  });

  it('rejects β outside [0, 1)', () => {
    for (const beta of [-0.1, 1, 1.2]) {
      expect(() => new IntentLearner(omegaOf(V3), { priorMix: { beta, weight: sizeWeight } })).toThrow('pca-intent: priorMix.beta must be in [0, 1)');
    }
  });

  it('rejects a weight that is not finite and non-negative', () => {
    for (const bad of [NaN, -1, Infinity]) {
      expect(() => new IntentLearner(omegaOf(V3), { priorMix: { beta: 0.5, weight: () => bad } })).toThrow('pca-intent: priorMix.weight must be finite and >= 0');
    }
  });

  it('hands the weight function an exact membership test for each hypothesis, in order', () => {
    const rows: boolean[][] = [];
    const N = nCellsOf(V3);
    const probes = [-1, ...range(N), N, 0.5, 1.5, NaN];
    new IntentLearner(omegaOf(V3), {
      priorMix: {
        beta: 0.5,
        weight: (_vs, contains) => {
          rows.push(probes.map((c) => contains(c)));
          return 1;
        },
      },
    });
    const sets = hypothesisCellSets(V3).sets;
    expect(rows.length).toBe(sets.length + 1);
    expect(rows[0]).toEqual(probes.map(() => false));
    sets.forEach((s, i) => {
      expect(rows[i + 1]).toEqual([false, ...Array.from(s).map((x) => x === 1), false, false, false, false]);
    });
  });
});

// ---- elicit and the audit round ------------------------------------------------------------------------------

describe('learner: elicit', () => {
  const truth01 = (q: Question): 0 | 1 => (q.cell[0]! <= 1 ? 1 : 0);

  it('stops "converged" once residual risk and burden are within tolerance', () => {
    const l = new IntentLearner(omegaOf(V3));
    const r = elicit(l, truth01, { epsRisk: 0, epsBurden: 0, maxQuestions: 50 });
    expect(r.stop).toBe('converged');
    expect(r.questions).toBeGreaterThan(0);
    expect(r.questions).toBe(r.asked.length);
    expect(r.seedQuestions).toBe(0);
    expect(r.auditQuestions).toBe(0);
    expect(l.observations.length).toBe(r.questions);
    expect(l.observations.every((o) => o.source === 'elicitation')).toBe(true);
    expect(l.metrics().questions).toBe(r.questions);
    expect(l.acceptance(rep(V3, 0))).toBe(1);
    expect(l.acceptance(rep(V3, 1))).toBe(1);
    expect(l.acceptance(rep(V3, 2))).toBe(0);
  });

  it('a learner already within tolerance asks nothing; equality counts as within', () => {
    const none = new IntentLearner(omegaOf(V3), { nullMass: 1 });
    const r = elicit(none, truth01, { epsRisk: 0, epsBurden: 0, maxQuestions: 5 });
    expect(r).toEqual({ stop: 'converged', questions: 0, auditQuestions: 0, seedQuestions: 0, asked: [] });
    const loose = elicit(new IntentLearner(omegaOf(V3)), truth01, { epsRisk: 1e9, epsBurden: 1e9, maxQuestions: 5 });
    expect(loose.stop).toBe('converged');
    expect(loose.questions).toBe(0);
  });

  it('stops "budget" exactly at maxQuestions', () => {
    for (const max of [0, 1, 2]) {
      const l = new IntentLearner(omegaOf(V3));
      const r = elicit(l, truth01, { epsRisk: 0, epsBurden: 0, maxQuestions: max });
      expect(r.stop).toBe('budget');
      expect(r.questions).toBe(max);
      expect(l.observations.length).toBe(max);
    }
  });

  it('stops "no-disagreement" when nothing is left to ask', () => {
    const l = new IntentLearner(omegaOf(V3));
    const r = elicit(l, truth01, { epsRisk: -1, epsBurden: -1, maxQuestions: 50 });
    expect(r.stop).toBe('no-disagreement');
    expect(r.questions).toBe(r.asked.length);
    expect(l.nextQuestion()).toBeNull();
  });

  it('asks the seed questions first, in order, at most maxQuestions of them', () => {
    const seeds = [{ verb: 'v.a', cell: [0] }, { verb: 'v.a', cell: [2] }];
    const one = new IntentLearner(omegaOf(V3));
    const r1 = elicit(one, truth01, { epsRisk: -1, epsBurden: -1, maxQuestions: 1, seed: seeds });
    expect(r1.seedQuestions).toBe(1);
    expect(r1.questions).toBe(1);
    expect(r1.stop).toBe('budget');
    expect(r1.asked[0]!.cell).toEqual([0]);
    expect(r1.asked[0]!.outcome).toEqual(rep(V3, 0));
    expect(r1.asked[0]!.p).toBeCloseTo(refP(refPrior(boxCellSets(V3), 0.2), 0), 12);
    expect(r1.asked[0]!.score).toBe(0);
    expect(one.observations[0]!.source).toBe('elicitation');

    const two = new IntentLearner(omegaOf(V3));
    const r2 = elicit(two, truth01, { epsRisk: -1, epsBurden: -1, maxQuestions: 10, seed: seeds });
    expect(r2.seedQuestions).toBe(2);
    expect(r2.asked.slice(0, 2).map((q) => q.cell)).toEqual([[0], [2]]);
    expect(two.observations.every((o) => o.source === 'elicitation')).toBe(true);
  });

  it('skips seeds that name no verb, the wrong number of dimensions, or a settled cell', () => {
    const l = new IntentLearner(omegaOf(V3));
    const r = elicit(l, truth01, {
      epsRisk: -1,
      epsBurden: -1,
      maxQuestions: 1,
      seed: [{ verb: 'no.such', cell: [0] }, { verb: 'v.a', cell: [0, 0] }, { verb: 'v.a', cell: [1] }],
    });
    expect(r.seedQuestions).toBe(1);
    expect(r.asked.map((q) => q.cell)).toEqual([[1]]);
    expect(r.asked[0]!.verb).toBe('v.a');
  });

  it('seeds are cut short once the learner is within tolerance, on either measure', () => {
    const seed = [{ verb: 'v.a', cell: [0] }];
    expect(elicit(new IntentLearner(omegaOf(V3)), truth01, { epsRisk: 1e9, epsBurden: 1e9, maxQuestions: 5, seed }).seedQuestions).toBe(0);
    expect(elicit(new IntentLearner(omegaOf(V3)), truth01, { epsRisk: -1, epsBurden: 1e9, maxQuestions: 1, seed }).seedQuestions).toBe(1);
    expect(elicit(new IntentLearner(omegaOf(V3)), truth01, { epsRisk: 1e9, epsBurden: -1, maxQuestions: 1, seed }).seedQuestions).toBe(1);
  });

  it('finds the verb of a seed among several', () => {
    const vB = vspace('v.b', [numN(P + 'a', 3), cat(P + 'k')]);
    const l = new IntentLearner(omegaOf(V3, vB));
    const r = elicit(l, () => 1, { epsRisk: -1, epsBurden: -1, maxQuestions: 1, seed: [{ verb: 'v.b', cell: [1, 0] }] });
    expect(r.seedQuestions).toBe(1);
    expect(r.asked[0]!.verb).toBe('v.b');
    expect(r.asked[0]!.outcome).toEqual(rep(vB, 1, 0));
  });

  it('never asks about a cell whose probability is within 1e-9 of 0 or 1', () => {
    const seed = [{ verb: 'v.1', cell: [0] }];
    const stuck: LearnerOptions[] = [
      { nullMass: 1, priorMix: { beta: 1e-9, weight: (_vs, contains) => (contains(0) ? 1 : 0) } },
      { nullMass: 1e-9 },
    ];
    for (const opts of stuck) {
      const r = elicit(new IntentLearner(omegaOf(V1), opts), () => 1, { epsRisk: -1, epsBurden: -1, maxQuestions: 5, seed });
      expect(r).toEqual({ stop: 'no-disagreement', questions: 0, auditQuestions: 0, seedQuestions: 0, asked: [] });
    }
    const live = elicit(new IntentLearner(omegaOf(V1), { nullMass: 0.5 }), () => 1, { epsRisk: -1, epsBurden: -1, maxQuestions: 5, seed });
    expect(live.seedQuestions).toBe(1);
  });

  it('skips a vetoed seed cell', () => {
    const noisy = new IntentLearner(omegaOf(V1), { eta: 0.2 });
    noisy.observe(rep(V1, 0), 0, 'runtime');
    const r = elicit(noisy, () => 1, { epsRisk: -1, epsBurden: -1, maxQuestions: 5, seed: [{ verb: 'v.1', cell: [0] }] });
    expect(r.seedQuestions).toBe(0);
  });
});

describe('learner: the audit round', () => {
  const primed = (): IntentLearner => {
    const l = new IntentLearner(omegaOf(V3));
    l.observe(rep(V3, 0), 1);
    l.observe(rep(V3, 2), 1);
    return l;
  };

  it('does nothing unless asked to', () => {
    const l = primed();
    const asked: Question[] = [];
    expect(auditRound(l, () => 1, { epsRisk: 0, maxQuestions: 10 }, asked)).toEqual({ asked: 0, exhausted: false });
    expect(auditRound(l, () => 1, { epsRisk: 0, maxQuestions: 10, audit: false }, asked)).toEqual({ asked: 0, exhausted: false });
    expect(asked).toEqual([]);
    expect(l.observations.length).toBe(2);
  });

  it('stops when the unconfirmed weight is within epsRisk, equality included, or nothing is pending', () => {
    const w = primed().unconfirmedGrantCells()[0]!.weight;
    const l = primed();
    expect(auditRound(l, () => 1, { epsRisk: w, maxQuestions: 10, audit: true }, [])).toEqual({ asked: 0, exhausted: false });
    expect(auditRound(l, () => 1, { epsRisk: 1e9, maxQuestions: 10, audit: true }, [])).toEqual({ asked: 0, exhausted: false });
    const empty = new IntentLearner(omegaOf(V3));
    expect(auditRound(empty, () => 1, { epsRisk: -1, maxQuestions: 10, audit: true }, [])).toEqual({ asked: 0, exhausted: false });
    expect(l.observations.length).toBe(2);
  });

  it('asks the most consequential unconfirmed cell as an elicitation', () => {
    const l = primed();
    const w = l.unconfirmedGrantCells()[0]!.weight;
    const asked: Question[] = [];
    const r = auditRound(l, () => 1, { epsRisk: 0, maxQuestions: 10, audit: true }, asked);
    expect(r).toEqual({ asked: 1, exhausted: false });
    expect(asked.length).toBe(1);
    expect(asked[0]!.verb).toBe('v.a');
    expect(asked[0]!.cell).toEqual([1]);
    expect(asked[0]!.outcome).toEqual(rep(V3, 1));
    expect(asked[0]!.p).toBe(1);
    expect(asked[0]!.score).toBeCloseTo(w, 12);
    expect(l.observations.length).toBe(3);
    expect(l.observations[2]!.source).toBe('elicitation');
    expect(l.unconfirmedGrantCells()).toEqual([]);
  });

  it('reports the budget running out, with the count asked so far', () => {
    const l = primed();
    expect(auditRound(l, () => 1, { epsRisk: 0, maxQuestions: 0, audit: true }, [])).toEqual({ asked: 0, exhausted: true });
    const filler = [{} as Question];
    expect(auditRound(l, () => 1, { epsRisk: 0, maxQuestions: 1, audit: true }, filler)).toEqual({ asked: 0, exhausted: true });
    expect(l.observations.length).toBe(2);
  });

  it('finds the verb of the cell it asks about', () => {
    const vB = vspace('v.b', [numN(P + 'a', 3), cat(P + 'k')]);
    const l = new IntentLearner(omegaOf(V3, vB));
    l.observe(rep(vB, 0, 0), 1);
    l.observe(rep(vB, 2, 0), 1);
    const asked: Question[] = [];
    auditRound(l, () => 1, { epsRisk: 0, maxQuestions: 5, audit: true }, asked);
    expect(asked.length).toBe(1);
    expect(asked[0]!.verb).toBe('v.b');
    expect(asked[0]!.outcome).toEqual(rep(vB, 1, 0));
  });

  it('elicit runs the audit after the main loop and reports an exhausted budget as "budget"', () => {
    const lo = primed();
    const r0 = elicit(lo, () => 1, { epsRisk: 0, epsBurden: 1e9, maxQuestions: 0, audit: true });
    expect(r0.stop).toBe('budget');
    expect(r0.questions).toBe(0);
    expect(r0.auditQuestions).toBe(0);

    const hi = primed();
    const r1 = elicit(hi, () => 1, { epsRisk: 0, epsBurden: 1e9, maxQuestions: 5, audit: true });
    expect(r1.stop).toBe('converged');
    expect(r1.auditQuestions).toBe(1);
    expect(r1.questions).toBe(1);
    expect(r1.asked.length).toBe(1);
    expect(hi.observations[2]!.source).toBe('elicitation');
  });
});

// ---- synthesis -----------------------------------------------------------------------------------------------

describe('boxesToPredicates', () => {
  const where = (field: string, lo: number, hi: number) => [{ field, op: 'gte', value: lo }, { field, op: 'lte', value: hi }];
  const maskOf = (N: number, cells: number[]): Uint8Array => {
    const m = new Uint8Array(N);
    cells.forEach((c) => (m[c] = 1));
    return m;
  };
  const policyOf = (preds: Predicate[]) => ({ predicates: preds, caveats: [] });

  it('covers an L-shaped region with maximal boxes, extending downwards over covered cells', () => {
    const VL = vspace('v.l', [numN(P + 'a', 3), numN(P + 'b', 3)]);
    const preds = boxesToPredicates(VL, maskOf(9, [0, 1, 2, 5, 8]));
    expect(preds).toEqual([
      { verb: 'v.l', resource: '*', where: [...where(P + 'a', 0, 0), ...where(P + 'b', 0, 2)] },
      { verb: 'v.l', resource: '*', where: [...where(P + 'a', 0, 2), ...where(P + 'b', 2, 2)] },
    ]);
  });

  it('never grows a range past the edge of the grid', () => {
    const VG = vspace('v.g', [numN(P + 'a', 2), numN(P + 'b', 3)]);
    expect(boxesToPredicates(VG, maskOf(6, [1, 2, 3]))).toEqual([
      { verb: 'v.g', resource: '*', where: [...where(P + 'a', 0, 0), ...where(P + 'b', 1, 2)] },
      { verb: 'v.g', resource: '*', where: [...where(P + 'a', 1, 1), ...where(P + 'b', 0, 0)] },
    ]);
    expect(boxesToPredicates(VG, maskOf(6, [2, 3, 4, 5]))).toEqual([
      { verb: 'v.g', resource: '*', where: [...where(P + 'a', 0, 1), ...where(P + 'b', 2, 2)] },
      { verb: 'v.g', resource: '*', where: [...where(P + 'a', 1, 1), ...where(P + 'b', 0, 2)] },
    ]);
  });

  const K = P + 'k';
  const VK = vspace('v.k', [cat(K, ['a', 'b', 'p/x'], ['p/', 'p/q/'])]); // a0 b1 p/x2 p/3 p/q/4 other5
  const one = (cells: number[]) => boxesToPredicates(VK, maskOf(6, cells));
  const pred = (...w: unknown[]) => [{ verb: 'v.k', resource: '*', ...(w.length ? { where: w } : {}) }];
  const f = (op: string, value: unknown) => ({ field: K, op, value });

  it('writes a categorical subset as eq / in / prefix / exclusion conditions', () => {
    expect(one(range(6))).toEqual(pred());
    expect(one([0])).toEqual(pred(f('eq', 'a')));
    expect(one([2])).toEqual(pred(f('eq', 'p/x')));
    expect(one([0, 1])).toEqual(pred(f('in', ['a', 'b'])));
    expect(one([4])).toEqual(pred(f('prefix', 'p/q/')));
    expect(one([3])).toEqual(pred({ all_of: [f('prefix', 'p/'), f('nin', ['p/x']), { not: f('prefix', 'p/q/') }] }));
    expect(one([5])).toEqual(pred({ all_of: [f('nin', ['a', 'b', 'p/x']), { not: f('prefix', 'p/') }, { not: f('prefix', 'p/q/') }] }));
    expect(one([0, 4])).toEqual(pred({ any_of: [f('eq', 'a'), f('prefix', 'p/q/')] }));
    expect(one([0, 1, 3])).toEqual(pred({ any_of: [f('in', ['a', 'b']), { all_of: [f('prefix', 'p/'), f('nin', ['p/x']), { not: f('prefix', 'p/q/') }] }] }));
  });

  it('with no exact values, OTHER and a prefix need no exclusion list', () => {
    const VKP = vspace('v.kp', [cat(K, [], ['p/'])]);
    expect(boxesToPredicates(VKP, maskOf(2, [1]))).toEqual([{ verb: 'v.kp', resource: '*', where: [{ not: f('prefix', 'p/') }] }]);
    expect(boxesToPredicates(VKP, maskOf(2, [0]))).toEqual([{ verb: 'v.kp', resource: '*', where: [f('prefix', 'p/')] }]);
  });

  it('writes the alternatives of a subset in ascending cell order, whatever order the box was grown in', () => {
    const VQ = vspace('v.q', [numN(P + 'a', 2), cat(K, ['a'], ['p/', 'q/'])]); // a0 p/1 q/2 other3
    // cells (a=0,k=p/) = 1, (1,p/) = 5, (1,other) = 7: the second box starts at OTHER, then adds p/
    const preds = boxesToPredicates(VQ, maskOf(8, [1, 5, 7]));
    expect(preds).toEqual([
      { verb: 'v.q', resource: '*', where: [...where(P + 'a', 0, 1), f('prefix', 'p/')] },
      {
        verb: 'v.q',
        resource: '*',
        where: [
          ...where(P + 'a', 1, 1),
          { any_of: [f('prefix', 'p/'), { all_of: [f('nin', ['a']), { not: f('prefix', 'p/') }, { not: f('prefix', 'q/') }] }] },
        ],
      },
    ]);
  });

  it('the predicates admit exactly the allowed cells', () => {
    const r = rng(20260512);
    const spaces: [VerbSpace, number][] = [
      [vspace('v.o', [numN(P + 'a', 3), cat(K, ['a', 'p/x'], ['p/', 'p/q/'])]), 0.5],
      [vspace('v.nn', [numN(P + 'a', 3), numN(P + 'b', 4)]), 0.6],
      [vspace('v.nn', [numN(P + 'a', 3), numN(P + 'b', 4)]), 0.4],
      [vspace('v.nn', [numN(P + 'a', 4), cat(K, ['a']), numN(P + 'b', 2)]), 0.55],
    ];
    for (const [vs, density] of spaces) {
      const N = nCellsOf(vs);
      for (let t = 0; t < 60; t++) {
        const allowed = new Uint8Array(N);
        for (let c = 0; c < N; c++) allowed[c] = r() < density ? 1 : 0;
        if (!allowed.some((x) => x === 1)) continue;
        const adm = admitter(policyOf(boxesToPredicates(vs, allowed)));
        for (let c = 0; c < N; c++) expect(adm.admits(vs, cellRep(vs, decodeCell(vs, c)))).toBe(allowed[c] === 1);
      }
    }
  });
});
