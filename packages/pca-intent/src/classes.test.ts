import { describe, expect, it } from 'vitest';
import {
  createLearner,
  decodeCell,
  deriveOmega,
  elicit,
  emitIntentMap,
  encodeCell,
  hypothesisCellSets,
  IntentLearner,
  numCells,
  rng,
  verbCellCount,
  verifyIntentMap,
  type HypothesisClassSpec,
  type Omega,
  type Question,
  type VerbSpace,
} from './index';

const AMT = 'action.params.amount';
const RCP = 'action.params.recipient';

/** One verb, amount cells {0},[1,99],{100},[101,199],{200},[201,..]; recipient alice, bob, ⊥: 18 cells. */
const omega: Omega = deriveOmega({
  policies: [],
  slots: { verbs: ['stripe.refund'], constraints: [{ path: AMT, min: 0, max: 100 }, { path: AMT, max: 200 }, { path: RCP, oneOf: ['alice', 'bob'] }] },
});
const vs: VerbSpace = omega.verbs[0]!;
const N = verbCellCount(vs);

/** A random box as a cell set (numeric: a random contiguous range; categorical: a random non-empty subset). */
function randomBox(r: () => number): Set<number> {
  const sides = vs.dims.map((d) => {
    const n = d.kind === 'num' ? numCells(d).length : d.values.length;
    if (d.kind === 'num') {
      const a = Math.floor(r() * n);
      const b = Math.floor(r() * n);
      return (x: number) => x >= Math.min(a, b) && x <= Math.max(a, b);
    }
    let mask = 0;
    while (mask === 0) mask = Math.floor(r() * (1 << n));
    return (x: number) => ((mask >> x) & 1) === 1;
  });
  const out = new Set<number>();
  for (let c = 0; c < N; c++) {
    const idx = decodeCell(vs, c);
    if (sides.every((f, k) => f(idx[k]!))) out.add(c);
  }
  return out;
}

const cellAnswer = (truth: Set<number>) => (q: Question): 0 | 1 => (truth.has(encodeCell(vs, q.cell)) ? 1 : 0);

function grantCells(l: IntentLearner): Set<number> {
  const s = new Set<number>();
  l.cells().forEach((c) => {
    if (c.inGrant) s.add(encodeCell(vs, c.cell));
  });
  return s;
}

const subset = (a: Set<number>, b: Set<number>) => [...a].every((x) => b.has(x));

/** X01's shape: amount ≤ 200 for anyone, or any amount for "alice" (the internal account). */
const x01 = new Set<number>();
for (let c = 0; c < N; c++) {
  const [a, r] = decodeCell(vs, c);
  if (a! <= 4 || r === 0) x01.add(c);
}

describe('richer hypothesis classes (M6)', () => {
  it('the box class cannot represent a union of two boxes; the audit keeps it safe at a burden cost', () => {
    const l = createLearner(omega, { nullMass: 0.05 });
    elicit(l, cellAnswer(x01), { epsRisk: 0, epsBurden: 0, maxQuestions: 60, audit: true });
    expect(subset(grantCells(l), x01)).toBe(true);
  });

  const classes: [HypothesisClassSpec, string][] = [
    [{ kind: 'union', k: 2 }, 'per-verb-union/v1'],
    [{ kind: 'decision-list', maxRules: 2 }, 'per-verb-decision-list/v2'],
    [{ kind: 'decision-list', maxRules: 2, conditions: 'atomic' }, 'per-verb-decision-list/v1'],
  ];
  for (const [hc, className] of classes) {
    const label = hc.kind === 'decision-list' ? `${hc.kind}/${hc.conditions ?? 'box'}` : hc.kind;
    it(`${label}: an X01-shaped intent is realizable — exact grant, no conflict`, () => {
      const l = createLearner(omega, { nullMass: 0.05, hypothesisClass: hc });
      const r = elicit(l, cellAnswer(x01), { epsRisk: 0, epsBurden: 0, maxQuestions: 60, audit: true });
      expect(l.metrics().conflicts).toBe(0);
      expect(r.stop).not.toBe('budget');
      expect([...grantCells(l)].sort((a, b) => a - b)).toEqual([...x01].sort((a, b) => a - b));
    });
    it(`${label}: the map records the class and replays exactly`, () => {
      const l = createLearner(omega, { nullMass: 0.05, hypothesisClass: hc });
      elicit(l, cellAnswer(x01), { epsRisk: 0, epsBurden: 0, maxQuestions: 10 });
      const m = emitIntentMap(l, 'ref');
      expect(m.learner.hypothesis_class).toBe(className);
      expect(verifyIntentMap(m)).toEqual({ ok: true, problems: [] });
    });
  }

  it('the box class is a sub-class: on a box-shaped truth the union class reaches the same grant', () => {
    const r = rng(5);
    for (let t = 0; t < 8; t++) {
      const truth = randomBox(r);
      const a = createLearner(omega, { nullMass: 0.05 });
      const b = createLearner(omega, { nullMass: 0.05, hypothesisClass: { kind: 'union', k: 2 } });
      elicit(a, cellAnswer(truth), { epsRisk: 0, epsBurden: 0, maxQuestions: 80 });
      elicit(b, cellAnswer(truth), { epsRisk: 0, epsBurden: 0, maxQuestions: 80 });
      expect(grantCells(a)).toEqual(truth);
      expect(grantCells(b)).toEqual(truth);
    }
  });

  it('PROPERTY T1/T2 (union of 2 boxes, η = 0, τ = 1): G ⊆ truth after EVERY answer, and G only grows', () => {
    const r = rng(11);
    for (let t = 0; t < 25; t++) {
      const truth = new Set([...randomBox(r), ...(r() < 0.6 ? randomBox(r) : [])]);
      const l = createLearner(omega, { nullMass: 0.1, hypothesisClass: { kind: 'union', k: 2 } });
      let prev = grantCells(l);
      expect(subset(prev, truth)).toBe(true);
      for (let i = 0; i < 40; i++) {
        const q = l.nextQuestion();
        if (!q) break;
        l.observe(q.outcome, cellAnswer(truth)(q));
        const g = grantCells(l);
        expect(subset(g, truth)).toBe(true);
        expect(subset(prev, g)).toBe(true);
        prev = g;
      }
      expect(l.metrics().conflicts).toBe(0);
    }
  });

  it('PROPERTY (decision lists ≤ 2 rules): G ⊆ truth whenever the truth is a 2-rule list', () => {
    const r = rng(17);
    const d0 = vs.dims[0]!;
    if (d0.kind !== 'num') throw new Error('expected the amount dimension first');
    const n0 = numCells(d0).length;
    for (let t = 0; t < 20; t++) {
      const thr = Math.floor(r() * n0);
      const who = Math.floor(r() * 3);
      const y1 = r() < 0.5 ? 1 : 0;
      const truth = new Set<number>();
      for (let c = 0; c < N; c++) {
        const [a, rc] = decodeCell(vs, c);
        const y = rc === who ? y1 : a! <= thr ? 1 : 0;
        if (y) truth.add(c);
      }
      if (truth.size === 0) continue;
      const l = createLearner(omega, { nullMass: 0.1, hypothesisClass: { kind: 'decision-list', maxRules: 2 } });
      for (let i = 0; i < 40; i++) {
        const q = l.nextQuestion();
        if (!q) break;
        l.observe(q.outcome, cellAnswer(truth)(q));
        expect(subset(grantCells(l), truth)).toBe(true);
      }
    }
  });

  it('refuses classes whose enumeration exceeds the cap', () => {
    expect(() => new IntentLearner(omega, { hypothesisClass: { kind: 'union', k: 3 }, maxEnumeration: 1000 })).toThrow(/enumeration cap/);
  });
});

describe('decision lists over box conditions contain the box class (spec §9.1a)', () => {
  /** amount cells {0},[1,99],{100},[101,..]; recipient alice, bob, carol, ⊥: 16 cells. */
  const omega3: Omega = deriveOmega({
    policies: [],
    slots: { verbs: ['stripe.refund'], constraints: [{ path: AMT, min: 0, max: 100 }, { path: RCP, oneOf: ['alice', 'bob', 'carol'] }] },
  });
  const vs3 = omega3.verbs[0]!;
  const N3 = verbCellCount(vs3);
  const rcpIdx = (name: string) => {
    const d = vs3.dims[1]!;
    if (d.kind !== 'cat') throw new Error('expected the recipient dimension second');
    return d.values.findIndex((v) => v.kind === 'exact' && v.value === name);
  };
  // amount ≤ 100 AND recipient ∉ {bob, carol}: one box, but its complement has THREE one-dimension pieces (a cap and two
  // excluded values), so no list of 2 one-dimension rules expresses it (the R04 / BK05 / SA20 shape)
  const bob = rcpIdx('bob');
  const carol = rcpIdx('carol');
  const capBox = new Set<number>();
  for (let c = 0; c < N3; c++) {
    const [a, r] = decodeCell(vs3, c);
    if (a! <= 2 && r !== bob && r !== carol) capBox.add(c);
  }
  const keys = (sets: Uint8Array[]) => new Set(sets.map((m) => Array.from(m).join('')));
  const keyOfSet = (cells: Set<number>, n: number) => Array.from({ length: n }, (_, c) => (cells.has(c) ? 1 : 0)).join('');
  const answer3 = (truth: Set<number>) => (q: Question): 0 | 1 => (truth.has(encodeCell(vs3, q.cell)) ? 1 : 0);

  it('the test case is a box that needs ≥ 3 one-dimension rules: outside the atomic 2-rule class, inside the box-condition one', () => {
    expect(bob).toBeGreaterThanOrEqual(0);
    expect(carol).toBeGreaterThanOrEqual(0);
    const k = keyOfSet(capBox, N3);
    expect(keys(hypothesisCellSets(vs3).sets).has(k)).toBe(true);
    expect(keys(hypothesisCellSets(vs3, { kind: 'decision-list', maxRules: 2, conditions: 'atomic' }).sets).has(k)).toBe(false);
    expect(keys(hypothesisCellSets(vs3, { kind: 'decision-list', maxRules: 3, conditions: 'atomic' }).sets).has(k)).toBe(true);
    for (const L of [1, 2]) expect(keys(hypothesisCellSets(vs3, { kind: 'decision-list', maxRules: L }).sets).has(k)).toBe(true);
  });

  it('learned with 0 conflicts and an exact grant by box-condition lists (L = 1, 2); the atomic 2-rule class conflicts', () => {
    for (const L of [1, 2]) {
      const l = createLearner(omega3, { nullMass: 0.05, hypothesisClass: { kind: 'decision-list', maxRules: L } });
      const r = elicit(l, answer3(capBox), { epsRisk: 0, epsBurden: 0, maxQuestions: 60, audit: true });
      expect(l.metrics().conflicts).toBe(0);
      expect(r.stop).not.toBe('budget');
      const g = new Set<number>();
      l.cells().forEach((c) => c.inGrant && g.add(encodeCell(vs3, c.cell)));
      expect(g).toEqual(capBox);
    }
    const old = createLearner(omega3, { nullMass: 0.05, hypothesisClass: { kind: 'decision-list', maxRules: 2, conditions: 'atomic' } });
    elicit(old, answer3(capBox), { epsRisk: 0, epsBurden: 0, maxQuestions: 60, audit: true });
    expect(old.metrics().conflicts).toBeGreaterThan(0);
  });

  it('PROPERTY (superset): box ⊆ DL_box(L) at complexity 1, and DL_atomic(L) ⊆ DL_box(L), for L = 1, 2', () => {
    for (const v of [vs, vs3]) {
      const boxes = keys(hypothesisCellSets(v).sets);
      for (const L of [1, 2]) {
        const dl = hypothesisCellSets(v, { kind: 'decision-list', maxRules: L });
        const cx = new Map(dl.sets.map((m, i) => [Array.from(m).join(''), dl.complexity[i]!]));
        for (const b of boxes) expect(cx.get(b)).toBe(1);
        for (const a of keys(hypothesisCellSets(v, { kind: 'decision-list', maxRules: L, conditions: 'atomic' }).sets)) expect(cx.has(a)).toBe(true);
        // the union class contains the box class too (1-box unions)
        const unions = keys(hypothesisCellSets(v, { kind: 'union', k: L }).sets);
        for (const b of boxes) expect(unions.has(b)).toBe(true);
      }
    }
  });

  it('PROPERTY (superset, behaviour): on random box truths the box-condition list learner never conflicts and reaches the exact grant', () => {
    const r = rng(29);
    for (let t = 0; t < 12; t++) {
      const truth = randomBox(r);
      for (const L of [1, 2]) {
        const l = createLearner(omega, { nullMass: 0.05, hypothesisClass: { kind: 'decision-list', maxRules: L } });
        let prev = grantCells(l);
        for (let i = 0; i < 80; i++) {
          const q = l.nextQuestion();
          if (!q) break;
          l.observe(q.outcome, cellAnswer(truth)(q));
          const g = grantCells(l);
          expect(subset(g, truth)).toBe(true); // T1 after every answer
          expect(subset(prev, g)).toBe(true); // T2: the grant only grows
          prev = g;
        }
        expect(l.metrics().conflicts).toBe(0);
        expect(grantCells(l)).toEqual(truth);
      }
    }
  });

  it('rejects an unknown condition kind', () => {
    expect(() => new IntentLearner(omega, { hypothesisClass: { kind: 'decision-list', maxRules: 2, conditions: 'nope' as 'box' } })).toThrow(/conditions/);
  });
});

describe('agnostic selection (A²-style candidate set)', () => {
  it('slack 0 on a realizable truth gives the same posterior as the version space', () => {
    const r = rng(3);
    const truth = randomBox(r);
    const a = createLearner(omega, { nullMass: 0.1 });
    const b = createLearner(omega, { nullMass: 0.1, agnosticSlack: 0 });
    for (let i = 0; i < 12; i++) {
      const q = a.nextQuestion();
      if (!q) break;
      a.observe(q.outcome, cellAnswer(truth)(q));
      b.observe(q.outcome, cellAnswer(truth)(q));
      a.cells().forEach((c, j) => expect(b.cells()[j]!.p).toBeCloseTo(c.p, 12));
    }
  });

  it('PROPERTY: with slack ≥ 1 one wrong answer never makes the grant unsafe (box truth)', () => {
    const r = rng(23);
    for (let t = 0; t < 20; t++) {
      const truth = randomBox(r);
      const l = createLearner(omega, { nullMass: 0.1, agnosticSlack: 1 });
      const flipAt = Math.floor(r() * 6);
      for (let i = 0; i < 30; i++) {
        const q = l.nextQuestion();
        if (!q) break;
        const y = cellAnswer(truth)(q);
        l.observe(q.outcome, i === flipAt ? ((1 - y) as 0 | 1) : y);
        expect(subset(grantCells(l), truth)).toBe(true);
      }
    }
  });

  it('rejects agnostic selection combined with a noise model', () => {
    expect(() => new IntentLearner(omega, { eta: 0.05, agnosticSlack: 1 })).toThrow(/agnostic/);
  });
});

describe('committee prior and seed questions (M3 wiring)', () => {
  const g200 = { predicates: [{ verb: 'stripe.refund', resource: '*', where: [{ field: AMT, op: 'gte' as const, value: 0 }, { field: AMT, op: 'lte' as const, value: 200 }] }], caveats: [] };
  const g100 = { predicates: [{ verb: 'stripe.refund', resource: '*', where: [{ field: AMT, op: 'gte' as const, value: 0 }, { field: AMT, op: 'lte' as const, value: 100 }] }], caveats: [] };
  it('a mixture of anchors puts prior mass on every reading and round-trips through the map', () => {
    const plain = createLearner(omega, { nullMass: 0.1 });
    const mix = createLearner(omega, { nullMass: 0.1, anchors: [{ policy: g100, lambda: 8 }, { policy: g200, lambda: 8 }] });
    // amount 101 (cell 101..199), alice: inside the 200 reading only
    const o = { verb: 'stripe.refund', values: { [AMT]: 101, [RCP]: 'alice' } };
    expect(mix.acceptance(o)).toBeGreaterThan(plain.acceptance(o));
    const m = emitIntentMap(mix, 'r');
    expect(m.learner.anchors?.length).toBe(2);
    expect(verifyIntentMap(m).ok).toBe(true);
  });
  it('seed questions are asked first, once, while uncertain', () => {
    const l = createLearner(omega, { nullMass: 0.1 });
    const seed = [{ verb: 'stripe.refund', cell: [3, 0] }, { verb: 'stripe.refund', cell: [3, 0] }];
    const r = elicit(l, () => 0, { epsRisk: 0, epsBurden: 0, maxQuestions: 5, seed });
    expect(r.seedQuestions).toBe(1);
    expect(r.asked[0]!.cell).toEqual([3, 0]);
  });
});
