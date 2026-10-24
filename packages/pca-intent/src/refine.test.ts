import { describe, expect, it } from 'vitest';
import {
  answerPartial,
  createLearner,
  decodeCell,
  deriveOmega,
  elicit,
  elicitAdaptive,
  encodeCell,
  numCells,
  refineLearner,
  refineOmega,
  repValue,
  rng,
  verbCellCount,
  type AdaptiveAnswer,
  type IntentLearner,
  type Omega,
  type PartialAnswer,
  type Question,
} from './index';

const AMT = 'action.params.amount';
const RCP = 'action.params.recipient';
const HR = 'env.hour';

/**
 * A truthful partial-capable principal for ONE numeric dimension: "yes" if the whole questioned range is
 * acceptable, "no" if none of it is, otherwise "partly" with a cut at every point where acceptability changes.
 */
function numericPrincipal(path: string, accept: (x: number) => boolean) {
  return (q: Question, l: IntentLearner): AdaptiveAnswer => {
    const vs = l.omega.verbs.find((v) => v.verb === q.verb)!;
    const k = vs.dims.findIndex((d) => d.path === path);
    const d = vs.dims[k]!;
    if (d.kind !== 'num') throw new Error('numeric dimension expected');
    const c = numCells(d)[q.cell[k]!]!;
    const runs: { lo: number; hi: number; y: 0 | 1 }[] = [];
    for (let x = c.lo; x <= c.hi; x++) {
      const y = accept(x) ? 1 : 0;
      const last = runs[runs.length - 1];
      if (last && last.y === y) last.hi = x;
      else runs.push({ lo: x, hi: x, y });
      if (c.hi - c.lo > 5000 && x > c.lo + 2000) {
        // beyond the interesting region every test truth is constant: close the last run at the cell's end
        runs[runs.length - 1]!.hi = c.hi;
        break;
      }
    }
    if (runs.length === 1) return runs[0]!.y;
    const a: PartialAnswer = { kind: 'partial', path, cuts: runs.slice(1).map((r) => r.lo), parts: runs };
    return a;
  };
}

const refundOmega = (cuts: number[]): Omega =>
  deriveOmega({ policies: [], slots: { verbs: ['stripe.refund'], constraints: cuts.map((max) => ({ path: AMT, max })) } });

describe('cut refinement (M6)', () => {
  it('refineOmega inserts cuts and named values without touching other verbs', () => {
    const o = deriveOmega({ policies: [], slots: { verbs: ['stripe.refund', 'stripe.charge'], constraints: [{ path: AMT, max: 100 }, { path: RCP, oneOf: ['alice'] }] } });
    const r = refineOmega(refineOmega(o, { verb: 'stripe.refund', path: AMT, cuts: [120, 100] }), { verb: 'stripe.refund', path: RCP, values: ['reseller'] });
    const refund = r.verbs.find((v) => v.verb === 'stripe.refund')!;
    const charge = r.verbs.find((v) => v.verb === 'stripe.charge')!;
    expect(refund.dims[0]).toMatchObject({ cuts: [100, 120] });
    expect(refund.dims[1]!.kind === 'cat' && refund.dims[1]!.values.map((v) => v.value)).toEqual(['alice', 'reseller', '⊥']);
    expect(charge).toEqual(o.verbs.find((v) => v.verb === 'stripe.charge'));
    expect(() => refineOmega(o, { verb: 'stripe.refund', path: 'env.hour', cuts: [3] })).toThrow(/newDim/);
  });

  it('X03-style: the true threshold (120) is not a cut; "partly: up to 120" makes it exact', () => {
    const omega = refundOmega([0, 100]);
    const accept = (x: number) => x >= 0 && x <= 120;
    const r = elicitAdaptive(createLearner(omega, { nullMass: 0.05 }), numericPrincipal(AMT, accept), { epsRisk: 0, epsBurden: 0, maxQuestions: 40, audit: true });
    expect(r.refinements).toBeGreaterThanOrEqual(1);
    for (const x of [0, 1, 99, 100, 101, 119, 120, 121, 500, 99_999]) {
      expect(r.learner.admitsOutcome({ verb: 'stripe.refund', values: { [AMT]: x } })).toBe(accept(x));
    }
  });

  it('X04-style: a lunch hole (12) inside the hours range; union class + "partly: except 12" is exact', () => {
    const omega = deriveOmega({ policies: [], slots: { verbs: ['calendar.create_event'], constraints: [{ path: HR, min: 9, max: 17 }] } });
    const accept = (h: number) => (h >= 9 && h <= 11) || (h >= 13 && h <= 17);
    const r = elicitAdaptive(createLearner(omega, { nullMass: 0.05, hypothesisClass: { kind: 'union', k: 2 } }), numericPrincipal(HR, accept), { epsRisk: 0, epsBurden: 0, maxQuestions: 40, audit: true });
    for (let h = 0; h <= 23; h++) expect(r.learner.admitsOutcome({ verb: 'calendar.create_event', values: { [HR]: h } })).toBe(accept(h));
    expect(r.learner.metrics().conflicts).toBe(0);
  });

  it('X02-style: a dimension nobody captured is ADDED by "partly: not for recipient reseller"', () => {
    const omega = refundOmega([0, 200]);
    const ok = (amount: number, who: string) => amount >= 0 && amount <= 200 && who !== 'reseller';
    let added = false;
    const answer = (q: Question, l: IntentLearner): AdaptiveAnswer => {
      const vs = l.omega.verbs[0]!;
      const a = vs.dims.find((d) => d.path === AMT)!;
      if (a.kind !== 'num') throw new Error('x');
      const ka = vs.dims.indexOf(a);
      const cell = numCells(a)[q.cell[ka]!]!;
      const amountOk = cell.lo >= 0 && cell.hi <= 200;
      const kr = vs.dims.findIndex((d) => d.path === RCP);
      if (kr < 0) {
        if (!amountOk) return 0;
        added = true;
        return { kind: 'partial', path: RCP, newDim: { kind: 'cat', path: RCP, values: [{ kind: 'exact', value: 'reseller' }, { kind: 'other', value: '⊥' }] }, parts: [{ values: ['reseller'], y: 0 }, { other: true, y: 1 }] };
      }
      const who = String(repValue(vs.dims[kr]!, q.cell[kr]!));
      return amountOk && ok(cell.lo, who) ? 1 : 0;
    };
    const r = elicitAdaptive(createLearner(omega, { nullMass: 0.05 }), answer, { epsRisk: 0, epsBurden: 0, maxQuestions: 40, audit: true });
    expect(added).toBe(true);
    for (const [x, who] of [[50, 'bob'], [50, 'reseller'], [200, 'acme'], [201, 'bob'], [0, 'reseller']] as const) {
      expect(r.learner.admitsOutcome({ verb: 'stripe.refund', values: { [AMT]: x, [RCP]: who } })).toBe(ok(x, who));
    }
  });

  it('answerPartial leaves the old learner untouched and records one observation per labelled sub-cell', () => {
    const omega = refundOmega([0, 100]);
    const l = createLearner(omega, { nullMass: 0.05 });
    const q = { verb: 'stripe.refund', cell: [3], outcome: { verb: 'stripe.refund', values: { [AMT]: 101 } }, p: 0.5, score: 1 };
    const { learner, added } = answerPartial(l, q, { kind: 'partial', path: AMT, cuts: [121], parts: [{ lo: 101, hi: 120, y: 1 }, { lo: 121, hi: 100_000, y: 0 }] });
    expect(l.observations).toHaveLength(0);
    expect(l.omega.verbs[0]!.dims[0]).toMatchObject({ cuts: [0, 100] });
    expect(added.map((o) => o.y)).toEqual([1, 0, 0]); // [101,120] yes; {121} no; [122, 100000] no
    expect(learner.observations).toHaveLength(3);
  });

  it('PROPERTY T8: refining Ω never widens the conservative grant (η = 0, τ = 1)', () => {
    const r = rng(41);
    for (let t = 0; t < 30; t++) {
      const omega = deriveOmega({ policies: [], slots: { verbs: ['stripe.refund'], constraints: [{ path: AMT, min: 0, max: 100 }, { path: AMT, max: 200 }, { path: RCP, oneOf: ['alice', 'bob'] }] } });
      const vs = omega.verbs[0]!;
      const n = verbCellCount(vs);
      const truth = new Set<number>();
      for (let c = 0; c < n; c++) if (r() < 0.5) truth.add(c);
      const l = createLearner(omega, { nullMass: 0.1 });
      for (let i = 0; i < 6; i++) {
        const q = l.nextQuestion();
        if (!q) break;
        l.observe(q.outcome, truth.has(encodeCell(vs, q.cell)) ? 1 : 0);
      }
      const cut = 1 + Math.floor(r() * 400);
      const fine = r() < 0.5 ? refineLearner(l, { verb: 'stripe.refund', path: AMT, cuts: [cut] }) : refineLearner(l, { verb: 'stripe.refund', path: RCP, values: ['carol'] });
      const fvs = fine.omega.verbs[0]!;
      for (let c = 0; c < verbCellCount(fvs); c++) {
        const o = { verb: 'stripe.refund', values: Object.fromEntries(fvs.dims.map((d, k) => [d.path, repValue(d, decodeCell(fvs, c)[k]!)])) };
        if (fine.admitsOutcome(o)) expect(l.admitsOutcome(o)).toBe(true);
      }
    }
  });

  it('PROPERTY: interval truths with arbitrary thresholds become exact under partial answers (box class)', () => {
    const r = rng(43);
    for (let t = 0; t < 25; t++) {
      const a = Math.floor(r() * 300);
      const b = a + Math.floor(r() * 400);
      const accept = (x: number) => x >= a && x <= b;
      const omega = refundOmega([100]);
      const res = elicitAdaptive(createLearner(omega, { nullMass: 0.05 }), numericPrincipal(AMT, accept), { epsRisk: 0, epsBurden: 0, maxQuestions: 60, audit: true });
      for (const x of [0, a - 1, a, a + 1, b - 1, b, b + 1, 1000, 99_999].filter((v) => v >= 0 && v <= 100_000)) {
        const got = res.learner.admitsOutcome({ verb: 'stripe.refund', values: { [AMT]: x } });
        if (got) expect(accept(x)).toBe(true); // safety at every point
        expect(got).toBe(accept(x)); // and exactness once the cuts are in
      }
    }
  });

  it('without partial answers the same truths stay SAFE (burden, never risk) with the audit', () => {
    const r = rng(47);
    for (let t = 0; t < 15; t++) {
      const a = Math.floor(r() * 300);
      const b = a + Math.floor(r() * 400);
      const omega = refundOmega([100]);
      const l = createLearner(omega, { nullMass: 0.05 });
      const vs = omega.verbs[0]!;
      const d = vs.dims[0]!;
      if (d.kind !== 'num') throw new Error('x');
      elicit(l, (q) => {
        const c = numCells(d)[q.cell[0]!]!;
        return c.lo >= a && c.hi <= b ? 1 : 0;
      }, { epsRisk: 0, epsBurden: 0, maxQuestions: 60, audit: true });
      for (let x = 0; x <= 800; x += 7) if (l.admitsOutcome({ verb: 'stripe.refund', values: { [AMT]: x } })) expect(x >= a && x <= b).toBe(true);
    }
  });
});
