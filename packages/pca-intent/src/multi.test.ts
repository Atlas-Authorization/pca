import { describe, expect, it } from 'vitest';
import {
  admitter,
  aggregateIntentMaps,
  answerPartial,
  cellRep,
  combineIntentMaps,
  commonRefinement,
  createLearner,
  crossOrgAggregate,
  decodeCell,
  deriveOmega,
  effectiveVetoers,
  elicit,
  emitIntentMap,
  jointAcceptance,
  learnerFromMap,
  normalizeRule,
  parseCardAnswer,
  questionCard,
  rng,
  verbCellCount,
  verifyAggregate,
  verifyCrossOrgAggregate,
  type IntentMap,
  type Omega,
  type PolicyInput,
} from './index';

const AMT = 'action.params.amount';
const RCP = 'action.params.recipient';
const omega = deriveOmega({ policies: [], slots: { verbs: ['stripe.refund'], constraints: [{ path: AMT, max: 100 }, { path: AMT, max: 200 }, { path: RCP, oneOf: ['alice', 'bob'] }] } });
const pol = (max: number, who?: string[]): PolicyInput => ({
  predicates: [{ verb: 'stripe.refund', resource: '*', where: [{ field: AMT, op: 'gte', value: 0 }, { field: AMT, op: 'lte', value: max }, ...(who ? [{ field: RCP, op: 'in' as const, value: who }] : [])] }],
});

function mapFor(ref: string, truth: PolicyInput, om: Omega = omega, maxQuestions = 80): IntentMap {
  const l = createLearner(om, { nullMass: 0.05 });
  const t = admitter(truth);
  elicit(l, (q) => (t.admits(om.verbs.find((v) => v.verb === q.verb)!, q.outcome) ? 1 : 0), { epsRisk: 0, epsBurden: 0, maxQuestions });
  return emitIntentMap(l, ref);
}

const A = mapFor('A', pol(200));
const B = mapFor('B', pol(100));
const C = mapFor('C', pol(200, ['alice']));
const grantSet = (m: IntentMap) => new Set(m.cells.map((c, i) => (c.in_grant ? i : -1)).filter((i) => i >= 0));
const sub = (a: Set<number>, b: Set<number>) => [...a].every((x) => b.has(x));

describe('aggregation rules (M7)', () => {
  it('unanimity is the intersection (T5) and is what combineIntentMaps computes', () => {
    const u = combineIntentMaps([A, B, C]);
    const expected = new Set([...grantSet(A)].filter((i) => grantSet(B).has(i) && grantSet(C).has(i)));
    expect(grantSet(u)).toEqual(expected);
    expect(u.aggregation?.rule).toBe('unanimity');
    const gu = admitter(u.grant);
    omega.verbs.forEach((vs) => {
      for (let c = 0; c < verbCellCount(vs); c++) {
        const o = cellRep(vs, decodeCell(vs, c));
        expect(gu.admits(vs, o)).toBe(expected.has(c));
      }
    });
  });
  it('quorum: k = n is unanimity, k = 1 is the union, and the grant shrinks as k grows', () => {
    const g = [1, 2, 3].map((k) => grantSet(aggregateIntentMaps([A, B, C], { kind: 'quorum', k })));
    expect(g[2]).toEqual(grantSet(combineIntentMaps([A, B, C])));
    expect(g[0]).toEqual(new Set([...grantSet(A), ...grantSet(B), ...grantSet(C)]));
    expect(sub(g[1]!, g[0]!)).toBe(true);
    expect(sub(g[2]!, g[1]!)).toBe(true);
  });
  it('a vetoer bounds the joint grant by its own grant, whatever the rule', () => {
    const q = aggregateIntentMaps([A, B, C], { kind: 'quorum', k: 1, vetoers: ['B'] });
    expect(sub(grantSet(q), grantSet(B))).toBe(true);
    expect(q.aggregation?.vetoers).toEqual(['B']);
  });
  it('weighted: a principal whose weight others cannot make up for is an implicit vetoer', () => {
    const rule = { kind: 'weighted' as const, weights: { A: 3, B: 1, C: 1 }, threshold: 4 };
    expect(effectiveVetoers(rule, ['A', 'B', 'C'])).toEqual(['A']);
    expect(sub(grantSet(aggregateIntentMaps([A, B, C], rule)), grantSet(A))).toBe(true);
    expect(() => aggregateIntentMaps([A, B, C], { kind: 'weighted', weights: { A: 1, B: 1 }, threshold: 1 })).toThrow(/weight/);
    expect(() => aggregateIntentMaps([A, B, C], { kind: 'quorum', k: 4 })).toThrow(/quorum/);
  });
  it('PROPERTY: joint acceptance equals brute-force enumeration', () => {
    const r = rng(29);
    for (let t = 0; t < 200; t++) {
      const n = 1 + Math.floor(r() * 5);
      const refs = Array.from({ length: n }, (_, i) => `p${i}`);
      const weights = Object.fromEntries(refs.map((x) => [x, Math.floor(r() * 4)]));
      const W = Object.values(weights).reduce((s, w) => s + w, 0);
      if (W === 0) continue;
      const threshold = 1 + Math.floor(r() * W);
      const vetoers = refs.filter(() => r() < 0.2);
      const nr = normalizeRule({ kind: 'weighted', weights, threshold, vetoers }, refs);
      const ps = refs.map(() => r());
      let brute = 0;
      for (let mask = 0; mask < 1 << n; mask++) {
        let pr = 1;
        let w = 0;
        let ok = true;
        refs.forEach((x, i) => {
          const yes = ((mask >> i) & 1) === 1;
          pr *= yes ? ps[i]! : 1 - ps[i]!;
          if (yes) w += weights[x]!;
          else if (vetoers.includes(x)) ok = false;
        });
        if (ok && w >= threshold) brute += pr;
      }
      expect(jointAcceptance(nr, ps)).toBeCloseTo(brute, 12);
    }
  });
  it('PROPERTY (T5, estimate form): each vetoer\'s own estimated risk of the joint grant is at most that of its own grant', () => {
    const r = rng(31);
    for (let t = 0; t < 12; t++) {
      const maps = ['A', 'B', 'C'].map((ref) => mapFor(ref, pol([100, 200, 500][Math.floor(r() * 3)]!, r() < 0.5 ? ['alice'] : undefined), omega, 1 + Math.floor(r() * 3)));
      for (const rule of [{ kind: 'unanimity' as const }, { kind: 'quorum' as const, k: 2, vetoers: ['A'] }]) {
        const agg = aggregateIntentMaps(maps, rule);
        const bound = effectiveVetoers(rule, ['A', 'B', 'C']);
        for (const pp of agg.aggregation!.per_principal) {
          if (!bound.includes(pp.intent_ref)) continue;
          const own = maps.find((m) => m.intent_ref === pp.intent_ref)!.metrics.residual_risk_ppm;
          // per_principal is computed from the ppm-rounded p (|Δp| ≤ 5e-7 per cell): allow E[h]·1e-6 of slack
          expect(pp.residual_risk_ppm).toBeLessThanOrEqual(own + agg.metrics.mean_harm_ppm * 1e-6 + 2);
        }
      }
    }
  });
  it('an aggregate re-verifies from its inputs; tampering is detected', () => {
    const q = aggregateIntentMaps([A, B, C], { kind: 'quorum', k: 2 });
    expect(verifyAggregate(q, [A, B, C])).toEqual({ ok: true, problems: [] });
    const bad = JSON.parse(JSON.stringify(q)) as IntentMap;
    bad.cells[0]!.in_grant = !bad.cells[0]!.in_grant;
    expect(verifyAggregate(bad, [A, B, C]).ok).toBe(false);
    const badIn = JSON.parse(JSON.stringify(B)) as IntentMap;
    badIn.metrics.residual_risk_ppm += 10;
    expect(verifyAggregate(q, [A, badIn, C]).ok).toBe(false);
  });
});

describe('cross-org maps over different Ω', () => {
  const om1 = deriveOmega({ policies: [], slots: { verbs: ['stripe.refund'], constraints: [{ path: AMT, max: 100 }] } });
  const om2 = deriveOmega({ policies: [], slots: { verbs: ['stripe.refund', 'stripe.charge'], constraints: [{ path: AMT, max: 200 }, { path: RCP, oneOf: ['alice'] }] } });
  const X = mapFor('X', pol(100), om1);
  const Y = mapFor('Y', { predicates: [...(pol(200, ['alice']).predicates as object[]), { verb: 'stripe.charge', resource: '*' }] } as PolicyInput, om2);
  it('the common refinement unions verbs, dimensions, cuts and values', () => {
    const c = commonRefinement([learnerFromMap(X).omega, learnerFromMap(Y).omega]);
    expect(c.verbs.map((v) => v.verb)).toEqual(['stripe.charge', 'stripe.refund']);
    const refund = c.verbs.find((v) => v.verb === 'stripe.refund')!;
    expect(refund.dims.map((d) => d.path)).toEqual([AMT, RCP]);
    expect(refund.dims[0]).toMatchObject({ cuts: [100, 200] });
  });
  it('lifting never widens a map (L-lift), and a verb a map never covered is denied for it', () => {
    const { lifted, omega: om, aggregate } = crossOrgAggregate([X, Y], { kind: 'unanimity' }, { orgs: { X: 'org-x', Y: 'org-y' } });
    const orig = [learnerFromMap(X), learnerFromMap(Y)];
    lifted.forEach((m, i) => {
      const g = admitter(m.grant);
      for (const vs of om.verbs) {
        for (let c = 0; c < verbCellCount(vs); c++) {
          const o = cellRep(vs, decodeCell(vs, c));
          if (g.admits(vs, o)) expect(orig[i]!.admitsOutcome(o)).toBe(true);
        }
      }
    });
    const charge = om.verbs.find((v) => v.verb === 'stripe.charge')!;
    expect(admitter(lifted[0]!.grant).admits(charge, cellRep(charge, decodeCell(charge, 0)))).toBe(false);
    expect(aggregate.aggregation?.per_principal.map((p) => p.org)).toEqual(['org-x', 'org-y']);
    expect(verifyCrossOrgAggregate(aggregate, [X, Y], { orgs: { X: 'org-x', Y: 'org-y' } })).toEqual({ ok: true, problems: [] });
  });
});

describe('question cards (M4 UX components)', () => {
  const l = createLearner(omega, { nullMass: 0.05 });
  const q = l.nextQuestion()!;
  const card = questionCard(omega, q);
  it('is deterministic and content-addressed', () => {
    expect(questionCard(omega, q)).toEqual(card);
    expect(card.answers).toEqual(['yes', 'no', 'partly']);
    expect(card.facts.map((f) => f.path)).toEqual([AMT, RCP]);
  });
  it('validates partial answers against the card and produces learner answers', () => {
    expect(parseCardAnswer(card, { answer: 'yes' })).toEqual({ ok: true, answer: 1 });
    expect(parseCardAnswer(card, { answer: 'partly', path: 'env.hour', upTo: 3 }).ok).toBe(false);
    expect(parseCardAnswer(card, { answer: 'partly', newField: 'action.params.recipient', notFor: ['x'] }).ok).toBe(false);
    const nf = parseCardAnswer(card, { answer: 'partly', newField: 'action.params.channel', notFor: ['#general'] });
    expect(nf.ok).toBe(true);
    const slot = card.partial.find((s) => s.path === AMT)!;
    if (slot.kind !== 'num') throw new Error('x');
    if (slot.hi > slot.lo) {
      const up = parseCardAnswer(card, { answer: 'partly', path: AMT, upTo: slot.lo });
      expect(up.ok).toBe(true);
      if (up.ok && typeof up.answer === 'object') {
        const { learner } = answerPartial(l, q, up.answer);
        expect(learner.omega.verbs[0]!.dims[0]).toMatchObject({ path: AMT });
      }
      expect(parseCardAnswer(card, { answer: 'partly', path: AMT, upTo: slot.hi }).ok).toBe(false);
    }
  });
});
