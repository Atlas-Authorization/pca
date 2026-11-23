import { describe, expect, it } from 'vitest';
import type { Caveat, Predicate } from '@atlasauth/pca';
import {
  IntentLearner,
  OTHER,
  createLearner,
  grantDigest,
  emitIntentMap,
  learnerOptionsOf,
  mapLearnerOptions,
  omegaFromJSON,
  omegaToJSON,
  verifyIntentMap,
  type IntentMap,
  type Omega,
  type OmegaJSON,
} from './index';

const AMOUNT = 'action.params.amount';
const num = (lo: number, hi: number, cuts: number[]) => ({ kind: 'num' as const, path: AMOUNT, lo, hi, cuts, dist: 'uniform' as const });
const verb = (name: string, weight: number, lo = 0, hi = 9, cuts: number[] = [5]) => ({ verb: name, reversibility: 'reversible' as const, weight, dims: [num(lo, hi, cuts)] });
const omega1 = (): Omega => ({ v: 1, approximate: [], verbs: [verb('x.a', 1)] });
const omega2 = (): Omega => ({ v: 1, approximate: [], verbs: [verb('x.a', 0.5, 0, 8, [3, 6]), verb('x.b', 0.5, 0, 8, [3, 6])] });
const at = (verbName: string, v: number) => ({ verb: verbName, values: { [AMOUNT]: v } });
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const allowAll = (v: string): Predicate[] => [{ verb: v, resource: '*' }];
const deadRate: Caveat = { type: 'rate', max: 0, per_secs: 60 };

describe('omega JSON conversion', () => {
  it('writes weight 1 for equal weights, ppm for unequal ones, and never below 1', () => {
    const eq = omegaToJSON({ v: 1, approximate: [], verbs: [verb('x.a', 0.5), verb('x.b', 0.5)] });
    expect(eq.verbs.map((v) => v.w)).toEqual([1, 1]);
    const ne = omegaToJSON({ v: 1, approximate: [], verbs: [verb('x.a', 0.25), verb('x.b', 0.75)] });
    expect(ne.verbs.map((v) => v.w)).toEqual([250_000, 750_000]);
    const tiny = omegaToJSON({ v: 1, approximate: [], verbs: [verb('x.a', 1e-9), verb('x.b', 1 - 1e-9)] });
    expect(tiny.verbs.map((v) => v.w)).toEqual([1, 1_000_000]);
  });

  it('serialises numeric and categorical dimensions and copies the approximate list', () => {
    const o: Omega = {
      v: 1,
      approximate: ['regex'],
      verbs: [
        {
          verb: 'x.a',
          reversibility: 'reversible',
          weight: 1,
          dims: [num(0, 9, [5]), { kind: 'cat', path: 'action.params.to', values: [{ kind: 'exact', value: 'a' }, { kind: 'other', value: OTHER }] }],
        },
      ],
    };
    const j = omegaToJSON(o);
    expect(j.approximate).toEqual(['regex']);
    expect(j.approximate).not.toBe(o.approximate);
    expect(j.verbs[0]!.dims).toEqual([
      { kind: 'num', path: AMOUNT, lo: 0, hi: 9, cuts: [5], dist: 'uniform' },
      { kind: 'cat', path: 'action.params.to', values: [{ kind: 'exact', value: 'a' }, { kind: 'other', value: OTHER }] },
    ]);
  });

  it('reads defaults back: missing cuts, dist and values, weights normalised, approximate copied', () => {
    const j: OmegaJSON = {
      approximate: ['cross-field'],
      verbs: [
        { verb: 'x.a', reversibility: 'reversible', w: 1, dims: [{ kind: 'num', path: AMOUNT, lo: 0, hi: 9 }, { kind: 'cat', path: 'action.params.to' }] },
        { verb: 'x.b', reversibility: 'reversible', w: 3, dims: [] },
      ],
    };
    const o = omegaFromJSON(j);
    expect(o.approximate).toEqual(['cross-field']);
    expect(o.approximate).not.toBe(j.approximate);
    expect(o.verbs.map((v) => v.weight)).toEqual([0.25, 0.75]);
    expect(o.verbs[0]!.dims).toEqual([
      { kind: 'num', path: AMOUNT, lo: 0, hi: 9, cuts: [], dist: 'uniform' },
      { kind: 'cat', path: 'action.params.to', values: [] },
    ]);
  });
});

describe('createLearner defaults', () => {
  it('derives tau from eta only when tau is not given', () => {
    expect(createLearner(omega1()).tau).toBe(1);
    expect(createLearner(omega1(), { eta: 0.1 }).tau).toBe(0.95);
    expect(createLearner(omega1(), { eta: 0.1, tau: 0.5 }).tau).toBe(0.5);
    expect(createLearner(omega1(), { tau: 0.9 }).tau).toBe(0.9);
  });

  it('defaults the strategy to disagreement and keeps an explicit one', () => {
    expect(createLearner(omega1()).strategy).toBe('disagreement');
    expect(createLearner(omega1(), { strategy: 'risk' }).strategy).toBe('risk');
  });

  it('builds the decision-list class as given (kind, rules, quantised decay, conditions)', () => {
    const l = createLearner(omega1(), { hypothesisClass: { kind: 'decision-list', maxRules: 2, decay: 0.5, conditions: 'atomic' } });
    expect(l.hypothesisClass).toEqual({ kind: 'decision-list', maxRules: 2, decay: 0.5, conditions: 'atomic' });
    const d = createLearner(omega1(), { hypothesisClass: { kind: 'decision-list', maxRules: 1 } });
    expect(d.hypothesisClass).toEqual({ kind: 'decision-list', maxRules: 1, decay: 0.25, conditions: 'box' });
  });

  it('learnerOptionsOf refuses a learner that was not built by createLearner', () => {
    expect(() => learnerOptionsOf(new IntentLearner(omega1()))).toThrow('pca-intent: build the learner with createLearner() so its parameters are serialisable');
  });
});

describe('priorMix as data', () => {
  const mk = (cells: { verb: string; cell: number; q: number }[], beta = 0.8) => () => createLearner(omega2(), { priorMix: { beta, cells } });

  it('rejects q outside [0, 1] and bad cell indices with the exact message', () => {
    const msg = 'pca-intent: priorMix cells need q in [0, 1] and a cell index >= 0';
    expect(mk([{ verb: 'x.a', cell: 0, q: 1.5 }])).toThrow(msg);
    expect(mk([{ verb: 'x.a', cell: 0, q: -0.5 }])).toThrow(msg);
    expect(mk([{ verb: 'x.a', cell: 0, q: Number.NaN }])).toThrow(msg);
    expect(mk([{ verb: 'x.a', cell: 0.5, q: 0.5 }])).toThrow(msg);
    expect(mk([{ verb: 'x.a', cell: -1, q: 0.5 }])).toThrow(msg);
    expect(mk([{ verb: 'x.a', cell: 0, q: 2 }])).toThrow(msg);
  });

  it('accepts the closed endpoints q = 0 and q = 1 and cell 0', () => {
    expect(mk([{ verb: 'x.a', cell: 0, q: 0 }])).not.toThrow();
    expect(mk([{ verb: 'x.a', cell: 0, q: 1 }])).not.toThrow();
    expect(mk([{ verb: 'x.a', cell: 0, q: 0.5 }])).not.toThrow();
  });

  it('weights hypotheses by prod q^[c in h] (1-q)^[c not in h] per verb, and leaves unlisted verbs neutral', () => {
    const cells = [
      { verb: 'x.a', cell: 0, q: 0.9 },
      { verb: 'x.a', cell: 2, q: 0.1 },
    ];
    const made = createLearner(omega2(), { priorMix: { beta: 0.8, cells } });
    const ref = new IntentLearner(omega2(), {
      eta: 0,
      tau: 1,
      strategy: 'disagreement',
      nullMass: () => 0.2,
      hypothesisClass: { kind: 'box' },
      priorMix: {
        beta: 0.8,
        weight: (vs, contains) => {
          let lw = 0;
          if (vs.verb === 'x.a') for (const t of cells) lw += contains(t.cell) ? Math.log(t.q) : Math.log(1 - t.q);
          return Math.exp(lw);
        },
      },
    });
    const plain = createLearner(omega2());
    expect(made.cells()).toEqual(ref.cells());
    expect(made.cells()).not.toEqual(plain.cells());
  });
});

describe('anchors', () => {
  const p1 = { predicates: allowAll('x.a') };
  it('quantises lambda to milli and keeps the anchor caveats in the learner prior', () => {
    const base = { eta: 0, tau: 1, strategy: 'disagreement' as const, nullMass: () => 0.2, hypothesisClass: { kind: 'box' as const } };
    const made = createLearner(omega1(), { anchor: { policy: { predicates: p1.predicates, caveats: [deadRate] }, lambda: 3.12345 } });
    const ref = new IntentLearner(omega1(), { ...base, anchor: { policy: { predicates: p1.predicates, caveats: [deadRate] }, lambda: 3.123 } });
    const noCaveat = new IntentLearner(omega1(), { ...base, anchor: { policy: { predicates: p1.predicates, caveats: [] }, lambda: 3.123 } });
    expect(made.cells()).toEqual(ref.cells());
    expect(made.cells()).not.toEqual(noCaveat.cells());
    const madeList = createLearner(omega1(), { anchors: [{ policy: { predicates: p1.predicates, caveats: [deadRate] }, lambda: 3.12345 }] });
    const refList = new IntentLearner(omega1(), { ...base, anchors: [{ policy: { predicates: p1.predicates, caveats: [deadRate] }, lambda: 3.123 }] });
    expect(madeList.cells()).toEqual(refList.cells());
  });

  it('an anchor without caveats gets an empty caveat list in the learner prior', () => {
    const base = { eta: 0, tau: 1, strategy: 'disagreement' as const, nullMass: () => 0.2, hypothesisClass: { kind: 'box' as const } };
    const pr: Predicate[] = [{ verb: 'x.a', resource: '*', where: [{ field: AMOUNT, op: 'lte', value: 5 }] }];
    const made = createLearner(omega1(), { anchor: { policy: { predicates: pr }, lambda: 3 } });
    const ref = new IntentLearner(omega1(), { ...base, anchor: { policy: { predicates: pr, caveats: [] }, lambda: 3 } });
    expect(made.cells()).toEqual(ref.cells());
  });

  it('serialises anchors with lambda in milli and caveats defaulting to []', () => {
    const l = createLearner(omega1(), { anchor: { policy: p1, lambda: 0.12345 }, anchors: [{ policy: { predicates: p1.predicates, caveats: [deadRate] }, lambda: 0.5 }] });
    const m = emitIntentMap(l);
    expect(m.learner.anchor).toEqual({ policy: { predicates: p1.predicates, caveats: [] }, lambda_milli: 123 });
    expect(m.learner.anchors).toEqual([{ policy: { predicates: p1.predicates, caveats: [deadRate] }, lambda_milli: 500 }]);
    const o = mapLearnerOptions(m);
    expect(o.anchor).toEqual({ policy: { predicates: p1.predicates, caveats: [] }, lambda: 0.123 });
    expect(o.anchors).toEqual([{ policy: { predicates: p1.predicates, caveats: [deadRate] }, lambda: 0.5 }]);
  });
});

describe('emitIntentMap fields', () => {
  it('records principals from the intent ref', () => {
    expect(emitIntentMap(createLearner(omega1())).principals).toEqual([]);
    const m = emitIntentMap(createLearner(omega1()), 'ref-1');
    expect(m.principals).toEqual(['ref-1']);
    expect(m.intent_ref).toBe('ref-1');
  });

  it('writes class_params per class: union k and decay, decision-list rules and decay, none for box', () => {
    const u = emitIntentMap(createLearner(omega1(), { hypothesisClass: { kind: 'union', k: 2, decay: 0.5 } }));
    expect(u.learner.hypothesis_class).toBe('per-verb-union/v1');
    expect(u.learner.class_params).toEqual({ k: 2, decay_ppm: 500_000 });
    const u0 = emitIntentMap(createLearner(omega1(), { hypothesisClass: { kind: 'union', k: 3 } }));
    expect(u0.learner.class_params).toEqual({ k: 3, decay_ppm: 250_000 });
    const d = emitIntentMap(createLearner(omega1(), { hypothesisClass: { kind: 'decision-list', maxRules: 2, decay: 0.5, conditions: 'atomic' } }));
    expect(d.learner.hypothesis_class).toBe('per-verb-decision-list/v1');
    expect(d.learner.class_params).toEqual({ max_rules: 2, decay_ppm: 500_000 });
    const d2 = emitIntentMap(createLearner(omega1(), { hypothesisClass: { kind: 'decision-list', maxRules: 1 } }));
    expect(d2.learner.hypothesis_class).toBe('per-verb-decision-list/v2');
    expect(d2.learner.class_params).toEqual({ max_rules: 1, decay_ppm: 250_000 });
    const b = emitIntentMap(createLearner(omega1()));
    expect(b.learner).not.toHaveProperty('class_params');
  });

  it('writes agnostic_slack only for an agnostic learner', () => {
    expect(emitIntentMap(createLearner(omega1(), { agnosticSlack: 1 })).learner.agnostic_slack).toBe(1);
    expect(emitIntentMap(createLearner(omega1())).learner).not.toHaveProperty('agnostic_slack');
  });

  it('writes noise when either asymmetric rate is given and not otherwise', () => {
    expect(emitIntentMap(createLearner(omega1(), { etaPos: 0.1 })).learner.noise).toEqual({ eta_pos_ppm: 100_000, eta_neg_ppm: 0 });
    expect(emitIntentMap(createLearner(omega1(), { etaNeg: 0.2 })).learner.noise).toEqual({ eta_pos_ppm: 0, eta_neg_ppm: 200_000 });
    expect(emitIntentMap(createLearner(omega1(), { eta: 0.1 })).learner).not.toHaveProperty('noise');
  });

  it('carries the region of a partial answer and omits the key otherwise', () => {
    const l = createLearner(omega1());
    const region = { verb: 'x.a', dims: { [AMOUNT]: { kind: 'num' as const, lo: 0, hi: 4 } } };
    l.observe(at('x.a', 2), 1, 'elicitation', region);
    l.observe(at('x.a', 7), 1, 'elicitation');
    const m = emitIntentMap(l);
    expect(m.observations[0]!.region).toEqual(region);
    expect(m.observations[1]).not.toHaveProperty('region');
  });

  it('fidelity, entropy and log2 version space follow the learner metrics', () => {
    const l = createLearner(omega1(), { eta: 0.1, tau: 0.5 });
    l.observe(at('x.a', 7), 1);
    l.observe(at('x.a', 2), 0);
    const lm = l.metrics();
    let rmax = 0;
    for (const c of l.cells()) rmax += c.mass * (1 - c.p) * c.harm;
    expect(l.cells().some((c) => c.inGrant && c.p < 1)).toBe(true);
    const expected = Math.round((1 - lm.residualRisk / rmax) * 1_000_000);
    expect(expected).toBeGreaterThan(0);
    expect(expected).toBeLessThan(1_000_000);
    const m = emitIntentMap(l).metrics;
    expect(m.fidelity_est_ppm).toBe(expected);
    expect(lm.entropyBits).toBeGreaterThan(0);
    expect(m.entropy_mbits).toBe(Math.round(lm.entropyBits * 1000));
    expect(m.log2_vs_mbits).toBeNull();
    const exact = createLearner(omega1());
    const em = emitIntentMap(exact).metrics;
    expect(exact.metrics().log2VersionSpace).toBeGreaterThan(0);
    expect(em.log2_vs_mbits).toBe(Math.round(exact.metrics().log2VersionSpace! * 1000));
  });

  it('reports fidelity 1 when nothing can still be lost (every cell known accepted)', () => {
    const l = createLearner({ v: 1, approximate: [], verbs: [verb('x.a', 1, 0, 1, [1])] });
    l.observe(at('x.a', 0), 1);
    l.observe(at('x.a', 1), 1);
    expect(l.cells().every((c) => c.p === 1)).toBe(true);
    const m = emitIntentMap(l).metrics;
    expect(m.fidelity_est_ppm).toBe(1_000_000);
    expect(m.residual_risk_ppm).toBe(0);
  });
});

describe('mapLearnerOptions', () => {
  it('reads class parameters, with defaults when class_params is absent', () => {
    const m = emitIntentMap(createLearner(omega1(), { hypothesisClass: { kind: 'union', k: 3, decay: 0.5 } }));
    expect(mapLearnerOptions(m).hypothesisClass).toEqual({ kind: 'union', k: 3, decay: 0.5 });
    const noCp = clone(m);
    delete noCp.learner.class_params;
    expect(mapLearnerOptions(noCp).hypothesisClass).toEqual({ kind: 'union', k: 2, decay: 0.25 });
    const partial = clone(m);
    partial.learner.class_params = { decay_ppm: 100_000 } as IntentMap['learner']['class_params'];
    expect(mapLearnerOptions(partial).hypothesisClass).toEqual({ kind: 'union', k: 2, decay: 0.1 });
    const noDecay = clone(m);
    noDecay.learner.class_params = { k: 4 } as IntentMap['learner']['class_params'];
    expect(mapLearnerOptions(noDecay).hypothesisClass).toEqual({ kind: 'union', k: 4, decay: 0.25 });

    const dl = emitIntentMap(createLearner(omega1(), { hypothesisClass: { kind: 'decision-list', maxRules: 3, decay: 0.5, conditions: 'atomic' } }));
    expect(mapLearnerOptions(dl).hypothesisClass).toEqual({ kind: 'decision-list', maxRules: 3, decay: 0.5, conditions: 'atomic' });
    const dl2 = clone(dl);
    dl2.learner.hypothesis_class = 'per-verb-decision-list/v2';
    expect(mapLearnerOptions(dl2).hypothesisClass).toEqual({ kind: 'decision-list', maxRules: 3, decay: 0.5, conditions: 'box' });
    delete dl2.learner.class_params;
    expect(mapLearnerOptions(dl2).hypothesisClass).toEqual({ kind: 'decision-list', maxRules: 2, decay: 0.25, conditions: 'box' });
    const dl3 = clone(dl);
    dl3.learner.class_params = { decay_ppm: 100_000 } as IntentMap['learner']['class_params'];
    expect(mapLearnerOptions(dl3).hypothesisClass).toEqual({ kind: 'decision-list', maxRules: 2, decay: 0.1, conditions: 'atomic' });
    dl3.learner.class_params = { max_rules: 4 } as IntentMap['learner']['class_params'];
    expect(mapLearnerOptions(dl3).hypothesisClass).toEqual({ kind: 'decision-list', maxRules: 4, decay: 0.25, conditions: 'atomic' });
  });

  it('reads agnostic slack, monotone offMass and noise rates', () => {
    const ag = emitIntentMap(createLearner(omega1(), { agnosticSlack: 2 }));
    expect(mapLearnerOptions(ag).agnosticSlack).toBe(2);
    expect(mapLearnerOptions(emitIntentMap(createLearner(omega1()))).agnosticSlack).toBeUndefined();
    expect(mapLearnerOptions(emitIntentMap(createLearner(omega1()))) as object).not.toHaveProperty('agnosticSlack');
    const mono = emitIntentMap(createLearner(omega1(), { monotone: { paths: [AMOUNT], offMass: 0.25 } }));
    expect(mono.learner.monotone).toEqual({ paths: [AMOUNT], off_ppm: 250_000 });
    expect(mapLearnerOptions(mono).monotone).toEqual({ paths: [AMOUNT], offMass: 0.25 });
    const noise = emitIntentMap(createLearner(omega1(), { etaPos: 0.1, etaNeg: 0.2 }));
    const o = mapLearnerOptions(noise);
    expect(o.etaPos).toBe(0.1);
    expect(o.etaNeg).toBe(0.2);
  });

  it('round-trips the population prior', () => {
    const cells = [{ verb: 'x.a', cell: 1, q: 0.25 }];
    const m = emitIntentMap(createLearner(omega1(), { priorMix: { beta: 0.5, cells } }));
    expect(m.learner.prior_mix).toEqual({ beta_ppm: 500_000, cells: [{ verb: 'x.a', cell: 1, q_ppm: 250_000 }] });
    expect(mapLearnerOptions(m).priorMix).toEqual({ beta: 0.5, cells });
  });
});

describe('verifyIntentMap', () => {
  const build = (): IntentMap => {
    const l = createLearner(omega1());
    l.observe(at('x.a', 7), 1);
    l.observe(at('x.a', 2), 0);
    return emitIntentMap(l, 'ref-1');
  };

  it('accepts an honest map', () => {
    expect(verifyIntentMap(build())).toEqual({ ok: true, problems: [] });
  });

  it('refuses a non-map', () => {
    const notMap = { ok: false, problems: ['not an intent map v1'] };
    expect(verifyIntentMap({ ...build(), v: 2 } as unknown as IntentMap)).toEqual(notMap);
    expect(verifyIntentMap({ ...build(), kind: 'other' } as unknown as IntentMap)).toEqual(notMap);
    expect(verifyIntentMap(undefined as unknown as IntentMap)).toEqual(notMap);
  });

  it('refuses a combined map', () => {
    const combined = { ok: false, problems: ['combined map: verify each principal map and recombine with verifyAggregate'] };
    expect(verifyIntentMap({ ...build(), principals: ['a', 'b'] })).toEqual(combined);
    expect(verifyIntentMap({ ...build(), principals: ['a'], aggregation: { rule: 'unanimity', vetoers: [], per_principal: [] } })).toEqual(combined);
  });

  it('reports a grant that does not match the replayed posterior', () => {
    const m = build();
    m.grant_digest = 'bad';
    expect(verifyIntentMap(m)).toEqual({ ok: false, problems: ['grant does not match the replayed posterior'] });
  });

  it('reports a grant whose own digest matches but that the replay does not produce', () => {
    const m = build();
    m.grant = { predicates: [], caveats: [] };
    m.grant_digest = grantDigest(m.grant);
    expect(verifyIntentMap(m)).toEqual({ ok: false, problems: ['grant does not match the replayed posterior'] });
  });

  it('reports a different cell count', () => {
    const m = build();
    m.cells.push({ ...m.cells[0]! });
    expect(verifyIntentMap(m)).toEqual({ ok: false, problems: ['cell count differs'] });
  });

  it('checks each cell field on its own and tolerates 2 ppm on p', () => {
    const bad = { ok: false, problems: ['cell 0 differs'] };
    const v = build();
    v.cells[0]!.verb = 'x.z';
    expect(verifyIntentMap(v)).toEqual(bad);
    const g = build();
    g.cells[0]!.in_grant = !g.cells[0]!.in_grant;
    expect(verifyIntentMap(g)).toEqual(bad);
    for (const d of [1, 2, -2]) {
      const ok = build();
      ok.cells[0]!.p_ppm += d;
      expect(verifyIntentMap(ok).ok).toBe(true);
    }
    for (const d of [3, -3]) {
      const p = build();
      p.cells[0]!.p_ppm += d;
      expect(verifyIntentMap(p)).toEqual(bad);
    }
  });

  it('checks metrics with a 2 unit tolerance and names the claimed and replayed values', () => {
    for (const d of [1, 2, -2]) {
      const ok = build();
      ok.metrics.questions += d;
      expect(verifyIntentMap(ok).ok).toBe(true);
    }
    const m = build();
    const real = m.metrics.questions;
    m.metrics.questions = real + 3;
    expect(verifyIntentMap(m)).toEqual({ ok: false, problems: [`metric questions differs (${real + 3} claimed, ${real} replayed)`] });
  });

  it('compares a null log2 version space exactly, in both directions', () => {
    const noisy = createLearner(omega1(), { eta: 0.1 });
    noisy.observe(at('x.a', 7), 1);
    const n = emitIntentMap(noisy);
    expect(n.metrics.log2_vs_mbits).toBeNull();
    expect(verifyIntentMap(n).ok).toBe(true);
    for (const claim of [0, 1, 2]) {
      const t = clone(n);
      t.metrics.log2_vs_mbits = claim;
      expect(verifyIntentMap(t)).toEqual({ ok: false, problems: [`metric log2_vs_mbits differs (${claim} claimed, null replayed)`] });
    }

    const tiny = createLearner({ v: 1, approximate: [], verbs: [verb('x.a', 1, 0, 0, [])] });
    tiny.observe(at('x.a', 0), 1);
    const s = emitIntentMap(tiny);
    expect(s.metrics.log2_vs_mbits).toBe(0);
    expect(verifyIntentMap(s).ok).toBe(true);
    const nulled = clone(s);
    nulled.metrics.log2_vs_mbits = null;
    expect(verifyIntentMap(nulled)).toEqual({ ok: false, problems: ['metric log2_vs_mbits differs (null claimed, 0 replayed)'] });
    const two = clone(s);
    two.metrics.log2_vs_mbits = 2;
    expect(verifyIntentMap(two).ok).toBe(true);
    two.metrics.log2_vs_mbits = 3;
    expect(verifyIntentMap(two).ok).toBe(false);
  });

  it('turns a replay failure into a problem instead of throwing', () => {
    const m = build();
    m.learner.eta_ppm = 600_000;
    expect(verifyIntentMap(m)).toEqual({ ok: false, problems: ['replay failed: pca-intent: eta must be in [0, 0.5)'] });
  });
});
