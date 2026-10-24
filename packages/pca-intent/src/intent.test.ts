import { describe, expect, it } from 'vitest';
import { b64u, compilePolicy, generateKeyPair, mintGrant, verifyGoalCommit, DEFAULT_RISK_POLICY, type Predicate } from '@atlasauth/pca';
import {
  admitter,
  applyDivergence,
  backTranslationDiff,
  boundaryWitnesses,
  cellOf,
  cellRep,
  cellStats,
  checkWitnesses,
  combineIntentMaps,
  createLearner,
  decodeCell,
  deriveOmega,
  elicit,
  emitIntentMap,
  estimateResidualRiskMC,
  hoeffdingHalfWidth,
  harmMax,
  intentGoal,
  intentMapDigest,
  intentRef,
  measureGrant,
  acceptabilityOf,
  parseIntentGoal,
  renderGrant,
  signIntent,
  verbCellCount,
  verifyIntent,
  verifyIntentMap,
  type IntentSlots,
  type Omega,
} from './index';

const refund200 = { predicates: [{ verb: 'stripe.refund', resource: '*', where: [{ field: 'action.params.amount', op: 'lte', value: 200 }, { field: 'action.params.amount', op: 'gte', value: 0 }] }] as Predicate[], caveats: [] };
const slots: IntentSlots = {
  verbs: ['stripe.refund'],
  constraints: [
    { path: 'action.params.amount', max: 200, unit: 'USD' },
    { path: 'action.params.recipient', oneOf: ['alice', 'bob'] },
  ],
};
const truth = {
  predicates: [{ verb: 'stripe.refund', resource: '*', where: [{ field: 'action.params.amount', op: 'gte', value: 0 }, { field: 'action.params.amount', op: 'lte', value: 200 }, { field: 'action.params.recipient', op: 'in', value: ['alice', 'bob'] }] }] as Predicate[],
  caveats: [],
};

function everyCell(omega: Omega, f: (vsIdx: number, idx: number[]) => void): void {
  omega.verbs.forEach((vs, v) => {
    for (let c = 0; c < verbCellCount(vs); c++) f(v, decodeCell(vs, c));
  });
}

describe('outcome space Ω', () => {
  const omega = deriveOmega({ policies: [refund200], slots });
  it('derives typed dimensions from the grant + slots vocabulary', () => {
    expect(omega.verbs.map((v) => v.verb)).toEqual(['stripe.refund']);
    const dims = omega.verbs[0]!.dims;
    expect(dims.map((d) => d.path)).toEqual(['action.params.amount', 'action.params.recipient']);
    expect(dims[0]).toMatchObject({ kind: 'num', cuts: [0, 200], lo: 0, hi: 100_000 });
    expect(dims[1]!.kind).toBe('cat');
  });
  it('cells partition Ω: masses sum to 1 and every representative maps back to its own cell', () => {
    let total = 0;
    everyCell(omega, (v, idx) => {
      const vs = omega.verbs[v]!;
      total += cellStats(vs, idx).mass;
      expect(cellOf(vs, cellRep(vs, idx))).toEqual(idx);
    });
    expect(total).toBeCloseTo(1, 12);
  });
  it('wildcard verbs expand to catalog verbs of the mentioned connectors', () => {
    const o = deriveOmega({ policies: [{ predicates: [{ verb: '*' }] }], slots: { verbs: ['gmail.send'], constraints: [] } });
    expect(o.verbs.map((v) => v.verb)).toEqual(['gmail.delete', 'gmail.draft', 'gmail.send']);
  });
});

describe('deterministic renderer + back-translation diff', () => {
  it('renders the same text every time and names the limits', () => {
    const p = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$200' }, now: 0 });
    const a = renderGrant(p);
    expect(renderGrant(p)).toBe(a);
    expect(a).toContain('the amount is at most 200');
    expect(a).toContain('stripe.refund');
  });
  it('never drops an unknown caveat silently', () => {
    expect(renderGrant({ predicates: [{ verb: 'x.y' }], caveats: [{ type: 'mystery' }] })).toContain('NOT UNDERSTOOD');
  });
  it('flags a looser amount and a missing recipient constraint', () => {
    const omega = deriveOmega({ policies: [refund200], slots: { ...slots, constraints: [{ path: 'action.params.amount', max: 100 }, slots.constraints[1]!] } });
    const d = backTranslationDiff(refund200, { ...slots, constraints: [{ path: 'action.params.amount', max: 100 }, slots.constraints[1]!] }, omega);
    expect(d.map((x) => `${x.kind}:${x.path}`).sort()).toEqual(['looser:action.params.amount', 'looser:action.params.recipient']);
  });
  it('is empty for a faithful grant', () => {
    const omega = deriveOmega({ policies: [truth], slots });
    expect(backTranslationDiff(truth, slots, omega)).toEqual([]);
  });
});

describe('boundary witnesses (specification by example)', () => {
  const omega = deriveOmega({ policies: [refund200], slots });
  const w = boundaryWitnesses(refund200, omega);
  it('asks just inside and just outside every literal the grant uses', () => {
    const amounts = w.filter((x) => x.kind === 'boundary').map((x) => [x.outcome.values['action.params.amount'], x.grantAllows]);
    expect(amounts).toContainEqual([200, true]);
    expect(amounts).toContainEqual([201, false]);
  });
  it('probes a dimension the intent mentions but the grant ignores', () => {
    expect(w.some((x) => x.kind === 'unconstrained' && x.facet.includes('recipient'))).toBe(true);
  });
  it('a perfect principal finds a mismatch iff the grant is unfaithful', () => {
    const t = admitter(truth);
    const vs = omega.verbs[0]!;
    expect(checkWitnesses(w, (x) => t.admits(vs, x.outcome)).mismatches.length).toBeGreaterThan(0);
    const omega2 = deriveOmega({ policies: [truth], slots });
    const w2 = boundaryWitnesses(truth, omega2);
    expect(checkWitnesses(w2, (x) => t.admits(omega2.verbs[0]!, x.outcome)).mismatches).toEqual([]);
  });
  it('renders each witness as a plain question', () => {
    expect(w[0]!.question).toMatch(/^Should the agent be allowed to: /);
  });
});

describe('version-space learner (spec §2.4–2.6)', () => {
  const omega = deriveOmega({ policies: [refund200], slots });
  const t = admitter(truth);
  const answer = (q: { verb: string; outcome: { verb: string; values: Record<string, number | string> } }) => (t.admits(omega.verbs[0]!, q.outcome) ? 1 : 0) as 0 | 1;

  it('T1/T2: realizable + noise-free + τ=1 ⇒ G ⊆ θ*, version space shrinks, grant only grows', () => {
    const l = createLearner(omega);
    let lastVS = Infinity;
    let lastG = 0;
    for (let i = 0; i < 200; i++) {
      const m = l.metrics();
      expect(m.log2VersionSpace!).toBeLessThanOrEqual(lastVS + 1e-9);
      lastVS = m.log2VersionSpace!;
      const g = l.cells().filter((c) => c.inGrant).length;
      expect(g).toBeGreaterThanOrEqual(lastG);
      lastG = g;
      const grant = admitter(l.synthesize());
      everyCell(omega, (v, idx) => {
        const vs = omega.verbs[v]!;
        if (grant.admits(vs, cellRep(vs, idx))) expect(t.admits(vs, cellRep(vs, idx))).toBe(true);
      });
      expect(m.residualRisk).toBeLessThan(1e-9);
      const q = l.nextQuestion();
      if (!q) break;
      l.observe(q.outcome, answer(q));
    }
    // converged to exactly θ*
    const g = admitter(l.synthesize());
    everyCell(omega, (v, idx) => {
      const vs = omega.verbs[v]!;
      expect(g.admits(vs, cellRep(vs, idx))).toBe(t.admits(vs, cellRep(vs, idx)));
    });
    expect(l.metrics().disagreementMass).toBe(0);
  });

  it('T3: every noise-free question resolves its cell, so questions ≤ |cells|', () => {
    const l = createLearner(omega);
    const r = elicit(l, answer, { epsRisk: 0, epsBurden: 0, maxQuestions: 1000 });
    expect(r.stop).not.toBe('budget');
    expect(r.questions).toBeLessThanOrEqual(verbCellCount(omega.verbs[0]!));
  });

  it('synthesised predicates reproduce the allowed cell set exactly (prefixes, OTHER, ranges)', () => {
    const o2 = deriveOmega({
      policies: [{ predicates: [{ verb: 'files.read', resource: '/shared/*' }, { verb: 'files.read', resource: '/shared/secret' }, { verb: 'files.read', resource: '/shared/team/*' }] }],
      slots: { verbs: ['files.read'], constraints: [{ path: 'env.hour', min: 9, max: 17 }] },
    });
    const l = createLearner(o2, { eta: 0.1, tau: 0.6 });
    for (let i = 0; i < 25; i++) {
      const q = l.nextQuestion();
      if (!q) break;
      l.observe(q.outcome, (i * 7) % 3 === 0 ? 0 : 1);
    }
    const g = admitter(l.synthesize());
    const cells = l.cells();
    let k = 0;
    everyCell(o2, (v, idx) => {
      const vs = o2.verbs[v]!;
      expect(g.admits(vs, cellRep(vs, idx))).toBe(cells[k++]!.inGrant);
    });
  });

  it('flags a contradiction (truth outside Θ) instead of collapsing the posterior', () => {
    const l = createLearner(omega);
    const vs = omega.verbs[0]!;
    const at = (amount: number) => ({ verb: vs.verb, values: { 'action.params.amount': amount, 'action.params.recipient': 'alice' } });
    l.observe(at(0), 1);
    l.observe(at(201), 1);
    expect(l.observe(at(150), 0)!.conflict).toBe(true); // not a box: allowed on both sides of a hole
    expect(l.metrics().conflicts).toBe(1);
  });

  it('audit round: box-hull over-reach on a non-box intent is asked about and vetoed', () => {
    // truth: amount ≤ 200 for anyone, OR any amount for "alice" -- a union of two boxes (outside Θ)
    const o3 = deriveOmega({ policies: [refund200], slots });
    const vs = o3.verbs[0]!;
    const t3 = admitter({ predicates: [
      { verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'gte', value: 0 }, { field: 'action.params.amount', op: 'lte', value: 200 }] },
      { verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'gte', value: 0 }, { field: 'action.params.recipient', op: 'eq', value: 'alice' }] },
    ] });
    const ans = (q: { outcome: { verb: string; values: Record<string, number | string> } }) => (t3.admits(vs, q.outcome) ? 1 : 0) as 0 | 1;
    const l = createLearner(o3);
    const r = elicit(l, ans, { epsRisk: 0, epsBurden: 0.02, maxQuestions: 100, audit: true });
    const g = admitter(l.synthesize());
    everyCell(o3, (v, idx) => {
      const o = cellRep(o3.verbs[v]!, idx);
      if (g.admits(o3.verbs[v]!, o)) expect(t3.admits(o3.verbs[v]!, o)).toBe(true); // safe despite misspecification
    });
    expect(l.unconfirmedGrantCells()).toEqual([]);
    expect(r.auditQuestions).toBeGreaterThanOrEqual(0);
  });

  it('trust ramp: a negative runtime observation vetoes its cell for good', () => {
    const l = createLearner(omega);
    elicit(l, answer, { epsRisk: 0, epsBurden: 0, maxQuestions: 1000 });
    const ok = { verb: 'stripe.refund', values: { 'action.params.amount': 50, 'action.params.recipient': 'alice' } };
    expect(admitter(l.synthesize()).admits(omega.verbs[0]!, ok)).toBe(true);
    const r = applyDivergence(l, ok, 0);
    expect(r.after).toBe(r.before - 1);
    expect(admitter(r.grant).admits(omega.verbs[0]!, ok)).toBe(false);
  });

  it('T4: the Monte Carlo estimate of R̂ lies within the Hoeffding half-width of the exact cell sum', () => {
    const l = createLearner(omega, { eta: 0.1, tau: 0.7 });
    for (let i = 0; i < 6; i++) {
      const q = l.nextQuestion();
      if (!q) break;
      l.observe(q.outcome, answer(q));
    }
    const exact = l.metrics().residualRisk;
    const M = 20_000;
    const mc = estimateResidualRiskMC(l, { samples: M, seed: 3 });
    expect(Math.abs(mc - exact)).toBeLessThanOrEqual(hoeffdingHalfWidth(harmMax(omega), M, 0.001));
  });

  it('T6: attenuation never raises measured risk (same samples)', () => {
    const a = acceptabilityOf(truth);
    const wide = measureGrant(omega, refund200, a, { samples: 4000 });
    const narrow = measureGrant(omega, { predicates: [{ ...refund200.predicates[0]!, where: [...refund200.predicates[0]!.where!, { field: 'action.params.amount', op: 'lte', value: 100 }] }] }, a, { samples: 4000 });
    expect(narrow.risk).toBeLessThanOrEqual(wide.risk);
    expect(narrow.burden).toBeGreaterThanOrEqual(wide.burden);
    expect(measureGrant(omega, truth, a, { samples: 4000 }).risk).toBe(0);
  });
});

describe('intent map', () => {
  const omega = deriveOmega({ policies: [refund200], slots });
  const t = admitter(truth);
  const run = (eta = 0) => {
    const l = createLearner(omega, { eta, nullMass: { 'stripe.refund': 0.05 } });
    elicit(l, (q) => (t.admits(omega.verbs[0]!, q.outcome) ? 1 : 0), { epsRisk: 0, epsBurden: 0.001, maxQuestions: 40 });
    return l;
  };
  it('emits a replayable, content-addressed map that verifies', () => {
    const m = emitIntentMap(run(), 'ref-1');
    expect(verifyIntentMap(m)).toEqual({ ok: true, problems: [] });
    expect(intentMapDigest(m)).toBe(intentMapDigest(JSON.parse(JSON.stringify(m))));
    const m2 = emitIntentMap(run(0.05), 'ref-1');
    expect(verifyIntentMap(m2).ok).toBe(true);
  });
  it('detects a tampered grant or inflated fidelity', () => {
    const m = emitIntentMap(run(), 'ref-1');
    const bad = JSON.parse(JSON.stringify(m));
    bad.grant.predicates[0].where[1].value = 99999;
    expect(verifyIntentMap(bad).ok).toBe(false);
    // inflate: claim a denied cell is confidently acceptable and raise the fidelity figure
    const bad2 = JSON.parse(JSON.stringify(m));
    const i = bad2.cells.findIndex((c: { p_ppm: number }) => c.p_ppm < 500_000);
    expect(i).toBeGreaterThanOrEqual(0);
    bad2.cells[i].p_ppm = 1_000_000;
    bad2.cells[i].in_grant = true;
    expect(verifyIntentMap(bad2).ok).toBe(false);
    const bad3 = JSON.parse(JSON.stringify(m));
    bad3.metrics.residual_risk_ppm += 5_000;
    expect(verifyIntentMap(bad3).ok).toBe(false);
  });
  it('T5: combining principals intersects their grants', () => {
    const a = emitIntentMap(run(), 'A');
    const l2 = createLearner(omega);
    const t2 = admitter({ predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'lte', value: 200 }] }] });
    elicit(l2, (q) => (t2.admits(omega.verbs[0]!, q.outcome) ? 1 : 0), { epsRisk: 0, epsBurden: 0, maxQuestions: 100 });
    const b = emitIntentMap(l2, 'B');
    const j = combineIntentMaps([a, b]);
    expect(j.principals).toEqual(['A', 'B']);
    const gj = admitter(j.grant);
    const ga = admitter(a.grant);
    const gb = admitter(b.grant);
    everyCell(omega, (v, idx) => {
      const vs = omega.verbs[v]!;
      const o = cellRep(vs, idx);
      expect(gj.admits(vs, o)).toBe(ga.admits(vs, o) && gb.admits(vs, o));
    });
  });
});

describe('intent statement + intent_ref binding', () => {
  const kp = generateKeyPair();
  const s = signIntent({ v: 1, text: 'Refund customers up to $200, only alice or bob', slots, sources: [{ kind: 'ticket', uri: 'T-1', digest: b64u(new Uint8Array(32)) }], created_at: 1, nonce: 'n1' }, kp.secretKey);
  it('signs and verifies; any edit breaks it', () => {
    expect(verifyIntent(s)).toEqual({ ok: true });
    expect(verifyIntent({ ...s, text: s.text + '!' }).ok).toBe(false);
    expect(verifyIntent({ ...s, slots: { ...slots, verbs: ['stripe.payout'] } }).ok).toBe(false);
  });
  it('intent_ref is stable and rides the grant goal commitment', () => {
    const ref = intentRef(s);
    expect(intentRef({ ...s })).toBe(ref);
    const goal = intentGoal(ref, 'mapdigest');
    expect(parseIntentGoal(goal)).toEqual({ intentRef: ref, mapDigest: 'mapdigest' });
    const agent = generateKeyPair();
    const { goalCommit, goalSalt } = mintGrant({
      principalSecret: kp.secretKey,
      principalPublic: b64u(kp.publicKey),
      holder: b64u(agent.publicKey),
      envelope: { predicates: truth.predicates, caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
      goal,
    });
    expect(verifyGoalCommit(goalCommit, goal, goalSalt)).toBe(true);
    expect(verifyGoalCommit(goalCommit, intentGoal(ref + 'x', 'mapdigest'), goalSalt)).toBe(false);
  });
});
