import { describe, expect, it } from 'vitest';
import {
  RevocationSet,
  b64u,
  evaluatePredicates,
  publicKeyOf,
  sha256,
  signRevocationEpoch,
  utf8,
  verifyChain,
} from '@atlasauth/pca';
import {
  conformAction,
  profileRevocationId,
  profileRevocationScope,
  type AccumulatorDecl,
  type IntentEvent,
  type MonitorDecl,
  type UnsignedActionSchema,
} from '@atlasauth/pca/ext/intent';
import {
  accDimPath,
  augmentOmega,
  cellCoords,
  cellFromCoords,
  createLearner,
  decideVisit,
  defaultAccumulators,
  deltaCells,
  deriveOmegaFromSchema,
  describeAccCell,
  dimCellStats,
  dimKindOf,
  emitIntentMap,
  intentProfileDigest,
  learnerFromMap,
  liftAction,
  mintDelta,
  monDimPath,
  numCells,
  profileApplies,
  profileUsable,
  profileVetoCells,
  rng,
  sampleOutcome,
  signIntentProfile,
  standingAdmits,
  standingPermits,
  stepTrajectory,
  trajectoryHarmRange,
  verifyIntentProfile,
  verifyProfileSuccession,
  verifyIntentMap,
  type IntentLearner,
  type IntentProfileBody,
  type NumDim,
  type Omega,
  type Outcome,
  type Psi,
} from './index';

const seed = (l: string) => sha256(utf8(`pca-intent-v2-test/${l}`));
const key = (l: string) => {
  const sk = seed(l);
  return { sk, pub: b64u(publicKeyOf(sk)) };
};
const principal = key('principal');
const agent = key('agent');
const NOW = 1_800_000_000_000;

// ---- a tiny Ω̃: one verb, the per-action amount and the session total -------------------------------------------
const SPEND: AccumulatorDecl = { id: 'spend', agg: 'sum', val: 'action.params.amount', sel: { verbs: ['pay'] }, win: { kind: 'task' }, key: null, domain_max: 200, holder: { kind: 'site_local' } };
const PSI: Psi = { accumulators: [SPEND], monitors: [] };
const BASE: Omega = { v: 1, approximate: [], verbs: [{ verb: 'pay', reversibility: 'irreversible', weight: 1, dims: [{ kind: 'num', path: 'action.params.amount', lo: 0, hi: 100, cuts: [50], dist: 'uniform' }] }] };
const OT = augmentOmega(BASE, PSI, { cuts: { spend: [100] } });
/** The principal's (Ψ-expressible, realizable) trajectory intent: each payment ≤ 50 AND the session total ≤ 100. */
const aTilde = (o: Outcome) => ((o.values['action.params.amount'] as number) <= 50 && (o.values[accDimPath('spend')] as number) <= 100 ? 1 : 0);
const learnTruth = (l: IntentLearner, max = 64) => {
  for (let n = 0; n < max; n++) {
    const q = l.nextQuestion();
    if (!q) return n;
    l.observe(q.outcome, aTilde(q.outcome) as 0 | 1, 'elicitation');
  }
  return max;
};

describe('trajectory intent over Ω̃ (V2)', () => {
  it('Ω̃ adds one numeric dimension per accumulator and one closed categorical per monitor', () => {
    const mon: MonitorDecl = { id: 'after', kind: 'requires_prior', p: { verb: 'pay' }, q: { verb: 'refund' } };
    const o = augmentOmega(BASE, { accumulators: [SPEND], monitors: [mon] }, { cuts: { spend: [100, 400] } });
    const dims = o.verbs[0]!.dims;
    expect(dims.map((d) => [d.path, dimKindOf(d.path)])).toEqual([
      ['action.params.amount', 'param'],
      [accDimPath('spend'), 'acc'],
      [monDimPath('after'), 'mon'],
    ]);
    expect(dims[1]).toMatchObject({ kind: 'num', lo: 0, hi: 200, cuts: [100] }); // 400 is outside A_ψ
    expect(dims[2]).toMatchObject({ kind: 'cat', values: [{ kind: 'exact', value: 'unmet' }, { kind: 'exact', value: 'met' }] });
    expect(() => augmentOmega(BASE, { accumulators: [{ ...SPEND, domain_max: undefined }], monitors: [] })).toThrow(/domain_max/);
  });

  it('lift reads the post value from the history (splitting does not change it)', () => {
    const h: IntentEvent[] = [{ id: 'a', verb: 'pay', resource: 'r', params: { amount: 40 }, t: NOW, status: 'committed' }];
    expect(liftAction(OT, PSI, h, { verb: 'pay', resource: 'r', params: { amount: 30 }, t: NOW + 1 })!.values).toEqual({ 'action.params.amount': 30, [accDimPath('spend')]: 70 });
    const split: IntentEvent[] = [20, 20].map((amount, i) => ({ id: `s${i}`, verb: 'pay', resource: 'r', params: { amount }, t: NOW, status: 'reserved' as const }));
    expect(liftAction(OT, PSI, split, { verb: 'pay', resource: 'r', params: { amount: 30 }, t: NOW + 1 })!.values[accDimPath('spend')]).toBe(70);
  });

  it('T10 (property): under RZ, NF and τ = 1 every step G̃_1 admits has a* = 1, for random agent strategies', () => {
    const l = createLearner(OT, { eta: 0, tau: 1 });
    learnTruth(l);
    const G = new Set(l.cells().filter((c) => c.inGrant).map((c) => c.cell.join(',')));
    expect(G.size).toBe(4); // amount ≤ 50 (2 cells) × total ≤ 100 (2 cells): the truth, learned exactly
    const rand = rng(7);
    for (let run = 0; run < 200; run++) {
      let h: IntentEvent[] = [];
      for (let k = 0; k < 8; k++) {
        const amount = Math.floor(rand() * 101);
        const cand = { id: `r${run}-${k}`, verb: 'pay', resource: 'r', params: { amount }, t: NOW + k };
        const s = stepTrajectory(OT, PSI, h, cand, (_v, cell) => G.has(cell.join(',')));
        if (s.admitted) expect(aTilde(s.lifted!)).toBe(1);
        h = s.history;
      }
      const total = h.reduce((x, e) => x + (e.params.amount as number), 0);
      expect(total).toBeLessThanOrEqual(100); // T11 falls out of T10 for this intent
    }
  });

  it('T30: a downward-closed accumulator intent is learned in ≤ ⌈log2(k+1)⌉ questions with the monotone prior', () => {
    const chain: Omega = { v: 1, approximate: [], verbs: [{ verb: 'pay', reversibility: 'irreversible', weight: 1, dims: [{ kind: 'num', path: accDimPath('spend'), lo: 0, hi: 40, cuts: [10, 20, 30], dist: 'uniform' }] }] };
    const k = numCells(chain.verbs[0]!.dims[0] as NumDim).length; // 7
    const boxes = (k * (k + 1)) / 2;
    const bound = Math.ceil(Math.log2(k + 1));
    for (let c = -1; c < k; c++) {
      const l = createLearner(chain, { eta: 0, tau: 1, nullMass: 1 / (boxes + 1), monotone: { paths: [accDimPath('spend')] } });
      let n = 0;
      for (let q = l.nextQuestion(); q; q = l.nextQuestion()) {
        l.observe(q.outcome, q.cell[0]! <= c ? 1 : 0, 'elicitation');
        n++;
      }
      expect(n).toBeLessThanOrEqual(bound);
      // the learned grant is exactly the prefix {0..c}
      expect(l.cells().filter((x) => x.inGrant).map((x) => x.cell[0])).toEqual(Array.from({ length: c + 1 }, (_, i) => i));
      // and the map replays (the monotone prior is serialised)
      expect(verifyIntentMap(emitIntentMap(l)).ok).toBe(true);
    }
  });

  it('the wallet floor adds spend accumulators for every unit and every untagged money amount, plus the question cap', () => {
    const schema: UnsignedActionSchema = {
      v: 1, kind: 'pca-action-schema', site: 's', aud: 'a', version: '1',
      verbs: [
        { verb: 'air.book', kind: 'write', params: { 'action.params.total': { type: 'integer', semantic: 'money.amount', sensitivity: 'critical', accumulates_into: ['spend.usd_cents'] } } },
        { verb: 'tip', kind: 'write', params: { 'action.params.amount': { type: 'integer', semantic: 'money.amount', sensitivity: 'free' } } },
      ],
    };
    expect(defaultAccumulators(schema, { spendDomainMax: 1_000_000 }).map((a) => [a.id, a.sel, a.holder.kind])).toEqual([
      ['spend_spend_usd_cents', { accumulates_into: 'spend.usd_cents' }, 'site_local'],
      ['spend_tip_amount', { verbs: ['tip'] }, 'site_local'],
      ['questions', { event: 'intent_required' }, 'wallet'],
    ]);
  });

  it('the map serialises the v2 noise model and the population prior, and replays them', () => {
    const l = createLearner(BASE, { eta: 0.1, etaPos: 0.15, etaNeg: 0.05, priorMix: { beta: 0.3, cells: [{ verb: 'pay', cell: 0, q: 0.9 }] } });
    l.observe({ verb: 'pay', values: { 'action.params.amount': 10 } }, 1, 'elicitation');
    const m = emitIntentMap(l);
    expect(m.learner.noise).toEqual({ eta_pos_ppm: 150_000, eta_neg_ppm: 50_000 });
    expect(m.learner.prior_mix).toEqual({ beta_ppm: 300_000, cells: [{ verb: 'pay', cell: 0, q_ppm: 900_000 }] });
    expect(verifyIntentMap(m).ok).toBe(true);
    // the v1 map shape is unchanged when neither is set
    expect('noise' in emitIntentMap(createLearner(BASE, { eta: 0.1 })).learner).toBe(false);
  });

  it('renders an accumulator cell as a range fact and bounds the trajectory harm (T29)', () => {
    const d = OT.verbs[0]!.dims.find((x) => x.path === accDimPath('spend'))! as NumDim;
    expect(describeAccCell(d, 2, "this trip's total", 130)).toBe("this trip's total: between 101 and 200 (this action: 130)");
    expect(trajectoryHarmRange(8, 10)).toBe(80);
  });
});

// ---- huge declared domains cost O(cells) ---------------------------------------------------------------------------
describe('numeric dimensions are statistics over cells, never per-value tables', () => {
  it('per-cell mass and default harm match a brute-force sum on long loguniform cells', () => {
    const d: NumDim = { kind: 'num', path: 'action.params.amount', lo: 0, hi: 100_000, cuts: [50, 9_000], dist: 'loguniform' };
    let tot = 0;
    const w = numCells(d).map(() => ({ m: 0, g: 0 }));
    for (let x = 0; x <= d.hi; x++) {
      const c = numCells(d).findIndex((k) => x >= k.lo && x <= k.hi);
      w[c]!.m += 1 / (x + 1);
      w[c]!.g += (1 / (x + 1)) * (1 + x / 100);
      tot += 1 / (x + 1);
    }
    numCells(d).forEach((_, i) => {
      const s = dimCellStats(d, i);
      expect(Math.abs(s.mass - w[i]!.m / tot)).toBeLessThan(1e-12);
      expect(Math.abs(s.harm - w[i]!.g / w[i]!.m) / s.harm).toBeLessThan(1e-12);
    });
  });

  it('a money amount declared up to 2^53 - 1 learns and samples without allocating per value', () => {
    const big: Omega = { v: 1, approximate: [], verbs: [{ verb: 'pay', reversibility: 'irreversible', weight: 1, dims: [{ kind: 'num', path: 'action.params.amount', lo: 0, hi: Number.MAX_SAFE_INTEGER, cuts: [40_000, 80_000], dist: 'loguniform' }] }] };
    const t0 = Date.now();
    const l = createLearner(big, { eta: 0, tau: 1 });
    const mass = l.cells().reduce((x, c) => x + c.mass, 0);
    expect(Math.abs(mass - 1)).toBeLessThan(1e-9);
    for (let q = l.nextQuestion(); q; q = l.nextQuestion()) l.observe(q.outcome, (q.outcome.values['action.params.amount'] as number) <= 40_000 ? 1 : 0, 'elicitation');
    expect(verifyIntentMap(emitIntentMap(l)).ok).toBe(true);
    const r = rng(3);
    for (let i = 0; i < 100; i++) {
      const x = sampleOutcome(big, r).o.values['action.params.amount'] as number;
      expect(Number.isSafeInteger(x) && x >= 0).toBe(true);
    }
    expect(Date.now() - t0).toBeLessThan(5_000);
  });
});

// ---- Ω from the site schema (V1) --------------------------------------------------------------------------------
const SCHEMA: UnsignedActionSchema = {
  v: 1, kind: 'pca-action-schema', site: 'https://skyair.example', aud: 'skyair.example', version: '1',
  verbs: [
    {
      verb: 'air.book', kind: 'write',
      params: {
        'action.params.total': { type: 'integer', min: 0, max: 100_000, semantic: 'money.amount', sensitivity: 'critical' },
        'action.params.add_ons': { type: 'set', values: ['none', 'tripshield'], default: ['none'], principal_neutral_default: true, semantic: 'product.addon', sensitivity: 'material' },
        'action.params.refundable': { type: 'boolean', semantic: 'flag', sensitivity: 'material' },
        'action.params.note': { type: 'string', semantic: 'text.note', sensitivity: 'free', required: false },
        'action.params.payee': { type: 'string', semantic: 'party.payee', sensitivity: 'free', required: false },
      },
      reversibility_by: { param: 'action.params.refundable', map: { true: 'reversible', false: 'irreversible' } },
    },
  ],
};

describe('Ω from the action schema (V1, T12)', () => {
  const r = deriveOmegaFromSchema({ schema: SCHEMA, slots: { verbs: ['air.book'], constraints: [{ verb: 'air.book', path: 'action.params.total', max: 40_000 }] } });
  const vs = r.omega.verbs[0]!;
  it('projects free parameters away, floors party/money types, and uses canonical projections for sets and booleans', () => {
    expect(vs.dims.map((d) => d.path)).toEqual(['action.params.payee', 'action.params.total', 'env.canon.add_ons', 'env.canon.refundable']);
    expect(r.overrides).toEqual([{ verb: 'air.book', path: 'action.params.payee', semantic: 'party.payee', declared: 'free', effective: 'material' }]);
    expect(vs.dims[1]).toMatchObject({ kind: 'num', lo: 0, hi: 100_000, cuts: [40_000] });
    expect(vs.reversibility).toBe('irreversible');
    expect(r.canonOf).toEqual({ 'env.canon.add_ons': 'action.params.add_ons', 'env.canon.refundable': 'action.params.refundable' });
  });
  it('pins a silent parameter to its principal-neutral default set (the first non-default value is a question)', () => {
    expect(r.defaults).toEqual([{ verb: 'air.book', path: 'env.canon.add_ons', oneOf: ['["none"]'] }]);
    const addOns = vs.dims[2]!;
    expect(addOns.kind === 'cat' && addOns.values.map((v) => v.value)).toEqual(['["none"]', '⊥']);
  });
  it('every categorical dimension keeps ⊥; an undeclared verb is never a cell', () => {
    for (const d of vs.dims) if (d.kind === 'cat') expect(d.values[d.values.length - 1]!.kind).toBe('other');
    expect(deriveOmegaFromSchema({ schema: SCHEMA, verbs: ['air.cancel'] }).omega.verbs).toEqual([]);
  });
});

// ---- lazy elicitation and delta grants (V3, T13, T14) -----------------------------------------------------------
describe('lazy elicitation (T13, T14) and delta grants (T15)', () => {
  const twoDim: Omega = {
    v: 1, approximate: [],
    verbs: [{ verb: 'pay', reversibility: 'irreversible', weight: 1, dims: [
      { kind: 'num', path: 'action.params.amount', lo: 0, hi: 100, cuts: [20, 50, 80], dist: 'uniform' },
      { kind: 'cat', path: 'action.params.payee', values: [{ kind: 'exact', value: 'alice' }, { kind: 'exact', value: 'bob' }, { kind: 'other', value: '⊥' }] },
    ] }],
  };
  const truth = (o: Outcome) => ((o.values['action.params.amount'] as number) <= 50 && o.values['action.params.payee'] !== 'mallory' && o.values['action.params.payee'] !== 'x' ? 1 : 0);
  const uncertain = (l: IntentLearner) => new Set(l.cells().filter((c) => c.p > 0 && c.p < 1 && !c.vetoed).map((c) => c.cell.join(',')));
  const OK = { ok: true as const, verb: { verb: 'pay', kind: 'write' as const, params: {} } };

  it('T13 + T14 (property): every question is about a visited uncertain cell, asked once; G^eff ⊆ θ* in any visit order', () => {
    const rand = rng(11);
    const amounts = [5, 20, 30, 50, 60, 80, 95];
    const payees = ['alice', 'bob', 'x'];
    for (let run = 0; run < 40; run++) {
      const l = createLearner(twoDim, { eta: 0, tau: 1 });
      const U0 = uncertain(l);
      const asked: string[] = [];
      const visited = new Set<string>();
      let prevU = U0;
      for (let k = 0; k < 30; k++) {
        const o: Outcome = { verb: 'pay', values: { 'action.params.amount': amounts[Math.floor(rand() * amounts.length)]!, 'action.params.payee': payees[Math.floor(rand() * payees.length)]! } };
        const d = decideVisit({ learner: l, lifted: o, conform: OK, inEffective: l.admitsOutcome(o) });
        const cell = d.kind === 'admit' || d.kind === 'intent_required' ? d.cell.join(',') : null;
        if (cell) visited.add(cell);
        if (d.kind === 'admit') expect(truth(o)).toBe(1); // T14
        if (d.kind === 'intent_required') {
          asked.push(d.cell.join(','));
          l.observe(o, truth(o) as 0 | 1, 'elicitation');
          const U = uncertain(l);
          for (const c of U) expect(prevU.has(c)).toBe(true); // T13(a): U_{k+1} ⊆ U_k
          prevU = U;
        }
      }
      expect(new Set(asked).size).toBe(asked.length); // T13(b): once per cell
      expect(asked.every((c) => U0.has(c) && visited.has(c))).toBe(true); // Q ≤ |U_0 ∩ Vis|
    }
  });

  it('decides in the normative order: ⊠, ceiling, denied, admit, question', () => {
    const l = createLearner(twoDim, { eta: 0, tau: 1 });
    const o: Outcome = { verb: 'pay', values: { 'action.params.amount': 30, 'action.params.payee': 'alice' } };
    expect(decideVisit({ learner: l, lifted: o, conform: { ok: false, code: 'undeclared_param', reason: 'x' }, inEffective: true }).kind).toBe('schema_violation');
    expect(decideVisit({ learner: l, lifted: { verb: 'pay', values: { 'action.params.amount': 101, 'action.params.payee': 'alice' } }, conform: OK, inEffective: true }).kind).toBe('schema_violation');
    expect(decideVisit({ learner: l, lifted: o, conform: OK, ceilings: [() => false], inEffective: true }).kind).toBe('ceiling');
    l.observe(o, 0, 'runtime'); // a veto
    expect(decideVisit({ learner: l, lifted: o, conform: OK, inEffective: true })).toEqual({ kind: 'intent_denied', vetoed: true });
  });

  it('cell coordinates round-trip and never carry the value text of a numeric cell', () => {
    const vs = twoDim.verbs[0]!;
    const c = cellCoords(vs, [2, 1]);
    expect(c).toEqual({ 'action.params.amount': [2, 2], 'action.params.payee': ['bob'] });
    expect(cellFromCoords(vs, c)).toEqual([2, 1]);
    expect(cellFromCoords(vs, { ...c, extra: [0, 0] })).toBeNull();
  });

  it('a "yes" mints a principal-signed delta D_k = G̃_1(m_k) ∖ G̃_1(m_{k-1}) chained to the previous grant; a "no" mints nothing', () => {
    const l = createLearner(twoDim, { eta: 0, tau: 1 });
    const prev = learnerFromMap(emitIntentMap(l));
    const o: Outcome = { verb: 'pay', values: { 'action.params.amount': 30, 'action.params.payee': 'alice' } };
    l.observe(o, 1, 'elicitation');
    const SESSION = b64u(seed('s'));
    const ROOT = b64u(seed('root'));
    const g0 = { id: b64u(seed('g0')) } as Parameters<typeof mintDelta>[2]['prevGrant'];
    const minted = mintDelta(prev, l, { principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, session: SESSION, seq: 1, root: ROOT, mapDigest: b64u(seed('m1')), prevGrant: g0, salt: 's1' })!;
    expect(minted.cells).toBeGreaterThan(0);
    expect(minted.grant.issuer).toBe(principal.pub);
    expect(verifyChain([minted.grant], principal.pub).ok).toBe(true);
    expect(minted.grant.caveats.find((c) => c.type === 'intent_session')).toEqual({ type: 'intent_session', session: SESSION, seq: 1, root: ROOT, prev: g0.id });
    // every admitted cell of the delta is in the truth (T14) and the delta's predicates admit exactly them
    const env = minted.grant.caveats.find((c) => c.type === 'envelope') as unknown as { predicates: Parameters<typeof evaluatePredicates>[0] };
    expect(evaluatePredicates(env.predicates, { action: { verb: 'pay', resource: 'r', params: { amount: 30, payee: 'alice' } } }).allowed).toBe(true);
    for (const [, cells] of deltaCells(prev, l)) expect(cells.reduce((s, x) => s + x, 0)).toBe(minted.cells);
    const after = learnerFromMap(emitIntentMap(l));
    l.observe({ verb: 'pay', values: { 'action.params.amount': 90, 'action.params.payee': 'bob' } }, 0, 'elicitation');
    expect(mintDelta(after, l, { principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, session: SESSION, seq: 2, root: ROOT, mapDigest: b64u(seed('m2')), prevGrant: minted.grant, salt: 's2' })).toBeNull();
  });
});

// ---- profiles (V10, T22–T24) -----------------------------------------------------------------------------------
describe('intent profiles (V10)', () => {
  const body = (over: Partial<IntentProfileBody> = {}): Omit<IntentProfileBody, 'owner'> => ({
    v: 1, kind: 'pca-intent-profile', profile_id: 'prof_ana', version: 1,
    scope: { sites: ['skyair.example'] },
    standing: { deny: [{ verb: 'air.book', where: [{ field: 'action.params.add_ons', op: 'eq', value: ['tripshield'] }] }], permit: [{ verb: 'air.seat', where: [{ field: 'action.params.total', op: 'lte', value: 3_000 }] }] },
    prior: { observations: [{ verb: 'pay', values: { 'action.params.amount': 90, 'action.params.payee': 'bob' }, y: 0, at: NOW }, { verb: 'pay', values: { 'action.params.amount': 10, 'action.params.payee': 'bob' }, y: 1, at: NOW }], maps: [] },
    expires_at: NOW + 86_400_000,
    revocation: { epoch_uri: 'https://atlas.example/rev' },
    ...over,
  });
  const v1 = signIntentProfile(body(), principal.sk);
  const v2 = signIntentProfile(body({ version: 2, prev: intentProfileDigest(v1) }), principal.sk);
  const use = { aud: 'skyair.example', verb: 'air.book', now: NOW };

  it('signs, verifies and enforces append-only succession', () => {
    expect(verifyIntentProfile(v1)).toEqual({ ok: true });
    expect(verifyIntentProfile({ ...v1, version: 3 })).toMatchObject({ ok: false });
    expect(verifyProfileSuccession(v1, v2)).toEqual({ ok: true });
    const fork = signIntentProfile(body({ version: 2, prev: b64u(seed('x')) }), principal.sk);
    expect(verifyProfileSuccession(v1, fork)).toMatchObject({ ok: false });
    expect(() => signIntentProfile(body({ version: 2 }), principal.sk)).toThrow(/prev/);
  });

  it('standing deny rules are a ceiling (deny wins); permits are the only positive import; scope and expiry apply', () => {
    expect(standingAdmits(v1, use, { action: { verb: 'air.book', resource: 'r', params: { add_ons: ['tripshield'] } } })).toBe(false);
    expect(standingAdmits(v1, use, { action: { verb: 'air.book', resource: 'r', params: { add_ons: ['none'] } } })).toBe(true);
    expect(standingAdmits(v1, { ...use, aud: 'other.example' }, { action: { verb: 'air.book', resource: 'r', params: { add_ons: ['tripshield'] } } })).toBe(true);
    expect(standingPermits(v1, { ...use, verb: 'air.seat' }, { action: { verb: 'air.seat', resource: 'r', params: { total: 2_000 } } })).toBe(true);
    expect(profileApplies(v1, { ...use, now: NOW + 86_400_000 })).toBe(false);
  });

  it('T24: only negative prior observations become vetoes; positive ones never admit', () => {
    const omega: Omega = { v: 1, approximate: [], verbs: [{ verb: 'pay', reversibility: 'irreversible', weight: 1, dims: [
      { kind: 'num', path: 'action.params.amount', lo: 0, hi: 100, cuts: [50], dist: 'uniform' },
      { kind: 'cat', path: 'action.params.payee', values: [{ kind: 'exact', value: 'bob' }, { kind: 'other', value: '⊥' }] },
    ] }] };
    expect(profileVetoCells(v1, omega)).toEqual([{ verb: 'pay', cell: [2, 0] }]);
  });

  it('a revoked or stale-epoch profile version is unusable (T22)', () => {
    const epoch = (revoked: string[], issued: number) => {
      const set = new RevocationSet(revoked);
      return {
        epoch: signRevocationEpoch(principal.sk, { instance_id: 'ana', grant_ref: profileRevocationScope('prof_ana'), epoch: set.size, set_size: set.size, root: set.root, issued_at: issued, not_after: issued + 300_000 }),
        revoked: set.list(),
      };
    };
    expect(profileUsable(v1, { now: NOW, maxAgeMs: 60_000, revocation: epoch([], NOW - 1_000) })).toEqual({ ok: true });
    expect(profileUsable(v1, { now: NOW, maxAgeMs: 60_000, revocation: epoch([profileRevocationId('prof_ana', 1)], NOW - 1_000) })).toMatchObject({ ok: false });
    expect(profileUsable(v1, { now: NOW, maxAgeMs: 60_000, revocation: epoch([], NOW - 61_000) })).toMatchObject({ ok: false });
    expect(profileUsable(v1, { now: NOW + 86_400_000, maxAgeMs: 60_000, revocation: epoch([], NOW + 86_399_000) })).toMatchObject({ ok: false });
    // append-only: an owner epoch that drops the profile version revoked in the tracked last epoch is refused
    const last = epoch([profileRevocationId('prof_ana', 1)], NOW - 5_000);
    expect(profileUsable(v1, { now: NOW, maxAgeMs: 60_000, revocation: epoch(['pca-intent:profile:other@1'], NOW - 1_000), last })).toMatchObject({ ok: false });
    expect(profileUsable(v1, { now: NOW, maxAgeMs: 60_000, revocation: epoch([], NOW - 1_000), last: epoch([], NOW - 5_000) })).toEqual({ ok: true });
  });
});

it('conformAction is the closed-world gate the wallet and the site share', () => {
  expect(conformAction(SCHEMA, 'air.book', { total: 1, add_ons: ['none'], refundable: true })).toMatchObject({ ok: true });
  expect(conformAction(SCHEMA, 'air.book', { total: 1, add_ons: ['none'], refundable: true, x: 1 })).toMatchObject({ ok: false, code: 'undeclared_param' });
});
