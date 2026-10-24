import { describe, expect, it } from 'vitest';
import {
  admitter,
  cellOf,
  cellRep,
  classifierDim,
  createLearner,
  decodeCell,
  deriveOmega,
  elicit,
  excessDim,
  isTainted,
  liftOutcome,
  optimalityCondition,
  provenanceBanner,
  provenanceDim,
  provenanceFriction,
  regretReport,
  rng,
  verbCellCount,
  withDims,
  withinGrantRegret,
  worldDim,
  type Outcome,
} from './index';

// Intent Layer v2 milestones V6/V7/V8 on the wallet side: world, optimality, provenance and classifier dimensions
// of Ω̃ (T26 refinement), lifting with the verifier env, banners, friction floors and within-grant regret.

const AMT = 'action.params.amount';
const PAYEE = 'action.params.payee';
const V = 'stripe.payout';
const base = deriveOmega({ policies: [], slots: { verbs: [V], constraints: [{ path: AMT, max: 100 }, { path: PAYEE, oneOf: ['acct_ana'] }] } });

describe('Ω̃ dimension builders', () => {
  it('world, excess, provenance and classifier dimensions have the documented cells', () => {
    expect(worldDim('fare', { lo: 0, hi: 1000, cuts: [500, 2000, 500] })).toEqual({ kind: 'num', path: 'env.world.fare', lo: 0, hi: 1000, cuts: [500], dist: 'uniform' });
    expect(excessDim('excess_cents', 100_000).cuts).toEqual([0]);
    expect(provenanceDim(PAYEE).values.map((v) => v.value)).toEqual(['first_party', 'trusted', '⊥']);
    expect(classifierDim('tone', ['neutral', 'apologetic', 'neutral']).values.map((v) => v.value)).toEqual(['apologetic', 'neutral', '⊥']);
    expect(optimalityCondition('excess_cents')).toEqual({ field: 'env.world.excess_cents', op: 'lte', value: 0 });
  });

  it('withDims refines Ω̃: every new cell projects onto exactly one old cell (T26)', () => {
    const fine = withDims(base, V, [provenanceDim(PAYEE)]);
    const vsOld = base.verbs[0]!;
    const vsNew = fine.verbs[0]!;
    expect(verbCellCount(vsNew)).toBe(verbCellCount(vsOld) * 3);
    for (let f = 0; f < verbCellCount(vsNew); f++) {
      const rep = cellRep(vsNew, decodeCell(vsNew, f));
      const old = cellOf(vsOld, rep);
      expect(old).not.toBeNull();
    }
    expect(() => withDims(fine, V, [provenanceDim(PAYEE)])).toThrow(/already/);
    expect(() => withDims(base, 'nope', [provenanceDim(PAYEE)])).toThrow(/no verb/);
  });

  it('liftOutcome reads the verifier env; a missing provenance label is agent (the tainted cell)', () => {
    const o: Outcome = { verb: V, values: { [AMT]: 50, [PAYEE]: 'acct_ana' } };
    const env = { world: { fare: 39_800 }, prov: { action: { params: { payee: 'first_party' } } }, class: { tone: 'neutral' } };
    const paths = ['env.world.fare', 'env.prov.action.params.payee', 'env.prov.action.params.amount', 'env.class.tone'];
    expect(liftOutcome(o, env, paths).values).toEqual({ [AMT]: 50, [PAYEE]: 'acct_ana', 'env.world.fare': 39_800, 'env.prov.action.params.payee': 'first_party', 'env.prov.action.params.amount': 'agent', 'env.class.tone': 'neutral' });
  });

  it('T26: under NF and τ = 1 a "yes" for a payee given with trusted provenance never admits the same payee from page content', () => {
    const fine = withDims(base, V, [provenanceDim(PAYEE)]);
    const vs = fine.verbs[0]!;
    const truth = admitter({ predicates: [{ verb: V, resource: '*', where: [{ field: AMT, op: 'lte', value: 100 }, { field: PAYEE, op: 'eq', value: 'acct_ana' }, { field: 'env.prov.action.params.payee', op: 'in', value: ['trusted', 'first_party'] }] }] });
    for (let seed = 1; seed <= 10; seed++) {
      const r = rng(seed);
      const l = createLearner(fine, { nullMass: 0.05 });
      // the principal confirms the trusted-provenance cell, then elicitation runs in a random-length prefix
      l.observe({ verb: V, values: { [AMT]: 50, [PAYEE]: 'acct_ana', 'env.prov.action.params.payee': 'trusted' } }, 1);
      elicit(l, (q) => (truth.admits(vs, q.outcome) ? 1 : 0), { epsRisk: 0, epsBurden: 0, maxQuestions: Math.floor(r() * 12) });
      const tainted = { verb: V, values: { [AMT]: 50, [PAYEE]: 'acct_ana', 'env.prov.action.params.payee': 'web' } };
      expect(l.admitsOutcome(tainted)).toBe(false);
    }
  });
});

describe('provenance banners and friction floors', () => {
  it('banners are fixed text for tainted values only', () => {
    expect(provenanceBanner('web', 'payee')).toBe('This payee was suggested by content on the page, not by you.');
    expect(provenanceBanner('agent')).toMatch(/your agent/);
    expect(provenanceBanner('tool')).toMatch(/another service/);
    expect(provenanceBanner('trusted')).toBeNull();
    expect(provenanceBanner('first_party')).toBeNull();
    expect(['trusted', 'first_party', 'tool', 'web', 'agent'].map((l) => isTainted(l as 'web'))).toEqual([false, false, true, true, true]);
  });

  it('provenance can only raise friction', () => {
    const tiers = ['tap', 'hold', 'typed', 'device'] as const;
    for (const b of tiers) {
      for (const lvl of ['trusted', 'first_party', 'tool', 'web', 'agent'] as const) {
        for (const s of ['material', 'critical'] as const) {
          const f = provenanceFriction(b, s, lvl);
          expect(tiers.indexOf(f)).toBeGreaterThanOrEqual(tiers.indexOf(b));
          if (isTainted(lvl) && s === 'critical') expect(tiers.indexOf(f)).toBeGreaterThanOrEqual(tiers.indexOf('typed'));
          if (!isTainted(lvl)) expect(f).toBe(b);
        }
      }
    }
  });
});

describe('within-grant regret', () => {
  const opt = (price: number, addon = false): Outcome => ({ verb: 'air.book', values: { price, addon: addon ? 'tripshield' : 'none' } });
  const u = (o: Outcome) => -(o.values.price as number) - (o.values.addon === 'tripshield' ? 2900 : 0);
  const cap = (o: Outcome) => (o.values.price as number) <= 40_000;

  it('an injected but acceptable choice has R = 0 and positive regret; the best admitted choice has none', () => {
    const feasible = [opt(38_900), opt(39_800), opt(39_800, true), opt(41_200)];
    expect(withinGrantRegret({ feasible, chosen: opt(39_800, true), admits: cap, utility: u })).toMatchObject({ regret: 3_800, admitted: true });
    expect(withinGrantRegret({ feasible, chosen: opt(38_900), admits: cap, utility: u }).regret).toBe(0);
    expect(withinGrantRegret({ feasible, chosen: opt(41_200), admits: cap, utility: u })).toMatchObject({ regret: 0, admitted: false });
  });

  it('regret >= 0, and is 0 when the chosen option maximises utility over the admitted feasible set', () => {
    const r = rng(7);
    for (let i = 0; i < 200; i++) {
      const feasible = Array.from({ length: 1 + Math.floor(r() * 6) }, () => opt(Math.floor(r() * 50_000), r() < 0.3));
      const chosen = feasible[Math.floor(r() * feasible.length)]!;
      const res = withinGrantRegret({ feasible, chosen, admits: cap, utility: u });
      expect(res.regret).toBeGreaterThanOrEqual(0);
      const admittedU = feasible.filter(cap).map(u);
      if (cap(chosen) && u(chosen) === Math.max(...admittedU)) expect(res.regret).toBe(0);
    }
  });

  it('regretReport aggregates admitted cases only and reports ppm of the scale', () => {
    const feasible = [opt(38_900), opt(39_800, true)];
    const rep = regretReport([
      { feasible, chosen: opt(39_800, true), admits: cap, utility: u },
      { feasible, chosen: opt(38_900), admits: cap, utility: u },
      { feasible: [opt(45_000)], chosen: opt(45_000), admits: cap, utility: u },
    ], 40_000);
    expect(rep).toEqual({ cases: 3, admitted: 2, positive: 1, mean: 1_900, max: 3_800, regret_est_ppm: 47_500 });
  });
});
