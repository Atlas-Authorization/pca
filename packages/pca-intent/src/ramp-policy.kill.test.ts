import { describe, expect, it } from 'vitest';
import { b64u } from '@atlasauth/pca';
import { signIntentObservation } from '@atlasauth/pca/ext/intent';
import {
  createLearner,
  DriftDetector,
  narrowStart,
  normalizePolicy,
  outcomeToAction,
  OTHER,
  provenanceBanner,
  provenanceFriction,
  regretReport,
  TrustRamp,
  vsOf,
  withinGrantRegret,
  type Dim,
  type Omega,
  type Outcome,
  type PolicyInput,
  type ProvenanceFrictionTier,
  type VerbSpace,
} from './index';

const A = 'action.params.a';
const vspace = (verb: string, dims: Dim[]): VerbSpace => ({ verb, reversibility: 'reversible', weight: 1, dims });
const omegaOf = (...verbs: VerbSpace[]): Omega => ({ v: 1, verbs, approximate: [] });
const V3 = vspace('v.a', [{ kind: 'num', path: A, lo: 0, hi: 2, cuts: [1, 2], dist: 'uniform' }]);
const VC = vspace('v.c3', [{ kind: 'cat', path: 'action.params.k', values: [{ kind: 'exact', value: 'a' }, { kind: 'other', value: OTHER }] }]);

describe('normalizePolicy', () => {
  it('a missing policy and non-array members normalise to empty lists', () => {
    expect(normalizePolicy(undefined as unknown as PolicyInput)).toEqual({ predicates: [], caveats: [] });
    expect(normalizePolicy({ predicates: 'x', caveats: 'y' } as unknown as PolicyInput)).toEqual({ predicates: [], caveats: [] });
  });
});

describe('outcomeToAction', () => {
  const vs = vspace('v', []);
  it('only action.params.<x>, env.<x> and subject.<x> paths fill the trees; nested paths share their parent', () => {
    const values = { 'action.resource': 'r1', 'action.params.a.b': 1, 'action.params.a.c': 2, 'action.params': 9, 'action.foo.x': 3, 'zz.params.q': 4, 'zz.yy.ww': 5, env: 6, subject: 7, 'zz.q': 8 };
    expect(outcomeToAction(vs, { verb: 'v', values })).toEqual({ verb: 'v', resource: 'r1', params: { a: { b: 1, c: 2 } }, reversibilityClass: 'reversible' });
  });

  it('a null or scalar parent is replaced by an object; env and subject appear only when used', () => {
    const values = { 'action.params.a': null, 'action.params.a.b': 1, 'action.params.n': 5, 'action.params.n.m': 2, 'env.r': 'eu', 'subject.t': 'g' } as unknown as Record<string, number | string>;
    expect(outcomeToAction(vs, { verb: 'v', values })).toEqual({ verb: 'v', resource: 'resource:any', params: { a: { b: 1 }, n: { m: 2 } }, reversibilityClass: 'reversible', env: { r: 'eu' }, subject: { t: 'g' } });
  });

  it('vsOf finds the verb space of an outcome, or nothing', () => {
    const om = omegaOf(V3, VC);
    expect(vsOf(om, { verb: 'v.c3', values: {} })).toBe(om.verbs[1]);
    expect(vsOf(om, { verb: 'zz', values: {} })).toBeUndefined();
  });
});

describe('provenance', () => {
  it('the banner names the value by default', () => {
    expect(provenanceBanner('web')).toBe('This value was suggested by content on the page, not by you.');
  });

  it('friction floors: none for trusted (even over an unknown base), hold for tainted material, typed for tainted critical', () => {
    expect(provenanceFriction('bogus' as ProvenanceFrictionTier, 'material', 'trusted')).toBe('tap');
    expect(provenanceFriction('tap', 'material', 'web')).toBe('hold');
    expect(provenanceFriction('tap', 'critical', 'web')).toBe('typed');
  });

  const o = (verb: string): Outcome => ({ verb, values: {} });
  const U: Record<string, number> = { a: 10, b: 5, b2: 5, c: 1 };
  const u = (x: Outcome) => U[x.verb]!;

  it('only admitted options compete, and the first of equally good options is the best', () => {
    const [a, b, b2, c] = [o('a'), o('b'), o('b2'), o('c')];
    expect(withinGrantRegret({ feasible: [a, b, c], chosen: c, admits: (x) => x !== a, utility: u })).toEqual({ regret: 4, best: b, admitted: true });
    expect(withinGrantRegret({ feasible: [b, b2], chosen: b2, admits: () => true, utility: u }).best).toBe(b);
  });

  it('with no admitted option there is no regret, even for a chosen utility of -Infinity', () => {
    expect(withinGrantRegret({ feasible: [], chosen: o('c'), admits: () => true, utility: () => -Infinity })).toEqual({ regret: 0, best: null, admitted: true });
  });

  it('the report counts positive regret and treats a zero scale as 1', () => {
    const [a, c] = [o('a'), o('c')];
    expect(regretReport([{ feasible: [a, c], chosen: c, admits: () => true, utility: u }], 0)).toEqual({ cases: 1, admitted: 1, positive: 1, mean: 9, max: 9, regret_est_ppm: 9_000_000 });
  });
});

describe('narrowStart and the drift detector', () => {
  it('slot verbs get 0.5 and the others 0.95 by default; explicit masses are used', () => {
    const om = omegaOf(V3, VC);
    const slots = { verbs: ['v.a'], constraints: [] };
    expect(narrowStart(om, slots)).toEqual({ eta: 0, tau: 1, nullMass: { 'v.a': 0.5, 'v.c3': 0.95 } });
    expect(narrowStart(om, slots, { slotNullMass: 0.3, otherNullMass: 0.7 })).toEqual({ eta: 0, tau: 1, nullMass: { 'v.a': 0.3, 'v.c3': 0.7 } });
  });

  it('equal rates are refused', () => {
    expect(() => new DriftDetector({ rho0: 0.3, rho1: 0.3 })).toThrow('DriftDetector: need 0 < rho0 < rho1 < 1');
  });

  it('a non-divergence after a divergence adds log((1 - rho1) / (1 - rho0))', () => {
    const d = new DriftDetector();
    d.update(true);
    expect(d.update(false)).toEqual({ statistic: Math.log(0.25 / 0.02) + Math.log(0.75 / 0.98), alarm: false, informative: 2, divergences: 1 });
  });

  it('a statistic exactly at h raises the alarm', () => {
    expect(new DriftDetector({ h: Math.log(0.25 / 0.02) }).update(true)).toEqual({ statistic: Math.log(0.25 / 0.02), alarm: true, informative: 1, divergences: 1 });
  });
});

describe('TrustRamp records', () => {
  const at = (x: number): Outcome => ({ verb: 'v.a', values: { [A]: x } });
  // cells {0} and {1} confirmed (in the grant), {2} at p = 0.5
  const primed = () => {
    const l = createLearner(omegaOf(V3));
    l.observe(at(0), 1);
    l.observe(at(1), 1);
    return l;
  };
  const S1 = Math.log(0.25 / 0.02);

  it('exact records: grant sizes before and after, drift on in-grant signals only for negatives', () => {
    const r = new TrustRamp(primed());
    expect(r.log).toEqual([]);
    const a = r.record(at(0), 'postcondition-violation');
    const b = r.record(at(1), 'principal-confirm');
    expect(a).toEqual({ signal: 'postcondition-violation', y: 0, wasInGrant: true, before: 2, after: 1, applied: true, drift: { statistic: S1, alarm: false, informative: 1, divergences: 1 } });
    expect(b).toEqual({ signal: 'principal-confirm', y: 1, wasInGrant: true, before: 1, after: 1, applied: true, drift: { statistic: S1 + Math.log(0.75 / 0.98), alarm: false, informative: 2, divergences: 1 } });
    expect(r.log).toEqual([a, b]);
    expect(r.learner.observations.at(-1)).toEqual({ verb: 'v.a', values: { [A]: 1 }, cell: [1], y: 1, source: 'runtime' });
  });

  it('while frozen a positive signal is queued with its outcome and signal', () => {
    const r = new TrustRamp(primed(), { h: S1 });
    r.record(at(0), 'jit-refuse');
    const b = r.record(at(2), 'jit-approve');
    expect(b).toEqual({ signal: 'jit-approve', y: 1, wasInGrant: false, before: 1, after: 1, applied: false, drift: { statistic: S1, alarm: true, informative: 1, divergences: 1 } });
    expect(r.pending).toEqual([{ o: at(2), signal: 'jit-approve' }]);
  });

  describe('signed observations', () => {
    const md = b64u(new Uint8Array(32).fill(1));
    const secret = new Uint8Array(32).fill(5);
    const sig = (y: 0 | 1, source: 'runtime' | 'elicitation') => signIntentObservation({ map_digest: md, verb: 'v.a', values: { [A]: 0 }, y, source, observed_at: 1 }, secret);

    it('y = 1 is a principal confirmation and y = 0 a postcondition violation', () => {
      const yes = sig(1, 'runtime');
      expect(new TrustRamp(primed()).recordObservation(yes, { mapDigest: md, trustedSigners: [yes.signer] })).toEqual({
        ok: true,
        record: { signal: 'principal-confirm', y: 1, wasInGrant: true, before: 2, after: 2, applied: true, drift: { statistic: 0, alarm: false, informative: 1, divergences: 0 } },
      });
      const no = sig(0, 'runtime');
      const r = new TrustRamp(primed()).recordObservation(no, { mapDigest: md, trustedSigners: [no.signer] });
      expect(r.ok && r.record.signal).toBe('postcondition-violation');
    });

    it('exact refusals: another map, a non-runtime source, the verify options', () => {
      const yes = sig(1, 'runtime');
      const r = new TrustRamp(primed());
      expect(r.recordObservation(yes, { mapDigest: b64u(new Uint8Array(32)), trustedSigners: [yes.signer] })).toEqual({ ok: false, reason: 'observation is about a different map' });
      expect(r.recordObservation(sig(0, 'elicitation'), { mapDigest: md, trustedSigners: [yes.signer] })).toEqual({ ok: false, reason: 'only runtime observations feed the ramp' });
      expect(r.recordObservation(yes, { mapDigest: md, trustedSigners: [yes.signer], verify: { expectedSigner: 'x' } })).toEqual({ ok: false, reason: 'signer mismatch' });
    });
  });
});
