import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical, publicKeyOf } from '@atlasauth/pca';
import { actionDigest, semanticRiskContribution, signJudgeVerdict, verdictDigest, verifySemanticThreshold, type Calibration } from '@atlasauth/pca/ext/intent';
import { bondAmount, DEFAULT_BOND_POLICY } from '@atlasauth/pca/ext/optimistic';
import type { IntentLearner } from './learner';
import { DEFAULT_HARM, type Omega, type Outcome, type VerbSpace } from './omega';
import { renderAction } from './render';
import {
  calibrationDigest,
  checkIntentConformance,
  foldSemanticRisk,
  icAttDigest,
  intentConformanceAttestation,
  jitConsentDigest,
  jitConsentRequest,
  judgeInputOf,
  pcactnActionOf,
  recordJitDecision,
  routeAction,
  verifyICAtt,
  type ICAtt,
  type JitConsentRequest,
  type JudgeInput,
  type JudgePanel,
} from './runtime';

const AMT = 'action.params.amount';
const dim = { kind: 'num', path: AMT, lo: 0, hi: 100, cuts: [], dist: 'uniform' } as const;
const vsR: VerbSpace = { verb: 'r.v', reversibility: 'reversible', weight: 0.5, dims: [dim] };
const vsI: VerbSpace = { verb: 'i.v', reversibility: 'irreversible', weight: 0.5, dims: [dim] };
const omega: Omega = { v: 1, verbs: [vsR, vsI], approximate: [] };
const out = (verb: string, x: number): Outcome => ({ verb, values: { [AMT]: x } });
const fake = (p: number, inGrant = true, vetoed = false, om: Omega = omega) =>
  ({ omega: om, harm: DEFAULT_HARM, acceptance: () => p, admitsOutcome: () => inGrant, isVetoed: () => vetoed }) as unknown as IntentLearner;

describe('routeAction: outside the space', () => {
  it('an unknown verb is denied with reversibility unknown and full risk', () => {
    expect(routeAction(fake(1), out('nope', 1))).toEqual({
      route: 'deny', p: 0, inGrant: false, vetoed: false, reversibility: 'unknown', harm: 0, risk: 1, judges: false,
      reason: "outside the Intent Map's outcome space",
    });
  });
  it('a known verb with a value outside Ω keeps the verb reversibility', () => {
    expect(routeAction(fake(1), out('r.v', 500))).toEqual({
      route: 'deny', p: 0, inGrant: false, vetoed: false, reversibility: 'reversible', harm: 0, risk: 1, judges: false,
      reason: "outside the Intent Map's outcome space",
    });
  });
});

describe('routeAction: the decision table', () => {
  const base = { p: 0.5, inGrant: true, vetoed: false, reversibility: 'reversible', harm: 1.5, risk: 0.25 } as const;
  it('outside the conservative grant: deny, with the reason telling a veto apart', () => {
    expect(routeAction(fake(0.5, false), out('r.v', 50), { hMax: 3 })).toEqual({
      ...base, inGrant: false, route: 'deny', judges: false, reason: 'outside the conservative grant (p_n < τ)',
    });
    expect(routeAction(fake(0.5, false, true), out('r.v', 50), { hMax: 3 })).toEqual({
      ...base, inGrant: false, vetoed: true, route: 'deny', judges: false, reason: 'the cell was vetoed by a runtime divergence',
    });
  });
  it('irreversible: just-in-time consent, judges always asked', () => {
    expect(routeAction(fake(1), out('i.v', 50), { hMax: 30 })).toEqual({
      p: 1, inGrant: true, vetoed: false, reversibility: 'irreversible', harm: 15, risk: 0, route: 'jit-consent', judges: true,
      reason: 'irreversible: just-in-time consent on the rendered action',
    });
  });
  it('confirmed reversible and low risk: allow without judges', () => {
    expect(routeAction(fake(1), out('r.v', 50), { hMax: 3 })).toEqual({
      ...base, p: 1, risk: 0, route: 'allow', judges: false, reason: 'confirmed region, reversible, low risk',
    });
  });
  it('unconfirmed: optimistic with the bond sized on the harm', () => {
    expect(routeAction(fake(0.5), out('r.v', 50), { hMax: 3 })).toEqual({
      ...base, route: 'optimistic', judges: true, bond: bondAmount(DEFAULT_BOND_POLICY, 1.5), reason: 'unconfirmed region (p_n < 1): bonded claim + judges',
    });
  });
  it('risk is (1 - p) * h / hMax, with hMax defaulting to the harm maximum of Ω and a zero hMax read as 1', () => {
    const single: Omega = { v: 1, verbs: [vsR], approximate: [] };
    expect(routeAction(fake(0.5, true, false, single), out('r.v', 50)).risk).toBe(0.375);
    expect(routeAction(fake(0.5), out('r.v', 50), { hMax: 3 }).risk).toBe(0.25);
    expect(routeAction(fake(0.5), out('r.v', 50), { hMax: 0 }).risk).toBe(0.75);
    expect(routeAction(fake(0.5), out('r.v', 50), { hMax: -3 }).risk).toBe(0.75);
  });
  it('the risk threshold defaults to 0.5 and the p threshold sits at 1 - 1e-12', () => {
    const nearly = 1 - 1e-13;
    const hot = routeAction(fake(nearly), out('r.v', 50), { hMax: 1e-13 });
    expect(hot.risk).toBe(1);
    expect(hot.route).toBe('optimistic');
    expect(hot.reason).toBe('risk ≥ θ₂: bonded claim + judges');
    const edge = 1 - 1e-12;
    const r = ((1 - edge) * 1.5) / 3;
    const atTheta = routeAction(fake(edge), out('r.v', 50), { hMax: 3, theta2: r });
    expect(atTheta.route).toBe('optimistic');
    expect(atTheta.reason).toBe('risk ≥ θ₂: bonded claim + judges');
    expect(routeAction(fake(edge), out('r.v', 50), { hMax: 3 }).route).toBe('allow');
    expect(routeAction(fake(1), out('r.v', 50), { hMax: 3 }).judges).toBe(false);
  });
});

describe('judgeInputOf and jitConsentRequest', () => {
  const ctx = { intentRef: 'ref', mapDigest: 'map', statementText: 'text', slots: { verbs: [], constraints: [] }, goalCommitment: 'goal' };
  it('refuse a verb that Ω does not have, naming it', () => {
    expect(() => judgeInputOf(fake(1), out('nope', 1), ctx)).toThrow(new Error('judgeInputOf: no verb nope in Ω'));
    expect(() => jitConsentRequest(fake(1), out('nope', 1), ctx)).toThrow(new Error('jitConsentRequest: no verb nope in Ω'));
  });
  it('the judge input is built from the outcome verb, with the exact rendering, p and action digest', () => {
    const o = out('i.v', 50);
    expect(judgeInputOf(fake(0.25), o, ctx)).toEqual({
      ...ctx,
      renderedAction: renderAction(vsI, o.values),
      p: 0.25,
      reversibility: 'irreversible',
      actionDigest: actionDigest(pcactnActionOf(vsI, o)),
    });
  });
  it('the consent request is about the outcome verb, not the first verb', () => {
    const o = out('i.v', 50);
    const req = jitConsentRequest(fake(0.123456789), o, ctx);
    expect(req).toEqual({
      v: 1,
      kind: 'pca-intent-jit',
      intent_ref: 'ref',
      map_digest: 'map',
      verb: 'i.v',
      values: { [AMT]: 50 },
      reversibility: 'irreversible',
      p_ppm: 123457,
      text: `${renderAction(vsI, o.values)} This cannot be undone. Approve?`,
    });
    expect(req.values).not.toBe(o.values);
  });
  it('the consent digest is the domain-separated canonical hash of the request', () => {
    const req = jitConsentRequest(fake(0.5), out('i.v', 50), ctx);
    expect(jitConsentDigest(req)).toBe(hashCanonical({ d: 'atlas-pca/intent-jit/v1', r: JSON.parse(JSON.stringify(req)) as unknown }));
    expect(jitConsentDigest({ ...req, p_ppm: req.p_ppm + 1 })).not.toBe(jitConsentDigest(req));
  });
});

describe('recordJitDecision', () => {
  const req: JitConsentRequest = { v: 1, kind: 'pca-intent-jit', intent_ref: 'r', map_digest: 'm', verb: 'i.v', values: { [AMT]: 5 }, reversibility: 'irreversible', p_ppm: 1, text: 't' };
  const spy = () => {
    const calls: unknown[][] = [];
    const l = { observe: (...a: unknown[]) => calls.push(a), cells: () => [], synthesize: () => ({ predicates: [], caveats: [] }) } as unknown as IntentLearner;
    return { l, calls };
  };
  it('approve is a positive and deny a negative runtime observation of the requested outcome', () => {
    const a = spy();
    expect(recordJitDecision(a.l, req, 'approve')).toEqual({ before: 0, after: 0, grant: { predicates: [], caveats: [] } });
    expect(a.calls).toEqual([[{ verb: 'i.v', values: { [AMT]: 5 } }, 1, 'runtime']]);
    const d = spy();
    recordJitDecision(d.l, req, 'deny');
    expect(d.calls).toEqual([[{ verb: 'i.v', values: { [AMT]: 5 } }, 0, 'runtime']]);
  });
});

describe('the intent-conformance attestation', () => {
  const AD = b64u(new Uint8Array(32).fill(1));
  const GC = b64u(new Uint8Array(32).fill(7));
  const sks = [1, 2, 3].map((n) => new Uint8Array(32).fill(n));
  const judgeKeys = sks.map((s) => b64u(publicKeyOf(s)));
  const input: JudgeInput = { intentRef: 'ref', mapDigest: 'map', statementText: 't', slots: { verbs: [], constraints: [] }, renderedAction: 'x', p: 1, reversibility: 'irreversible', actionDigest: AD, goalCommitment: GC };
  const verdicts = sks.map((s) => signJudgeVerdict(s, { actionDigest: AD, goalCommitment: GC, faithful: true, score: 0.9 }));
  const opts = { judgeKeys, k: 2 };

  it('records every field of a passing panel, with sorted verdict digests in either input order', () => {
    const sorted = verdicts.map(verdictDigest).sort();
    const expected: ICAtt = {
      v: 1, kind: 'pca-ic-att', intent_ref: 'ref', map_digest: 'map', action_digest: AD, goal_commitment: GC, verdict_digests: sorted,
      calibration_digest: null, k: 2, ok: true, agree_count: 3, aggregate_score_ppm: 900000, cutoff_ppm: null,
    };
    expect(intentConformanceAttestation(input, verdicts, opts)).toStrictEqual(expected);
    expect(intentConformanceAttestation(input, [...verdicts].reverse(), opts).verdict_digests).toEqual(sorted);
  });
  it('a calibration sets the cutoff and is committed by digest; it can fail the panel', () => {
    const cal: Calibration = { alpha: 0.5, samples: [{ score: 0.2, faithful: false }, { score: 0.4, faithful: false }, { score: 0.6, faithful: false }, { score: 0.99, faithful: true }] };
    const att = intentConformanceAttestation(input, verdicts, { ...opts, calibration: cal });
    expect(att.ok).toBe(true);
    expect(att.cutoff_ppm).toBe(400000);
    const expectedDigest = hashCanonical({ d: 'atlas-pca/intent-calibration/v1', alpha: 0.5, samples: cal.samples.map((s) => ({ score: s.score, faithful: s.faithful })) });
    expect(att.calibration_digest).toBe(expectedDigest);
    expect(calibrationDigest(cal)).toBe(expectedDigest);
    expect(calibrationDigest({ ...cal, alpha: 0.4 })).not.toBe(expectedDigest);
    expect(calibrationDigest({ ...cal, samples: [{ score: 0.2, faithful: true }] })).not.toBe(expectedDigest);

    const strict: Calibration = { alpha: 0.5, samples: [{ score: 0.95, faithful: false }, { score: 0.97, faithful: false }] };
    const failed = intentConformanceAttestation(input, verdicts, { ...opts, calibration: strict });
    const direct = verifySemanticThreshold(verdicts, { judgeKeys, k: 2, goalCommitment: GC, actionDigest: AD, calibration: strict });
    expect(failed.ok).toBe(false);
    expect(failed.cutoff_ppm).toBe(970000);
    expect(failed.reason).toBe(direct.reason);
    expect(typeof failed.reason).toBe('string');
  });
  it('the attested-judge gate is passed to the verifier', () => {
    const att = intentConformanceAttestation(input, verdicts, { ...opts, attestation: { resolve: () => undefined, require: true } });
    expect(att.ok).toBe(false);
    expect(att.agree_count).toBe(0);
    expect(att.aggregate_score_ppm).toBe(0);
    expect(att.reason).toBe('only 0 distinct trusted judge(s) agree, need 2');
  });
  it('checkIntentConformance returns the panel verdicts with the attestation', async () => {
    const panel: JudgePanel = { verdicts: () => verdicts };
    const r = await checkIntentConformance(panel, input, opts);
    expect(r.verdicts).toBe(verdicts);
    expect(r.att).toEqual(intentConformanceAttestation(input, verdicts, opts));
  });
  it('verifyICAtt names each problem exactly', () => {
    const att = intentConformanceAttestation(input, verdicts, opts);
    expect(verifyICAtt(att, input, verdicts, opts)).toEqual({ ok: true, problems: [] });
    expect(verifyICAtt({ ...att, agree_count: 99 }, input, verdicts, opts)).toEqual({
      ok: false,
      problems: ['IC-Att does not match the recomputation from its verdicts'],
    });
    const k4 = { ...opts, k: 4 };
    const weak = intentConformanceAttestation(input, verdicts, k4);
    expect(verifyICAtt(weak, input, verdicts, k4)).toEqual({
      ok: false,
      problems: ['panel does not pass: only 3 distinct trusted judge(s) agree, need 4'],
    });
    expect(icAttDigest(att)).not.toBe(icAttDigest(weak));
  });
  it('the risk fold takes 1 - score from parts per million and never lowers r', () => {
    const att = intentConformanceAttestation(input, verdicts, opts);
    const c = semanticRiskContribution(0.9);
    expect(foldSemanticRisk(0.05, att)).toBe(c);
    expect(foldSemanticRisk(0.5, att)).toBe(0.5);
  });
});
