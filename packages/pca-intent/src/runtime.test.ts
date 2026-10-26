import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { signIntentObservation, signJudgeVerdict } from '@atlasauth/pca/ext/intent';
import {
  admitter,
  checkIntentConformance,
  checkPostconditions,
  createLearner,
  decodeCell,
  deriveOmega,
  DriftDetector,
  elicit,
  encodeCell,
  foldSemanticRisk,
  icAttDigest,
  jitConsentDigest,
  jitConsentRequest,
  judgeInputOf,
  narrowStart,
  recordJitDecision,
  rng,
  routeAction,
  signalLabel,
  TrustRamp,
  verbCellCount,
  verifyICAtt,
  verifyOutcome,
  cellRep,
  type IntentLearner,
  type IntentSlots,
  type JudgePanel,
  type RuntimeSignal,
} from './index';

const AMT = 'action.params.amount';
const RCP = 'action.params.recipient';
const slots: IntentSlots = { verbs: ['stripe.charge', 'stripe.refund', 'stripe.payout'], constraints: [{ path: AMT, max: 200 }, { path: RCP, oneOf: ['alice'] }] };
const omega = deriveOmega({ policies: [], slots });
const truth = admitter({
  predicates: ['stripe.charge', 'stripe.refund', 'stripe.payout'].map((verb) => ({ verb, resource: '*', where: [{ field: AMT, op: 'gte' as const, value: 0 }, { field: AMT, op: 'lte' as const, value: 200 }, { field: RCP, op: 'eq' as const, value: 'alice' }] })),
});

function learned(): IntentLearner {
  const l = createLearner(omega, { nullMass: 0.05 });
  elicit(l, (q) => (truth.admits(omega.verbs.find((v) => v.verb === q.verb)!, q.outcome) ? 1 : 0), { epsRisk: 0, epsBurden: 0, maxQuestions: 80 });
  return l;
}
const o = (verb: string, amount: number, who = 'alice') => ({ verb, values: { [AMT]: amount, [RCP]: who } });

describe('runtime routing by p_n and reversibility (§4.4–4.5)', () => {
  const l = learned();
  it('confirmed reversible / rate-limited actions are allowed; irreversible ones need JIT consent + judges', () => {
    expect(routeAction(l, o('stripe.charge', 50)).route).toBe('allow');
    expect(routeAction(l, o('stripe.refund', 50)).route).toBe('allow');
    const p = routeAction(l, o('stripe.payout', 50));
    expect(p.route).toBe('jit-consent');
    expect(p.judges).toBe(true);
  });
  it('outside the grant, or outside Ω, is denied', () => {
    expect(routeAction(l, o('stripe.charge', 201)).route).toBe('deny');
    expect(routeAction(l, o('stripe.charge', 50, 'mallory')).route).toBe('deny');
    expect(routeAction(l, { verb: 'gmail.send', values: {} }).route).toBe('deny');
  });
  it('an unconfirmed in-grant cell (p < 1) runs optimistically, bonded at ≥ its harm, with judges', () => {
    const n = createLearner(omega, { eta: 0.05, tau: 0.5, nullMass: 0.05 });
    const vs = omega.verbs.find((v) => v.verb === 'stripe.refund')!;
    n.observe(o('stripe.refund', 50), 1);
    const c = n.cells().find((x) => x.verb === 'stripe.refund' && x.inGrant && x.p < 1);
    expect(c).toBeDefined();
    const d = routeAction(n, cellRep(vs, c!.cell));
    expect(d.route).toBe('optimistic');
    expect(d.judges).toBe(true);
    expect(d.bond!).toBeGreaterThanOrEqual(d.harm);
  });
});

describe('judge panel hook → IC-Att (B3 reused unchanged)', () => {
  const l = learned();
  const judges = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
  const goalCommitment = b64u(new Uint8Array(32).fill(7));
  const input = judgeInputOf(l, o('stripe.payout', 50), { intentRef: 'ref', mapDigest: 'map', statementText: 'Pay alice up to 200.', slots, goalCommitment });
  const panel = (faithful: boolean[], digest = input.actionDigest): JudgePanel => ({
    verdicts: () => judges.map((j, i) => signJudgeVerdict(j.secretKey, { actionDigest: digest, goalCommitment, faithful: faithful[i]!, score: 0.9 })),
  });
  const opts = { judgeKeys: judges.map((j) => b64u(j.publicKey)), k: 2 };
  it('judges see the deterministic rendering, never raw payloads', () => {
    expect(input.renderedAction).toContain('stripe.payout');
    expect(input.renderedAction).toContain('amount 50');
  });
  it('k-of-n passes, is content-addressed and re-verifies from its verdicts', async () => {
    const { att, verdicts } = await checkIntentConformance(panel([true, true, false]), input, opts);
    expect(att.ok).toBe(true);
    expect(att.agree_count).toBe(2);
    expect(verifyICAtt(att, input, verdicts, opts)).toEqual({ ok: true, problems: [] });
    expect(verifyICAtt({ ...att, agree_count: 3 }, input, verdicts, opts).ok).toBe(false);
    expect(icAttDigest(att)).toBe(icAttDigest(JSON.parse(JSON.stringify(att))));
  });
  it('verdicts bound to another action do not count', async () => {
    const { att } = await checkIntentConformance(panel([true, true, true], b64u(new Uint8Array(32))), input, opts);
    expect(att.ok).toBe(false);
  });
  it('PROPERTY: the semantic risk fold never lowers r', async () => {
    const { att } = await checkIntentConformance(panel([true, true, true]), input, opts);
    const r = rng(3);
    for (let i = 0; i < 200; i++) {
      const x = r();
      expect(foldSemanticRisk(x, att)).toBeGreaterThanOrEqual(x);
    }
  });
});

describe('JIT consent (§4.5)', () => {
  it('a refusal is a negative runtime observation that vetoes the cell', () => {
    const l = learned();
    const req = jitConsentRequest(l, o('stripe.payout', 50), { intentRef: 'ref', mapDigest: 'map' });
    expect(req.text).toContain('cannot be undone');
    expect(jitConsentDigest(req)).toBe(jitConsentDigest({ ...req }));
    expect(l.admitsOutcome(o('stripe.payout', 50))).toBe(true);
    recordJitDecision(l, req, 'deny');
    expect(l.isVetoed(o('stripe.payout', 50))).toBe(true);
    expect(l.admitsOutcome(o('stripe.payout', 50))).toBe(false);
  });
});

describe('effect postconditions (§4.5 item 1)', () => {
  const vs = omega.verbs.find((v) => v.verb === 'stripe.refund')!;
  it('ok / violated / pending / not applicable', () => {
    expect(checkPostconditions(vs, o('stripe.refund', 100), { amount: 100, recipient: 'alice' }).status).toBe('ok');
    const bad = checkPostconditions(vs, o('stripe.refund', 100), { amount: 150, recipient: 'alice' });
    expect(bad.status).toBe('violated');
    expect(bad.violated).toEqual(['stripe.refund.amount']);
    expect(checkPostconditions(vs, o('stripe.refund', 100), { amount: 100, recipient: 'bob' }).violated).toEqual(['stripe.refund.recipient']);
    const pend = checkPostconditions(vs, o('stripe.refund', 100), { amount: 100 });
    expect(pend.status).toBe('pending');
    expect(pend.missing).toEqual(['env.effect.recipient']);
    const na = checkPostconditions(vs, { verb: 'stripe.refund', values: { [AMT]: 100 } }, { amount: 100 });
    expect(na.status).toBe('ok');
    expect(na.notApplicable).toEqual(['stripe.refund.recipient']);
  });
  it('a violation feeds back as a veto; ok never widens', () => {
    const l = learned();
    const before = l.cells().filter((c) => c.inGrant).length;
    verifyOutcome(l, o('stripe.refund', 100), { amount: 100, recipient: 'alice' });
    expect(l.cells().filter((c) => c.inGrant).length).toBe(before);
    const r = verifyOutcome(l, o('stripe.refund', 100), { amount: 100, recipient: 'eve' });
    expect(r.divergence).toBeDefined();
    expect(l.isVetoed(o('stripe.refund', 100))).toBe(true);
  });
});

describe('trust ramp + drift (§4.6)', () => {
  const signals: RuntimeSignal[] = ['jit-approve', 'principal-confirm', 'jit-refuse', 'challenge-upheld', 'judge-deny-upheld', 'postcondition-violation'];
  it('signal labels', () => {
    expect(signals.map(signalLabel)).toEqual([1, 1, 0, 0, 0, 0]);
  });
  it('narrowStart: τ = 1, η = 0, no anchor, unnamed verbs nearly denied', () => {
    const big = deriveOmega({ policies: [], slots, extraVerbs: ['gmail.send'] });
    const opt = narrowStart(big, slots);
    expect(opt).toMatchObject({ eta: 0, tau: 1 });
    expect((opt.nullMass as Record<string, number>)['gmail.send']).toBe(0.95);
    expect(opt.anchor).toBeUndefined();
  });
  it('PROPERTY (ratchet): vetoes only accumulate and a vetoed cell is never admitted again', () => {
    const r = rng(9);
    for (let t = 0; t < 10; t++) {
      const ramp = new TrustRamp(createLearner(omega, narrowStart(omega, slots)), { h: 1e9 });
      let vetoed = new Set<string>();
      for (let i = 0; i < 40; i++) {
        const vs = omega.verbs[Math.floor(r() * omega.verbs.length)]!;
        const idx = decodeCell(vs, Math.floor(r() * verbCellCount(vs)));
        const s = signals[Math.floor(r() * signals.length)]!;
        ramp.record(cellRep(vs, idx), s);
        const now = new Set(ramp.learner.vetoedCells());
        for (const v of vetoed) expect(now.has(v)).toBe(true);
        for (const c of ramp.learner.cells()) if (c.inGrant) expect(now.has(`${c.verb}|${encodeCell(omega.verbs.find((x) => x.verb === c.verb)!, c.cell)}`)).toBe(false);
        vetoed = now;
      }
    }
  });
  it('divergences inside the grant raise a sticky alarm; then positives are queued, negatives still apply', () => {
    const ramp = new TrustRamp(learned());
    ramp.record(o('stripe.charge', 10), 'postcondition-violation');
    expect(ramp.frozen).toBe(false);
    ramp.record(o('stripe.charge', 200), 'challenge-upheld'); // a different in-grant cell ({200}); the first is now vetoed
    expect(ramp.frozen).toBe(true);
    const n = ramp.learner.observations.length;
    const rec = ramp.record(o('stripe.charge', 500), 'jit-approve');
    expect(rec.applied).toBe(false);
    expect(ramp.pending).toHaveLength(1);
    expect(ramp.learner.observations.length).toBe(n);
    ramp.record(o('stripe.refund', 10), 'jit-refuse');
    expect(ramp.learner.isVetoed(o('stripe.refund', 10))).toBe(true);
    ramp.record(o('stripe.charge', 20), 'principal-confirm'); // no-divergence evidence does not clear the alarm
    expect(ramp.frozen).toBe(true);
    ramp.rebase(learned());
    expect(ramp.frozen).toBe(false);
    expect(ramp.pending).toHaveLength(0);
  });
  it('signals about actions outside the grant carry no drift evidence', () => {
    const ramp = new TrustRamp(learned());
    for (let i = 0; i < 10; i++) ramp.record(o('stripe.charge', 5000), 'jit-refuse');
    expect(ramp.drift.state.statistic).toBe(0);
    expect(ramp.drift.state.informative).toBe(0);
  });
  it('PROPERTY: the CUSUM statistic is non-negative and an alarm is sticky', () => {
    const r = rng(13);
    const d = new DriftDetector();
    let alarmed = false;
    for (let i = 0; i < 2000; i++) {
      const s = d.update(r() < 0.08);
      expect(s.statistic).toBeGreaterThanOrEqual(0);
      if (alarmed) expect(s.alarm).toBe(true);
      alarmed = s.alarm;
    }
  });
  it('signed runtime observations: verified, trusted signer, right map', () => {
    const kp = generateKeyPair();
    const mapDigest = b64u(new Uint8Array(32).fill(1));
    const obs = signIntentObservation({ map_digest: mapDigest, verb: 'stripe.refund', values: { [AMT]: 10, [RCP]: 'alice' }, y: 0, source: 'runtime', observed_at: 1 }, kp.secretKey);
    const ramp = new TrustRamp(learned());
    expect(ramp.recordObservation(obs, { mapDigest, trustedSigners: [] })).toEqual({ ok: false, reason: 'untrusted observation signer' });
    expect(ramp.recordObservation(obs, { mapDigest: b64u(new Uint8Array(32)), trustedSigners: [obs.signer] }).ok).toBe(false);
    expect(ramp.recordObservation({ ...obs, y: 1 }, { mapDigest, trustedSigners: [obs.signer] }).ok).toBe(false);
    expect(ramp.recordObservation(obs, { mapDigest, trustedSigners: [obs.signer] }).ok).toBe(true);
    expect(ramp.learner.isVetoed({ verb: 'stripe.refund', values: { [AMT]: 10, [RCP]: 'alice' } })).toBe(true);
  });
});
