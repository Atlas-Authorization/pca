import { describe, expect, it } from 'vitest';
import { b64u, unb64u } from './hash';
import { generateKeyPair, publicKeyOf } from './keys';
import {
  type Calibration,
  type JudgeVerdict,
  type LabeledScore,
  SCORE_SCALE,
  actionDigest,
  conformalThreshold,
  createSemanticVerifier,
  empiricalFalseAllowRate,
  quantizeScore,
  type SemanticAttestationOpts,
  semanticJudgeMessage,
  semanticRiskContribution,
  signJudgeVerdict,
  statementOf,
  verifyJudgeAttestation,
  verifyJudgeVerdict,
  verifySemanticThreshold,
} from './semantic-threshold';
import type { HardwareAttestationResult, MeasuredIdentity } from './attestation';

// A fixed goal + action binding reused across the agreement tests.
const GOAL = b64u(new Uint8Array(32).fill(7));
const ACTION = actionDigest({ verb: 'pay', resource: '/vendor/acme', params_digest: b64u(new Uint8Array(32).fill(3)), reversibility_class: 'reversible' });

/** n fresh judge keypairs. */
function judges(n: number) {
  return Array.from({ length: n }, () => generateKeyPair());
}

/** A faithful=true verdict from a judge, bound to GOAL/ACTION. */
function faithfulVerdict(secret: Uint8Array, score = 0.9, bind: { actionDigest?: string; goalCommitment?: string } = {}): JudgeVerdict {
  return signJudgeVerdict(secret, {
    actionDigest: bind.actionDigest ?? ACTION,
    goalCommitment: bind.goalCommitment ?? GOAL,
    faithful: true,
    score,
    judgeMeasurement: 'judge-model-x@1',
  });
}

describe('JudgeVerdict signing + binding', () => {
  it('a well-formed verdict verifies; score is bound via its quantized value', () => {
    const j = generateKeyPair();
    const v = faithfulVerdict(j.secretKey, 0.812345);
    expect(v.judge).toBe(b64u(publicKeyOf(j.secretKey)));
    expect(verifyJudgeVerdict(v, { actionDigest: ACTION, goalCommitment: GOAL })).toBe(true);

    // Tamper the score => signature no longer matches the signed (quantized) statement.
    expect(verifyJudgeVerdict({ ...v, score: 0.5 }, { actionDigest: ACTION, goalCommitment: GOAL })).toBe(false);
    // Tamper the verdict bit.
    expect(verifyJudgeVerdict({ ...v, faithful: false }, { actionDigest: ACTION, goalCommitment: GOAL })).toBe(false);
    // Tamper the judgeMeasurement.
    expect(verifyJudgeVerdict({ ...v, judgeMeasurement: 'other' }, { actionDigest: ACTION, goalCommitment: GOAL })).toBe(false);
  });

  it('signature tampering (flipped sig bit) is rejected', () => {
    const j = generateKeyPair();
    const v = faithfulVerdict(j.secretKey);
    const raw = Uint8Array.from(unb64u(v.sig));
    raw[0] = (raw[0]! ^ 0x01) & 0xff;
    const tampered: JudgeVerdict = { ...v, sig: b64u(raw) };
    expect(verifyJudgeVerdict(tampered, { actionDigest: ACTION, goalCommitment: GOAL })).toBe(false);
  });

  it('mis-bound verdicts (wrong action or goal) are rejected', () => {
    const j = generateKeyPair();
    const vWrongAction = faithfulVerdict(j.secretKey, 0.9, { actionDigest: b64u(new Uint8Array(32).fill(9)) });
    const vWrongGoal = faithfulVerdict(j.secretKey, 0.9, { goalCommitment: b64u(new Uint8Array(32).fill(9)) });
    expect(verifyJudgeVerdict(vWrongAction, { actionDigest: ACTION, goalCommitment: GOAL })).toBe(false);
    expect(verifyJudgeVerdict(vWrongGoal, { actionDigest: ACTION, goalCommitment: GOAL })).toBe(false);
  });

  it('statementOf quantizes score and the message is domain-separated + deterministic', () => {
    const s = statementOf({ actionDigest: ACTION, goalCommitment: GOAL, faithful: true, score: 0.5, judgeMeasurement: 'm' });
    expect(s.score_ppm).toBe(500_000);
    const m1 = semanticJudgeMessage(s);
    const m2 = semanticJudgeMessage(s);
    expect(b64u(m1)).toBe(b64u(m2));
    // sub-ppm scores collapse to 0 rather than throwing (strict-canonical safe).
    expect(quantizeScore(1e-9)).toBe(0);
    expect(quantizeScore(2)).toBe(SCORE_SCALE);
    expect(quantizeScore(-1)).toBe(0);
  });
});

describe('verifySemanticThreshold — k-of-n agreement', () => {
  it('k met => ok; k-1 => fail', () => {
    const js = judges(5);
    const keys = js.map((j) => b64u(publicKeyOf(j.secretKey)));
    const verdicts = js.slice(0, 3).map((j) => faithfulVerdict(j.secretKey));

    const met = verifySemanticThreshold(verdicts, { judgeKeys: keys, k: 3, goalCommitment: GOAL, actionDigest: ACTION });
    expect(met.ok).toBe(true);
    expect(met.agreeCount).toBe(3);

    const short = verifySemanticThreshold(verdicts, { judgeKeys: keys, k: 4, goalCommitment: GOAL, actionDigest: ACTION });
    expect(short.ok).toBe(false);
    expect(short.agreeCount).toBe(3);
  });

  it('a duplicate judge key is counted once', () => {
    const js = judges(3);
    const keys = js.map((j) => b64u(publicKeyOf(j.secretKey)));
    const v0a = faithfulVerdict(js[0]!.secretKey, 0.9);
    const v0b = faithfulVerdict(js[0]!.secretKey, 0.9); // identical re-submission
    const v1 = faithfulVerdict(js[1]!.secretKey, 0.9);
    const res = verifySemanticThreshold([v0a, v0b, v1], { judgeKeys: keys, k: 2, goalCommitment: GOAL, actionDigest: ACTION });
    expect(res.agreeCount).toBe(2); // not 3
    expect(res.ok).toBe(true);
    const need3 = verifySemanticThreshold([v0a, v0b, v1], { judgeKeys: keys, k: 3, goalCommitment: GOAL, actionDigest: ACTION });
    expect(need3.ok).toBe(false);
  });

  it('unknown / untrusted judges are ignored', () => {
    const trusted = judges(2);
    const keys = trusted.map((j) => b64u(publicKeyOf(j.secretKey)));
    const stranger = generateKeyPair(); // NOT on the allowlist
    const verdicts = [faithfulVerdict(trusted[0]!.secretKey), faithfulVerdict(stranger.secretKey)];
    const res = verifySemanticThreshold(verdicts, { judgeKeys: keys, k: 2, goalCommitment: GOAL, actionDigest: ACTION });
    expect(res.agreeCount).toBe(1); // stranger does not count
    expect(res.ok).toBe(false);
  });

  it('mis-bound verdicts do not count', () => {
    const js = judges(2);
    const keys = js.map((j) => b64u(publicKeyOf(j.secretKey)));
    const good = faithfulVerdict(js[0]!.secretKey);
    const wrong = faithfulVerdict(js[1]!.secretKey, 0.9, { actionDigest: b64u(new Uint8Array(32).fill(1)) });
    const res = verifySemanticThreshold([good, wrong], { judgeKeys: keys, k: 2, goalCommitment: GOAL, actionDigest: ACTION });
    expect(res.agreeCount).toBe(1);
    expect(res.ok).toBe(false);
  });

  it('a self-contradicting judge (mixed verdicts) is dropped, fail-closed', () => {
    const js = judges(2);
    const keys = js.map((j) => b64u(publicKeyOf(j.secretKey)));
    const yes = faithfulVerdict(js[0]!.secretKey, 0.9);
    const no = signJudgeVerdict(js[0]!.secretKey, { actionDigest: ACTION, goalCommitment: GOAL, faithful: false, score: 0.9, judgeMeasurement: 'judge-model-x@1' });
    const other = faithfulVerdict(js[1]!.secretKey, 0.9);
    const res = verifySemanticThreshold([yes, no, other], { judgeKeys: keys, k: 2, goalCommitment: GOAL, actionDigest: ACTION });
    expect(res.agreeCount).toBe(1); // conflicted judge dropped; only `other` counts
    expect(res.ok).toBe(false);
  });

  it('only faithful=true votes count toward agreement', () => {
    const js = judges(3);
    const keys = js.map((j) => b64u(publicKeyOf(j.secretKey)));
    const yes = faithfulVerdict(js[0]!.secretKey);
    const no = signJudgeVerdict(js[1]!.secretKey, { actionDigest: ACTION, goalCommitment: GOAL, faithful: false, score: 0.9, judgeMeasurement: 'm' });
    const res = verifySemanticThreshold([yes, no], { judgeKeys: keys, k: 2, goalCommitment: GOAL, actionDigest: ACTION });
    expect(res.agreeCount).toBe(1);
  });

  it('rejects invalid quorum / missing binding', () => {
    expect(verifySemanticThreshold([], { judgeKeys: [], k: 0, goalCommitment: GOAL, actionDigest: ACTION }).ok).toBe(false);
    expect(verifySemanticThreshold([], { judgeKeys: [], k: 1, goalCommitment: GOAL, actionDigest: ACTION as unknown as string }).agreeCount).toBe(0);
  });
});

describe('aggregateScore determinism', () => {
  it('is the mean of agreeing judges and independent of verdict order', () => {
    const js = judges(3);
    const keys = js.map((j) => b64u(publicKeyOf(j.secretKey)));
    const a = faithfulVerdict(js[0]!.secretKey, 0.6);
    const b = faithfulVerdict(js[1]!.secretKey, 0.8);
    const c = faithfulVerdict(js[2]!.secretKey, 1.0);
    const r1 = verifySemanticThreshold([a, b, c], { judgeKeys: keys, k: 3, goalCommitment: GOAL, actionDigest: ACTION });
    const r2 = verifySemanticThreshold([c, a, b], { judgeKeys: keys, k: 3, goalCommitment: GOAL, actionDigest: ACTION });
    expect(r1.aggregateScore).toBeCloseTo((0.6 + 0.8 + 1.0) / 3, 12);
    expect(r1.aggregateScore).toBe(r2.aggregateScore); // byte-exact determinism
    expect(verifySemanticThreshold([], { judgeKeys: keys, k: 1, goalCommitment: GOAL, actionDigest: ACTION }).aggregateScore).toBe(0);
  });
});

// ---- conformal calibration -----------------------------------------------------------------

/** mulberry32 — deterministic PRNG so the "random" property tests are reproducible. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randomCalibration(r: () => number): LabeledScore[] {
  // Unfaithful actions score lower on average than faithful ones, but the classes overlap — a
  // realistic calibration set where a plain cutoff would NOT trivially separate them.
  const nUnfaithful = 10 + Math.floor(r() * 90);
  const nFaithful = 10 + Math.floor(r() * 90);
  const out: LabeledScore[] = [];
  for (let i = 0; i < nUnfaithful; i++) out.push({ faithful: false, score: Math.min(1, Math.max(0, 0.35 + (r() - 0.5) * 0.8)) });
  for (let i = 0; i < nFaithful; i++) out.push({ faithful: true, score: Math.min(1, Math.max(0, 0.65 + (r() - 0.5) * 0.8)) });
  return out;
}

describe('conformalThreshold — bounded false-allow rate', () => {
  it('PROPERTY: empirical false-allow rate <= alpha over random calibration sets and alphas', () => {
    const r = rng(0xc0ffee);
    for (let trial = 0; trial < 400; trial++) {
      const samples = randomCalibration(r);
      const alpha = 0.01 + r() * 0.5; // alpha in ~(0.01, 0.51)
      const cal: Calibration = { samples, alpha };
      const cutoff = conformalThreshold(cal);
      const fa = empiricalFalseAllowRate(samples, cutoff);
      // allow rule is score > cutoff; empirical false-allow must not exceed alpha.
      expect(fa).toBeLessThanOrEqual(alpha + 1e-9);
    }
  });

  it('PROPERTY: cutoff is monotonically non-increasing in alpha', () => {
    const r = rng(0x1234abcd);
    for (let trial = 0; trial < 200; trial++) {
      const samples = randomCalibration(r);
      const alphas = [0.05, 0.1, 0.2, 0.3, 0.5];
      let prev = Infinity;
      for (const alpha of alphas) {
        const cutoff = conformalThreshold({ samples, alpha });
        expect(cutoff).toBeLessThanOrEqual(prev + 1e-12);
        prev = cutoff;
      }
    }
  });

  it('fail-closed: no unfaithful examples, or too few to certify alpha, => +Infinity cutoff', () => {
    expect(conformalThreshold({ samples: [{ faithful: true, score: 0.9 }], alpha: 0.1 })).toBe(Infinity);
    // m=2 negatives, alpha=0.1 => rank=ceil(3*0.9)=3 > 2 => Infinity (cannot certify 10% on 2 samples).
    expect(conformalThreshold({ samples: [{ faithful: false, score: 0.1 }, { faithful: false, score: 0.2 }], alpha: 0.1 })).toBe(Infinity);
  });

  it('a +Infinity cutoff denies every action through the ensemble gate', () => {
    const js = judges(2);
    const keys = js.map((j) => b64u(publicKeyOf(j.secretKey)));
    const verdicts = js.map((j) => faithfulVerdict(j.secretKey, 1.0));
    const res = verifySemanticThreshold(verdicts, {
      judgeKeys: keys,
      k: 2,
      goalCommitment: GOAL,
      actionDigest: ACTION,
      calibration: { samples: [{ faithful: true, score: 0.9 }], alpha: 0.1 }, // no negatives => Infinity
    });
    expect(res.agreeCount).toBe(2);
    expect(res.cutoff).toBe(Infinity);
    expect(res.ok).toBe(false); // quorum met but score gate denies
  });

  it('calibration gate: agreement met AND aggregateScore clears the cutoff => ok', () => {
    const js = judges(3);
    const keys = js.map((j) => b64u(publicKeyOf(j.secretKey)));
    const verdicts = js.map((j) => faithfulVerdict(j.secretKey, 0.95));
    // Unfaithful scores all low => a 10% cutoff well below 0.95.
    const samples: LabeledScore[] = Array.from({ length: 50 }, (_, i) => ({ faithful: false, score: 0.1 + (i % 10) * 0.01 }));
    const res = verifySemanticThreshold(verdicts, {
      judgeKeys: keys,
      k: 3,
      goalCommitment: GOAL,
      actionDigest: ACTION,
      calibration: { samples, alpha: 0.1 },
    });
    expect(res.ok).toBe(true);
    expect(res.cutoff).toBeLessThan(0.95);
    expect(res.aggregateScore).toBeCloseTo(0.95, 12);
  });
});

// ---- attested-judge binding -----------------------------------------------------------------

/** The enclave measurement a judge's verdict asserts (equals `faithfulVerdict`'s judgeMeasurement). */
const JUDGE_MEAS = 'judge-model-x@1';

/** A verified+bound hardware attestation whose measured runtime_measurement is `meas`. */
function attestedResult(meas: string, extra: Partial<MeasuredIdentity> = {}): HardwareAttestationResult {
  const measured: MeasuredIdentity = {
    model_id: '',
    weights_digest: '',
    runtime_measurement: meas,
    operator: 'chip-operator-1',
    ...extra,
  };
  return { ok: true, bound: true, measured };
}

describe('verifyJudgeAttestation — bind judgeMeasurement to a measured TEE', () => {
  it('accepts a verified+bound attestation whose measurement matches the signed label', () => {
    const res = verifyJudgeAttestation(JUDGE_MEAS, attestedResult(JUDGE_MEAS));
    expect(res.ok).toBe(true);
    expect(res.measured?.runtime_measurement).toBe(JUDGE_MEAS);
  });

  it('fails closed when the attestation is absent', () => {
    expect(verifyJudgeAttestation(JUDGE_MEAS, undefined).ok).toBe(false);
  });

  it('fails closed when not report_data-bound', () => {
    const r = verifyJudgeAttestation(JUDGE_MEAS, { ok: true, bound: false, measured: attestedResult(JUDGE_MEAS).measured });
    expect(r.ok).toBe(false);
  });

  it('fails closed when the attested enclave measurement differs from the signed judgeMeasurement', () => {
    expect(verifyJudgeAttestation(JUDGE_MEAS, attestedResult('some-other-measurement')).ok).toBe(false);
  });

  it('appraises the measured identity against the approved AgentBinding reference', () => {
    // approved by exact min_measurement + operator.
    const ok = verifyJudgeAttestation(JUDGE_MEAS, attestedResult(JUDGE_MEAS), { min_measurement: JUDGE_MEAS, operator: 'chip-operator-1' });
    expect(ok.ok).toBe(true);
    // wrong operator => not in approved reference.
    const badOp = verifyJudgeAttestation(JUDGE_MEAS, attestedResult(JUDGE_MEAS), { operator: 'other-operator' });
    expect(badOp.ok).toBe(false);
    // require_measured_weights fails closed when the digest is not hardware-measured.
    const needW = verifyJudgeAttestation(JUDGE_MEAS, attestedResult(JUDGE_MEAS), { require_measured_weights: true });
    expect(needW.ok).toBe(false);
  });
});

describe('verifySemanticThreshold — attested-judge gate', () => {
  it('require: an attested judge with an approved measurement is accepted', () => {
    const js = judges(3);
    const keys = js.map((j) => b64u(publicKeyOf(j.secretKey)));
    const verdicts = js.map((j) => faithfulVerdict(j.secretKey));
    const attestation: SemanticAttestationOpts = {
      require: true,
      resolve: () => attestedResult(JUDGE_MEAS),
      approved: { min_measurement: JUDGE_MEAS },
    };
    const res = verifySemanticThreshold(verdicts, { judgeKeys: keys, k: 3, goalCommitment: GOAL, actionDigest: ACTION, attestation });
    expect(res.ok).toBe(true);
    expect(res.agreeCount).toBe(3);
  });

  it('require: an unattested judge is dropped (its vote does not count), fail-closed', () => {
    const js = judges(3);
    const keys = js.map((j) => b64u(publicKeyOf(j.secretKey)));
    const verdicts = js.map((j) => faithfulVerdict(j.secretKey));
    const attestedKey = keys[0]!;
    const attestation: SemanticAttestationOpts = {
      require: true,
      // only the first judge resolves to a verified attestation; the rest are unattested.
      resolve: (v) => (v.judge === attestedKey ? attestedResult(JUDGE_MEAS) : undefined),
    };
    const res = verifySemanticThreshold(verdicts, { judgeKeys: keys, k: 3, goalCommitment: GOAL, actionDigest: ACTION, attestation });
    expect(res.agreeCount).toBe(1); // two unattested judges dropped
    expect(res.ok).toBe(false);
  });

  it('require: a wrong-measurement attestation is rejected', () => {
    const js = judges(2);
    const keys = js.map((j) => b64u(publicKeyOf(j.secretKey)));
    const verdicts = js.map((j) => faithfulVerdict(j.secretKey));
    const attestation: SemanticAttestationOpts = {
      require: true,
      resolve: () => attestedResult('mismatched-measurement'), // != the signed JUDGE_MEAS
    };
    const res = verifySemanticThreshold(verdicts, { judgeKeys: keys, k: 2, goalCommitment: GOAL, actionDigest: ACTION, attestation });
    expect(res.agreeCount).toBe(0);
    expect(res.ok).toBe(false);
  });

  it('require: a measurement outside the approved reference is rejected', () => {
    const js = judges(2);
    const keys = js.map((j) => b64u(publicKeyOf(j.secretKey)));
    const verdicts = js.map((j) => faithfulVerdict(j.secretKey));
    const attestation: SemanticAttestationOpts = {
      require: true,
      resolve: () => attestedResult(JUDGE_MEAS),
      approved: { min_measurement: 'a-different-approved-measurement' },
    };
    const res = verifySemanticThreshold(verdicts, { judgeKeys: keys, k: 2, goalCommitment: GOAL, actionDigest: ACTION, attestation });
    expect(res.agreeCount).toBe(0);
    expect(res.ok).toBe(false);
  });

  it('backward-compat: unattested flows still work when attestation is not required', () => {
    const js = judges(3);
    const keys = js.map((j) => b64u(publicKeyOf(j.secretKey)));
    const verdicts = js.map((j) => faithfulVerdict(j.secretKey));
    // No attestation opt at all => unchanged.
    expect(verifySemanticThreshold(verdicts, { judgeKeys: keys, k: 3, goalCommitment: GOAL, actionDigest: ACTION }).ok).toBe(true);
    // Attestation present but require:false => unattested judges still count.
    const attestation: SemanticAttestationOpts = { require: false, resolve: () => undefined };
    const res = verifySemanticThreshold(verdicts, { judgeKeys: keys, k: 3, goalCommitment: GOAL, actionDigest: ACTION, attestation });
    expect(res.ok).toBe(true);
    expect(res.agreeCount).toBe(3);
  });

  it('hook: createSemanticVerifier threads the attested-judge gate per action', () => {
    const js = judges(2);
    const keys = js.map((j) => b64u(publicKeyOf(j.secretKey)));
    const pcactn = { action: { verb: 'pay', resource: '/vendor/acme', params_digest: b64u(new Uint8Array(32).fill(3)), reversibility_class: 'reversible' } } as any;
    const ctx = { pcactn, grant: {} as any };
    const verdicts = js.map((j) =>
      signJudgeVerdict(j.secretKey, { actionDigest: actionDigest(pcactn.action), goalCommitment: GOAL, faithful: true, score: 0.9, judgeMeasurement: JUDGE_MEAS }),
    );

    // Attested => ok.
    const hookOk = createSemanticVerifier({
      judgeKeys: keys,
      k: 2,
      verdicts: () => verdicts,
      goalCommitment: () => GOAL,
      attestation: () => ({ require: true, resolve: () => attestedResult(JUDGE_MEAS) }),
    });
    expect(hookOk(ctx as any)).toEqual({ enforced: true, ok: true });

    // Unattested + required => fail-closed.
    const hookClosed = createSemanticVerifier({
      judgeKeys: keys,
      k: 2,
      verdicts: () => verdicts,
      goalCommitment: () => GOAL,
      attestation: () => ({ require: true, resolve: () => undefined }),
    });
    const closed = hookClosed(ctx as any) as { enforced: true; ok: boolean };
    expect(closed.ok).toBe(false);
  });
});

describe('createSemanticVerifier — hook shape', () => {
  it('returns a pass/fail HookResult and is fail-closed when the ensemble is absent', () => {
    const js = judges(2);
    const keys = js.map((j) => b64u(publicKeyOf(j.secretKey)));
    const pcactn = { action: { verb: 'pay', resource: '/vendor/acme', params_digest: b64u(new Uint8Array(32).fill(3)), reversibility_class: 'reversible' } } as any;
    const ctx = { pcactn, grant: {} as any };

    const verdicts = js.map((j) =>
      signJudgeVerdict(j.secretKey, { actionDigest: actionDigest(pcactn.action), goalCommitment: GOAL, faithful: true, score: 0.9, judgeMeasurement: 'm' }),
    );

    const hookOk = createSemanticVerifier({
      judgeKeys: keys,
      k: 2,
      verdicts: () => verdicts,
      goalCommitment: () => GOAL,
    });
    expect(hookOk(ctx as any)).toEqual({ enforced: true, ok: true });

    // Fail-closed (default) when verdicts/goal missing.
    const hookClosed = createSemanticVerifier({ judgeKeys: keys, k: 2, verdicts: () => undefined, goalCommitment: () => GOAL });
    const closed = hookClosed(ctx as any) as { enforced: true; ok: boolean };
    expect(closed.enforced).toBe(true);
    expect(closed.ok).toBe(false);

    // optionalWhenAbsent => not-enforced.
    const hookOptional = createSemanticVerifier({ judgeKeys: keys, k: 2, verdicts: () => undefined, goalCommitment: () => undefined, optionalWhenAbsent: true });
    expect(hookOptional(ctx as any)).toEqual({ enforced: false });
  });

  it('semanticRiskContribution is 1 - aggregateScore, clamped and monotone', () => {
    expect(semanticRiskContribution(1)).toBe(0);
    expect(semanticRiskContribution(0)).toBe(1);
    expect(semanticRiskContribution(0.7)).toBeCloseTo(0.3, 12);
    expect(semanticRiskContribution(NaN)).toBe(1);
    expect(semanticRiskContribution(2)).toBe(0);
    expect(semanticRiskContribution(-1)).toBe(1);
  });
});
