/**
 * Mutation-kill tests for semantic-threshold.ts: quantization, statement/message layout, every verifyJudgeVerdict guard
 * (reached with a VALID signature over the tampered body), attestation reasons, conformal rank arithmetic, quorum /
 * conflict / aggregate semantics, exact reason strings, and the hook wrapper.
 */
import { describe, expect, it } from 'vitest';
import { b64u, canonicalBytesStrict, compareUtf8, hashCanonical, utf8 } from './hash';
import { generateKeyPair, publicKeyOf, sign } from './keys';
import { mlDsa65Keygen } from './pq';
import {
  SCORE_SCALE,
  SEMANTIC_JUDGE_DOMAIN,
  actionDigest,
  conformalThreshold,
  createSemanticVerifier,
  empiricalFalseAllowRate,
  quantizeScore,
  semanticJudgeMessage,
  semanticRiskContribution,
  signJudgeVerdict,
  statementOf,
  verdictDigest,
  verifyJudgeAttestation,
  verifyJudgeVerdict,
  verifySemanticThreshold,
  type JudgeVerdict,
} from './semantic-threshold';
import type { MeasuredIdentity } from './attestation';
import type { HookResult } from './pcactn';

/** The semantic verifier is synchronous: unwrap its verdict (fails the test if a Promise came back). */
const syncVerdict = (r: HookResult | Promise<HookResult>): HookResult => {
  if (r instanceof Promise) throw new Error('expected a synchronous verdict');
  return r;
};

const GOAL = b64u(new Uint8Array(32).fill(7));
const ACT = b64u(new Uint8Array(32).fill(9));
const EXP = { actionDigest: ACT, goalCommitment: GOAL };
const mkV = (secret: Uint8Array, score = 0.9, faithful = true, meas = 'm@1'): JudgeVerdict =>
  signJudgeVerdict(secret, { actionDigest: ACT, goalCommitment: GOAL, faithful, score, judgeMeasurement: meas });
/** Re-sign an arbitrary (possibly ill-typed) body so ONLY the targeted guard can reject it. */
const forge = (secret: Uint8Array, v: JudgeVerdict, over: Record<string, unknown>): JudgeVerdict => {
  const body = { ...v, ...over } as JudgeVerdict;
  return { ...body, sig: b64u(sign(secret, semanticJudgeMessage(statementOf(body)))) };
};

describe('quantizeScore', () => {
  it('rounds, clamps, non-finite => 0', () => {
    expect(SCORE_SCALE).toBe(1_000_000);
    expect(quantizeScore(0)).toBe(0);
    expect(quantizeScore(1)).toBe(1_000_000);
    expect(quantizeScore(0.5)).toBe(500_000);
    expect(quantizeScore(0.4e-6)).toBe(0);
    expect(quantizeScore(0.5e-6 + 1e-9)).toBe(1);
    expect(quantizeScore(0.9999996)).toBe(1_000_000);
    expect(quantizeScore(-0.5)).toBe(0);
    expect(Object.is(quantizeScore(-1e-7), 0)).toBe(true);
    expect(Object.is(quantizeScore(-0), 0)).toBe(true);
    expect(quantizeScore(1.5)).toBe(1_000_000);
    expect(quantizeScore(NaN)).toBe(0);
    expect(quantizeScore(Infinity)).toBe(0);
    expect(quantizeScore(-Infinity)).toBe(0);
  });
});

describe('statement + message + digest', () => {
  it('statementOf exact fields', () => {
    expect(statementOf({ actionDigest: 'a', goalCommitment: 'g', faithful: true, score: 0.25, judgeMeasurement: 'jm' })).toEqual({
      v: 1,
      actionDigest: 'a',
      goalCommitment: 'g',
      faithful: true,
      score_ppm: 250_000,
      judgeMeasurement: 'jm',
    });
    // coercions
    const s = statementOf({ actionDigest: 'a', goalCommitment: 'g', faithful: 'true' as never, score: 0, judgeMeasurement: null as never });
    expect(s.faithful).toBe(false);
    expect(s.judgeMeasurement).toBe('');
    expect(statementOf({ actionDigest: 'a', goalCommitment: 'g', faithful: true, score: 0, judgeMeasurement: undefined as never }).judgeMeasurement).toBe('');
    // suite fields bound for non-default suite
    const h = statementOf({ actionDigest: 'a', goalCommitment: 'g', faithful: true, score: 0, judgeMeasurement: '', alg: 'hybrid-ed25519-ml-dsa-65', pq_pk: 'PK' });
    expect(h.alg).toBe('hybrid-ed25519-ml-dsa-65');
    expect(h.pq_pk).toBe('PK');
  });
  it('message = DOMAIN || strict canonical', () => {
    expect(SEMANTIC_JUDGE_DOMAIN).toBe('atlas-pca/semantic-judge/v1\0');
    const st = statementOf({ actionDigest: ACT, goalCommitment: GOAL, faithful: true, score: 0.5, judgeMeasurement: 'x' });
    const m = semanticJudgeMessage(st);
    const d = utf8(SEMANTIC_JUDGE_DOMAIN);
    const b = canonicalBytesStrict(st);
    expect(m.length).toBe(d.length + b.length);
    expect(Array.from(m.slice(0, d.length))).toEqual(Array.from(d));
    expect(Array.from(m.slice(d.length))).toEqual(Array.from(b));
  });
  it('actionDigest / verdictDigest are hashCanonical', () => {
    const a = { verb: 'pay', resource: '/x', params_digest: ACT, reversibility_class: 'reversible' } as never;
    expect(actionDigest(a)).toBe(hashCanonical(a));
    const v = mkV(generateKeyPair().secretKey);
    expect(verdictDigest(v)).toBe(hashCanonical(v));
    expect(verdictDigest({ ...v, score: 0.1 })).not.toBe(verdictDigest(v));
  });
});

describe('signJudgeVerdict', () => {
  const K = generateKeyPair();
  it('fields', () => {
    const v = signJudgeVerdict(K.secretKey, { actionDigest: ACT, goalCommitment: GOAL, faithful: false, score: 0.3 });
    expect(v.judge).toBe(b64u(publicKeyOf(K.secretKey)));
    expect(v.judgeMeasurement).toBe('');
    expect(v.faithful).toBe(false);
    expect(v.score).toBe(0.3);
    expect(v.actionDigest).toBe(ACT);
    expect(v.goalCommitment).toBe(GOAL);
    expect('alg' in v).toBe(false);
    expect(Object.keys(v).sort()).toEqual(['actionDigest', 'faithful', 'goalCommitment', 'judge', 'judgeMeasurement', 'score', 'sig']);
    expect(signJudgeVerdict(K.secretKey, { actionDigest: ACT, goalCommitment: GOAL, faithful: 1 as never, score: 1 }).faithful).toBe(false);
  });
  it('explicit ed25519 == default bytes; unknown alg throws exact message', () => {
    const a = signJudgeVerdict(K.secretKey, { actionDigest: ACT, goalCommitment: GOAL, faithful: true, score: 1 });
    const b = signJudgeVerdict(K.secretKey, { actionDigest: ACT, goalCommitment: GOAL, faithful: true, score: 1 }, { alg: 'ed25519' });
    expect(b).toEqual(a);
    expect(() => signJudgeVerdict(K.secretKey, { actionDigest: ACT, goalCommitment: GOAL, faithful: true, score: 1 }, { alg: 'nope' as never })).toThrow(
      "signJudgeVerdict: unknown signature alg 'nope'",
    );
  });
  it('hybrid and pure ml-dsa verdicts need pins; sigs bound', () => {
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(4));
    for (const alg of ['hybrid-ed25519-ml-dsa-65', 'ml-dsa-65'] as const) {
      const v = signJudgeVerdict(K.secretKey, { actionDigest: ACT, goalCommitment: GOAL, faithful: true, score: 0.8 }, { alg, mlDsa: ml });
      expect(v.alg).toBe(alg);
      expect(typeof v.pq_pk).toBe('string');
      expect('pq_sig' in v).toBe(alg === 'hybrid-ed25519-ml-dsa-65');
      expect(verifyJudgeVerdict(v, EXP)).toBe(false);
      expect(verifyJudgeVerdict(v, EXP, { allowUnboundPq: true })).toBe(true);
      expect(verifyJudgeVerdict(v, EXP, { pqPins: { [v.judge]: v.pq_pk! } })).toBe(true);
      expect(verifyJudgeVerdict({ ...v, score: 0.7 }, EXP, { allowUnboundPq: true })).toBe(false);
    }
  });
});

describe('verifyJudgeVerdict guards (each reached with a valid signature)', () => {
  const K = generateKeyPair();
  const good = mkV(K.secretKey, 0.5);
  it('baseline + boundary scores 0 and 1 accepted', () => {
    expect(verifyJudgeVerdict(good, EXP)).toBe(true);
    expect(verifyJudgeVerdict(mkV(K.secretKey, 0), EXP)).toBe(true);
    expect(verifyJudgeVerdict(mkV(K.secretKey, 1), EXP)).toBe(true);
  });
  it('non-object', () => {
    expect(verifyJudgeVerdict(null as never, EXP)).toBe(false);
    expect(verifyJudgeVerdict(undefined as never, EXP)).toBe(false);
    expect(verifyJudgeVerdict('x' as never, EXP)).toBe(false);
  });
  it('judge key shape', () => {
    expect(verifyJudgeVerdict({ ...good, judge: 5 } as never, EXP)).toBe(false);
    expect(verifyJudgeVerdict({ ...good, judge: b64u(new Uint8Array(31)) }, EXP)).toBe(false);
    expect(verifyJudgeVerdict({ ...good, judge: b64u(new Uint8Array(33)) }, EXP)).toBe(false);
  });
  it('binding mismatch on either field', () => {
    expect(verifyJudgeVerdict(good, { ...EXP, actionDigest: GOAL })).toBe(false);
    expect(verifyJudgeVerdict(good, { ...EXP, goalCommitment: ACT })).toBe(false);
  });
  it('non-string digests are rejected even when expected equals them', () => {
    const v = forge(K.secretKey, good, { actionDigest: 5 });
    expect(verifyJudgeVerdict(v, { actionDigest: 5 as never, goalCommitment: GOAL })).toBe(false);
    const w = forge(K.secretKey, good, { goalCommitment: 5 });
    expect(verifyJudgeVerdict(w, { actionDigest: ACT, goalCommitment: 5 as never })).toBe(false);
  });
  it('faithful must be a boolean', () => {
    const v = forge(K.secretKey, mkV(K.secretKey, 0.5, false), { faithful: 0 });
    expect(verifyJudgeVerdict(v, EXP)).toBe(false);
    const w = forge(K.secretKey, mkV(K.secretKey, 0.5, false), { faithful: undefined });
    expect(verifyJudgeVerdict(w, EXP)).toBe(false);
  });
  it('score must be a finite number in [0,1]', () => {
    expect(verifyJudgeVerdict(forge(K.secretKey, mkV(K.secretKey, 0), { score: '0.5' }), EXP)).toBe(false);
    expect(verifyJudgeVerdict(forge(K.secretKey, mkV(K.secretKey, 0), { score: NaN }), EXP)).toBe(false);
    expect(verifyJudgeVerdict(forge(K.secretKey, mkV(K.secretKey, 0), { score: Infinity }), EXP)).toBe(false);
    expect(verifyJudgeVerdict(forge(K.secretKey, mkV(K.secretKey, 0), { score: -1 }), EXP)).toBe(false);
    expect(verifyJudgeVerdict(forge(K.secretKey, mkV(K.secretKey, 1), { score: 2 }), EXP)).toBe(false);
    expect(verifyJudgeVerdict(forge(K.secretKey, mkV(K.secretKey, 1), { score: 1 + 1e-9 }), EXP)).toBe(false);
  });
  it('judgeMeasurement must be a string; sig must be a string; unknown alg', () => {
    expect(verifyJudgeVerdict(forge(K.secretKey, mkV(K.secretKey, 0.5, true, ''), { judgeMeasurement: null }), EXP)).toBe(false);
    expect(verifyJudgeVerdict({ ...good, sig: 5 } as never, EXP)).toBe(false);
    expect(verifyJudgeVerdict({ ...good, sig: undefined } as never, EXP)).toBe(false);
    expect(verifyJudgeVerdict(forge(K.secretKey, good, { alg: 'nope' }), EXP)).toBe(false);
  });
  it('a different key cannot sign for the named judge', () => {
    const other = generateKeyPair();
    const forged = { ...good, sig: mkV(other.secretKey, 0.5).sig };
    expect(verifyJudgeVerdict(forged, EXP)).toBe(false);
  });
});

describe('verifyJudgeAttestation', () => {
  const meas: MeasuredIdentity = { model_id: 'm', weights_digest: 'w', runtime_measurement: 'RM', operator: 'op' };
  it('reasons in order', () => {
    expect(verifyJudgeAttestation('RM', undefined)).toEqual({ ok: false, reason: 'no verified attestation for this judge (fail-closed)' });
    expect(verifyJudgeAttestation('RM', { ok: false })).toEqual({ ok: false, reason: 'no verified attestation for this judge (fail-closed)' });
    expect(verifyJudgeAttestation('RM', { ok: false, reason: 'bad quote' })).toEqual({ ok: false, reason: 'bad quote' });
    expect(verifyJudgeAttestation('RM', { ok: 1 as never, bound: true, measured: meas }).ok).toBe(false);
    expect(verifyJudgeAttestation('RM', { ok: true, measured: meas })).toEqual({
      ok: false,
      reason: 'judge attestation not bound to a TEE report (report_data binding unconfirmed)',
    });
    expect(verifyJudgeAttestation('RM', { ok: true, bound: 1 as never, measured: meas }).ok).toBe(false);
    expect(verifyJudgeAttestation('RM', { ok: true, bound: true })).toEqual({ ok: false, reason: 'judge attestation carries no measured identity' });
    expect(verifyJudgeAttestation('RM', { ok: true, bound: true, measured: 'x' as never })).toEqual({
      ok: false,
      reason: 'judge attestation carries no measured identity',
    });
    expect(verifyJudgeAttestation('', { ok: true, bound: true, measured: meas })).toEqual({
      ok: false,
      reason: 'verdict carries no judgeMeasurement to bind to the attested identity',
    });
    expect(verifyJudgeAttestation(5 as never, { ok: true, bound: true, measured: { ...meas, runtime_measurement: 5 as never } })).toEqual({
      ok: false,
      reason: 'verdict carries no judgeMeasurement to bind to the attested identity',
    });
    expect(verifyJudgeAttestation('OTHER', { ok: true, bound: true, measured: meas })).toEqual({
      ok: false,
      reason: 'attested enclave measurement does not match the signed judgeMeasurement',
    });
    expect(verifyJudgeAttestation('RM', { ok: true, bound: true, measured: meas }, { operator: 'evil' })).toEqual({
      ok: false,
      reason: 'operator op is not the bound operator',
    });
  });
  it('success returns the same measured object', () => {
    const r = verifyJudgeAttestation('RM', { ok: true, bound: true, measured: meas }, { operator: 'op' });
    expect(r.ok).toBe(true);
    expect(r.measured).toBe(meas);
    expect('reason' in r).toBe(false);
    expect(verifyJudgeAttestation('RM', { ok: true, bound: true, measured: meas }).ok).toBe(true);
  });
});

describe('conformalThreshold / empiricalFalseAllowRate', () => {
  const neg = (...s: number[]) => s.map((score) => ({ score, faithful: false }));
  it('rank arithmetic and boundary (rank == m is a value, rank > m is Infinity)', () => {
    const samples = neg(0.4, 0.1, 0.3, 0.2); // unsorted on purpose
    expect(conformalThreshold({ samples, alpha: 0.2 })).toBe(0.4); // ceil(5*0.8)=4=m
    expect(conformalThreshold({ samples, alpha: 0.1 })).toBe(Infinity); // ceil(4.5)=5>m
    expect(conformalThreshold({ samples, alpha: 0.5 })).toBe(0.3); // ceil(2.5)=3 (floor would give 2)
    expect(conformalThreshold({ samples, alpha: 0.6 })).toBe(0.2); // ceil(2)=2
    expect(conformalThreshold({ samples, alpha: 0.9 })).toBe(0.1); // ceil(0.5)=1
  });
  it('alpha clamping', () => {
    const samples = neg(0.1, 0.2, 0.3, 0.4);
    expect(conformalThreshold({ samples, alpha: 0 })).toBe(Infinity);
    expect(conformalThreshold({ samples, alpha: -3 })).toBe(Infinity);
    // alpha >= 1 (and non-numeric / non-finite, which clamp to 1) => the smallest unfaithful score, never undefined
    for (const a of [1, 1.0000001, 7, NaN, Infinity, '0.5', undefined, null]) {
      expect(conformalThreshold({ samples, alpha: a as never }), String(a)).toBe(0.1);
    }
    // MIN_VALUE (not 0, not 1) for alpha<=0: with large m the clamp differs from a bigger alpha
    const big = neg(...Array.from({ length: 99 }, (_, i) => (i + 1) / 100));
    expect(conformalThreshold({ samples: big, alpha: 0 })).toBe(Infinity);
    expect(conformalThreshold({ samples: big, alpha: 0.01 })).toBe(0.99);
  });
  it('only finite-score unfaithful samples count; junk tolerated', () => {
    const samples = [
      ...neg(0.2, 0.4),
      { score: 0.99, faithful: true },
      { score: NaN, faithful: false },
      { score: Infinity, faithful: false },
      { score: '0.9', faithful: false },
      { score: 0.95 },
      null,
      undefined,
    ] as never;
    expect(conformalThreshold({ samples, alpha: 0.5 })).toBe(0.4); // m=2, ceil(3*.5)=2
    expect(conformalThreshold({ samples: [{ score: 0.5, faithful: true }], alpha: 0.5 })).toBe(Infinity);
    expect(conformalThreshold({ samples: [], alpha: 0.5 })).toBe(Infinity);
    expect(conformalThreshold({ samples: 'x' as never, alpha: 0.5 })).toBe(Infinity);
    expect(conformalThreshold(undefined as never)).toBe(Infinity);
  });
  it('m=1 boundary', () => {
    expect(conformalThreshold({ samples: neg(0.5), alpha: 0.5 })).toBe(0.5); // ceil(2*0.5)=1 <= m
  });
  it('empirical false-allow rate: strict >, only unfaithful, 0 when none', () => {
    const s = [...neg(0.1, 0.5, 0.5, 0.9), { score: 0.99, faithful: true }];
    expect(empiricalFalseAllowRate(s, 0.5)).toBe(0.25);
    expect(empiricalFalseAllowRate(s, 0.4)).toBe(0.75);
    expect(empiricalFalseAllowRate(s, 0.9)).toBe(0);
    expect(empiricalFalseAllowRate(s, -1)).toBe(1);
    expect(empiricalFalseAllowRate([{ score: 1, faithful: true }], 0)).toBe(0);
    expect(empiricalFalseAllowRate([], 0)).toBe(0);
    expect(empiricalFalseAllowRate('x' as never, 0)).toBe(0);
    expect(empiricalFalseAllowRate([...neg(0.9), { score: NaN, faithful: false }, null, { score: '1', faithful: false }, { score: 1 }] as never, 0.5)).toBe(1);
  });
});

describe('verifySemanticThreshold', () => {
  const Ks = Array.from({ length: 5 }, () => generateKeyPair());
  const keys = Ks.map((k) => b64u(publicKeyOf(k.secretKey)));
  const base = (over: Record<string, unknown> = {}) => ({ judgeKeys: keys, k: 2, goalCommitment: GOAL, actionDigest: ACT, ...over }) as never;

  it('exact reasons: binding then k (binding first)', () => {
    expect(verifySemanticThreshold([], base({ actionDigest: 5 }))).toEqual({ ok: false, agreeCount: 0, aggregateScore: 0, reason: 'missing action/goal binding' });
    expect(verifySemanticThreshold([], base({ goalCommitment: undefined }))).toEqual({ ok: false, agreeCount: 0, aggregateScore: 0, reason: 'missing action/goal binding' });
    expect(verifySemanticThreshold([], base({ actionDigest: undefined, k: 0 })).reason).toBe('missing action/goal binding');
    expect(verifySemanticThreshold([], undefined as never).reason).toBe('missing action/goal binding');
    for (const [k, txt] of [[0, '0'], [-1, '-1'], [1.5, '1.5'], ['2', '2'], [undefined, 'undefined'], [NaN, 'NaN']] as const) {
      expect(verifySemanticThreshold([], base({ k }))).toEqual({ ok: false, agreeCount: 0, aggregateScore: 0, reason: `invalid quorum k=${txt}` });
    }
  });

  it('quorum: k=1 boundary, exact reason, mean score', () => {
    const vs = [mkV(Ks[0]!.secretKey, 0.5), mkV(Ks[1]!.secretKey, 0.7)];
    const r1 = verifySemanticThreshold(vs.slice(0, 1), base({ k: 2 }));
    expect(r1).toEqual({ ok: false, agreeCount: 1, aggregateScore: 0.5, reason: 'only 1 distinct trusted judge(s) agree, need 2' });
    const r2 = verifySemanticThreshold(vs, base({ k: 2 }));
    expect(r2.ok).toBe(true);
    expect(r2.agreeCount).toBe(2);
    expect(r2.aggregateScore).toBeCloseTo(0.6, 12);
    expect('reason' in r2).toBe(false);
    expect('cutoff' in r2).toBe(false);
    const r0 = verifySemanticThreshold([], base({ k: 1 }));
    expect(r0).toEqual({ ok: false, agreeCount: 0, aggregateScore: 0, reason: 'only 0 distinct trusted judge(s) agree, need 1' });
    expect(verifySemanticThreshold(vs.slice(0, 1), base({ k: 1 })).ok).toBe(true);
  });

  it('allowlist: unknown/malformed keys are ignored; non-array judgeKeys => nobody trusted', () => {
    const v = mkV(Ks[0]!.secretKey);
    expect(verifySemanticThreshold([v], base({ judgeKeys: [], k: 1 })).agreeCount).toBe(0);
    expect(verifySemanticThreshold([v], base({ judgeKeys: 'x', k: 1 })).agreeCount).toBe(0);
    expect(verifySemanticThreshold([v], base({ judgeKeys: undefined, k: 1 })).agreeCount).toBe(0);
    expect(verifySemanticThreshold([v], base({ judgeKeys: [5, 'short', v.judge], k: 1 })).agreeCount).toBe(1);
    expect(verifySemanticThreshold([v], base({ judgeKeys: [keys[1]], k: 1 })).agreeCount).toBe(0);
  });

  it('verdicts: junk skipped; non-array => none; unfaithful, mis-bound, bad sig do not count', () => {
    const v = mkV(Ks[0]!.secretKey);
    expect(verifySemanticThreshold([null, undefined, 5, { judge: 5 }, v] as never, base({ k: 1 })).agreeCount).toBe(1);
    expect(verifySemanticThreshold('x' as never, base({ k: 1 })).agreeCount).toBe(0);
    expect(verifySemanticThreshold([mkV(Ks[0]!.secretKey, 0.9, false)], base({ k: 1 })).agreeCount).toBe(0);
    expect(verifySemanticThreshold([v], base({ k: 1, actionDigest: GOAL })).agreeCount).toBe(0);
    expect(verifySemanticThreshold([{ ...v, score: 0.1 }], base({ k: 1 })).agreeCount).toBe(0);
  });

  it('one-key-one-vote: duplicates count once; contradictions drop the judge entirely', () => {
    const a = Ks[0]!.secretKey;
    const dup = [mkV(a, 0.5), mkV(a, 0.5)];
    const r = verifySemanticThreshold(dup, base({ k: 1 }));
    expect(r.agreeCount).toBe(1);
    expect(r.aggregateScore).toBe(0.5);
    expect(verifySemanticThreshold(dup, base({ k: 2 })).ok).toBe(false);
    // different scores => conflict (faithful same)
    expect(verifySemanticThreshold([mkV(a, 0.5), mkV(a, 0.6)], base({ k: 1 })).agreeCount).toBe(0);
    // mixed faithful => conflict
    expect(verifySemanticThreshold([mkV(a, 0.5), mkV(a, 0.5, false)], base({ k: 1 })).agreeCount).toBe(0);
    expect(verifySemanticThreshold([mkV(a, 0.5, false), mkV(a, 0.5)], base({ k: 1 })).agreeCount).toBe(0);
    // conflict does not poison others, nor the aggregate
    const r2 = verifySemanticThreshold([mkV(a, 0.5), mkV(a, 0.6), mkV(Ks[1]!.secretKey, 0.8)], base({ k: 1 }));
    expect(r2.agreeCount).toBe(1);
    expect(r2.aggregateScore).toBe(0.8);
  });

  it('scores equal after quantization are the same vote', () => {
    const a = Ks[0]!.secretKey;
    const r = verifySemanticThreshold([mkV(a, 0.5), mkV(a, 0.5 + 1e-9)], base({ k: 1 }));
    expect(r.agreeCount).toBe(1);
  });

  it('aggregate is the mean of QUANTIZED scores summed in compareUtf8(judge) order (deterministic)', () => {
    // find a key set + scores for which sum order matters in floating point
    let found: { ks: ReturnType<typeof generateKeyPair>[]; scores: number[] } | undefined;
    const pool = [0.1, 0.2, 0.3, 0.7, 0.9, 0.35];
    for (let t = 0; t < 400 && !found; t++) {
      const ks = Array.from({ length: 6 }, () => generateKeyPair());
      const ids = ks.map((k) => b64u(publicKeyOf(k.secretKey)));
      const idx = ids.map((_, i) => i).sort((x, y) => compareUtf8(ids[x]!, ids[y]!));
      const q = (i: number) => quantizeScore(pool[i]!) / SCORE_SCALE;
      const fwd = idx.reduce((a, i) => a + q(i), 0);
      const rev = [...idx].reverse().reduce((a, i) => a + q(i), 0);
      if (fwd !== rev) found = { ks, scores: pool };
    }
    expect(found).toBeDefined();
    const { ks, scores } = found!;
    const ids = ks.map((k) => b64u(publicKeyOf(k.secretKey)));
    const idx = ids.map((_, i) => i).sort((x, y) => compareUtf8(ids[x]!, ids[y]!));
    const expected = idx.reduce((a, i) => a + quantizeScore(scores[i]!) / SCORE_SCALE, 0) / 6;
    const vs = ks.map((k, i) => mkV(k.secretKey, scores[i]!));
    const r = verifySemanticThreshold(vs, { judgeKeys: ids, k: 6, goalCommitment: GOAL, actionDigest: ACT });
    expect(r.aggregateScore).toBe(expected);
    const r2 = verifySemanticThreshold([...vs].reverse(), { judgeKeys: ids, k: 6, goalCommitment: GOAL, actionDigest: ACT });
    expect(r2.aggregateScore).toBe(expected);
  });

  it('calibration gate: strict >, cutoff reported on both outcomes, exact reason', () => {
    const vs = [mkV(Ks[0]!.secretKey, 0.5), mkV(Ks[1]!.secretKey, 0.5)];
    const cal = (c: number) => ({ samples: [{ score: c, faithful: false }], alpha: 0.5 });
    const eq = verifySemanticThreshold(vs, base({ k: 2, calibration: cal(0.5) }));
    expect(eq).toEqual({
      ok: false,
      agreeCount: 2,
      aggregateScore: 0.5,
      cutoff: 0.5,
      reason: 'aggregateScore 0.5 does not exceed calibrated cutoff 0.5',
    });
    const below = verifySemanticThreshold(vs, base({ k: 2, calibration: cal(0.4) }));
    expect(below).toEqual({ ok: true, agreeCount: 2, aggregateScore: 0.5, cutoff: 0.4 });
    const inf = verifySemanticThreshold(vs, base({ k: 2, calibration: { samples: [], alpha: 0.5 } }));
    expect(inf.ok).toBe(false);
    expect(inf.cutoff).toBe(Infinity);
    expect(inf.reason).toBe('aggregateScore 0.5 does not exceed calibrated cutoff Infinity');
    // quorum failure precedes calibration and carries no cutoff
    const q = verifySemanticThreshold(vs.slice(0, 1), base({ k: 2, calibration: cal(0.4) }));
    expect('cutoff' in q).toBe(false);
  });

  it('PQ pin policy is forwarded to verdict verification', () => {
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(6));
    const v = signJudgeVerdict(Ks[0]!.secretKey, { actionDigest: ACT, goalCommitment: GOAL, faithful: true, score: 0.9 }, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml });
    expect(verifySemanticThreshold([v], base({ k: 1 })).agreeCount).toBe(0);
    expect(verifySemanticThreshold([v], base({ k: 1, pqPins: { [v.judge]: v.pq_pk } })).agreeCount).toBe(1);
    expect(verifySemanticThreshold([v], base({ k: 1, allowUnboundPq: true })).agreeCount).toBe(1);
  });

  describe('attestation gate', () => {
    const meas = (rm: string): MeasuredIdentity => ({ model_id: 'm', weights_digest: 'w', runtime_measurement: rm, operator: 'op' });
    const good = (rm: string) => ({ ok: true, bound: true, measured: meas(rm) });
    const vs = [mkV(Ks[0]!.secretKey, 0.5, true, 'A'), mkV(Ks[1]!.secretKey, 0.5, true, 'B')];
    it('require:true drops unattested / mismatched / unapproved; require:false or absent keeps everything', () => {
      const resolve = (v: JudgeVerdict) => (v.judgeMeasurement === 'A' ? good('A') : undefined);
      expect(verifySemanticThreshold(vs, base({ k: 1, attestation: { resolve, require: true } })).agreeCount).toBe(1);
      expect(verifySemanticThreshold(vs, base({ k: 1, attestation: { resolve, require: false } })).agreeCount).toBe(2);
      expect(verifySemanticThreshold(vs, base({ k: 1, attestation: { resolve, require: undefined } })).agreeCount).toBe(2);
      expect(verifySemanticThreshold(vs, base({ k: 1, attestation: { resolve, require: 'yes' } })).agreeCount).toBe(2);
      expect(verifySemanticThreshold(vs, base({ k: 1 })).agreeCount).toBe(2);
      // wrong measurement
      expect(verifySemanticThreshold(vs, base({ k: 1, attestation: { resolve: () => good('Z'), require: true } })).agreeCount).toBe(0);
      // approved reference applied
      const all = (v: JudgeVerdict) => good(v.judgeMeasurement);
      expect(verifySemanticThreshold(vs, base({ k: 2, attestation: { resolve: all, require: true } })).ok).toBe(true);
      expect(verifySemanticThreshold(vs, base({ k: 1, attestation: { resolve: all, approved: { operator: 'nope' }, require: true } })).agreeCount).toBe(0);
      expect(verifySemanticThreshold(vs, base({ k: 1, attestation: { resolve: all, approved: { operator: 'op' }, require: true } })).agreeCount).toBe(2);
    });
    it('resolve receives the verdict', () => {
      const seen: JudgeVerdict[] = [];
      verifySemanticThreshold(vs, base({ k: 1, attestation: { resolve: (v: JudgeVerdict) => (seen.push(v), good(v.judgeMeasurement)), require: true } }));
      expect(seen).toEqual(vs);
    });
    it('resolve is not consulted for invalid verdicts', () => {
      let n = 0;
      verifySemanticThreshold([{ ...vs[0]!, score: 0.1 }], base({ k: 1, attestation: { resolve: () => (n++, undefined), require: true } }));
      expect(n).toBe(0);
    });
  });
});

describe('createSemanticVerifier', () => {
  const Ks = [generateKeyPair(), generateKeyPair()];
  const keys = Ks.map((k) => b64u(publicKeyOf(k.secretKey)));
  const action = { verb: 'pay', resource: '/x', params_digest: ACT, reversibility_class: 'reversible' };
  const ctx = { pcactn: { action } } as never;
  const AD = actionDigest(action as never);
  const mine = (secret: Uint8Array, faithful = true) => signJudgeVerdict(secret, { actionDigest: AD, goalCommitment: GOAL, faithful, score: 0.9, judgeMeasurement: 'm' });
  const base = (over: Record<string, unknown> = {}) =>
    ({ judgeKeys: keys, k: 2, verdicts: () => Ks.map((k) => mine(k.secretKey)), goalCommitment: () => GOAL, ...over }) as never;

  it('ok => {enforced, ok}; default digest is actionDigest(ctx.pcactn.action)', () => {
    expect(createSemanticVerifier(base())(ctx)).toEqual({ enforced: true, ok: true });
  });
  it('quorum failure => exact reason', () => {
    expect(createSemanticVerifier(base({ verdicts: () => [mine(Ks[0]!.secretKey)] }))(ctx)).toEqual({
      enforced: true,
      ok: false,
      reason: 'only 1 distinct trusted judge(s) agree, need 2',
    });
  });
  it('absent goal / verdicts: fail-closed by default, not-enforced when optional', () => {
    const fc = { enforced: true, ok: false, reason: 'no semantic ensemble available for this action (fail-closed)' };
    expect(createSemanticVerifier(base({ goalCommitment: () => undefined }))(ctx)).toEqual(fc);
    expect(createSemanticVerifier(base({ verdicts: () => undefined }))(ctx)).toEqual(fc);
    expect(createSemanticVerifier(base({ goalCommitment: () => undefined, optionalWhenAbsent: true }))(ctx)).toEqual({ enforced: false });
    expect(createSemanticVerifier(base({ verdicts: () => undefined, optionalWhenAbsent: true }))(ctx)).toEqual({ enforced: false });
    // empty verdict list is "available" (not absent): normal quorum failure
    expect(syncVerdict(createSemanticVerifier(base({ verdicts: () => [], optionalWhenAbsent: true }))(ctx)).enforced).toBe(true);
    // empty-string goal commitment is a string => available
    expect(createSemanticVerifier(base({ goalCommitment: () => '' }))(ctx)).toEqual({
      enforced: true,
      ok: false,
      reason: 'only 0 distinct trusted judge(s) agree, need 2',
    });
  });
  it('actionDigest override, ctx forwarded to resolvers', () => {
    const seen: unknown[] = [];
    const v = createSemanticVerifier(
      base({
        actionDigest: () => ACT,
        verdicts: (c: unknown) => (seen.push(c), Ks.map((k) => mkV(k.secretKey))),
        goalCommitment: (c: unknown) => (seen.push(c), GOAL),
      }),
    );
    expect(v(ctx)).toEqual({ enforced: true, ok: true });
    expect(seen).toEqual([ctx, ctx]);
    // default digest does NOT match verdicts bound to ACT
    expect(createSemanticVerifier(base({ verdicts: () => Ks.map((k) => mkV(k.secretKey)) }))(ctx)).toMatchObject({ enforced: true, ok: false });
  });
  it('calibration and attestation are forwarded', () => {
    const calib = { samples: [{ score: 0.95, faithful: false }], alpha: 0.5 };
    const r = createSemanticVerifier(base({ calibration: calib }))(ctx);
    expect(r).toEqual({ enforced: true, ok: false, reason: 'aggregateScore 0.9 does not exceed calibrated cutoff 0.95' });
    const meas = (rm: string) => ({ ok: true, bound: true, measured: { model_id: 'm', weights_digest: 'w', runtime_measurement: rm, operator: 'op' } });
    const seen: unknown[] = [];
    const att = createSemanticVerifier(base({ attestation: (c: unknown) => (seen.push(c), { resolve: () => meas('nope'), require: true }) }))(ctx);
    expect(att).toMatchObject({ enforced: true, ok: false });
    expect(seen).toEqual([ctx]);
    const att2 = createSemanticVerifier(base({ attestation: () => ({ resolve: () => meas('m'), require: true }) }))(ctx);
    expect(att2).toEqual({ enforced: true, ok: true });
    expect(createSemanticVerifier(base({ attestation: () => undefined }))(ctx)).toEqual({ enforced: true, ok: true });
  });
});

describe('semanticRiskContribution', () => {
  it('1 - score clamped, non-finite => 1', () => {
    expect(semanticRiskContribution(0.3)).toBeCloseTo(0.7, 12);
    expect(semanticRiskContribution(1)).toBe(0);
    expect(semanticRiskContribution(0)).toBe(1);
    expect(semanticRiskContribution(1.5)).toBe(0);
    expect(semanticRiskContribution(-0.5)).toBe(1);
    expect(semanticRiskContribution(NaN)).toBe(1);
    expect(semanticRiskContribution(Infinity)).toBe(1);
    expect(semanticRiskContribution(-Infinity)).toBe(1);
  });
});

describe('verifyJudgeVerdict: judge key shape is enforced even for PQ suites (no Ed25519 check to lean on)', () => {
  const K = generateKeyPair();
  const ml = mlDsa65Keygen(new Uint8Array(32).fill(2));
  const v = signJudgeVerdict(K.secretKey, { actionDigest: ACT, goalCommitment: GOAL, faithful: true, score: 0.5 }, { alg: 'ml-dsa-65', mlDsa: ml });
  it('baseline accepted; non-string / short / long / non-b64u judge refused', () => {
    expect(verifyJudgeVerdict(v, EXP, { allowUnboundPq: true })).toBe(true);
    for (const judge of [5, null, 'short', b64u(new Uint8Array(31)), b64u(new Uint8Array(33)), '!!!!']) {
      expect(verifyJudgeVerdict({ ...v, judge } as never, EXP, { allowUnboundPq: true }), String(judge)).toBe(false);
    }
  });
});
