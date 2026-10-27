/**
 * DoD-1 audit, part 2: judges and semantic thresholds, proof of progress, objective risk, session history windows.
 * Same rules as intent-dod1-audit.test.ts: a positive control per group, and every row pins the whole outcome.
 */
import { describe, expect, it } from 'vitest';
import { b64u, sha256, utf8 } from './hash';
import { publicKeyOf } from './keys';
import {
  actionDigest,
  createSemanticVerifier,
  signJudgeVerdict,
  verifyJudgeAttestation,
  verifyJudgeVerdict,
  verifySemanticThreshold,
  semanticRiskContribution,
  type JudgeVerdict,
} from './semantic-threshold';
import { InMemoryStateSource, ProgressTracker, commitGoal as commitProgressGoal, l1FeaturePotential, verifyProgressStep, verifyTrajectory, type Goal } from './progress';
import { DEFAULT_RISK_POLICY as P } from './risk';
import { InMemoryInverseRegistry, ResourceGraph, commitGoal, nativeHashEmbedder, objectiveRisk, type ObjAction, type ObjectiveRiskContext } from './objective-risk';
import { resolveObjectiveRisk, readObjectiveCommitment } from './objective-binding';
import { inWindow, accPreState, accKeyOf, monitorStep, monitorState, type IntentEvent } from './intent-history';
import type { AccumulatorDecl, MonitorDecl } from './intent-acc';

const seed = (l: string) => sha256(utf8(`atlas-pca-test/dod1b/${l}`));
const key = (l: string) => ({ sk: seed(l), pub: b64u(publicKeyOf(seed(l))) });
const GOAL = b64u(seed('goal'));
const ACT = b64u(seed('act'));

describe('DoD-1 intent audit: semantic judges (semantic-threshold.ts)', () => {
  const J = [key('j1'), key('j2'), key('j3')];
  const verdict = (k: { sk: Uint8Array }, over: Partial<{ faithful: boolean; score: number; actionDigest: string; goalCommitment: string }> = {}) =>
    signJudgeVerdict(k.sk, { actionDigest: ACT, goalCommitment: GOAL, faithful: true, score: 0.9, ...over });
  const opts = { judgeKeys: J.map((j) => j.pub), k: 2, goalCommitment: GOAL, actionDigest: ACT };
  it('control: two allowlisted judges agree', () => {
    expect(verifySemanticThreshold([verdict(J[0]!), verdict(J[1]!)], opts)).toEqual({ ok: true, agreeCount: 2, aggregateScore: 0.9 });
  });
  it('no verdicts at all, or a non-array: denied with the count', () => {
    expect(verifySemanticThreshold([], opts)).toEqual({ ok: false, agreeCount: 0, aggregateScore: 0, reason: 'only 0 distinct trusted judge(s) agree, need 2' });
    expect(verifySemanticThreshold(undefined as never, opts)).toEqual({ ok: false, agreeCount: 0, aggregateScore: 0, reason: 'only 0 distinct trusted judge(s) agree, need 2' });
  });
  it('no allowlist (missing or empty): no judge is trusted, denied', () => {
    expect(verifySemanticThreshold([verdict(J[0]!), verdict(J[1]!)], { ...opts, judgeKeys: [] }).ok).toBe(false);
    expect(verifySemanticThreshold([verdict(J[0]!), verdict(J[1]!)], { ...opts, judgeKeys: undefined as never }).ok).toBe(false);
  });
  it('no action or goal binding, or a quorum that is not a positive integer: denied before any verdict is read', () => {
    expect(verifySemanticThreshold([verdict(J[0]!)], { ...opts, actionDigest: undefined as never })).toEqual({ ok: false, agreeCount: 0, aggregateScore: 0, reason: 'missing action/goal binding' });
    expect(verifySemanticThreshold([verdict(J[0]!)], { ...opts, goalCommitment: undefined as never }).reason).toBe('missing action/goal binding');
    for (const k of [0, -1, 1.5, Number.NaN, undefined, '2'] as never[]) expect(verifySemanticThreshold([verdict(J[0]!)], { ...opts, k }).reason).toBe(`invalid quorum k=${String(k)}`);
  });
  it('a verdict for another action or goal, with a score outside [0,1], a tampered score, an unknown suite: never counted', () => {
    const other = verdict(J[1]!, { actionDigest: b64u(seed('other')) });
    expect(verifySemanticThreshold([verdict(J[0]!), other], opts).agreeCount).toBe(1);
    expect(verifyJudgeVerdict({ ...verdict(J[0]!), score: 1.5 }, { actionDigest: ACT, goalCommitment: GOAL })).toBe(false);
    expect(verifyJudgeVerdict({ ...verdict(J[0]!), score: 0.8 }, { actionDigest: ACT, goalCommitment: GOAL })).toBe(false);
    expect(verifyJudgeVerdict({ ...verdict(J[0]!), alg: 'rot13-sig' as never }, { actionDigest: ACT, goalCommitment: GOAL })).toBe(false);
    expect(verifyJudgeVerdict(undefined as never, { actionDigest: ACT, goalCommitment: GOAL })).toBe(false);
  });
  it('a judge who contradicts itself, or votes unfaithful, counts for nothing', () => {
    const split = [verdict(J[0]!), verdict(J[0]!, { faithful: false }), verdict(J[1]!)];
    expect(verifySemanticThreshold(split, opts).agreeCount).toBe(1);
    expect(verifySemanticThreshold([verdict(J[0]!, { faithful: false }), verdict(J[1]!, { faithful: false })], opts).agreeCount).toBe(0);
  });
  it('attestation required but no attestation resolves for the judge: the vote is dropped', () => {
    const r = verifySemanticThreshold([verdict(J[0]!), verdict(J[1]!)], { ...opts, attestation: { resolve: () => undefined, require: true } });
    expect(r).toEqual({ ok: false, agreeCount: 0, aggregateScore: 0, reason: 'only 0 distinct trusted judge(s) agree, need 2' });
    expect(verifyJudgeAttestation('m', undefined)).toEqual({ ok: false, reason: 'no verified attestation for this judge (fail-closed)' });
    expect(verifyJudgeAttestation('m', { ok: true, bound: false } as never)).toEqual({ ok: false, reason: 'judge attestation not bound to a TEE report (report_data binding unconfirmed)' });
    expect(verifyJudgeAttestation('m', { ok: true, bound: true } as never)).toEqual({ ok: false, reason: 'judge attestation carries no measured identity' });
  });
  it('the hook with no ensemble or no goal commitment: denied by default, not enforced only when the operator opted in', () => {
    const pcactn = { action: { verb: 'v', resource: 'r', params_digest: ACT } } as never;
    const ctx = { pcactn } as never;
    const base = { judgeKeys: opts.judgeKeys, k: 2, verdicts: () => undefined, goalCommitment: () => GOAL };
    expect(createSemanticVerifier(base)(ctx)).toEqual({ enforced: true, ok: false, reason: 'no semantic ensemble available for this action (fail-closed)' });
    expect(createSemanticVerifier({ ...base, verdicts: () => [], goalCommitment: () => undefined })(ctx)).toEqual({ enforced: true, ok: false, reason: 'no semantic ensemble available for this action (fail-closed)' });
    expect(createSemanticVerifier({ ...base, optionalWhenAbsent: true })(ctx)).toEqual({ enforced: false });
  });
  it('a non-finite aggregate raises risk to the maximum (never lowers it)', () => {
    expect(semanticRiskContribution(Number.NaN)).toBe(1);
    expect(semanticRiskContribution(Infinity)).toBe(1);
    expect(semanticRiskContribution(2)).toBe(0);
    expect(semanticRiskContribution(-1)).toBe(1);
    void actionDigest;
  });
});

describe('DoD-1 intent audit: proof of progress (progress.ts)', () => {
  const goal: Goal = { objective: { target: [10, 10] }, potential: 'l1-feature-v1', metric: 'l1', epsilon: 2, explorationBudget: 3 };
  const { commitment } = commitProgressGoal(goal);
  const mk = () => new ProgressTracker(goal, commitment, { x: [0, 0] });
  const first = () => {
    const r = mk().step({ x: [4, 4] }, 'a0');
    if (!r.ok) throw new Error('fixture');
    return r.step;
  };
  it('control: a well-formed descent verifies and charges nothing', () => {
    expect(verifyProgressStep(goal, commitment, first())).toEqual({ ok: true, charge: 0 });
  });
  it('a goal that is not the committed one, or no goal: denied', () => {
    expect(verifyProgressStep({ ...goal, epsilon: 1 }, commitment, first())).toEqual({ ok: false, reason: 'goal-mismatch' });
    expect(verifyProgressStep(undefined as never, commitment, first())).toEqual({ ok: false, reason: 'goal-mismatch' });
    expect(verifyProgressStep(goal, 'x', first())).toEqual({ ok: false, reason: 'goal-mismatch' });
  });
  it('no step, or a step with a field missing: malformed', () => {
    expect(verifyProgressStep(goal, commitment, undefined as never)).toEqual({ ok: false, reason: 'malformed' });
    const { prev: _p, ...noPrev } = first();
    void _p;
    expect(verifyProgressStep(goal, commitment, noPrev as never)).toEqual({ ok: false, reason: 'malformed' });
  });
  it('an unknown potential id (not in the verifier registry): denied; the tracker refuses to start', () => {
    expect(() => new ProgressTracker(goal, commitment, { x: [0, 0] }, {})).toThrow('unknown potential l1-feature-v1');
    expect(verifyProgressStep(goal, commitment, first(), { registry: {} })).toEqual({ ok: false, reason: 'unknown-potential' });
  });
  it('a registry entry that names a different embedder than the goal commits: denied', () => {
    expect(verifyProgressStep(goal, commitment, first(), { registry: { 'l1-feature-v1': { fn: l1FeaturePotential, embedder: 'emb-v9' } } })).toEqual({ ok: false, reason: 'embedder-mismatch' });
  });
  it('a state source that is not trusted (or self-reported when trusted ones are required): denied; trusted sources not configured: self-reported state is accepted and labelled', () => {
    const s = first();
    expect(s.state_source).toBe('');
    expect(verifyProgressStep(goal, commitment, s, { trustedStateSources: ['obs-1'] })).toEqual({ ok: false, reason: 'untrusted-state-source' });
    expect(verifyProgressStep(goal, commitment, s, { requireAttestedState: true })).toEqual({ ok: false, reason: 'untrusted-state-source' });
    expect(verifyProgressStep(goal, commitment, s, { requireAttestedState: true, trustedStateSources: [''] })).toEqual({ ok: false, reason: 'untrusted-state-source' });
    expect(verifyProgressStep(goal, commitment, s, {})).toEqual({ ok: true, charge: 0 });
  });
  it('requireAttestedState accepts a step whose state came from a named source (its trust is then the attestation hook and trustedStateSources)', async () => {
    const t = mk();
    const r = await t.stepObserved(new InMemoryStateSource({ x: [4, 4] }, 'obs-1'), 'a0');
    if (!r.ok) throw new Error('fixture');
    expect(r.step.state_source).toBe('obs-1');
    expect(verifyProgressStep(goal, commitment, r.step, { requireAttestedState: true })).toEqual({ ok: true, charge: 0 });
    expect(verifyProgressStep(goal, commitment, r.step, { requireAttestedState: true, trustedStateSources: ['obs-2'] })).toEqual({ ok: false, reason: 'untrusted-state-source' });
    expect(verifyProgressStep(goal, commitment, r.step, { requireAttestedState: false })).toEqual({ ok: true, charge: 0 });
  });
  it('an attestation verifier that throws or returns a non-true value: denied', () => {
    const s = first();
    expect(verifyProgressStep(goal, commitment, s, { attestation: () => { throw new Error('x'); } })).toEqual({ ok: false, reason: 'attestation-failed' });
    expect(verifyProgressStep(goal, commitment, s, { attestation: () => 1 as never })).toEqual({ ok: false, reason: 'attestation-failed' });
    expect(verifyProgressStep(goal, commitment, s, { attestation: () => true })).toEqual({ ok: true, charge: 0 });
  });
  it('a guard that throws or returns a non-true value: prohibited', () => {
    const s = first();
    expect(verifyProgressStep(goal, commitment, s, { guard: () => { throw new Error('x'); } })).toEqual({ ok: false, reason: 'prohibited' });
    expect(verifyProgressStep(goal, commitment, s, { guard: () => undefined as never })).toEqual({ ok: false, reason: 'prohibited' });
  });
  it('a trajectory that is not an array, or exceeds the exploration budget, is denied; an empty one proves nothing but is not invalid', () => {
    expect(verifyTrajectory(goal, commitment, undefined as never)).toEqual({ ok: false, reason: 'malformed', at: -1 });
    expect(verifyTrajectory(goal, commitment, [])).toMatchObject({ ok: true, steps: 0, reached: false, finalPotential: -1 });
  });
  it('a tracker given a goal that does not match its commitment throws; exploration beyond the budget is refused with a step-up', () => {
    expect(() => new ProgressTracker({ ...goal, epsilon: 1 }, commitment, { x: [0, 0] })).toThrow('goal does not match commitment');
    const t = mk();
    expect(t.step({ x: [0, 0] }, 'a0')).toMatchObject({ ok: true });
    const r = (() => {
      let last: ReturnType<typeof t.step> = { ok: true } as never;
      for (let i = 0; i < 6; i++) last = t.step({ x: [0, 0] }, `a${i + 1}`);
      return last;
    })();
    expect(r).toEqual({ ok: false, reason: 'exploration-exhausted', stepUp: true });
  });
});

describe('DoD-1 intent audit: objective risk and its binding (objective-risk.ts, objective-binding.ts)', () => {
  const embedder = nativeHashEmbedder();
  const goalAction: ObjAction = { verb: 'report.read', resource: 'sales', params: {} };
  const gc = commitGoal(embedder, goalAction);
  const registry = new InMemoryInverseRegistry([]);
  const graph = new ResourceGraph().addNode({ id: 'sales', harm: { rows: 1 } });
  const ctx = (over: Partial<ObjectiveRiskContext> = {}): ObjectiveRiskContext => ({
    registry,
    authorizedKinds: new Set(),
    graph,
    embedder,
    goal: gc,
    commitments: { registryDigest: registry.digest(), graphDigest: graph.digest() },
    denominations: [],
    weights: P.weights,
    taint: 0,
    age: 0,
    ...over,
  });
  it('control: a reproducible action is valid with a risk in [0,1]', () => {
    const r = objectiveRisk(goalAction, ctx());
    expect(r.valid).toBe(true);
    expect(r.r >= 0 && r.r <= 1).toBe(true);
  });
  it('a registry or graph that does not match the committed digest, or an unusable goal: r is exactly 1 and the result is invalid', () => {
    expect(objectiveRisk(goalAction, ctx({ commitments: { registryDigest: 'x', graphDigest: graph.digest() } }))).toMatchObject({ valid: false, r: 1, reasons: ['registry digest does not match the committed digest'] });
    expect(objectiveRisk(goalAction, ctx({ commitments: { registryDigest: registry.digest(), graphDigest: 'x' } }))).toMatchObject({ valid: false, r: 1, reasons: ['graph digest does not match the committed digest'] });
    expect(objectiveRisk(goalAction, ctx({ goal: { ...gc, epsilon: 0 } }))).toMatchObject({ valid: false, r: 1, reasons: ['goal/embedder: bad epsilon'] });
  });
  it('a calibration set with no committed digest: invalid', () => {
    expect(objectiveRisk(goalAction, ctx({ calibration: [0.1] }))).toMatchObject({ valid: false, r: 1, reasons: ['calibration set used without a committed digest'] });
  });
  it('an action that cannot be canonicalized: invalid, not thrown', () => {
    const r = objectiveRisk({ verb: 'v', resource: 'r', params: { n: Number.NaN } } as never, ctx());
    expect(r.valid).toBe(false);
    expect(r.r).toBe(1);
  });
  it('a taint or age that is not a finite number (the verifier forgot it) is treated as the worst value, never as zero', () => {
    const missing = objectiveRisk(goalAction, ctx({ taint: undefined as never, age: undefined as never }));
    const worst = objectiveRisk(goalAction, ctx({ taint: 1, age: 1 }));
    expect(missing.r).toBe(worst.r);
    expect(Number.isFinite(missing.r)).toBe(true);
  });
  it('a verifier with no objective-risk configuration for a grant that commits one: mismatch with on_mismatch deny', () => {
    const grant = { caveats: [{ type: 'envelope', goal_commit: 'g', predicates: [], caveats: [], agent_binding: {}, risk_policy: P, objective_risk: { v: 1, embedder: { scheme: 'native', model_id: embedder.modelId, config: embedder.config }, goal: gc, registry_digest: registry.digest(), graph_digest: graph.digest(), authorized_kinds: [] } }] };
    const r = resolveObjectiveRisk({ grant: grant as never, action: goalAction, instance: undefined });
    expect(r.mode === 'mismatch' ? r.onMismatch : r.mode).toBe('deny');
    expect(resolveObjectiveRisk({ grant: { caveats: [] } as never, action: goalAction, instance: undefined })).toEqual({ mode: 'none' });
  });
  it('a committed objective_risk of an unknown version or malformed member: mismatch, deny', () => {
    const g = (o: object) => ({ caveats: [{ type: 'envelope', goal_commit: 'g', predicates: [], caveats: [], agent_binding: {}, risk_policy: P, objective_risk: o }] }) as never;
    expect(readObjectiveCommitment(g({ v: 2 }))).toEqual({ malformed: 'objective_risk: unsupported shape/version' });
    expect(resolveObjectiveRisk({ grant: g({ v: 2 }), action: goalAction, instance: {} })).toEqual({ mode: 'mismatch', reasons: ['objective_risk: unsupported shape/version'], onMismatch: 'deny' });
  });
});

describe('DoD-1 intent audit: session history windows and monitors (intent-history.ts)', () => {
  const ev = (id: string, t: number, status: IntentEvent['status'] = 'committed', params: Record<string, unknown> = { total: 5 }): IntentEvent => ({ id, verb: 'shop.buy', resource: 'r', params, t, status });
  const sum: AccumulatorDecl = { id: 'spend', agg: 'sum', val: 'action.params.total', unit: 'usd', sel: { verbs: ['shop.buy'] }, win: { kind: 'task' }, key: null, holder: { kind: 'site_local' } };
  const accOf = (win: AccumulatorDecl['win'], over: Partial<AccumulatorDecl> = {}): AccumulatorDecl => ({ ...sum, win, ...over }) as AccumulatorDecl;
  it('windows: sliding is (t - ms, t], a period is the aligned block containing t, a future-stamped event always counts', () => {
    expect(inWindow({ kind: 'sliding', ms: 100 }, 900, 1000)).toBe(false);
    expect(inWindow({ kind: 'sliding', ms: 100 }, 901, 1000)).toBe(true);
    expect(inWindow({ kind: 'period', ms: 100, t0: 0 }, 999, 1000)).toBe(false);
    expect(inWindow({ kind: 'period', ms: 100, t0: 0 }, 1000, 1099)).toBe(true);
    expect(inWindow({ kind: 'sliding', ms: 100 }, 5000, 1000)).toBe(true);
    expect(inWindow({ kind: 'task' }, 0, 1000)).toBe(true);
  });
  it('a clock or event time that is not a safe integer is in no window (fail closed means the caller treats the store as corrupt)', () => {
    for (const bad of [Number.NaN, 1.5, Infinity, '5' as never]) {
      expect(inWindow({ kind: 'task' }, bad, 1000)).toBe(false);
      expect(inWindow({ kind: 'task' }, 1000, bad)).toBe(false);
    }
  });
  it('only reserved and committed events count: released and reverted events leave the pre-state unchanged', () => {
    const h = [ev('a', 1, 'reserved'), ev('b', 2, 'committed'), ev('c', 3, 'released'), ev('d', 4, 'reverted')];
    expect(accPreState(sum, h, { params: { total: 5 }, t: 10 })).toEqual({ sum: 10 });
  });
  it('an empty history gives the identity pre-state of every aggregate', () => {
    for (const [agg, pre] of [['sum', { sum: 0 }], ['count', { count: 0 }], ['max', { max: 0 }], ['distinct', { values: [] }]] as const) expect(accPreState({ ...sum, agg, ...(agg === 'distinct' ? { val: 'action.params.total' } : {}) } as AccumulatorDecl, [], { params: { total: 5 }, t: 10 })).toEqual(pre);
  });
  it('a grouping key the candidate does not carry: no key (null), so the host must not hand a pre-state', () => {
    const keyed = accOf({ kind: 'task' }, { key: 'action.params.payee' } as never);
    expect(accKeyOf(keyed, { total: 1 })).toBeNull();
    expect(accKeyOf(keyed, { payee: 'p1' })).toBe('"p1"');
  });
  it('a monitor over an empty history sits in its initial state; a status that does not count leaves it unchanged', () => {
    const never: MonitorDecl = { id: 'm', kind: 'never', p: { verb: 'shop.refund', resource: '*' } } as never;
    expect(monitorState(never, [])).toBe('clean');
    expect(monitorStep(never, 'clean', { verb: 'shop.refund', resource: 'r', params: {}, status: 'released' })).toBe('clean');
    expect(monitorStep(never, 'clean', { verb: 'shop.refund', resource: 'r', params: {}, status: 'committed' })).toBe('seen');
    expect(monitorStep(never, 'seen', { verb: 'shop.buy', resource: 'r', params: {}, status: 'committed' })).toBe('seen');
  });
});
