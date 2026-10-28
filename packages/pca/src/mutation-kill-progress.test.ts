/**
 * Mutation-kill tests for progress.ts: registry + built-in potentials (exact error messages), goal validation,
 * step classification boundaries, tracker semantics, attested state sources, every verifyProgressStep denial in order,
 * trajectory + signed-trajectory verdicts (reason, index, fields).
 */
import { describe, expect, it } from 'vitest';
import { b64u, canonicalBytes, hashCanonical, utf8 } from './hash';
import { generateKeyPair, sign, verifyB64u } from './keys';
import { mlDsa65Keygen } from './pq';
import { AttestedStateSource, DEFAULT_POTENTIALS, InMemoryStateSource, PROGRESS_SIG_DOMAIN, PROGRESS_VERSION, PotentialRegistry, ProgressTracker, STATE_ATTESTATION_DOMAIN, TRAJECTORY_ANCHOR_DOMAIN, anchorTrajectoryHead, attestedStateVerifier, commitGoal, dagRemainingPotential, dagWeightedPotential, goalDigest, l1FeaturePotential, progressStepDigest, signProgressStep, stateDigest, trajectoryAnchorCommit, trajectoryHead, verifyGoalCommitment, verifyStateAttestation, verifyTrajectoryAnchor, type Goal, type ProgressStep, type StateAttestation, type VerifySignedStepOptions, type VerifyStepResult } from './progress';
import { verifyProgressStep, verifySignedProgressStep, verifySignedTrajectory, verifyTrajectory } from './test-support/progress-selfreported';

const GOAL: Goal = { objective: { target: [10] }, potential: 'l1-feature-v1', metric: 'dist', epsilon: 2, explorationBudget: 5 };
const C = commitGoal(GOAL).commitment;
const MAXI = Number.MAX_SAFE_INTEGER;
const body = (s: ProgressStep) => {
  const { digest: _d, ...b } = s;
  void _d;
  return b;
};
const redigest = (s: ProgressStep, over: Record<string, unknown> = {}): ProgressStep => {
  const b = { ...body(s), ...over };
  return { ...b, digest: hashCanonical({ t: 'pca-progress-step', v: 2, ...b }) } as ProgressStep;
};
/** Re-chain + re-commit a list of steps (so a test can verify them against a different goal commitment). */
const relink = (steps: readonly ProgressStep[], commitment: string): ProgressStep[] => {
  const out: ProgressStep[] = [];
  let prev = 'genesis';
  for (const s of steps) {
    const n = redigest(s, { goal_commitment: commitment, prev });
    out.push(n);
    prev = n.digest;
  }
  return out;
};
/** progress(0->3) , exploration(3->4, charge 1), progress(4->10 reaches goal) */
function run3(goal: Goal = GOAL) {
  const c = commitGoal(goal).commitment;
  const t = new ProgressTracker(goal, c, { x: [0] });
  const ads = ['a0', 'a1', 'a2'];
  const rs = [t.step({ x: [3] }, ads[0]!), t.step({ x: [4] }, ads[1]!), t.step({ x: [10] }, ads[2]!)];
  for (const r of rs) expect(r.ok).toBe(true);
  return { t, c, ads, steps: t.steps as ProgressStep[] };
}

/** The denial reason of a step verdict, or 'OK' (so an unexpected accept fails the reason assertion). */
const reasonOf = (r: VerifyStepResult): string => (r.ok ? 'OK' : r.reason);

describe('PotentialRegistry', () => {
  it('register validations with exact messages', () => {
    const r = new PotentialRegistry();
    const f = () => 0;
    expect(() => r.register('', f)).toThrow('potential id: 1..128 chars');
    expect(() => r.register(5 as never, f)).toThrow('potential id: 1..128 chars');
    expect(() => r.register('x'.repeat(129), f)).toThrow('potential id: 1..128 chars');
    expect(r.register('x'.repeat(128), f)).toBe(r);
    expect(() => r.register('a', 5 as never)).toThrow('potential must be a function');
    expect(() => r.register('a', f, 5 as never)).toThrow('embedder must be a string');
    expect(r.has('a')).toBe(false);
    r.register('a', f);
    expect(() => r.register('a', f)).toThrow('potential a already registered');
    expect(r.has('a')).toBe(true);
    expect(r.has('b')).toBe(false);
    expect(r.get('a')).toEqual({ fn: f, embedder: '' });
    expect(r.get('constructor')).toBeUndefined();
    expect(r.get('__proto__')).toBeUndefined();
    expect(r.has('constructor')).toBe(false);
    expect(r.freeze()).toBe(r);
    expect(() => r.register('zz', f)).toThrow('registry is frozen');
  });
  it('ids sorted; from() accepts functions and specs; defaults()', () => {
    const f = () => 0;
    const g = () => 1;
    const r = PotentialRegistry.from({ zeta: f, alpha: { fn: g }, mid: { fn: f, embedder: 'e1' } });
    expect(r.ids()).toEqual(['alpha', 'mid', 'zeta']);
    expect(r.get('zeta')).toEqual({ fn: f, embedder: '' });
    expect(r.get('alpha')).toEqual({ fn: g, embedder: '' });
    expect(r.get('mid')).toEqual({ fn: f, embedder: 'e1' });
    expect(PotentialRegistry.defaults().ids()).toEqual(['dag-remaining-v1', 'dag-weighted-v1', 'l1-feature-v1']);
    expect(PotentialRegistry.defaults().get('l1-feature-v1')!.fn).toBe(l1FeaturePotential);
    expect(PotentialRegistry.defaults().get('dag-remaining-v1')!.fn).toBe(dagRemainingPotential);
    expect(PotentialRegistry.defaults().get('dag-weighted-v1')!.fn).toBe(dagWeightedPotential);
    expect(() => DEFAULT_POTENTIALS.register('q', f)).toThrow('registry is frozen');
    expect(PotentialRegistry.defaults().register('q', f).has('q')).toBe(true);
  });
});

describe('l1FeaturePotential', () => {
  it('value + shape errors with messages', () => {
    expect(l1FeaturePotential({ target: [10, 0] }, { x: [7, 4] })).toBe(7);
    expect(l1FeaturePotential({ target: [] }, { x: [] })).toBe(0);
    const bad = 'l1-feature-v1: bad shape';
    expect(() => l1FeaturePotential(null, { x: [] })).toThrow(bad);
    expect(() => l1FeaturePotential(undefined, { x: [] })).toThrow(bad);
    expect(() => l1FeaturePotential({ target: [] }, null)).toThrow(bad);
    expect(() => l1FeaturePotential({ target: [] }, undefined)).toThrow(bad);
    expect(() => l1FeaturePotential({ target: {} }, { x: [] })).toThrow(bad);
    expect(() => l1FeaturePotential({ target: [] }, { x: {} })).toThrow(bad);
    expect(() => l1FeaturePotential({ target: { length: 1 } }, { x: [1] })).toThrow(bad);
    expect(() => l1FeaturePotential({ target: [1] }, { x: { length: 1 } })).toThrow(bad);
    expect(() => l1FeaturePotential({ target: [1] }, { x: [1, 2] })).toThrow(bad);
    expect(() => l1FeaturePotential({ target: [1, 2] }, { x: [1] })).toThrow(bad);
    expect(() => l1FeaturePotential({ target: [1.5] }, { x: [1] })).toThrow('target: safe integer required');
    expect(() => l1FeaturePotential({ target: ['1'] }, { x: [1] })).toThrow('target: safe integer required');
    expect(() => l1FeaturePotential({ target: [1] }, { x: [0.5] })).toThrow('x: safe integer required');
    expect(() => l1FeaturePotential({ target: [MAXI] }, { x: [-MAXI] })).toThrow('distance: safe integer required');
  });
});

describe('dagRemainingPotential', () => {
  const T = [
    { id: 'a', cost: 3 },
    { id: 'b', cost: 4 },
  ];
  it('value + error messages', () => {
    expect(dagRemainingPotential({ tasks: T }, { done: [] })).toBe(7);
    expect(dagRemainingPotential({ tasks: T }, { done: ['a'] })).toBe(4);
    expect(dagRemainingPotential({ tasks: T }, { done: ['a', 'a', 'b'] })).toBe(0);
    expect(dagRemainingPotential({ tasks: [{ id: 'z', cost: 0 }] }, { done: [] })).toBe(0);
    const bad = 'dag-remaining-v1: bad shape';
    expect(() => dagRemainingPotential(null, { done: [] })).toThrow(bad);
    expect(() => dagRemainingPotential({ tasks: T }, null)).toThrow(bad);
    expect(() => dagRemainingPotential({ tasks: {} }, { done: [] })).toThrow(bad);
    expect(() => dagRemainingPotential({ tasks: T }, { done: {} })).toThrow(bad);
    expect(() => dagRemainingPotential({ tasks: { length: 2 } }, { done: [] })).toThrow(bad);
    expect(() => dagRemainingPotential({ tasks: [] }, { done: { length: 0 } })).toThrow(bad);
    expect(() => dagRemainingPotential({ tasks: [...T, { id: 'a', cost: 1 }] }, { done: [] })).toThrow('dag-remaining-v1: duplicate task id');
    expect(() => dagRemainingPotential({ tasks: T }, { done: ['zz'] })).toThrow('dag-remaining-v1: unknown task zz');
    expect(() => dagRemainingPotential({ tasks: [{ id: 'a', cost: 1.5 }] }, { done: [] })).toThrow('cost: safe integer required');
    expect(() => dagRemainingPotential({ tasks: [{ id: 'a', cost: -1 }] }, { done: [] })).toThrow('negative cost');
    expect(() => dagRemainingPotential({ tasks: [{ id: 'a', cost: MAXI }, { id: 'b', cost: 1 }] }, { done: [] })).toThrow('remaining: safe integer required');
  });
});

describe('dagWeightedPotential', () => {
  const T = [
    { id: 'a', cost: 1 },
    { id: 'b', cost: 2, deps: ['a'] },
    { id: 'c', cost: 4, deps: ['a'] },
    { id: 'd', cost: 8, deps: ['b', 'c', 'b'] },
  ];
  it('values (diamond DAG)', () => {
    expect(dagWeightedPotential({ tasks: T }, { done: [] })).toBe(15);
    expect(dagWeightedPotential({ tasks: T }, { done: ['a'] })).toBe(14);
    expect(dagWeightedPotential({ tasks: T }, { done: ['a', 'c'] })).toBe(10);
    expect(dagWeightedPotential({ tasks: T }, { done: ['a', 'b', 'c', 'd'] })).toBe(0);
    expect(dagWeightedPotential({ tasks: [{ id: 'z', cost: 0 }] }, { done: [] })).toBe(0);
  });
  it('error messages', () => {
    const bad = 'dag-weighted-v1: bad shape';
    expect(() => dagWeightedPotential(null, { done: [] })).toThrow(bad);
    expect(() => dagWeightedPotential({ tasks: T }, null)).toThrow(bad);
    expect(() => dagWeightedPotential({ tasks: {} }, { done: [] })).toThrow(bad);
    expect(() => dagWeightedPotential({ tasks: [] }, { done: {} })).toThrow(bad);
    expect(() => dagWeightedPotential({ tasks: { length: 0 } }, { done: [] })).toThrow(bad);
    expect(() => dagWeightedPotential({ tasks: [] }, { done: { length: 0 } })).toThrow(bad);
    const task = 'dag-weighted-v1: bad task';
    expect(() => dagWeightedPotential({ tasks: [null] }, { done: [] })).toThrow(task);
    expect(() => dagWeightedPotential({ tasks: [[]] }, { done: [] })).toThrow(task);
    expect(() => dagWeightedPotential({ tasks: [{ id: 5, cost: 1 }] }, { done: [] })).toThrow(task);
    expect(() => dagWeightedPotential({ tasks: [{ cost: 1 }] }, { done: [] })).toThrow(task);
    expect(() => dagWeightedPotential({ tasks: [{ id: '', cost: 1 }] }, { done: [] })).toThrow(task);
    expect(() => dagWeightedPotential({ tasks: [{ id: 'a', cost: 1 }, { id: 'a', cost: 1 }] }, { done: [] })).toThrow('dag-weighted-v1: duplicate task id');
    expect(() => dagWeightedPotential({ tasks: [{ id: 'a', cost: 0.5 }] }, { done: [] })).toThrow('cost: safe integer required');
    expect(() => dagWeightedPotential({ tasks: [{ id: 'a', cost: -1 }] }, { done: [] })).toThrow('negative cost');
    const deps = 'dag-weighted-v1: bad deps';
    expect(() => dagWeightedPotential({ tasks: [{ id: 'a', cost: 1, deps: 'b' }] }, { done: [] })).toThrow(deps);
    expect(() => dagWeightedPotential({ tasks: [{ id: 'a', cost: 1, deps: [1] }] }, { done: [] })).toThrow(deps);
    expect(() => dagWeightedPotential({ tasks: [{ id: 'a', cost: 1, deps: ['a'] }] }, { done: [] })).toThrow('dag-weighted-v1: bad dependency a');
    expect(() => dagWeightedPotential({ tasks: [{ id: 'a', cost: 1, deps: ['q'] }] }, { done: [] })).toThrow('dag-weighted-v1: bad dependency q');
    expect(() =>
      dagWeightedPotential({ tasks: [{ id: 'a', cost: 1, deps: ['b'] }, { id: 'b', cost: 1, deps: ['a'] }] }, { done: [] }),
    ).toThrow('dag-weighted-v1: cycle');
    expect(() => dagWeightedPotential({ tasks: T }, { done: ['zz'] })).toThrow('dag-weighted-v1: unknown task zz');
    expect(() => dagWeightedPotential({ tasks: T }, { done: [5] })).toThrow('dag-weighted-v1: unknown task 5');
    expect(() => dagWeightedPotential({ tasks: T }, { done: ['a', 'a'] })).toThrow('dag-weighted-v1: duplicate done');
    expect(() => dagWeightedPotential({ tasks: T }, { done: ['b'] })).toThrow('dag-weighted-v1: b done before dependency a');
    expect(() => dagWeightedPotential({ tasks: [{ id: 'a', cost: MAXI }, { id: 'b', cost: 1 }] }, { done: [] })).toThrow('remaining: safe integer required');
  });
});

describe('goal validation / commitment', () => {
  it('constants + digest layout', () => {
    expect(PROGRESS_VERSION).toBe(2);
    expect(PROGRESS_SIG_DOMAIN).toBe('atlas-pca/progress-step/v2');
    expect(goalDigest(GOAL)).toBe(
      hashCanonical({ t: 'pca-goal', v: 2, objective: GOAL.objective, potential: 'l1-feature-v1', embedder: '', metric: 'dist', epsilon: 2, explorationBudget: 5 }),
    );
    expect(goalDigest({ ...GOAL, embedder: 'e' })).not.toBe(goalDigest(GOAL));
    expect(goalDigest({ ...GOAL, metric: 'm2' })).not.toBe(goalDigest(GOAL));
    expect(goalDigest({ ...GOAL, epsilon: 3 })).not.toBe(goalDigest(GOAL));
    expect(goalDigest({ ...GOAL, explorationBudget: 6 })).not.toBe(goalDigest(GOAL));
    expect(goalDigest({ ...GOAL, potential: 'p2' })).not.toBe(goalDigest(GOAL));
    expect(goalDigest({ ...GOAL, objective: { target: [11] } })).not.toBe(goalDigest(GOAL));
  });
  it('validateGoal messages and order', () => {
    expect(() => goalDigest(null as never)).toThrow('goal must be an object');
    expect(() => goalDigest([] as never)).toThrow('goal must be an object');
    expect(() => goalDigest('x' as never)).toThrow('goal must be an object');
    expect(() => goalDigest({ ...GOAL, epsilon: 1.5 })).toThrow('epsilon: safe integer required');
    expect(() => goalDigest({ ...GOAL, explorationBudget: 0.5 })).toThrow('explorationBudget: safe integer required');
    expect(() => goalDigest({ ...GOAL, epsilon: 0, explorationBudget: 0.5 })).toThrow('explorationBudget: safe integer required');
    expect(() => goalDigest({ ...GOAL, epsilon: 0 })).toThrow(new RangeError('epsilon must be >= 1'));
    expect(() => goalDigest({ ...GOAL, epsilon: -3 })).toThrow('epsilon must be >= 1');
    expect(() => goalDigest({ ...GOAL, explorationBudget: -1 })).toThrow(new RangeError('explorationBudget must be >= 0'));
    expect(() => goalDigest({ ...GOAL, epsilon: 0, explorationBudget: -1 })).toThrow('epsilon must be >= 1');
    expect(() => goalDigest({ ...GOAL, potential: '' })).toThrow('potential id required');
    expect(() => goalDigest({ ...GOAL, potential: 5 as never })).toThrow('potential id required');
    expect(() => goalDigest({ ...GOAL, metric: 5 as never })).toThrow('metric must be a string');
    expect(() => goalDigest({ ...GOAL, embedder: 5 as never })).toThrow('embedder must be a string');
    expect(() => goalDigest({ ...GOAL, epsilon: 1, explorationBudget: 0, metric: '' })).not.toThrow();
    expect(() => goalDigest({ ...GOAL, embedder: '' })).not.toThrow();
  });
  it('commitGoal detaches; verifyGoalCommitment never throws', () => {
    const g: Goal = { ...GOAL, objective: { target: [10] } };
    const cg = commitGoal(g);
    expect(cg.commitment).toBe(goalDigest(g));
    (g.objective as { target: number[] }).target[0] = 99;
    expect(cg.goal.objective).toEqual({ target: [10] });
    expect(verifyGoalCommitment(GOAL, C)).toBe(true);
    expect(verifyGoalCommitment(GOAL, C + 'x')).toBe(false);
    expect(verifyGoalCommitment({ ...GOAL, epsilon: 0 }, C)).toBe(false);
    expect(verifyGoalCommitment(null as never, C)).toBe(false);
  });
});

describe('digests / head / anchors', () => {
  it('stateDigest + head + progressStepDigest', () => {
    expect(stateDigest({ x: [1] })).toBe(hashCanonical({ t: 'pca-state', state: { x: [1] } }));
    expect(trajectoryHead([])).toBe('genesis');
    const { steps } = run3();
    expect(trajectoryHead(steps)).toBe(steps[2]!.digest);
    expect(trajectoryHead(steps.slice(0, 1))).toBe(steps[0]!.digest);
    expect(progressStepDigest(steps[1]!)).toBe(steps[1]!.digest);
    expect(steps[0]!.digest).toBe(hashCanonical({ t: 'pca-progress-step', v: 2, ...body(steps[0]!) }));
  });
  it('anchor commit layout, validation, verification', () => {
    expect(TRAJECTORY_ANCHOR_DOMAIN).toBe('atlas-pca/trajectory-anchor/v1');
    expect(trajectoryAnchorCommit('s', 'h')).toBe(hashCanonical({ t: TRAJECTORY_ANCHOR_DOMAIN, salt: 's', head: 'h' }));
    const msg = 'trajectoryAnchorCommit: salt and head must be non-empty strings';
    expect(() => trajectoryAnchorCommit('', 'h')).toThrow(msg);
    expect(() => trajectoryAnchorCommit('s', '')).toThrow(msg);
    expect(() => trajectoryAnchorCommit(5 as never, 'h')).toThrow(msg);
    expect(() => trajectoryAnchorCommit('s', 5 as never)).toThrow(msg);
    const c = trajectoryAnchorCommit('s', 'h');
    expect(verifyTrajectoryAnchor(c, 's', 'h')).toBe(true);
    expect(verifyTrajectoryAnchor(c, 's2', 'h')).toBe(false);
    expect(verifyTrajectoryAnchor(c, 's', 'h2')).toBe(false);
    expect(verifyTrajectoryAnchor(c, '', 'h')).toBe(false);
    expect(verifyTrajectoryAnchor(c, 's', 5 as never)).toBe(false);
  });
  it('anchorTrajectoryHead', () => {
    const calls: string[] = [];
    const lh = { size: 4, root: 'r' };
    const ledger = {
      appendCommitment: (c: string) => (calls.push(c), { index: 3, commit: c }),
      head: () => lh,
    } as never;
    const { steps } = run3();
    const a = anchorTrajectoryHead(ledger, steps, { salt: 'SALT' });
    expect(a).toEqual({ head: steps[2]!.digest, salt: 'SALT', commit: trajectoryAnchorCommit('SALT', steps[2]!.digest), index: 3, ledgerHead: lh });
    expect(calls).toEqual([a.commit]);
    const e = anchorTrajectoryHead(ledger, [], { salt: 'S' });
    expect(e.head).toBe('genesis');
    const r1 = anchorTrajectoryHead(ledger, steps);
    const r2 = anchorTrajectoryHead(ledger, steps);
    expect(r1.salt).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(r1.salt).not.toBe(r2.salt);
    expect(r1.commit).toBe(trajectoryAnchorCommit(r1.salt, r1.head));
    expect(anchorTrajectoryHead(ledger, steps, {}).salt).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(() => anchorTrajectoryHead(ledger, steps, { salt: '' })).toThrow('salt and head must be non-empty strings');
  });
});

describe('ProgressTracker', () => {
  it('constructor checks', () => {
    expect(() => new ProgressTracker(GOAL, 'bogus', { x: [0] })).toThrow('goal does not match commitment');
    expect(() => new ProgressTracker(GOAL, C, { x: 'bad' })).toThrow('l1-feature-v1: bad shape');
    expect(() => new ProgressTracker({ ...GOAL, potential: 'nope' }, goalDigest({ ...GOAL, potential: 'nope' }), { x: [0] })).toThrow('unknown potential nope');
    const g2 = { ...GOAL, embedder: 'e9' };
    expect(() => new ProgressTracker(g2, goalDigest(g2), { x: [0] })).toThrow('embedder mismatch');
    // plain-record registry accepted
    const g3: Goal = { objective: null, potential: 'p', metric: '', epsilon: 1, explorationBudget: 0 };
    const t = new ProgressTracker(g3, goalDigest(g3), { v: 4 }, { p: (_o, s) => (s as { v: number }).v });
    expect(t.state).toEqual({ v: 4 });
    // negative / non-integer potentials
    expect(() => new ProgressTracker(g3, goalDigest(g3), { v: -1 }, { p: (_o, s) => (s as { v: number }).v })).toThrow('potential must be >= 0');
    expect(() => new ProgressTracker(g3, goalDigest(g3), { v: 1.5 }, { p: (_o, s) => (s as { v: number }).v })).toThrow('potential: safe integer required');
    // registry instance used as-is
    const reg = PotentialRegistry.from({ p: (_o, s) => (s as { v: number }).v });
    expect(new ProgressTracker(g3, goalDigest(g3), { v: 2 }, reg).state).toEqual({ v: 2 });
  });
  it('getters', () => {
    const c = commitGoal(GOAL);
    const init = { x: [0] };
    const t = new ProgressTracker(GOAL, c.commitment, init);
    expect(t.commitment).toBe(c.commitment);
    expect(t.goal).toEqual(GOAL);
    expect(t.goal).not.toBe(GOAL);
    expect(t.state).toEqual({ x: [0] });
    init.x[0] = 5;
    expect(t.state).toEqual({ x: [0] });
    expect(t.currentStateDigest).toBe(stateDigest({ x: [0] }));
    expect(t.spent).toBe(0);
    expect(t.remaining).toBe(5);
    expect(t.reached).toBe(false);
    expect(t.steps).toEqual([]);
    const r = t.step({ x: [3] }, 'a0');
    expect(r.ok && r.step.seq).toBe(0);
    expect(t.state).toEqual({ x: [3] });
    expect(t.currentStateDigest).toBe(stateDigest({ x: [3] }));
    const s1 = t.steps;
    expect(s1.length).toBe(1);
    (s1 as ProgressStep[]).pop();
    expect(t.steps.length).toBe(1);
    expect(new ProgressTracker(GOAL, C, { x: [10] }).reached).toBe(true);
  });
  it('step bodies, chaining and classification', () => {
    const { steps, c } = run3();
    const s0 = steps[0]!;
    expect(body(s0)).toEqual({
      goal_commitment: c,
      seq: 0,
      before: { x: [0] },
      after: { x: [3] },
      before_digest: stateDigest({ x: [0] }),
      after_digest: stateDigest({ x: [3] }),
      action_digest: 'a0',
      mode: 'progress',
      potential_before: 10,
      potential_after: 7,
      charge: 0,
      state_source: '',
      evidence_digest: '',
      prev: 'genesis',
    });
    expect(steps.map((s) => s.seq)).toEqual([0, 1, 2]);
    expect(steps[1]!.prev).toBe(s0.digest);
    expect(steps[2]!.prev).toBe(steps[1]!.digest);
    expect(steps[1]).toMatchObject({ mode: 'exploration', charge: 1, potential_before: 7, potential_after: 6 });
    expect(steps[2]).toMatchObject({ mode: 'progress', charge: 0, potential_before: 6, potential_after: 0 });
    expect(steps[1]!.before_digest).toBe(s0.after_digest);
  });
  it('classification boundaries', () => {
    const cl = (pb: number, pa: number, eps = 2, budget = 100) => {
      const g: Goal = { objective: null, potential: 'p', metric: '', epsilon: eps, explorationBudget: budget };
      const t = new ProgressTracker(g, goalDigest(g), { v: pb }, { p: (_o, s) => (s as { v: number }).v });
      const r = t.step({ v: pa }, 'a');
      return r.ok ? { mode: r.step.mode, charge: r.step.charge } : r;
    };
    expect(cl(10, 8)).toEqual({ mode: 'progress', charge: 0 }); // pa == pb - eps
    expect(cl(10, 9)).toEqual({ mode: 'exploration', charge: 1 }); // one short
    expect(cl(10, 10)).toEqual({ mode: 'exploration', charge: 2 });
    expect(cl(10, 12)).toEqual({ mode: 'exploration', charge: 4 });
    expect(cl(1, 0)).toEqual({ mode: 'progress', charge: 0 }); // reaching goal from closer than epsilon
    expect(cl(0, 0)).toEqual({ mode: 'exploration', charge: 2 }); // already at goal: no free pass
    expect(cl(3, 0, 5)).toEqual({ mode: 'progress', charge: 0 });
    expect(cl(1, 1)).toEqual({ mode: 'exploration', charge: 2 });
    // unsafe charge => bad-potential (not a thrown error)
    const g: Goal = { objective: null, potential: 'p', metric: '', epsilon: MAXI, explorationBudget: 0 };
    const t = new ProgressTracker(g, goalDigest(g), { v: 0 }, { p: (_o, s) => (s as { v: number }).v });
    expect(t.step({ v: 5 }, 'a')).toEqual({ ok: false, reason: 'bad-potential', stepUp: false });
  });
  it('budget: spending exactly the budget is allowed; exceeding is refused with stepUp and no advance', () => {
    const g: Goal = { objective: { target: [10] }, potential: 'l1-feature-v1', metric: '', epsilon: 2, explorationBudget: 2 };
    const t = new ProgressTracker(g, goalDigest(g), { x: [0] });
    const r1 = t.step({ x: [0] }, 'a'); // charge 2
    expect(r1.ok).toBe(true);
    if (r1.ok) {
      expect(r1.spent).toBe(2);
      expect(r1.remaining).toBe(0);
    }
    expect(t.spent).toBe(2);
    expect(t.remaining).toBe(0);
    const before = t.currentStateDigest;
    expect(t.step({ x: [0] }, 'b')).toEqual({ ok: false, reason: 'exploration-exhausted', stepUp: true });
    expect(t.currentStateDigest).toBe(before);
    expect(t.steps.length).toBe(1);
    expect(t.spent).toBe(2);
    // progress steps still fine at zero remaining
    const r3 = t.step({ x: [5] }, 'c');
    expect(r3.ok).toBe(true);
    if (r3.ok) expect(r3.step.seq).toBe(1);
  });
  it('malformed action digest / bad states', () => {
    const t = new ProgressTracker(GOAL, C, { x: [0] });
    expect(t.step({ x: [3] }, '')).toEqual({ ok: false, reason: 'malformed', stepUp: false });
    expect(t.step({ x: [3] }, 5 as never)).toEqual({ ok: false, reason: 'malformed', stepUp: false });
    expect(t.step({ x: 'bad' }, 'a')).toEqual({ ok: false, reason: 'bad-potential', stepUp: false });
    expect(t.step({ x: [1.5] }, 'a')).toEqual({ ok: false, reason: 'bad-potential', stepUp: false });
    expect(t.step({ x: [NaN] }, 'a')).toEqual({ ok: false, reason: 'bad-potential', stepUp: false });
    expect(t.steps.length).toBe(0);
  });
  it('guard: receives exact transition, deny on false/non-true/throw, precedes budget check', () => {
    const seen: unknown[] = [];
    const t = new ProgressTracker(GOAL, C, { x: [0] }, undefined, {
      guard: (x) => (seen.push(x), true),
    });
    t.step({ x: [3] }, 'a0');
    t.step({ x: [5] }, 'a1');
    expect(seen).toEqual([
      { seq: 0, before: { x: [0] }, after: { x: [3] }, action_digest: 'a0' },
      { seq: 1, before: { x: [3] }, after: { x: [5] }, action_digest: 'a1' },
    ]);
    for (const g of [() => false, () => 1 as never, () => undefined as never, () => { throw new Error('x'); }]) {
      const tt = new ProgressTracker(GOAL, C, { x: [0] }, undefined, { guard: g });
      expect(tt.step({ x: [3] }, 'a')).toEqual({ ok: false, reason: 'prohibited', stepUp: false });
      expect(tt.steps.length).toBe(0);
    }
    const g0: Goal = { ...GOAL, explorationBudget: 0 };
    const t0 = new ProgressTracker(g0, goalDigest(g0), { x: [0] }, undefined, { guard: () => false });
    expect(t0.step({ x: [0] }, 'a').ok).toBe(false);
    expect((t0.step({ x: [0] }, 'a') as { reason: string }).reason).toBe('prohibited');
  });
  it('stepObserved: request, commitments, and every mismatch', async () => {
    const t = new ProgressTracker(GOAL, C, { x: [0] });
    const src = new InMemoryStateSource({ x: [0] });
    expect(src.id).toBe('in-memory');
    src.apply({ x: [3] });
    const d0 = t.currentStateDigest;
    const r = await t.stepObserved(src, 'a0');
    expect(r.ok).toBe(true);
    expect(src.requests).toEqual([{ action_digest: 'a0', goal_commitment: C, prior_digest: d0 }]);
    if (r.ok) {
      expect(r.step.state_source).toBe('in-memory');
      expect(r.step.evidence_digest).toBe(
        hashCanonical({ t: 'pca-evidence', e: { kind: 'in-memory', n: 0, prior: d0, action: 'a0' } }),
      );
    }
    src.apply({ x: [5] });
    const r2 = await t.stepObserved(src, 'a1');
    expect(r2.ok && r2.step.evidence_digest).toBe(
      hashCanonical({ t: 'pca-evidence', e: { kind: 'in-memory', n: 1, prior: t.steps[0]!.after_digest, action: 'a1' } }),
    );
    expect(new InMemoryStateSource(1, 'custom').id).toBe('custom');
    const bad = { stepUp: false, ok: false, reason: 'state-source-mismatch' };
    const t2 = new ProgressTracker(GOAL, C, { x: [0] });
    const mk = (o: unknown) => ({ id: 's', observe: () => o }) as never;
    expect(await t2.stepObserved(mk(null), 'a')).toEqual(bad);
    expect(await t2.stepObserved(mk({ state: { x: [3] }, state_digest: stateDigest({ x: [3] }), source: 'other' }), 'a')).toEqual(bad);
    expect(await t2.stepObserved(mk({ state: { x: [3] }, state_digest: 'nope', source: 's' }), 'a')).toEqual(bad);
    expect(await t2.stepObserved({ id: 's', observe: () => { throw new Error('x'); } } as never, 'a')).toEqual(bad);
    expect(await t2.stepObserved({ id: 's', observe: () => Promise.reject(new Error('x')) } as never, 'a')).toEqual(bad);
    expect(await t2.stepObserved(mk({ state: { x: [3] }, state_digest: stateDigest({ x: [3] }), source: 's' }), '')).toEqual({ ok: false, reason: 'malformed', stepUp: false });
    // evidence omitted hashes as null
    const ok = await t2.stepObserved(mk({ state: { x: [3] }, state_digest: stateDigest({ x: [3] }), source: 's' }), 'a');
    expect(ok.ok && ok.step.evidence_digest).toBe(hashCanonical({ t: 'pca-evidence', e: null }));
    expect(t2.steps.length).toBe(1);
  });
});

describe('attested state source', () => {
  const K = generateKeyPair();
  const mkSrc = (suite?: never) => new AttestedStateSource({ id: 'rs1', signerSecret: K.secretKey, observeState: () => ({ x: [3] }), suite });
  it('constructor validation', () => {
    const base = { id: 'rs1', signerSecret: K.secretKey, observeState: () => ({}) };
    expect(() => new AttestedStateSource({ ...base, id: '' })).toThrow('AttestedStateSource: id is required');
    expect(() => new AttestedStateSource({ ...base, id: 5 as never })).toThrow('AttestedStateSource: id is required');
    expect(() => new AttestedStateSource({ ...base, signerSecret: 'k' as never })).toThrow('AttestedStateSource: signerSecret must be a Uint8Array');
    expect(() => new AttestedStateSource({ ...base, observeState: 5 as never })).toThrow('AttestedStateSource: observeState must be a function');
    expect(() => new AttestedStateSource({ ...base, suite: { alg: 'bogus' as never } })).toThrow("AttestedStateSource: unknown signature alg 'bogus'");
    expect(new AttestedStateSource(base).id).toBe('rs1');
  });
  it('observe emits a verifiable attestation with the exact statement; getter returns a copy', async () => {
    const reqs: unknown[] = [];
    const src = new AttestedStateSource({ id: 'rs1', signerSecret: K.secretKey, observeState: (r) => (reqs.push(r), { x: [3] }) });
    expect(src.publicKey).toBe(b64u(K.publicKey));
    const req = { action_digest: 'a0', goal_commitment: C, prior_digest: 'P' };
    const obs = await src.observe(req);
    expect(reqs).toEqual([req]);
    expect(obs.state).toEqual({ x: [3] });
    expect(obs.state_digest).toBe(stateDigest({ x: [3] }));
    expect(obs.source).toBe('rs1');
    const att = obs.evidence as StateAttestation;
    expect(att).toMatchObject({ source: 'rs1', goal_commitment: C, action_digest: 'a0', prior_digest: 'P', state_digest: obs.state_digest });
    expect('alg' in att).toBe(false);
    expect(Object.keys(att).sort()).toEqual(['action_digest', 'goal_commitment', 'prior_digest', 'sig', 'source', 'state_digest']);
    expect(src.attestations).toEqual([att]);
    (src.attestations as StateAttestation[]).pop();
    expect(src.attestations.length).toBe(1);
    // exact signed message: DOMAIN || canonical(statement)
    expect(STATE_ATTESTATION_DOMAIN).toBe('atlas-pca/progress-state-attestation/v1\0');
    const stmt = { source: 'rs1', goal_commitment: C, action_digest: 'a0', prior_digest: 'P', state_digest: obs.state_digest };
    const d = utf8(STATE_ATTESTATION_DOMAIN);
    const b = canonicalBytes(stmt);
    const m = new Uint8Array(d.length + b.length);
    m.set(d);
    m.set(b, d.length);
    expect(verifyB64u(src.publicKey, m, att.sig)).toBe(true);
    const mine: StateAttestation = { ...stmt, sig: b64u(sign(K.secretKey, m)) };
    expect(verifyStateAttestation(mine, src.publicKey)).toBe(true);
    expect(verifyStateAttestation(att, src.publicKey)).toBe(true);
  });
  it('verifyStateAttestation rejects every tamper / junk (never throws)', async () => {
    const src = mkSrc();
    const att = (await src.observe({ action_digest: 'a0', goal_commitment: C, prior_digest: 'P' })).evidence as StateAttestation;
    const pub = src.publicKey;
    expect(verifyStateAttestation(att, pub)).toBe(true);
    for (const k of ['source', 'goal_commitment', 'action_digest', 'prior_digest', 'state_digest'] as const) {
      expect(verifyStateAttestation({ ...att, [k]: att[k] + 'x' }, pub)).toBe(false);
    }
    expect(verifyStateAttestation(null as never, pub)).toBe(false);
    expect(verifyStateAttestation({ ...att, sig: 5 } as never, pub)).toBe(false);
    expect(verifyStateAttestation({ ...att, source: 5 } as never, pub)).toBe(false);
    expect(verifyStateAttestation(att, '')).toBe(false);
    expect(verifyStateAttestation(att, 5 as never)).toBe(false);
    expect(verifyStateAttestation(att, b64u(generateKeyPair().publicKey))).toBe(false);
    expect(verifyStateAttestation({ ...att, alg: 'bogus' } as never, pub)).toBe(false);
    expect(verifyStateAttestation({ ...att, sig: 'AAAA' }, pub)).toBe(false);
  });
  it('hybrid suite: needs pins; pins / allowUnboundPq forwarded', async () => {
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(8));
    const src = new AttestedStateSource({
      id: 'rs1',
      signerSecret: K.secretKey,
      observeState: () => ({ x: [3] }),
      suite: { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml },
    });
    const att = (await src.observe({ action_digest: 'a0', goal_commitment: C, prior_digest: 'P' })).evidence as StateAttestation;
    expect(att.alg).toBe('hybrid-ed25519-ml-dsa-65');
    expect(typeof att.pq_pk).toBe('string');
    expect(typeof att.pq_sig).toBe('string');
    expect(verifyStateAttestation(att, src.publicKey)).toBe(false);
    expect(verifyStateAttestation(att, src.publicKey, { pqPins: { [src.publicKey]: att.pq_pk! } })).toBe(true);
    expect(verifyStateAttestation(att, src.publicKey, { allowUnboundPq: true })).toBe(true);
    expect(verifyStateAttestation({ ...att, pq_pk: undefined }, src.publicKey, { allowUnboundPq: true })).toBe(false);
    // verifier hook forwards pins
    const t = new ProgressTracker(GOAL, C, { x: [0] });
    const r = await t.stepObserved(src, 'a0');
    expect(r.ok).toBe(true);
    const step = (r as { step: ProgressStep }).step;
    const trustedKeys = { rs1: src.publicKey };
    const v = (o: object) => attestedStateVerifier({ trustedKeys, attestations: src.attestations, ...o })(step);
    expect(v({})).toBe(false);
    expect(v({ pqPins: { [src.publicKey]: att.pq_pk } })).toBe(true);
    expect(v({ allowUnboundPq: true })).toBe(true);
  });
  it('attestedStateVerifier: trust, lookup, evidence binding, signature', async () => {
    const src = mkSrc();
    const t = new ProgressTracker(GOAL, C, { x: [0] });
    const r = await t.stepObserved(src, 'a0');
    const step = (r as { step: ProgressStep }).step;
    const trustedKeys = { rs1: src.publicKey };
    const mkv = (o: object = {}) => attestedStateVerifier({ trustedKeys, attestations: src.attestations, ...o });
    expect(mkv()(step)).toBe(true);
    // untrusted / absent / empty key
    expect(mkv({ trustedKeys: {} })(step)).toBe(false);
    expect(mkv({ trustedKeys: { rs1: '' } })(step)).toBe(false);
    expect(mkv({ trustedKeys: { rs1: 5 } })(step)).toBe(false);
    expect(mkv({ trustedKeys: undefined })(step)).toBe(false);
    expect(mkv({ attestations: undefined })(step)).toBe(false);
    expect(mkv({ attestations: [] })(step)).toBe(false);
    // wrong transition / wrong source / tampered evidence digest
    expect(mkv()({ ...step, action_digest: 'other' })).toBe(false);
    expect(mkv()({ ...step, before_digest: 'other' })).toBe(false);
    expect(mkv()({ ...step, after_digest: 'other' })).toBe(false);
    expect(mkv({ trustedKeys: { rs1: src.publicKey, other: src.publicKey } })({ ...step, state_source: 'other' })).toBe(false);
    expect(mkv()({ ...step, evidence_digest: step.evidence_digest + 'x' })).toBe(false);
    expect(mkv()({ ...step, evidence_digest: '' })).toBe(false);
    // forged signature: a different key's trusted key
    expect(mkv({ trustedKeys: { rs1: b64u(generateKeyPair().publicKey) } })(step)).toBe(false);
    // junk in attestations list is ignored, never throws
    expect(mkv({ attestations: [null, undefined, 5, ...src.attestations] })(step)).toBe(true);
    // attestation with non-string digest fields is NOT indexed (even when its string-coerced key would match)
    const real = src.attestations[0]!;
    for (const k of ['action_digest', 'prior_digest', 'state_digest'] as const) {
      const num = 5;
      const forged = { ...real, [k]: num };
      const msgStmt = { source: forged.source, goal_commitment: forged.goal_commitment, action_digest: forged.action_digest, prior_digest: forged.prior_digest, state_digest: forged.state_digest };
      const d = utf8(STATE_ATTESTATION_DOMAIN);
      const b = canonicalBytes(msgStmt);
      const m = new Uint8Array(d.length + b.length);
      m.set(d);
      m.set(b, d.length);
      const signedForged = { ...forged, sig: b64u(sign(K.secretKey, m)) };
      const fakeStep = {
        ...step,
        action_digest: String(signedForged.action_digest),
        before_digest: String(signedForged.prior_digest),
        after_digest: String(signedForged.state_digest),
        evidence_digest: hashCanonical({ t: 'pca-evidence', e: signedForged }),
      };
      expect(verifyStateAttestation(signedForged as never, src.publicKey)).toBe(true);
      expect(attestedStateVerifier({ trustedKeys, attestations: [signedForged as never] })(fakeStep)).toBe(false);
    }
    // a throwing step (getter) is a plain false
    const thrower = new Proxy(step, { get() { throw new Error('x'); } });
    expect(mkv()(thrower)).toBe(false);
  });
  it('end-to-end: attested trajectory verifies and any tamper is rejected', async () => {
    const src = new AttestedStateSource({ id: 'rs1', signerSecret: K.secretKey, observeState: (r) => ({ x: [r.action_digest === 'a0' ? 3 : 10] }) });
    const t = new ProgressTracker(GOAL, C, { x: [0] });
    await t.stepObserved(src, 'a0');
    await t.stepObserved(src, 'a1');
    const att = attestedStateVerifier({ trustedKeys: { rs1: src.publicKey }, attestations: src.attestations });
    const ok = verifyTrajectory(GOAL, C, t.steps, { trustedStateSources: ['rs1'], attestation: att });
    expect(ok).toMatchObject({ ok: true, reached: true, steps: 2 });
    const none = verifyTrajectory(GOAL, C, t.steps, { trustedStateSources: ['rs1'], attestation: attestedStateVerifier({ trustedKeys: { rs1: src.publicKey }, attestations: [] }) });
    expect(none).toEqual({ ok: false, reason: 'attestation-failed', at: 0 });
  });
});

describe('verifyProgressStep', () => {
  const { steps, c } = run3();
  const s0 = steps[0]!;
  const s1 = steps[1]!;
  const v = (s: unknown, o: object = {}, goal: Goal = GOAL, com: string = c) => verifyProgressStep(goal, com, s as ProgressStep, o);

  it('accepts good steps and reports the recomputed charge', () => {
    expect(v(s0)).toEqual({ ok: true, charge: 0 });
    expect(v(s1)).toEqual({ ok: true, charge: 1 });
    expect(v(s0, { expectedSeq: 0, expectedPrev: 'genesis', expectedActionDigest: 'a0', expectedBeforeDigest: s0.before_digest, expectedAfterDigest: s0.after_digest })).toEqual({ ok: true, charge: 0 });
  });
  it('goal binding', () => {
    expect(v(s0, {}, GOAL, 'wrong')).toEqual({ ok: false, reason: 'goal-mismatch' });
    expect(v(s0, {}, { ...GOAL, epsilon: 3 })).toEqual({ ok: false, reason: 'goal-mismatch' });
    expect(v(redigest(s0, { goal_commitment: 'other' }))).toEqual({ ok: false, reason: 'goal-mismatch' });
  });
  it('malformed: not an object / each required field', () => {
    for (const x of [null, undefined, 5, 'x', [], [s0]]) expect(v(x)).toEqual({ ok: false, reason: 'malformed' });
    const bads: Record<string, unknown[]> = {
      goal_commitment: [5, undefined],
      seq: [1.5, -1, '0', undefined, MAXI + 1, NaN],
      before_digest: [5, undefined],
      after_digest: [5, undefined],
      action_digest: [5, undefined],
      mode: ['bogus', undefined, 'Progress'],
      potential_before: [1.5, '10', undefined],
      potential_after: [1.5, '7', undefined],
      charge: [0.5, '0', undefined],
      state_source: [5, undefined],
      evidence_digest: [5, undefined],
      prev: [5, undefined],
      digest: [5, undefined],
    };
    for (const [k, vals] of Object.entries(bads)) {
      for (const val of vals) expect(v({ ...s0, [k]: val }), `${k}=${String(val)}`).toEqual({ ok: false, reason: 'malformed' });
    }
    const { before: _b, ...noBefore } = s0;
    const { after: _a, ...noAfter } = s0;
    void _b;
    void _a;
    expect(v(noBefore)).toEqual({ ok: false, reason: 'malformed' });
    expect(v(noAfter)).toEqual({ ok: false, reason: 'malformed' });
  });
  it('seq 0 is valid (boundary of >= 0)', () => {
    expect(v(s0).ok).toBe(true);
  });
  it('expected* options, in order, each with its own reason', () => {
    expect(v(s0, { expectedSeq: 1 })).toEqual({ ok: false, reason: 'seq-mismatch' });
    expect(v(s0, { expectedPrev: 'x' })).toEqual({ ok: false, reason: 'chain-break' });
    expect(v(s0, { expectedActionDigest: 'zz' })).toEqual({ ok: false, reason: 'action-mismatch' });
    expect(v(s0, { expectedBeforeDigest: 'zz' })).toEqual({ ok: false, reason: 'state-mismatch' });
    expect(v(s0, { expectedAfterDigest: 'zz' })).toEqual({ ok: false, reason: 'state-mismatch' });
    // order: seq < prev < action < before < after < digest
    const all = { expectedSeq: 9, expectedPrev: 'x', expectedActionDigest: 'x', expectedBeforeDigest: 'x', expectedAfterDigest: 'x' };
    expect(reasonOf(v({ ...s0, digest: 'bad' }, all))).toBe('seq-mismatch');
    const { expectedSeq: _s, ...r1 } = all;
    void _s;
    expect(reasonOf(v({ ...s0, digest: 'bad' }, r1))).toBe('chain-break');
    const { expectedPrev: _p, ...r2 } = r1;
    void _p;
    expect(reasonOf(v({ ...s0, digest: 'bad' }, r2))).toBe('action-mismatch');
    const { expectedActionDigest: _ad, ...r3 } = r2;
    void _ad;
    expect(reasonOf(v({ ...s0, digest: 'bad' }, r3))).toBe('state-mismatch');
    expect(reasonOf(v({ ...s0, digest: 'bad' }, { expectedAfterDigest: 'x' }))).toBe('state-mismatch');
    expect(reasonOf(v({ ...s0, digest: 'bad' }))).toBe('digest-mismatch');
    // a matching expectation passes through to later checks
    expect(reasonOf(v({ ...s0, digest: 'bad' }, { expectedSeq: 0 }))).toBe('digest-mismatch');
  });
  it('digest mismatch on any body tamper', () => {
    expect(v({ ...s0, charge: 3 })).toEqual({ ok: false, reason: 'digest-mismatch' });
    expect(v({ ...s0, state_source: 'x' })).toEqual({ ok: false, reason: 'digest-mismatch' });
    expect(v({ ...s0, evidence_digest: 'x' })).toEqual({ ok: false, reason: 'digest-mismatch' });
    expect(v({ ...s0, after: { x: [4] } })).toEqual({ ok: false, reason: 'digest-mismatch' });
  });
  it('state digests are recomputed (before and after independently)', () => {
    expect(v(redigest(s0, { before_digest: stateDigest({ x: [1] }) }))).toEqual({ ok: false, reason: 'state-digest-mismatch' });
    expect(v(redigest(s0, { after_digest: stateDigest({ x: [1] }) }))).toEqual({ ok: false, reason: 'state-digest-mismatch' });
    expect(v(redigest(s0, { before: { x: [1] } }))).toEqual({ ok: false, reason: 'state-digest-mismatch' });
  });
  it('potential resolution failures map to their denial codes', () => {
    const bad = { x: 'bad' };
    expect(v(redigest(s0, { before: bad, before_digest: stateDigest(bad) }))).toEqual({ ok: false, reason: 'bad-potential' });
    expect(v(redigest(s0, { after: bad, after_digest: stateDigest(bad) }))).toEqual({ ok: false, reason: 'bad-potential' });
    const g2: Goal = { ...GOAL, potential: 'nope' };
    const c2 = goalDigest(g2);
    expect(v(redigest(s0, { goal_commitment: c2 }), {}, g2, c2)).toEqual({ ok: false, reason: 'unknown-potential' });
    const g3: Goal = { ...GOAL, embedder: 'e9' };
    const c3 = goalDigest(g3);
    expect(v(redigest(s0, { goal_commitment: c3 }), {}, g3, c3)).toEqual({ ok: false, reason: 'embedder-mismatch' });
    // matching embedder in a custom registry works; spec embedder '' vs goal undefined is equal
    const reg = new PotentialRegistry().register('l1-feature-v1', l1FeaturePotential, 'e9');
    expect(v(redigest(s0, { goal_commitment: c3 }), { registry: reg }, g3, c3).ok).toBe(true);
    // negative potential
    const neg = { objective: null, potential: 'neg', metric: '', epsilon: 1, explorationBudget: 0 } as Goal;
    const cn = goalDigest(neg);
    const stepN = redigest(s0, { goal_commitment: cn, before: { v: -1 }, after: { v: -2 }, before_digest: stateDigest({ v: -1 }), after_digest: stateDigest({ v: -2 }) });
    expect(v(stepN, { registry: { neg: (_o: unknown, s: unknown) => (s as { v: number }).v } }, neg, cn)).toEqual({ ok: false, reason: 'bad-potential' });
    // plain-record registry
    expect(v(s0, { registry: { 'l1-feature-v1': l1FeaturePotential } }).ok).toBe(true);
    expect(v(s0, { registry: PotentialRegistry.defaults() }).ok).toBe(true);
    expect(v(s0, { registry: {} })).toEqual({ ok: false, reason: 'unknown-potential' });
  });
  it('claimed potentials / mode / charge are recomputed (each field independently)', () => {
    expect(v(redigest(s0, { potential_before: 11 }))).toEqual({ ok: false, reason: 'potential-mismatch' });
    expect(v(redigest(s0, { potential_after: 6 }))).toEqual({ ok: false, reason: 'potential-mismatch' });
    expect(v(redigest(s0, { mode: 'exploration' }))).toEqual({ ok: false, reason: 'mode-mismatch' });
    expect(v(redigest(s1, { mode: 'progress' }))).toEqual({ ok: false, reason: 'mode-mismatch' });
    expect(v(redigest(s1, { charge: 2 }))).toEqual({ ok: false, reason: 'charge-mismatch' });
    expect(v(redigest(s1, { charge: 0 }))).toEqual({ ok: false, reason: 'charge-mismatch' });
    // order: potential before mode before charge
    expect(reasonOf(v(redigest(s1, { potential_before: 99, mode: 'progress', charge: 7 })))).toBe('potential-mismatch');
    expect(reasonOf(v(redigest(s1, { mode: 'progress', charge: 7 })))).toBe('mode-mismatch');
  });
  it('trustedStateSources / guard / attestation hooks', () => {
    expect(v(s0, { trustedStateSources: ['x'] })).toEqual({ ok: false, reason: 'untrusted-state-source' });
    expect(v(s0, { trustedStateSources: [] })).toEqual({ ok: false, reason: 'untrusted-state-source' });
    expect(v(s0, { trustedStateSources: [''] }).ok).toBe(true);
    const ssrc = redigest(s0, { state_source: 'rs' });
    expect(v(ssrc, { trustedStateSources: ['rs'] }).ok).toBe(true);
    expect(v(ssrc, { trustedStateSources: [''] })).toEqual({ ok: false, reason: 'untrusted-state-source' });
    const seen: unknown[] = [];
    expect(v(s1, { guard: (t: unknown) => (seen.push(t), true) }).ok).toBe(true);
    expect(seen).toEqual([{ seq: 1, before: s1.before, after: s1.after, action_digest: 'a1' }]);
    for (const g of [() => false, () => 1, () => undefined, () => { throw new Error('x'); }]) {
      expect(v(s0, { guard: g })).toEqual({ ok: false, reason: 'prohibited' });
    }
    // order: trusted-source before guard before attestation
    expect(reasonOf(v(s0, { trustedStateSources: ['x'], guard: () => false, attestation: () => false }))).toBe('untrusted-state-source');
    expect(reasonOf(v(s0, { guard: () => false, attestation: () => false }))).toBe('prohibited');
    const got: ProgressStep[] = [];
    expect(v(s0, { attestation: (st: ProgressStep) => (got.push(st), true) }).ok).toBe(true);
    expect(got).toEqual([s0]);
    for (const a of [() => false, () => 1, () => undefined, () => 'true', () => { throw new Error('x'); }]) {
      expect(v(s0, { attestation: a })).toEqual({ ok: false, reason: 'attestation-failed' });
    }
  });
  it('anything unexpected is reported as malformed, never thrown', () => {
    expect(v(s0, { trustedStateSources: {} })).toEqual({ ok: false, reason: 'malformed' });
  });
});

describe('verifyTrajectory', () => {
  const { steps, c, ads } = run3();
  const vt = (s: unknown, o: object = {}, goal: Goal = GOAL, com: string = c) => verifyTrajectory(goal, com, s as ProgressStep[], o);
  it('full verdict fields', () => {
    expect(vt(steps)).toEqual({ ok: true, spent: 1, remaining: 4, reached: true, finalPotential: 0, steps: 3, head: steps[2]!.digest });
    expect(vt(steps.slice(0, 2))).toEqual({ ok: true, spent: 1, remaining: 4, reached: false, finalPotential: 6, steps: 2, head: steps[1]!.digest });
    expect(vt(steps, { initial: { x: [0] }, expectedActionDigests: ads }).ok).toBe(true);
    expect(vt(steps, { initialDigest: steps[0]!.before_digest }).ok).toBe(true);
  });
  it('goal / shape', () => {
    expect(vt(steps, {}, GOAL, 'bad')).toEqual({ ok: false, reason: 'goal-mismatch', at: -1 });
    expect(vt('x')).toEqual({ ok: false, reason: 'malformed', at: -1 });
    expect(vt(null)).toEqual({ ok: false, reason: 'malformed', at: -1 });
    expect(vt([null])).toEqual({ ok: false, reason: 'malformed', at: 0 });
    expect(vt([steps[0], { bad: 1 }])).toEqual({ ok: false, reason: 'malformed', at: 1 });
  });
  it('empty trajectories', () => {
    expect(vt([])).toEqual({ ok: true, spent: 0, remaining: 5, reached: false, finalPotential: -1, steps: 0, head: 'genesis' });
    expect(vt([], { initial: { x: [3] } })).toEqual({ ok: true, spent: 0, remaining: 5, reached: false, finalPotential: 7, steps: 0, head: 'genesis' });
    expect(vt([], { initial: { x: [10] } })).toMatchObject({ ok: true, reached: true, finalPotential: 0 });
    expect(vt([], { initial: { x: 'bad' } })).toEqual({ ok: false, reason: 'bad-potential', at: -1 });
    const g2: Goal = { ...GOAL, potential: 'nope' };
    expect(vt([], { initial: { x: [1] } }, g2, goalDigest(g2))).toEqual({ ok: false, reason: 'unknown-potential', at: -1 });
    // initial is only potential-checked when there are no steps
    expect(vt(steps, { initial: { x: 'bad' } })).toEqual({ ok: false, reason: 'discontinuous-state', at: 0 });
  });
  it('unhashable initial', () => {
    expect(vt(steps, { initial: { x: NaN } })).toEqual({ ok: false, reason: 'malformed', at: -1 });
    expect(vt(steps, { initial: undefined }).ok).toBe(true);
    expect(vt(steps, { initial: null })).toEqual({ ok: false, reason: 'discontinuous-state', at: 0 });
  });
  it('expectedActionDigests', () => {
    expect(vt(steps, { expectedActionDigests: ['a0'] })).toEqual({ ok: false, reason: 'action-mismatch', at: 1 });
    expect(vt(steps, { expectedActionDigests: [...ads, 'a3', 'a4'] })).toEqual({ ok: false, reason: 'action-mismatch', at: 3 });
    expect(vt([], { expectedActionDigests: ['a0'] })).toEqual({ ok: false, reason: 'action-mismatch', at: 0 });
    expect(vt(steps, { expectedActionDigests: ['a0', 'x', 'a2'] })).toEqual({ ok: false, reason: 'action-mismatch', at: 1 });
  });
  it('chain, sequence and continuity', () => {
    expect(vt([steps[1], steps[0], steps[2]])).toEqual({ ok: false, reason: 'seq-mismatch', at: 0 });
    expect(vt([steps[0], steps[2]])).toEqual({ ok: false, reason: 'seq-mismatch', at: 1 });
    expect(vt([steps[0], redigest(steps[1]!, { prev: 'x' })])).toEqual({ ok: false, reason: 'chain-break', at: 1 });
    expect(vt([redigest(steps[0]!, { prev: 'x' })])).toEqual({ ok: false, reason: 'chain-break', at: 0 });
    // continuity: step1 starts from a state that is not step0's after
    const other = { x: [1] };
    const broken = relink([steps[0]!, redigest(steps[1]!, { before: other, before_digest: stateDigest(other), potential_before: 9, mode: 'progress', charge: 0 })], c);
    expect(vt(broken)).toEqual({ ok: false, reason: 'discontinuous-state', at: 1 });
    expect(vt(steps, { initial: { x: [1] } })).toEqual({ ok: false, reason: 'discontinuous-state', at: 0 });
    expect(vt(steps, { initialDigest: 'zz' })).toEqual({ ok: false, reason: 'discontinuous-state', at: 0 });
    // initialDigest wins over initial
    expect(vt(steps, { initialDigest: steps[0]!.before_digest, initial: { x: [1] } }).ok).toBe(true);
  });
  it('global budget: sum(charge) <= budget, boundary inclusive, reported at the offending index', () => {
    const big: Goal = { ...GOAL, explorationBudget: 100 };
    const cb = goalDigest(big);
    const t = new ProgressTracker(big, cb, { x: [0] });
    // three exploration steps of charge 2,1,1 (stay put, then small moves)
    t.step({ x: [0] }, 'e0'); // charge 2
    t.step({ x: [1] }, 'e1'); // pb10 pa9: charge 1
    t.step({ x: [1] }, 'e2'); // pb9 pa9: charge 2
    const chain = t.steps as ProgressStep[];
    expect(chain.map((s) => s.charge)).toEqual([2, 1, 2]);
    const exactly = { ...GOAL, explorationBudget: 5 };
    const ce = goalDigest(exactly);
    expect(verifyTrajectory(exactly, ce, relink(chain, ce))).toMatchObject({ ok: true, spent: 5, remaining: 0 });
    const tight = { ...GOAL, explorationBudget: 4 };
    const ct = goalDigest(tight);
    expect(verifyTrajectory(tight, ct, relink(chain, ct))).toEqual({ ok: false, reason: 'budget-exceeded', at: 2 });
    const tighter = { ...GOAL, explorationBudget: 1 };
    const c1 = goalDigest(tighter);
    expect(verifyTrajectory(tighter, c1, relink(chain, c1))).toEqual({ ok: false, reason: 'budget-exceeded', at: 0 });
  });
  it('options are forwarded to every step check', () => {
    expect(vt(steps, { trustedStateSources: ['x'] })).toEqual({ ok: false, reason: 'untrusted-state-source', at: 0 });
    expect(vt(steps, { guard: (t: { seq: number }) => t.seq !== 1 })).toEqual({ ok: false, reason: 'prohibited', at: 1 });
    expect(vt(steps, { attestation: (s: ProgressStep) => s.seq !== 2 })).toEqual({ ok: false, reason: 'attestation-failed', at: 2 });
    expect(vt(steps, { registry: {} })).toEqual({ ok: false, reason: 'unknown-potential', at: 0 });
  });
});

describe('signed steps / trajectories', () => {
  const K = generateKeyPair();
  const holder = b64u(K.publicKey);
  const { steps, c, ads } = run3();
  const signedAll = steps.map((s) => signProgressStep(s, K.secretKey, holder));
  const vs = (sp: unknown, o: Partial<VerifySignedStepOptions> = {}, goal = GOAL, com = c) =>
    verifySignedProgressStep(goal, com, sp as never, { expectedActionDigest: 'a0', expectedHolder: holder, ...o });

  it('signature covers the exact binding message', () => {
    const sp = signedAll[0]!;
    expect(sp.step).toBe(steps[0]);
    expect(sp.holder).toBe(holder);
    const s = steps[0]!;
    const msg = canonicalBytes({
      d: PROGRESS_SIG_DOMAIN,
      b: {
        holder,
        goal_commitment: s.goal_commitment,
        action_digest: s.action_digest,
        before_digest: s.before_digest,
        after_digest: s.after_digest,
        seq: s.seq,
        prev: s.prev,
        step_digest: s.digest,
      },
    });
    expect(verifyB64u(holder, msg, sp.sig)).toBe(true);
  });
  it('verifySignedProgressStep verdicts', () => {
    expect(vs(signedAll[0])).toEqual({ ok: true, charge: 0 });
    for (const x of [null, undefined, 5, 'x', [], {}]) expect(vs(x)).toEqual({ ok: false, reason: 'malformed' });
    expect(vs({ ...signedAll[0], holder: 5 })).toEqual({ ok: false, reason: 'malformed' });
    expect(vs({ ...signedAll[0], sig: 5 })).toEqual({ ok: false, reason: 'malformed' });
    expect(vs({ ...signedAll[0], step: { ...steps[0], seq: 'x' } })).toEqual({ ok: false, reason: 'malformed' });
    expect(vs({ ...signedAll[0], step: null })).toEqual({ ok: false, reason: 'malformed' });
    expect(vs(signedAll[0], { expectedHolder: b64u(generateKeyPair().publicKey) })).toEqual({ ok: false, reason: 'holder-mismatch' });
    expect(vs(signedAll[0], { expectedActionDigest: 'zz' })).toEqual({ ok: false, reason: 'action-mismatch' });
    // rebinding to another goal (properly re-signed): goal-mismatch precedes the signature check
    const rebased = redigest(steps[0]!, { goal_commitment: 'other' });
    expect(vs(signProgressStep(rebased, K.secretKey, holder))).toEqual({ ok: false, reason: 'goal-mismatch' });
    // order: holder < action < goal < signature
    expect(reasonOf(vs({ ...signedAll[0], sig: 'AAAA' }, { expectedHolder: 'x', expectedActionDigest: 'zz' }))).toBe('holder-mismatch');
    expect(reasonOf(vs({ ...signedAll[0], sig: 'AAAA' }, { expectedActionDigest: 'zz' }))).toBe('action-mismatch');
    expect(reasonOf(vs({ ...signProgressStep(rebased, K.secretKey, holder), sig: 'AAAA' }))).toBe('goal-mismatch');
    expect(vs({ ...signedAll[0], sig: 'AAAA' })).toEqual({ ok: false, reason: 'bad-signature' });
    // signature by another key, same holder claimed
    const forged = signProgressStep(steps[0]!, generateKeyPair().secretKey, holder);
    expect(vs(forged)).toEqual({ ok: false, reason: 'bad-signature' });
    // signature over a different step body
    expect(vs({ ...signedAll[0], step: steps[1] }, { expectedActionDigest: 'a1' })).toEqual({ ok: false, reason: 'bad-signature' });
    // then the full step re-check runs with the options
    const lied = redigest(steps[0]!, { potential_after: 6 });
    expect(vs(signProgressStep(lied, K.secretKey, holder))).toEqual({ ok: false, reason: 'potential-mismatch' });
    expect(vs(signedAll[0], { expectedSeq: 3 })).toEqual({ ok: false, reason: 'seq-mismatch' });
    expect(vs(signedAll[0], { trustedStateSources: ['x'] })).toEqual({ ok: false, reason: 'untrusted-state-source' });
  });
  const vst = (sp: unknown, o: object = {}, goal = GOAL, com = c) =>
    verifySignedTrajectory(goal, com, sp as never, { expectedActionDigests: ads, expectedHolder: holder, ...o });
  it('verifySignedTrajectory verdicts', () => {
    expect(vst(signedAll)).toEqual({ ok: true, spent: 1, remaining: 4, reached: true, finalPotential: 0, steps: 3, head: steps[2]!.digest });
    expect(vst('x')).toEqual({ ok: false, reason: 'malformed', at: -1 });
    expect(vst(null)).toEqual({ ok: false, reason: 'malformed', at: -1 });
    expect(vst(signedAll.slice(0, 1))).toEqual({ ok: false, reason: 'action-mismatch', at: 1 });
    expect(vst(signedAll, { expectedActionDigests: ['a0'] })).toEqual({ ok: false, reason: 'action-mismatch', at: 1 });
    expect(vst([], { expectedActionDigests: ['a0', 'a1'] })).toEqual({ ok: false, reason: 'action-mismatch', at: 0 });
    for (const bad of [null, 5, {}, { ...signedAll[1], holder: 5 }, { ...signedAll[1], sig: 5 }, { ...signedAll[1], step: null }]) {
      expect(vst([signedAll[0], bad, signedAll[2]])).toEqual({ ok: false, reason: 'malformed', at: 1 });
    }
    expect(vst([signedAll[0], signProgressStep(steps[1]!, K.secretKey, b64u(generateKeyPair().publicKey)), signedAll[2]])).toEqual({ ok: false, reason: 'holder-mismatch', at: 1 });
    expect(vst(signedAll, { expectedActionDigests: ['a0', 'zz', 'a2'] })).toEqual({ ok: false, reason: 'action-mismatch', at: 1 });
    expect(vst([signedAll[0], { ...signedAll[1], sig: 'AAAA' }, signedAll[2]])).toEqual({ ok: false, reason: 'bad-signature', at: 1 });
    // per-step passes happen before the trajectory re-check (which still runs, with forwarded options)
    expect(vst(signedAll, { initial: { x: [1] } })).toEqual({ ok: false, reason: 'discontinuous-state', at: 0 });
    expect(vst(signedAll, { trustedStateSources: ['x'] })).toEqual({ ok: false, reason: 'untrusted-state-source', at: 0 });
    expect(vst(signedAll, { initial: { x: [0] } }).ok).toBe(true);
    // a mid-chain break is detected by the trajectory pass
    const swapped = [signedAll[0], signedAll[2], signedAll[1]];
    expect(vst(swapped, { expectedActionDigests: ['a0', 'a2', 'a1'] })).toMatchObject({ ok: false, at: 1 });
  });
});

describe('residual guards', () => {
  const K = generateKeyPair();
  const { steps, c, ads } = run3();
  const holder = b64u(K.publicKey);
  const signedAll = steps.map((s) => signProgressStep(s, K.secretKey, holder));

  it('verifyStateAttestation: a properly signed attestation with a non-string source is refused', () => {
    const stmt = { source: 5, goal_commitment: 'g', action_digest: 'a', prior_digest: 'p', state_digest: 's' };
    const d = utf8(STATE_ATTESTATION_DOMAIN);
    const b = canonicalBytes(stmt);
    const m = new Uint8Array(d.length + b.length);
    m.set(d);
    m.set(b, d.length);
    const att = { ...stmt, sig: b64u(sign(K.secretKey, m)) };
    expect(verifyB64u(holder, m, att.sig)).toBe(true);
    expect(verifyStateAttestation(att as never, holder)).toBe(false);
    expect(verifyStateAttestation({ ...att, source: 'ok' } as never, holder)).toBe(false);
  });
  it('verifyStateAttestation: trusted key must be a non-empty string even when the suite never consults it', async () => {
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(3));
    const src = new AttestedStateSource({ id: 'rs1', signerSecret: K.secretKey, observeState: () => ({ x: [3] }), suite: { alg: 'ml-dsa-65', mlDsa: ml } });
    const att = (await src.observe({ action_digest: 'a0', goal_commitment: c, prior_digest: 'P' })).evidence as StateAttestation;
    expect(att.alg).toBe('ml-dsa-65');
    expect(verifyStateAttestation(att, src.publicKey, { allowUnboundPq: true })).toBe(true);
    expect(verifyStateAttestation(att, '', { allowUnboundPq: true })).toBe(false);
    expect(verifyStateAttestation(att, 5 as never, { allowUnboundPq: true })).toBe(false);
    expect(verifyStateAttestation(att, undefined as never, { allowUnboundPq: true })).toBe(false);
  });

  it('verifySignedProgressStep: lone-surrogate holder (unsignable message) is reported as malformed, not thrown', () => {
    const bad = '\ud800';
    const sp = { step: steps[0]!, holder: bad, sig: 'AAAA' };
    expect(verifySignedProgressStep(GOAL, c, sp, { expectedActionDigest: 'a0', expectedHolder: bad })).toEqual({ ok: false, reason: 'malformed' });
  });
  it('verifySignedTrajectory: unsignable message => malformed at that index; length check precedes signature checks', () => {
    const bad = '\ud800';
    const sp = [signedAll[0]!, { step: steps[1]!, holder: bad, sig: 'AAAA' }, signedAll[2]!];
    expect(verifySignedTrajectory(GOAL, c, sp, { expectedActionDigests: ads, expectedHolder: bad })).toEqual({ ok: false, reason: 'holder-mismatch', at: 0 });
    const sp2 = [{ step: steps[0]!, holder: bad, sig: 'AAAA' }, { step: steps[1]!, holder: bad, sig: 'AAAA' }];
    expect(verifySignedTrajectory(GOAL, c, sp2, { expectedActionDigests: ['a0', 'a1'], expectedHolder: bad })).toEqual({ ok: false, reason: 'malformed', at: 0 });
    // a corrupted early signature must NOT mask the length mismatch
    const corrupted = [{ ...signedAll[0]!, sig: 'AAAA' }, signedAll[1]!, signedAll[2]!];
    expect(verifySignedTrajectory(GOAL, c, corrupted, { expectedActionDigests: ['a0'], expectedHolder: holder })).toEqual({ ok: false, reason: 'action-mismatch', at: 1 });
    expect(verifySignedTrajectory(GOAL, c, corrupted.slice(0, 1), { expectedActionDigests: ['a0', 'a1', 'a2'], expectedHolder: holder })).toEqual({ ok: false, reason: 'action-mismatch', at: 1 });
  });
  it('verifySignedTrajectory: an action mismatch at i is reported before a bad signature at a later step', () => {
    const later = [signedAll[0]!, signedAll[1]!, { ...signedAll[2]!, sig: 'AAAA' }];
    expect(verifySignedTrajectory(GOAL, c, later, { expectedActionDigests: ['a0', 'zz', 'a2'], expectedHolder: holder })).toEqual({ ok: false, reason: 'action-mismatch', at: 1 });
  });
});
