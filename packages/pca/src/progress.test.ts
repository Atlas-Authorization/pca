import { describe, expect, it } from 'vitest';
import {
  type Goal,
  InMemoryStateSource,
  PotentialRegistry,
  ProgressTracker,
  type ProgressStep,
  type StateObservation,
  type StateSource,
  commitGoal,
  dagWeightedPotential,
  signProgressStep,
  stateDigest,
  trajectoryHead,
  verifyGoalCommitment,
  verifyProgressStep,
  verifySignedProgressStep,
  verifySignedTrajectory,
  verifyTrajectory,
} from './progress';
import { b64u } from './hash';
import { generateKeyPair, sign } from './keys';

const goal = (over: Partial<Goal> = {}): Goal => ({
  objective: { target: [10, 10] },
  potential: 'l1-feature-v1',
  metric: 'l1',
  epsilon: 2,
  explorationBudget: 5,
  ...over,
});
const x = (a: number, b: number) => ({ x: [a, b] });
const setup = (over: Partial<Goal> = {}) => {
  const g = goal(over);
  const c = commitGoal(g);
  return { g, c: c.commitment, t: new ProgressTracker(g, c.commitment, x(0, 0)) };
};
const ok = <T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> => {
  if (!r.ok) throw new Error('expected ok: ' + JSON.stringify(r));
  return r as Extract<T, { ok: true }>;
};

describe('goal commitment', () => {
  it('binds: tampering objective/epsilon/budget/potential/metric/embedder breaks it', () => {
    const { goal: g, commitment } = commitGoal(goal());
    expect(verifyGoalCommitment(g, commitment)).toBe(true);
    expect(verifyGoalCommitment({ ...g, objective: { target: [10, 11] } }, commitment)).toBe(false);
    expect(verifyGoalCommitment({ ...g, epsilon: 1 }, commitment)).toBe(false);
    expect(verifyGoalCommitment({ ...g, explorationBudget: 6 }, commitment)).toBe(false);
    expect(verifyGoalCommitment({ ...g, potential: 'dag-remaining-v1' }, commitment)).toBe(false);
    expect(verifyGoalCommitment({ ...g, metric: 'other' }, commitment)).toBe(false);
    expect(verifyGoalCommitment({ ...g, embedder: 'emb-v1' }, commitment)).toBe(false);
  });
  it('embedder default is the empty string (explicit "" is the same commitment)', () => {
    expect(commitGoal(goal()).commitment).toBe(commitGoal(goal({ embedder: '' })).commitment);
  });
  it('rejects invalid parameters', () => {
    expect(() => commitGoal(goal({ epsilon: 0 }))).toThrow();
    expect(() => commitGoal(goal({ explorationBudget: -1 }))).toThrow();
    expect(() => commitGoal(goal({ epsilon: 1.5 }))).toThrow();
    expect(() => commitGoal(goal({ potential: '' }))).toThrow();
    expect(() => commitGoal(goal({ explorationBudget: Number.MAX_SAFE_INTEGER + 2 }))).toThrow();
    expect(verifyGoalCommitment(goal({ epsilon: 0 }), 'x')).toBe(false);
  });
  it('commitGoal snapshots: later mutation of the caller object cannot change the committed goal', () => {
    const g = goal();
    const c = commitGoal(g);
    (g.objective as { target: number[] }).target[0] = 99;
    expect(verifyGoalCommitment(c.goal, c.commitment)).toBe(true);
  });
  it('a step verified under a tampered goal fails', () => {
    const { g, c, t } = setup();
    const r = ok(t.step(x(5, 5), 'a0'));
    expect(verifyProgressStep(g, c, r.step).ok).toBe(true);
    expect(verifyProgressStep({ ...g, epsilon: 1 }, c, r.step)).toEqual({ ok: false, reason: 'goal-mismatch' });
  });
});

describe('per-action progress', () => {
  it('a progressing action proves out and spends nothing', () => {
    const { g, c, t } = setup();
    const r = t.step(x(5, 5), 'a0');
    expect(r.ok && r.step.mode).toBe('progress');
    expect(t.spent).toBe(0);
    if (r.ok) expect(verifyProgressStep(g, c, r.step)).toEqual({ ok: true, charge: 0 });
  });
  it('a regressing action fails unless it draws exploration budget', () => {
    const { t } = setup({ explorationBudget: 0 });
    expect(t.step(x(-1, 0), 'bad')).toMatchObject({ ok: false, reason: 'exploration-exhausted', stepUp: true });
    const s2 = setup({ explorationBudget: 20 });
    const r = ok(s2.t.step(x(-1, 0), 'explore')); // 20 -> 21, shortfall 21-(20-2)=3
    expect(r.step.mode).toBe('exploration');
    expect(r.step.charge).toBe(3);
    expect(s2.t.spent).toBe(3);
    expect(verifyProgressStep(s2.g, s2.c, r.step)).toEqual({ ok: true, charge: 3 });
  });
  it('insufficient descent (< epsilon) is exploration, charged the gap', () => {
    const { t } = setup();
    const r = t.step(x(1, 0), 'tiny'); // 20 -> 19, need 18, shortfall 1
    expect(r.ok && r.step.charge).toBe(1);
  });
  it('reaching the goal from closer than epsilon counts as progress', () => {
    const { t } = setup({ epsilon: 5 });
    ok(t.step(x(10, 7), 'a')); // 20 -> 3 (progress)
    const r = ok(t.step(x(10, 10), 'b')); // 3 -> 0, 0 > 3-5 not needed: pa===0 && pb>0
    expect(r.step.mode).toBe('progress');
    expect(t.reached).toBe(true);
  });
  it('mislabelled or forged steps are rejected on re-check', () => {
    const { g, c, t } = setup({ explorationBudget: 20 });
    const r = ok(t.step(x(-1, 0), 'e'));
    const forge = (patch: object) => verifyProgressStep(g, c, { ...r.step, ...patch });
    expect(forge({ mode: 'progress', charge: 0 }).ok).toBe(false);
    expect(forge({ charge: 0 }).ok).toBe(false);
    expect(forge({ potential_after: 5 }).ok).toBe(false);
  });
  it('any unsealed field change is a digest-mismatch', () => {
    const { g, c, t } = setup({ explorationBudget: 20 });
    const r = ok(t.step(x(-1, 0), 'e'));
    expect(verifyProgressStep(g, c, { ...r.step, charge: 0 })).toEqual({ ok: false, reason: 'digest-mismatch' });
    expect(verifyProgressStep(g, c, { ...r.step, action_digest: 'z' })).toEqual({ ok: false, reason: 'digest-mismatch' });
  });
  it('malformed step input fails closed and never throws', () => {
    const { g, c } = setup();
    for (const bad of [null, undefined, 5, {}, { digest: 1 }, []]) {
      expect(verifyProgressStep(g, c, bad as unknown as ProgressStep)).toEqual({ ok: false, reason: 'malformed' });
    }
  });
  it('rejects empty action digest', () => {
    const { t } = setup();
    expect(t.step(x(5, 5), '')).toMatchObject({ ok: false, reason: 'malformed' });
  });
  it('rejects states the potential cannot score, without advancing', () => {
    const { t } = setup();
    const before = t.currentStateDigest;
    expect(t.step({ x: [1.5, 0] }, 'a')).toMatchObject({ ok: false, reason: 'bad-potential' });
    expect(t.step({ nope: 1 }, 'a')).toMatchObject({ ok: false, reason: 'bad-potential' });
    expect(t.step({ x: [undefined, 0] }, 'a')).toMatchObject({ ok: false, reason: 'bad-potential' });
    expect(t.currentStateDigest).toBe(before);
    expect(t.steps.length).toBe(0);
  });
});

describe('exploration budget accounting is exact', () => {
  it('charges are the integer shortfalls and sum exactly to spent', () => {
    const { g, c, t } = setup({ explorationBudget: 9 });
    // 20 ->19 (charge 1) ->19 (charge 2) ->22 (3 over need 17 => 5)  total 8
    expect(ok(t.step(x(1, 0), 'a')).step.charge).toBe(1);
    expect(ok(t.step(x(1, 0), 'b')).step.charge).toBe(2);
    expect(ok(t.step(x(-2, 0), 'c')).step.charge).toBe(5);
    expect(t.spent).toBe(8);
    expect(t.remaining).toBe(1);
    // a charge-2 step does not fit in 1 remaining
    expect(t.step(x(-2, 0), 'd')).toMatchObject({ ok: false, reason: 'exploration-exhausted', stepUp: true });
    expect(t.spent).toBe(8);
    // a charge-exactly-1 step does fit and lands exactly on the budget
    expect(ok(t.step(x(-1, 0), 'e')).remaining).toBe(0);
    const r = ok(verifyTrajectory(g, c, t.steps));
    expect(r.spent).toBe(9);
    expect(r.remaining).toBe(0);
  });
  it('never exceeds the budget: strict (spent == budget allowed, +1 refused)', () => {
    const { t } = setup({ explorationBudget: 3 });
    ok(t.step(x(-1, 0), 'a')); // 20->21 need 18 -> 3
    expect(t.remaining).toBe(0);
    expect(t.step(x(-2, 0), 'b').ok).toBe(false);
    expect(t.step(x(5, 5), 'c').ok).toBe(true); // progress still free
  });
  it('exhaustion forces denial/step-up and leaves state unchanged', () => {
    const { t } = setup({ explorationBudget: 2 });
    expect(t.step(x(1, 0), 'e1').ok).toBe(true);
    expect(t.step(x(1, 1), 'e2').ok).toBe(true);
    const before = t.state;
    const r = t.step(x(0, 1), 'e3');
    expect(r).toMatchObject({ ok: false, reason: 'exploration-exhausted', stepUp: true });
    expect(t.state).toBe(before);
    expect(t.step(x(5, 5), 'ok').ok).toBe(true);
  });
  it('a verifier rejects a chain whose total charge exceeds the budget even if each step is valid', () => {
    // build under a big budget, then verify the SAME chain against a smaller budget goal: goal-mismatch
    const big = setup({ explorationBudget: 20 });
    ok(big.t.step(x(-5, 0), 'a'));
    ok(big.t.step(x(-10, 0), 'b'));
    const small = goal({ explorationBudget: 10 });
    const sc = commitGoal(small).commitment;
    expect(verifyTrajectory(small, sc, big.t.steps).ok).toBe(false);
    expect(verifyTrajectory({ ...big.g, explorationBudget: 10 }, big.c, big.t.steps)).toMatchObject({ reason: 'goal-mismatch' });
  });
});

describe('determinism & registry', () => {
  it('re-check is stable and independent of tracker', () => {
    const { g, c, t } = setup();
    const r = ok(t.step(x(4, 4), 'a'));
    const v = Array.from({ length: 5 }, () => verifyProgressStep(g, c, r.step));
    expect(new Set(v.map((a) => JSON.stringify(a))).size).toBe(1);
    const t2 = new ProgressTracker(g, c, x(0, 0));
    expect(ok(t2.step(x(4, 4), 'a')).step.digest).toBe(r.step.digest);
  });
  it('unknown potential id fails closed; custom registry (class or record) works', () => {
    const g = goal({ potential: 'sq', objective: null });
    const c = commitGoal(g).commitment;
    expect(() => new ProgressTracker(g, c, { v: 5 })).toThrow();
    const sq = (_o: unknown, s: unknown) => (s as { v: number }).v ** 2;
    const reg = new PotentialRegistry().register('sq', sq);
    const t = new ProgressTracker(g, c, { v: 5 }, reg);
    const r = ok(t.step({ v: 3 }, 'a')); // 25 -> 9
    expect(r.step.mode).toBe('progress');
    expect(verifyProgressStep(g, c, r.step)).toEqual({ ok: false, reason: 'unknown-potential' });
    expect(verifyProgressStep(g, c, r.step, { registry: reg }).ok).toBe(true);
    expect(verifyProgressStep(g, c, r.step, { registry: { sq } }).ok).toBe(true);
  });
  it('inherited object keys never resolve as potentials', () => {
    for (const id of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
      const g = goal({ potential: id });
      const c = commitGoal(g).commitment;
      expect(() => new ProgressTracker(g, c, x(0, 0))).toThrow(/unknown potential/);
      expect(() => new ProgressTracker(g, c, x(0, 0), {})).toThrow(/unknown potential/);
    }
  });
  it('registry: ids immutable, validated, sorted, freezable', () => {
    const r = new PotentialRegistry().register('b-v1', () => 0).register('a-v1', () => 0);
    expect(r.ids()).toEqual(['a-v1', 'b-v1']);
    expect(() => r.register('a-v1', () => 1)).toThrow(/already/);
    expect(() => r.register('', () => 1)).toThrow();
    expect(() => r.register('x', 5 as never)).toThrow();
    r.freeze();
    expect(() => r.register('c-v1', () => 0)).toThrow(/frozen/);
    expect(PotentialRegistry.defaults().ids()).toEqual(['dag-remaining-v1', 'dag-weighted-v1', 'l1-feature-v1']);
  });
  it('embedder is enforced: committed embedder must equal the registered one', () => {
    const fn = (_o: unknown, s: unknown) => (s as { v: number }).v;
    const reg = new PotentialRegistry().register('emb-pot-v1', fn, 'emb-A');
    const good = goal({ potential: 'emb-pot-v1', embedder: 'emb-A', objective: null });
    const bad = goal({ potential: 'emb-pot-v1', embedder: 'emb-B', objective: null });
    const noEmb = goal({ potential: 'emb-pot-v1', objective: null });
    expect(() => new ProgressTracker(good, commitGoal(good).commitment, { v: 3 }, reg)).not.toThrow();
    expect(() => new ProgressTracker(bad, commitGoal(bad).commitment, { v: 3 }, reg)).toThrow(/embedder/);
    expect(() => new ProgressTracker(noEmb, commitGoal(noEmb).commitment, { v: 3 }, reg)).toThrow(/embedder/);
    const t = new ProgressTracker(good, commitGoal(good).commitment, { v: 9 }, reg);
    const s = ok(t.step({ v: 5 }, 'a')).step;
    const otherReg = new PotentialRegistry().register('emb-pot-v1', fn, 'emb-Z');
    expect(verifyProgressStep(good, commitGoal(good).commitment, s, { registry: otherReg })).toEqual({
      ok: false,
      reason: 'embedder-mismatch',
    });
  });
  it('a potential returning a negative, fractional or throwing value is bad-potential', () => {
    for (const fn of [() => -1, () => 1.5, () => Number.NaN, () => { throw new Error('boom'); }]) {
      const g = goal({ potential: 'p', objective: null });
      const c = commitGoal(g).commitment;
      expect(() => new ProgressTracker(g, c, {}, { p: fn })).toThrow();
    }
  });
  it('tracker snapshots states: mutating a passed-in state afterwards does not corrupt the proof', () => {
    const { g, c, t } = setup();
    const s = x(5, 5);
    const r = ok(t.step(s, 'a'));
    s.x[0] = 1000;
    expect(verifyProgressStep(g, c, r.step).ok).toBe(true);
    expect(ok(t.step(x(8, 8), 'b')).step.before).toEqual(x(5, 5));
  });
});

describe('potentials', () => {
  it('l1-feature-v1: distance, shape and integer checks', () => {
    const { t } = setup();
    expect(ok(t.step(x(10, 4), 'a')).step.potential_after).toBe(6);
    expect(t.step({ x: [1, 2, 3] }, 'b')).toMatchObject({ ok: false, reason: 'bad-potential' });
    expect(() => new ProgressTracker(goal({ objective: { target: [1, 'a'] } }), commitGoal(goal({ objective: { target: [1, 'a'] } })).commitment, x(0, 0))).toThrow();
  });
  it('l1-feature-v1: overflow is rejected, not wrapped', () => {
    const M = Number.MAX_SAFE_INTEGER;
    const g = goal({ objective: { target: [M, M] } });
    const c = commitGoal(g).commitment;
    expect(() => new ProgressTracker(g, c, { x: [-M, -M] })).toThrow(/safe integer/);
  });
  it('dag-remaining-v1: remaining cost, duplicate ids rejected', () => {
    const g: Goal = {
      objective: { tasks: [{ id: 'a', cost: 3 }, { id: 'b', cost: 4 }, { id: 'c', cost: 2 }] },
      potential: 'dag-remaining-v1',
      metric: 'remaining-cost',
      epsilon: 2,
      explorationBudget: 3,
    };
    const c = commitGoal(g).commitment;
    const t = new ProgressTracker(g, c, { done: [] });
    expect(ok(t.step({ done: ['a'] }, '1')).step.potential_after).toBe(6);
    expect(ok(t.step({ done: ['a'] }, '2')).step.charge).toBe(2); // no-op
    expect(t.step({ done: ['a'] }, '3')).toMatchObject({ ok: false, stepUp: true });
    expect(t.step({ done: ['zzz'] }, '4')).toMatchObject({ ok: false, reason: 'bad-potential' });
    expect(ok(t.step({ done: ['a', 'b', 'c'] }, '5')).step.mode).toBe('progress');
    expect(verifyTrajectory(g, c, t.steps, { initial: { done: [] } })).toMatchObject({ ok: true, reached: true, spent: 2 });
    const dup: Goal = { ...g, objective: { tasks: [{ id: 'a', cost: 1 }, { id: 'a', cost: 1 }] } };
    expect(() => new ProgressTracker(dup, commitGoal(dup).commitment, { done: [] })).toThrow();
  });

  const wg = (over: Partial<Goal> = {}): Goal => ({
    objective: {
      tasks: [
        { id: 'design', cost: 2 },
        { id: 'build', cost: 8, deps: ['design'] },
        { id: 'test', cost: 3, deps: ['build'] },
        { id: 'docs', cost: 1, deps: ['design'] },
      ],
    },
    potential: 'dag-weighted-v1',
    metric: 'remaining-weighted-cost',
    epsilon: 1,
    explorationBudget: 0,
    ...over,
  });
  it('dag-weighted-v1: weighted remaining cost with dependency-closed states', () => {
    const g = wg();
    const c = commitGoal(g).commitment;
    const t = new ProgressTracker(g, c, { done: [] });
    expect(ok(t.step({ done: ['design'] }, '1')).step.potential_after).toBe(12);
    expect(ok(t.step({ done: ['design', 'docs'] }, '2')).step.potential_after).toBe(11);
    expect(ok(t.step({ done: ['design', 'docs', 'build'] }, '3')).step.potential_after).toBe(3);
    expect(ok(t.step({ done: ['design', 'docs', 'build', 'test'] }, '4')).step.mode).toBe('progress');
    expect(verifyTrajectory(g, c, t.steps, { initial: { done: [] } })).toMatchObject({ ok: true, reached: true, spent: 0 });
  });
  it('dag-weighted-v1: claiming a task done before its dependency is refused (cannot game out-of-order)', () => {
    const g = wg();
    const t = new ProgressTracker(g, commitGoal(g).commitment, { done: [] });
    expect(t.step({ done: ['build'] }, '1')).toMatchObject({ ok: false, reason: 'bad-potential' });
    expect(t.step({ done: ['design', 'design'] }, '1')).toMatchObject({ ok: false, reason: 'bad-potential' });
  });
  it('dag-weighted-v1: cycles, unknown deps, self deps, negative costs are rejected', () => {
    const f = (tasks: unknown) => () => dagWeightedPotential({ tasks }, { done: [] });
    expect(f([{ id: 'a', cost: 1, deps: ['b'] }, { id: 'b', cost: 1, deps: ['a'] }])).toThrow(/cycle/);
    expect(f([{ id: 'a', cost: 1, deps: ['a'] }])).toThrow();
    expect(f([{ id: 'a', cost: 1, deps: ['nope'] }])).toThrow();
    expect(f([{ id: 'a', cost: -1 }])).toThrow();
    expect(f([{ id: 'a', cost: 1.5 }])).toThrow();
    expect(f([{ id: 'a', cost: 1 }, { id: 'a', cost: 2 }])).toThrow();
    expect(f([{ id: '', cost: 1 }])).toThrow();
    expect(f([{ id: 'a', cost: 1, deps: [3] }])).toThrow();
    expect(f([{ id: 'a', cost: 0 }])).not.toThrow();
  });
  it('dag-weighted-v1: order-independent and diamond-safe', () => {
    const tasks = [
      { id: 'a', cost: 1 },
      { id: 'b', cost: 2, deps: ['a'] },
      { id: 'c', cost: 3, deps: ['a'] },
      { id: 'd', cost: 4, deps: ['b', 'c', 'b'] },
    ];
    expect(dagWeightedPotential({ tasks }, { done: ['a', 'c'] })).toBe(6);
    expect(dagWeightedPotential({ tasks }, { done: ['c', 'a'] })).toBe(6);
    expect(dagWeightedPotential({ tasks: [...tasks].reverse() }, { done: ['a', 'c'] })).toBe(6);
  });
  it('a unit-cost, epsilon=1, budget=0 DAG is a strict plan: only descending steps pass', () => {
    const g = wg({
      objective: { tasks: [{ id: 'p', cost: 1 }, { id: 'q', cost: 1, deps: ['p'] }] },
    });
    const t = new ProgressTracker(g, commitGoal(g).commitment, { done: [] });
    expect(t.step({ done: [] }, 'noop')).toMatchObject({ ok: false, stepUp: true });
    expect(t.step({ done: ['p'] }, 'p').ok).toBe(true);
  });
});

describe('trajectory and state-digest continuity', () => {
  it('a full adaptive trajectory stays within the exploration bound and reaches the goal', () => {
    const { g, c, t } = setup({ explorationBudget: 6 });
    const path = [x(3, 3), x(2, 3) /*regress*/, x(6, 5), x(7, 4) /*sidestep*/, x(9, 9), x(10, 10)];
    for (const [i, s] of path.entries()) expect(t.step(s, `a${i}`).ok).toBe(true);
    const r = ok(verifyTrajectory(g, c, t.steps, { initial: x(0, 0) }));
    expect(r).toMatchObject({ reached: true, finalPotential: 0, steps: 6 });
    expect(r.spent).toBeLessThanOrEqual(g.explorationBudget);
    expect(r.spent).toBe(t.spent);
    expect(r.spent).toBeGreaterThan(0);
    expect(r.head).toBe(trajectoryHead(t.steps));
  });
  it('each step commits before/after digests that chain end to start', () => {
    const { t } = setup();
    for (const s of [x(3, 3), x(6, 6), x(9, 9)]) ok(t.step(s, 'a'));
    const st = t.steps;
    expect(st[0]!.before_digest).toBe(stateDigest(x(0, 0)));
    for (let i = 0; i < st.length - 1; i++) expect(st[i]!.after_digest).toBe(st[i + 1]!.before_digest);
    expect(t.currentStateDigest).toBe(st[2]!.after_digest);
  });
  it('invariant holds under a long random walk (3000 steps): spent <= budget always, verified', () => {
    let seed = 12345;
    const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
    const { g, c, t } = setup({ explorationBudget: 15 });
    let accepted = 0;
    let sum = 0;
    for (let i = 0; i < 3000; i++) {
      const r = t.step(x(Math.floor(rnd() * 25) - 5, Math.floor(rnd() * 25) - 5), `a${i}`);
      if (r.ok) {
        accepted++;
        sum += r.step.charge;
      }
      expect(t.spent).toBeLessThanOrEqual(15);
    }
    expect(accepted).toBeGreaterThan(0);
    expect(sum).toBe(t.spent);
    const v = ok(verifyTrajectory(g, c, t.steps, { initial: x(0, 0) }));
    expect(v.spent).toBe(sum);
    expect(v.spent).toBeLessThanOrEqual(15);
  });
  it('detects splice, reorder, tampered charge, discontinuity, drop-first and over-budget forgeries', () => {
    const { g, c, t } = setup({ explorationBudget: 20 });
    for (const s of [x(3, 3), x(2, 3), x(6, 6)]) ok(t.step(s, 'a'));
    const st = t.steps;
    expect(verifyTrajectory(g, c, [st[0]!, st[2]!]).ok).toBe(false); // splice
    expect(verifyTrajectory(g, c, [st[1]!, st[0]!, st[2]!]).ok).toBe(false); // reorder
    expect(verifyTrajectory(g, c, [st[1]!, st[2]!])).toMatchObject({ ok: false, at: 0 }); // drop first
    expect(verifyTrajectory(g, c, [{ ...st[0]!, charge: 1 }, st[1]!]).ok).toBe(false); // forged charge
    expect(verifyTrajectory(g, c, st, { initial: x(1, 1) })).toMatchObject({ ok: false, reason: 'discontinuous-state' });
    expect(verifyTrajectory(g, c, st, { initialDigest: st[0]!.before_digest }).ok).toBe(true);
    expect(verifyTrajectory(g, c, st, { initialDigest: 'nope' })).toMatchObject({ ok: false, reason: 'discontinuous-state' });
    expect(verifyTrajectory({ ...g, explorationBudget: 1 }, c, st)).toMatchObject({ ok: false, reason: 'goal-mismatch' });
    expect(verifyTrajectory(g, c, 'x' as never)).toMatchObject({ ok: false, reason: 'malformed' });
  });
  it('a re-sealed chain with a state discontinuity is caught by digest continuity', () => {
    // two honest trackers, stitched together: each step is individually valid and correctly chained
    // inside its own tracker, but the seam is discontinuous / chain-broken.
    const a = setup({ explorationBudget: 20 });
    const b = setup({ explorationBudget: 20 });
    ok(a.t.step(x(3, 3), 'a'));
    ok(b.t.step(x(7, 7), 'b')); // seq 0 again
    ok(b.t.step(x(8, 8), 'c'));
    const stitched = [a.t.steps[0]!, b.t.steps[1]!];
    expect(verifyTrajectory(a.g, a.c, stitched)).toMatchObject({ ok: false, at: 1 });
  });
  it('tampered state with consistent claims is caught by the state digest', () => {
    const { g, c, t } = setup();
    const r = ok(t.step(x(5, 5), 'a'));
    const lie = { ...r.step, after: x(10, 10) };
    expect(verifyProgressStep(g, c, lie).ok).toBe(false);
    expect(verifyProgressStep(g, c, { ...r.step, before_digest: 'x' }).ok).toBe(false);
  });
  it('expectedActionDigests binds each step in a trajectory to its action', () => {
    const { g, c, t } = setup();
    ok(t.step(x(3, 3), 'A'));
    ok(t.step(x(6, 6), 'B'));
    expect(verifyTrajectory(g, c, t.steps, { expectedActionDigests: ['A', 'B'] }).ok).toBe(true);
    expect(verifyTrajectory(g, c, t.steps, { expectedActionDigests: ['B', 'A'] })).toMatchObject({ reason: 'action-mismatch', at: 0 });
    expect(verifyTrajectory(g, c, t.steps, { expectedActionDigests: ['A'] })).toMatchObject({ reason: 'action-mismatch' });
  });
  it('empty trajectory verifies; with initial it reports the potential', () => {
    const { g, c } = setup();
    expect(verifyTrajectory(g, c, [])).toMatchObject({ ok: true, steps: 0, reached: false, finalPotential: -1, head: 'genesis' });
    expect(verifyTrajectory(g, c, [], { initial: x(0, 0) })).toMatchObject({ ok: true, finalPotential: 20 });
    expect(verifyTrajectory(g, c, [], { initial: x(10, 10) })).toMatchObject({ ok: true, reached: true });
  });
});

describe('signed, bound proofs', () => {
  const kp = generateKeyPair();
  const holder = b64u(kp.publicKey);
  const signed = () => {
    const s = setup({ explorationBudget: 20 });
    const step = ok(s.t.step(x(5, 5), 'ACTION-1')).step;
    return { ...s, step, sp: signProgressStep(step, kp.secretKey, holder) };
  };
  const opts = (over = {}) => ({ expectedActionDigest: 'ACTION-1', expectedHolder: holder, ...over });

  it('verifies offline with only goal, commitment, action digest and holder key', () => {
    const { g, c, sp } = signed();
    expect(verifySignedProgressStep(g, c, sp, opts())).toEqual({ ok: true, charge: 0 });
    // a JSON round trip (wire) still verifies
    expect(verifySignedProgressStep(g, c, JSON.parse(JSON.stringify(sp)), opts()).ok).toBe(true);
  });
  it('rejects re-binding to another action', () => {
    const { g, c, sp } = signed();
    expect(verifySignedProgressStep(g, c, sp, opts({ expectedActionDigest: 'ACTION-2' }))).toEqual({ ok: false, reason: 'action-mismatch' });
  });
  it('rejects a lifted proof whose action_digest was rewritten (digest and signature break)', () => {
    const { g, c, sp } = signed();
    const lifted = { ...sp, step: { ...sp.step, action_digest: 'ACTION-2' } };
    expect(verifySignedProgressStep(g, c, lifted, opts({ expectedActionDigest: 'ACTION-2' })).ok).toBe(false);
  });
  it('rejects re-binding to another goal', () => {
    const { g, c, sp } = signed();
    const g2 = goal({ explorationBudget: 21 });
    const c2 = commitGoal(g2).commitment;
    expect(verifySignedProgressStep(g2, c2, sp, opts())).toEqual({ ok: false, reason: 'goal-mismatch' });
    expect(verifySignedProgressStep(g, c2, sp, opts()).ok).toBe(false);
  });
  it('rejects re-binding to another state transition', () => {
    const { g, c, sp, step } = signed();
    expect(verifySignedProgressStep(g, c, sp, opts({ expectedBeforeDigest: stateDigest(x(1, 1)) }))).toEqual({ ok: false, reason: 'state-mismatch' });
    expect(verifySignedProgressStep(g, c, sp, opts({ expectedAfterDigest: stateDigest(x(9, 9)) }))).toEqual({ ok: false, reason: 'state-mismatch' });
    expect(verifySignedProgressStep(g, c, sp, opts({ expectedBeforeDigest: step.before_digest, expectedAfterDigest: step.after_digest })).ok).toBe(true);
    const swapped = { ...sp, step: { ...sp.step, after: x(10, 10), after_digest: stateDigest(x(10, 10)) } };
    expect(verifySignedProgressStep(g, c, swapped, opts()).ok).toBe(false);
  });
  it('rejects a wrong holder, a foreign signer, a stripped/garbled signature and a wrong domain', () => {
    const { g, c, sp, step } = signed();
    const other = generateKeyPair();
    const otherId = b64u(other.publicKey);
    expect(verifySignedProgressStep(g, c, sp, opts({ expectedHolder: otherId }))).toEqual({ ok: false, reason: 'holder-mismatch' });
    // signer signs with its own key but claims the expected holder id
    const forged = signProgressStep(step, other.secretKey, holder);
    expect(verifySignedProgressStep(g, c, forged, opts())).toEqual({ ok: false, reason: 'bad-signature' });
    // honest other-key signature under its own id is fine only if that id is expected
    const mine = signProgressStep(step, other.secretKey, otherId);
    expect(verifySignedProgressStep(g, c, mine, opts({ expectedHolder: otherId })).ok).toBe(true);
    expect(verifySignedProgressStep(g, c, { ...sp, sig: '' }, opts())).toEqual({ ok: false, reason: 'bad-signature' });
    expect(verifySignedProgressStep(g, c, { ...sp, sig: 'AAAA' }, opts())).toEqual({ ok: false, reason: 'bad-signature' });
    expect(verifySignedProgressStep(g, c, null as never, opts())).toEqual({ ok: false, reason: 'malformed' });
  });
  it('a valid signature does not launder a forged claim: the recompute still runs', () => {
    const { g, c, t } = signed();
    // dishonest prover signs a step whose claimed state does not match: build body by hand is blocked by digest
    const step = ok(t.step(x(-3, 0), 'ACTION-1')).step; // exploration, charge > 0
    const sp = signProgressStep({ ...step, charge: 0 }, kp.secretKey, holder);
    expect(verifySignedProgressStep(g, c, sp, opts()).ok).toBe(false);
  });
  it('signature domain is separated: a signature over the bare step digest is not accepted', () => {
    const { g, c, step, sp } = signed();
    const naive = { ...sp, sig: b64u(sign(kp.secretKey, new TextEncoder().encode(step.digest))) };
    expect(verifySignedProgressStep(g, c, naive, opts())).toEqual({ ok: false, reason: 'bad-signature' });
  });
  it('signed trajectory: verifies, and rejects reorder, wrong actions, mixed holders, bad sigs', () => {
    const s = setup({ explorationBudget: 20 });
    for (const [i, st] of [x(3, 3), x(2, 3), x(6, 6)].entries()) ok(s.t.step(st, `A${i}`));
    const sps = s.t.steps.map((st) => signProgressStep(st, kp.secretKey, holder));
    const base = { expectedHolder: holder, expectedActionDigests: ['A0', 'A1', 'A2'], initial: x(0, 0) };
    expect(verifySignedTrajectory(s.g, s.c, sps, base)).toMatchObject({ ok: true, steps: 3 });
    expect(verifySignedTrajectory(s.g, s.c, [sps[1]!, sps[0]!, sps[2]!], base).ok).toBe(false);
    expect(verifySignedTrajectory(s.g, s.c, sps, { ...base, expectedActionDigests: ['A0', 'A1', 'A9'] })).toMatchObject({ reason: 'action-mismatch', at: 2 });
    expect(verifySignedTrajectory(s.g, s.c, sps.slice(0, 2), base)).toMatchObject({ reason: 'action-mismatch' });
    const o = generateKeyPair();
    const mixed = [sps[0]!, signProgressStep(s.t.steps[1]!, o.secretKey, b64u(o.publicKey)), sps[2]!];
    expect(verifySignedTrajectory(s.g, s.c, mixed, base)).toMatchObject({ reason: 'holder-mismatch', at: 1 });
    expect(verifySignedTrajectory(s.g, s.c, [sps[0]!, { ...sps[1]!, sig: sps[0]!.sig }, sps[2]!], base)).toMatchObject({ reason: 'bad-signature', at: 1 });
    expect(verifySignedTrajectory(s.g, s.c, sps, { ...base, initial: x(1, 1) })).toMatchObject({ reason: 'discontinuous-state' });
  });
});

describe('trusted state source contract', () => {
  it('stepObserved commits the source id + evidence digest and verifies under a trust policy', async () => {
    const { g, c, t } = setup();
    const src = new InMemoryStateSource(x(0, 0), 'rs-1');
    src.apply(x(5, 5));
    const r = ok(await t.stepObserved(src, 'A'));
    expect(r.step.state_source).toBe('rs-1');
    expect(r.step.evidence_digest).not.toBe('');
    expect(src.requests[0]).toMatchObject({ action_digest: 'A', goal_commitment: c, prior_digest: stateDigest(x(0, 0)) });
    expect(verifyProgressStep(g, c, r.step, { trustedStateSources: ['rs-1'] }).ok).toBe(true);
    expect(verifyProgressStep(g, c, r.step, { trustedStateSources: ['other'] })).toEqual({ ok: false, reason: 'untrusted-state-source' });
  });
  it('self-reported steps are visible as such and refused when a trust policy is set', () => {
    const { g, c, t } = setup();
    const r = ok(t.step(x(5, 5), 'A'));
    expect(r.step.state_source).toBe('');
    expect(verifyProgressStep(g, c, r.step, { trustedStateSources: ['rs-1'] })).toEqual({ ok: false, reason: 'untrusted-state-source' });
  });
  it('a source whose digest does not match its state, or that misnames itself, is refused without advancing', async () => {
    const { t } = setup();
    const before = t.currentStateDigest;
    const liar: StateSource = {
      id: 'liar',
      observe: (): StateObservation => ({ state: x(10, 10), state_digest: stateDigest(x(0, 0)), source: 'liar' }),
    };
    const alias: StateSource = {
      id: 'a',
      observe: (): StateObservation => ({ state: x(5, 5), state_digest: stateDigest(x(5, 5)), source: 'b' }),
    };
    const boom: StateSource = { id: 'boom', observe: () => { throw new Error('down'); } };
    for (const s of [liar, alias, boom]) {
      expect(await t.stepObserved(s, 'A')).toMatchObject({ ok: false, reason: 'state-source-mismatch' });
    }
    expect(t.currentStateDigest).toBe(before);
    expect(t.steps.length).toBe(0);
  });
  it('async sources work; a source reporting a regress still draws exploration budget (descent proof is source-independent)', async () => {
    const { g, c, t } = setup({ explorationBudget: 4 });
    const src = new InMemoryStateSource(x(0, 0), 'ex');
    const asyncSrc: StateSource = { id: 'ex', observe: async (q) => src.observe(q) };
    src.apply(x(-1, 0));
    const r = ok(await t.stepObserved(asyncSrc, 'A'));
    expect(r.step.mode).toBe('exploration');
    src.apply(x(-5, 0));
    expect(await t.stepObserved(asyncSrc, 'B')).toMatchObject({ ok: false, reason: 'exploration-exhausted', stepUp: true });
    expect(verifyTrajectory(g, c, t.steps, { trustedStateSources: ['ex'] }).ok).toBe(true);
  });
  it('attestation hook: evidence check is delegated to the verifier-supplied function', async () => {
    const { g, c, t } = setup();
    const src = new InMemoryStateSource(x(0, 0), 'tee');
    src.apply(x(4, 4));
    const r = ok(await t.stepObserved(src, 'A'));
    expect(verifyProgressStep(g, c, r.step, { attestation: (s) => s.state_source === 'tee' }).ok).toBe(true);
    expect(verifyProgressStep(g, c, r.step, { attestation: () => false })).toEqual({ ok: false, reason: 'attestation-failed' });
    expect(verifyProgressStep(g, c, r.step, { attestation: () => { throw new Error('x'); } })).toEqual({ ok: false, reason: 'attestation-failed' });
    expect(verifyProgressStep(g, c, r.step, { attestation: (() => 'yes') as never })).toEqual({ ok: false, reason: 'attestation-failed' });
  });
  it('InMemoryStateSource returns detached snapshots', () => {
    const src = new InMemoryStateSource({ x: [1, 2] }, 's');
    const o = src.observe({ action_digest: 'a', goal_commitment: 'g', prior_digest: 'p' });
    (o.state as { x: number[] }).x[0] = 99;
    expect(src.observe({ action_digest: 'a', goal_commitment: 'g', prior_digest: 'p' }).state).toEqual({ x: [1, 2] });
  });
});

describe('anti-Goodhart composition: prohibitions + bounded exploration', () => {
  // The potential only sees x; a prohibition forbids the region x[0] > 8 no matter how much it descends.
  const guard = ({ after }: { after: unknown }) => (after as { x: number[] }).x[0]! <= 8;
  it('descent cannot buy a prohibited action (tracker)', () => {
    const g = goal();
    const t = new ProgressTracker(g, commitGoal(g).commitment, x(0, 0), undefined, { guard });
    expect(t.step(x(10, 10), 'a')).toMatchObject({ ok: false, reason: 'prohibited', stepUp: false });
    expect(t.steps.length).toBe(0);
    expect(t.step(x(8, 8), 'a').ok).toBe(true);
  });
  it('the verifier re-runs the guard: a rogue prover without the guard is rejected', () => {
    const { g, c, t } = setup(); // no guard
    const r = ok(t.step(x(10, 10), 'a'));
    expect(verifyProgressStep(g, c, r.step).ok).toBe(true);
    expect(verifyProgressStep(g, c, r.step, { guard })).toEqual({ ok: false, reason: 'prohibited' });
    expect(verifyTrajectory(g, c, t.steps, { guard })).toMatchObject({ ok: false, reason: 'prohibited', at: 0 });
  });
  it('a throwing or non-true guard denies (fail closed)', () => {
    const g = goal();
    const c = commitGoal(g).commitment;
    const t1 = new ProgressTracker(g, c, x(0, 0), undefined, { guard: () => { throw new Error('x'); } });
    expect(t1.step(x(5, 5), 'a')).toMatchObject({ reason: 'prohibited' });
    const t2 = new ProgressTracker(g, c, x(0, 0), undefined, { guard: (() => 1) as never });
    expect(t2.step(x(5, 5), 'a')).toMatchObject({ reason: 'prohibited' });
  });
  it('gaming V by wandering is capped: an adversary maximizing steps never exceeds the budget, and net regress is bounded', () => {
    const { g, c, t } = setup({ explorationBudget: 10 });
    // adversary only ever tries zero-progress steps (stay put) until refused
    let accepted = 0;
    for (let i = 0; i < 1000; i++) if (t.step(x(0, 0), `n${i}`).ok) accepted++;
    // each no-op costs epsilon=2 => exactly 5 accepted
    expect(accepted).toBe(5);
    expect(t.spent).toBe(10);
    // trajectory-level bound: V(final) <= V(initial) - eps*#progress + budget
    const v = ok(verifyTrajectory(g, c, t.steps));
    const prog = t.steps.filter((s) => s.mode === 'progress').length;
    expect(v.finalPotential).toBeLessThanOrEqual(20 - g.epsilon * prog + g.explorationBudget);
  });
  it('the exact descent identity holds on a random mixed trajectory: V_final <= V0 - eps*(#non-terminal steps) + spent', () => {
    let seed = 7;
    const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
    const { g, c, t } = setup({ explorationBudget: 12 });
    for (let i = 0; i < 500; i++) t.step(x(Math.floor(rnd() * 21), Math.floor(rnd() * 21)), `a${i}`);
    const v = ok(verifyTrajectory(g, c, t.steps));
    const counted = t.steps.filter((s) => s.potential_after !== 0).length;
    expect(v.finalPotential).toBeLessThanOrEqual(20 - g.epsilon * counted + v.spent);
    expect(v.spent).toBeLessThanOrEqual(12);
  });
});
