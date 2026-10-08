/**
 * Proof-of-progress toward committed intent (frontier §3.1).
 *
 * Authority = faithful pursuit of a committed intent. At grant time the goal
 * (objective, potential id, embedder id, metric, epsilon, exploration budget) is hashed into a
 * commitment. Each action then carries a step proof that either
 *   (progress)    potential(after) <= potential(before) - epsilon, or
 *   (exploration) it does not, and the shortfall is charged to a bounded exploration budget.
 * A verifier recomputes the potential from the committed id and the carried states; nothing the
 * prover says about potentials is trusted. Invariant (strict): sum(exploration charges) <= budget.
 *
 * BINDING. Every step commits, inside one hash-chained body, to: the goal commitment, the PCActn
 * action digest, a before-STATE digest and an after-STATE digest, the sequence number and the
 * previous step. A step can be Ed25519-signed (domain-separated) by the acting holder; the signed
 * message repeats the binding fields, and the verifier REQUIRES the expected action digest and
 * holder, so a proof cannot be lifted onto another action, goal, state or key.
 *
 * TRUSTED STATE. The descent proof is only as honest as the states it is computed over. This module
 * fully builds the COMMITMENT to the states (state digests, continuity, the descent proof, optional
 * source id + evidence digest) and defines the {@link StateSource} contract that a resource-server
 * receipt / attested executor / TEE / zk system implements. Wiring a real source is an integration
 * concern (see the design note); an in-memory source is provided for tests.
 *
 * All quantities are safe integers so recomputation is bit-exact across implementations. Potentials
 * are pure functions resolved from a verifier-held {@link PotentialRegistry}; an unknown committed id
 * fails closed. Negative authority (prohibitions) composes through the {@link StepGuard} hook:
 * descent can never buy an action a guard forbids, and exploration is capped by the budget, which
 * together bound how far an agent can game the potential (anti-Goodhart; see design note).
 */
import { b64u, canonicalBytes, canonicalize, hashCanonical } from './hash';
import { sign, verifyB64u } from './keys';

/** Wire/commitment format version of goals, steps and signed proofs. */
export const PROGRESS_VERSION = 2;

/** Domain separator of the Ed25519 signature over a progress step. */
export const PROGRESS_SIG_DOMAIN = 'atlas-pca/progress-step/v2';

/** A potential maps (objective, state) to a non-negative safe integer: "distance to goal". Must be pure. */
export type PotentialFn = (objective: unknown, state: unknown) => number;

function assertInt(n: unknown, what: string): asserts n is number {
  if (typeof n !== 'number' || !Number.isSafeInteger(n)) throw new TypeError(`${what}: safe integer required`);
}

const isObj = (x: unknown): x is Record<string, unknown> => x !== null && typeof x === 'object' && !Array.isArray(x);
const isStr = (x: unknown): x is string => typeof x === 'string';

/** Deep, canonical, detached copy of a state/objective so later caller mutation cannot desync a proof. */
function snapshot<T>(v: T): T {
  return JSON.parse(canonicalize(v)) as T;
}

// ======================================================================================
// Potentials and the registry
// ======================================================================================

/** A registered potential: the function and the embedder id it is bound to (committed in the goal). */
export interface PotentialSpec {
  fn: PotentialFn;
  /** Id of the embedding/feature extractor the potential uses ('' = none). Must equal Goal.embedder. */
  embedder?: string;
}

/**
 * Verifier-held registry of version-pinned potentials. Lookups are by OWN key only (an id such as
 * `constructor` or `__proto__` can never resolve to an inherited function), ids cannot be shadowed
 * once registered, and the registry can be frozen. An id that is not registered fails closed.
 */
export class PotentialRegistry {
  private readonly m = new Map<string, PotentialSpec>();
  private frozen = false;

  /** Register `fn` under `id` (idempotent re-registration is refused: ids are immutable). */
  register(id: string, fn: PotentialFn, embedder = ''): this {
    if (this.frozen) throw new Error('registry is frozen');
    if (!isStr(id) || id.length === 0 || id.length > 128) throw new TypeError('potential id: 1..128 chars');
    if (typeof fn !== 'function') throw new TypeError('potential must be a function');
    if (!isStr(embedder)) throw new TypeError('embedder must be a string');
    if (this.m.has(id)) throw new Error(`potential ${id} already registered`);
    this.m.set(id, { fn, embedder });
    return this;
  }
  /** Resolve a committed id, or undefined (callers must treat that as a denial). */
  get(id: string): PotentialSpec | undefined {
    return this.m.get(id);
  }
  has(id: string): boolean {
    return this.m.has(id);
  }
  /** Registered ids, sorted (deterministic). */
  ids(): string[] {
    return [...this.m.keys()].sort();
  }
  /** Forbid further registration. Returns this. */
  freeze(): this {
    this.frozen = true;
    return this;
  }
  /** Build from a plain record (own enumerable keys only). */
  static from(rec: Record<string, PotentialFn | PotentialSpec>): PotentialRegistry {
    const r = new PotentialRegistry();
    for (const k of Object.keys(rec)) {
      const v = rec[k]!;
      if (typeof v === 'function') r.register(k, v);
      else r.register(k, v.fn, v.embedder ?? '');
    }
    return r;
  }
  /** A fresh, mutable registry holding the three built-in potentials. */
  static defaults(): PotentialRegistry {
    return new PotentialRegistry()
      .register('l1-feature-v1', l1FeaturePotential)
      .register('dag-remaining-v1', dagRemainingPotential)
      .register('dag-weighted-v1', dagWeightedPotential);
  }
}

/** Anything accepted where a registry is expected (a plain record is converted, own keys only). */
export type RegistryInput = PotentialRegistry | Record<string, PotentialFn | PotentialSpec>;

function toRegistry(r: RegistryInput | undefined): PotentialRegistry {
  if (r === undefined) return DEFAULT_POTENTIALS;
  return r instanceof PotentialRegistry ? r : PotentialRegistry.from(r);
}

/** Built-in potential 1: L1 distance in a committed feature space. objective {target:int[]}, state {x:int[]}. */
export const l1FeaturePotential: PotentialFn = (objective, state) => {
  const t = (objective as { target?: number[] })?.target;
  const x = (state as { x?: number[] })?.x;
  if (!Array.isArray(t) || !Array.isArray(x) || t.length !== x.length) throw new TypeError('l1-feature-v1: bad shape');
  let d = 0;
  for (let i = 0; i < t.length; i++) {
    assertInt(t[i], 'target');
    assertInt(x[i], 'x');
    d += Math.abs(t[i]! - x[i]!);
    assertInt(d, 'distance');
  }
  return d;
};

/** Built-in potential 2: task-set remaining work. objective {tasks:[{id,cost}]}, state {done:string[]}. */
export const dagRemainingPotential: PotentialFn = (objective, state) => {
  const tasks = (objective as { tasks?: { id: string; cost: number }[] })?.tasks;
  const done = (state as { done?: string[] })?.done;
  if (!Array.isArray(tasks) || !Array.isArray(done)) throw new TypeError('dag-remaining-v1: bad shape');
  const ids = new Set(tasks.map((t) => t.id));
  if (ids.size !== tasks.length) throw new TypeError('dag-remaining-v1: duplicate task id');
  const doneSet = new Set(done);
  for (const d of doneSet) if (!ids.has(d)) throw new TypeError(`dag-remaining-v1: unknown task ${d}`);
  let rem = 0;
  for (const t of tasks) {
    assertInt(t.cost, 'cost');
    if (t.cost < 0) throw new TypeError('negative cost');
    if (!doneSet.has(t.id)) rem += t.cost;
    assertInt(rem, 'remaining');
  }
  return rem;
};

/**
 * Built-in potential 3: weighted-DAG remaining cost with dependency integrity.
 * objective {tasks:[{id, cost:int>=0, deps?:string[]}]} (ids unique, deps known, graph acyclic);
 * state {done:string[]} (unique ids, DEPENDENCY-CLOSED: a task may be done only if all its deps are).
 * V = sum of cost over not-done tasks. The closure rule means a state cannot claim an expensive leaf
 * done while skipping its prerequisites, so remaining cost cannot be cheaply "gamed" by out-of-order
 * claims. Integer-only and order-independent (cross-language recomputable).
 */
export const dagWeightedPotential: PotentialFn = (objective, state) => {
  const tasks = (objective as { tasks?: { id: string; cost: number; deps?: string[] }[] })?.tasks;
  const done = (state as { done?: string[] })?.done;
  if (!Array.isArray(tasks) || !Array.isArray(done)) throw new TypeError('dag-weighted-v1: bad shape');
  const byId = new Map<string, { cost: number; deps: string[] }>();
  for (const t of tasks) {
    if (!isObj(t) || !isStr(t.id) || t.id.length === 0) throw new TypeError('dag-weighted-v1: bad task');
    if (byId.has(t.id)) throw new TypeError('dag-weighted-v1: duplicate task id');
    assertInt(t.cost, 'cost');
    if (t.cost < 0) throw new TypeError('negative cost');
    const deps = t.deps ?? [];
    if (!Array.isArray(deps) || !deps.every(isStr)) throw new TypeError('dag-weighted-v1: bad deps');
    byId.set(t.id, { cost: t.cost, deps });
  }
  // Dependencies must exist, and the graph must be acyclic (Kahn).
  const indeg = new Map<string, number>();
  const rev = new Map<string, string[]>();
  for (const [id, t] of byId) {
    indeg.set(id, new Set(t.deps).size);
    for (const d of new Set(t.deps)) {
      if (d === id || !byId.has(d)) throw new TypeError(`dag-weighted-v1: bad dependency ${d}`);
      rev.set(d, [...(rev.get(d) ?? []), id]);
    }
  }
  const q = [...indeg].filter(([, n]) => n === 0).map(([id]) => id);
  let seen = 0;
  while (q.length) {
    const id = q.pop()!;
    seen++;
    for (const n of rev.get(id) ?? []) {
      const k = indeg.get(n)! - 1;
      indeg.set(n, k);
      if (k === 0) q.push(n);
    }
  }
  if (seen !== byId.size) throw new TypeError('dag-weighted-v1: cycle');
  const doneSet = new Set<string>();
  for (const d of done) {
    if (!isStr(d) || !byId.has(d)) throw new TypeError(`dag-weighted-v1: unknown task ${String(d)}`);
    if (doneSet.has(d)) throw new TypeError('dag-weighted-v1: duplicate done');
    doneSet.add(d);
  }
  for (const d of doneSet) {
    for (const dep of byId.get(d)!.deps) {
      if (!doneSet.has(dep)) throw new TypeError(`dag-weighted-v1: ${d} done before dependency ${dep}`);
    }
  }
  let rem = 0;
  for (const [id, t] of byId) {
    if (!doneSet.has(id)) rem += t.cost;
    assertInt(rem, 'remaining');
  }
  return rem;
};

/** Frozen registry of the built-in potentials (used when none is supplied). */
export const DEFAULT_POTENTIALS: PotentialRegistry = PotentialRegistry.defaults().freeze();

// ======================================================================================
// Goal commitment
// ======================================================================================

export interface Goal {
  objective: unknown;
  /** Committed id of the potential function (resolved via the verifier's registry; unknown => deny). */
  potential: string;
  /** Committed id of the embedder/feature extractor the potential relies on ('' = none). */
  embedder?: string;
  /** Human-readable metric label, committed but not interpreted. */
  metric: string;
  /** Required per-step descent, integer >= 1. */
  epsilon: number;
  /** Total shortfall that may be spent on non-progress steps, integer >= 0. */
  explorationBudget: number;
}

export interface GoalCommitment {
  goal: Goal;
  /** base64url(sha256(canonical(domain-tagged goal))) — goes into the grant. */
  commitment: string;
}

/** Validate a goal's parameters (throws TypeError/RangeError). */
function validateGoal(goal: Goal): void {
  if (!isObj(goal)) throw new TypeError('goal must be an object');
  assertInt(goal.epsilon, 'epsilon');
  assertInt(goal.explorationBudget, 'explorationBudget');
  if (goal.epsilon < 1) throw new RangeError('epsilon must be >= 1');
  if (goal.explorationBudget < 0) throw new RangeError('explorationBudget must be >= 0');
  if (!isStr(goal.potential) || goal.potential.length === 0) throw new TypeError('potential id required');
  if (!isStr(goal.metric)) throw new TypeError('metric must be a string');
  if (goal.embedder !== undefined && !isStr(goal.embedder)) throw new TypeError('embedder must be a string');
}

/** The commitment hash of a goal. Binds objective, potential id, embedder, metric, epsilon and budget. */
export function goalDigest(goal: Goal): string {
  validateGoal(goal);
  return hashCanonical({
    t: 'pca-goal',
    v: PROGRESS_VERSION,
    objective: goal.objective,
    potential: goal.potential,
    embedder: goal.embedder ?? '',
    metric: goal.metric,
    epsilon: goal.epsilon,
    explorationBudget: goal.explorationBudget,
  });
}

/** Commit a goal. The returned goal is a detached canonical snapshot. */
export function commitGoal(goal: Goal): GoalCommitment {
  const c = goalDigest(goal);
  return { goal: snapshot(goal), commitment: c };
}

/** A goal is bound iff it hashes to the commitment the grant carries. Never throws. */
export function verifyGoalCommitment(goal: Goal, commitment: string): boolean {
  try {
    return goalDigest(goal) === commitment;
  } catch {
    return false;
  }
}

// ======================================================================================
// Steps
// ======================================================================================

export type StepMode = 'progress' | 'exploration';

export interface ProgressStep {
  goal_commitment: string;
  /** 0-based position in the trajectory. */
  seq: number;
  before: unknown;
  after: unknown;
  /** stateDigest(before) / stateDigest(after): the committed state transition. */
  before_digest: string;
  after_digest: string;
  /** Digest of the action this step belongs to (e.g. its PCActn params_digest) — binds proof to action. */
  action_digest: string;
  mode: StepMode;
  /** Claimed values; verifier recomputes and rejects any mismatch. */
  potential_before: number;
  potential_after: number;
  /** Exploration charge (0 for progress steps). */
  charge: number;
  /** Id of the StateSource that observed `after` ('' = self-reported by the prover). */
  state_source: string;
  /** hashCanonical(evidence) from the StateSource ('' = none). */
  evidence_digest: string;
  /** Digest of the previous step's body ('genesis' for the first). */
  prev: string;
  /** Digest of this step's body. */
  digest: string;
}

const GENESIS = 'genesis';

function stepBodyDigest(s: Omit<ProgressStep, 'digest'>): string {
  return hashCanonical({ t: 'pca-progress-step', v: PROGRESS_VERSION, ...s });
}

/** Digest committing to a state. States must be canonicalizable JSON (no floats NaN/undefined/cycles). */
export function stateDigest(state: unknown): string {
  return hashCanonical({ t: 'pca-state', state });
}

/** The trajectory head to publish / anchor: the digest of the last step ('genesis' if empty). */
export function trajectoryHead(steps: readonly ProgressStep[]): string {
  return steps.length ? steps[steps.length - 1]!.digest : GENESIS;
}

/** Digest to place in a PCActn (e.g. alongside params_digest) binding the proof to the action. */
export function progressStepDigest(step: ProgressStep): string {
  return step.digest;
}

export type StepDenial =
  | 'goal-mismatch'
  | 'unknown-potential'
  | 'embedder-mismatch'
  | 'bad-potential'
  | 'exploration-exhausted'
  | 'seq-mismatch'
  | 'chain-break'
  | 'discontinuous-state'
  | 'digest-mismatch'
  | 'state-digest-mismatch'
  | 'potential-mismatch'
  | 'mode-mismatch'
  | 'charge-mismatch'
  | 'budget-exceeded'
  | 'malformed'
  | 'action-mismatch'
  | 'state-mismatch'
  | 'bad-signature'
  | 'holder-mismatch'
  | 'prohibited'
  | 'untrusted-state-source'
  | 'attestation-failed'
  | 'state-source-mismatch';

class ProgressError extends Error {
  constructor(readonly code: StepDenial, msg: string) {
    super(msg);
  }
}

function resolve(goal: Goal, reg: PotentialRegistry): PotentialSpec {
  const spec = reg.get(goal.potential);
  if (!spec) throw new ProgressError('unknown-potential', `unknown potential ${goal.potential}`);
  if ((spec.embedder ?? '') !== (goal.embedder ?? '')) throw new ProgressError('embedder-mismatch', 'embedder mismatch');
  return spec;
}

function potentialOf(goal: Goal, reg: PotentialRegistry, state: unknown): number {
  const spec = resolve(goal, reg);
  let p: number;
  try {
    p = spec.fn(goal.objective, state);
    assertInt(p, 'potential');
  } catch (e) {
    throw new ProgressError('bad-potential', (e as Error).message);
  }
  if (p < 0) throw new ProgressError('bad-potential', 'potential must be >= 0');
  return p;
}

function denialOf(e: unknown): StepDenial {
  return e instanceof ProgressError ? e.code : 'bad-potential';
}

/**
 * The single source of truth for mode and charge. Reaching the goal (after == 0) from a state
 * closer than epsilon still counts as progress. Anything else short of `before - epsilon` is
 * exploration, charged the integer shortfall (>= 1).
 */
function classify(pb: number, pa: number, epsilon: number): { mode: StepMode; charge: number } {
  const required = pb - epsilon;
  if (pa <= required || (pa === 0 && pb > 0)) return { mode: 'progress', charge: 0 };
  const charge = pa - required;
  try {
    assertInt(charge, 'charge');
  } catch (e) {
    throw new ProgressError('bad-potential', (e as Error).message);
  }
  return { mode: 'exploration', charge };
}

/**
 * Negative-authority hook (compose a prohibition set here): return true to ALLOW the transition.
 * Throwing or returning anything but `true` denies. Runs in the tracker and in the verifier, so a
 * forbidden action cannot be laundered through a good-looking descent.
 */
export type StepGuard = (t: { seq: number; before: unknown; after: unknown; action_digest: string }) => boolean;

/** Hook letting the verifier check source-specific evidence (receipt / TEE quote / zk) for a step. */
export type StateAttestationVerifier = (step: ProgressStep) => boolean;

// ======================================================================================
// Trusted state contract
// ======================================================================================

/** What a StateSource hands back after an action. */
export interface StateObservation {
  /** The observed world state after the action (canonical JSON). */
  state: unknown;
  /** Must equal stateDigest(state); the commitment the source stands behind. */
  state_digest: string;
  /** Must equal the source's id; recorded in the step. */
  source: string;
  /** Source-specific proof (resource-server receipt, attested-executor statement, TEE quote, zk proof...). */
  evidence?: unknown;
}

/** The request the tracker makes of a source. */
export interface StateObservationRequest {
  action_digest: string;
  goal_commitment: string;
  /** Digest of the state the tracker believes the world is in before the action (continuity anchor). */
  prior_digest: string;
}

/**
 * The trust boundary. A production source observes the REAL effect of the action and attests to it:
 * a resource-server receipt, an attested executor, a TEE quote, or a zk proof that `state` is the
 * result of applying the action to a state with digest `prior_digest`. This module commits to what
 * the source returns; it does not (and cannot) establish the source's honesty.
 */
export interface StateSource {
  readonly id: string;
  observe(req: StateObservationRequest): StateObservation | Promise<StateObservation>;
}

/** In-memory StateSource for tests/demos: the "world" is a value the test mutates via `apply`. */
export class InMemoryStateSource implements StateSource {
  private cur: unknown;
  private n = 0;
  readonly requests: StateObservationRequest[] = [];
  constructor(initial: unknown, readonly id = 'in-memory') {
    this.cur = snapshot(initial);
  }
  /** Mutate the world (what the real action would do). */
  apply(next: unknown): void {
    this.cur = snapshot(next);
  }
  observe(req: StateObservationRequest): StateObservation {
    this.requests.push(req);
    const state = snapshot(this.cur);
    return {
      state,
      state_digest: stateDigest(state),
      source: this.id,
      evidence: { kind: 'in-memory', n: this.n++, prior: req.prior_digest, action: req.action_digest },
    };
  }
}

// ======================================================================================
// Prover / issuer side
// ======================================================================================

export type ProveResult =
  | { ok: true; step: ProgressStep; spent: number; remaining: number }
  | { ok: false; reason: StepDenial; /** exploration exhausted => human step-up or denial */ stepUp: boolean };

export interface TrackerOptions {
  /** Negative-authority check applied to every transition. */
  guard?: StepGuard;
}

/**
 * Stateful tracker of one trajectory: holds the last state, chain head and exploration spent. A step
 * that would push spent over budget is REFUSED (no proof is produced, state does not advance), which
 * is the "forces step-up/denial" mechanism. In-memory: concurrent agents sharing a goal need atomic
 * escrow (design note).
 */
export class ProgressTracker {
  private seq = 0;
  private head = GENESIS;
  private spentTotal = 0;
  private cur: unknown;
  private curDigest: string;
  private readonly log: ProgressStep[] = [];
  private readonly reg: PotentialRegistry;
  /** Detached snapshot of the committed goal. */
  readonly goal: Goal;

  constructor(
    goal: Goal,
    readonly commitment: string,
    initial: unknown,
    registry?: RegistryInput,
    private readonly opts: TrackerOptions = {},
  ) {
    if (!verifyGoalCommitment(goal, commitment)) throw new Error('goal does not match commitment');
    this.goal = snapshot(goal);
    this.reg = toRegistry(registry);
    this.cur = snapshot(initial);
    this.curDigest = stateDigest(this.cur);
    potentialOf(this.goal, this.reg, this.cur); // fail fast: unknown id / embedder / bad initial state
  }

  /** Total exploration charged so far (always <= explorationBudget). */
  get spent(): number {
    return this.spentTotal;
  }
  get remaining(): number {
    return this.goal.explorationBudget - this.spentTotal;
  }
  get state(): unknown {
    return this.cur;
  }
  /** Digest of the current state. */
  get currentStateDigest(): string {
    return this.curDigest;
  }
  get reached(): boolean {
    return potentialOf(this.goal, this.reg, this.cur) === 0;
  }
  /** Proofs issued so far (read-only copy). */
  get steps(): readonly ProgressStep[] {
    return [...this.log];
  }

  /** Attempt a step to a self-reported `after`. Does not advance state on denial. */
  step(after: unknown, actionDigest: string): ProveResult {
    return this.advance(after, actionDigest, '', '');
  }

  /**
   * Observe the post-action state from a trusted StateSource and step to it. The observation's
   * digest and source id are checked, and the source id + evidence digest are committed into the
   * step. Does not advance on any denial.
   */
  async stepObserved(source: StateSource, actionDigest: string): Promise<ProveResult> {
    let obs: StateObservation;
    try {
      obs = await source.observe({
        action_digest: actionDigest,
        goal_commitment: this.commitment,
        prior_digest: this.curDigest,
      });
      if (!obs || obs.source !== source.id || obs.state_digest !== stateDigest(obs.state)) {
        return { ok: false, reason: 'state-source-mismatch', stepUp: false };
      }
      return this.advance(obs.state, actionDigest, source.id, hashCanonical({ t: 'pca-evidence', e: obs.evidence ?? null }));
    } catch {
      return { ok: false, reason: 'state-source-mismatch', stepUp: false };
    }
  }

  private advance(afterIn: unknown, actionDigest: string, stateSource: string, evidenceDigest: string): ProveResult {
    if (!isStr(actionDigest) || actionDigest.length === 0) return { ok: false, reason: 'malformed', stepUp: false };
    let after: unknown, afterDigest: string, pb: number, pa: number, cls: { mode: StepMode; charge: number };
    try {
      after = snapshot(afterIn);
      afterDigest = stateDigest(after);
      pb = potentialOf(this.goal, this.reg, this.cur);
      pa = potentialOf(this.goal, this.reg, after);
      cls = classify(pb, pa, this.goal.epsilon);
    } catch (e) {
      return { ok: false, reason: denialOf(e), stepUp: false };
    }
    if (this.opts.guard && !runGuard(this.opts.guard, { seq: this.seq, before: this.cur, after, action_digest: actionDigest })) {
      return { ok: false, reason: 'prohibited', stepUp: false };
    }
    const nextSpent = this.spentTotal + cls.charge;
    if (!Number.isSafeInteger(nextSpent) || nextSpent > this.goal.explorationBudget) {
      return { ok: false, reason: 'exploration-exhausted', stepUp: true };
    }
    const body: Omit<ProgressStep, 'digest'> = {
      goal_commitment: this.commitment,
      seq: this.seq,
      before: this.cur,
      after,
      before_digest: this.curDigest,
      after_digest: afterDigest,
      action_digest: actionDigest,
      mode: cls.mode,
      potential_before: pb,
      potential_after: pa,
      charge: cls.charge,
      state_source: stateSource,
      evidence_digest: evidenceDigest,
      prev: this.head,
    };
    const step: ProgressStep = { ...body, digest: stepBodyDigest(body) };
    this.log.push(step);
    this.seq++;
    this.head = step.digest;
    this.spentTotal = nextSpent;
    this.cur = after;
    this.curDigest = afterDigest;
    return { ok: true, step, spent: this.spentTotal, remaining: this.remaining };
  }
}

function runGuard(g: StepGuard, t: Parameters<StepGuard>[0]): boolean {
  try {
    return g(t) === true;
  } catch {
    return false;
  }
}

// ======================================================================================
// Verifier side
// ======================================================================================

export interface VerifyStepOptions {
  expectedSeq?: number;
  expectedPrev?: string;
  /** Require the step to be bound to this action digest. */
  expectedActionDigest?: string;
  /** Require the step to start from / end at this state digest. */
  expectedBeforeDigest?: string;
  expectedAfterDigest?: string;
  registry?: RegistryInput;
  /** Negative-authority check re-run by the verifier. */
  guard?: StepGuard;
  /** If set, the step's state_source must be one of these ids ('' / self-reported is refused). */
  trustedStateSources?: readonly string[];
  /** If set, must return true for the step (evidence check). */
  attestation?: StateAttestationVerifier;
}

export type VerifyStepResult = { ok: true; charge: number } | { ok: false; reason: StepDenial };

const fail = (reason: StepDenial): { ok: false; reason: StepDenial } => ({ ok: false, reason });

function isStep(s: unknown): s is ProgressStep {
  if (!isObj(s)) return false;
  return (
    isStr(s.goal_commitment) &&
    Number.isSafeInteger(s.seq) &&
    (s.seq as number) >= 0 &&
    isStr(s.before_digest) &&
    isStr(s.after_digest) &&
    isStr(s.action_digest) &&
    (s.mode === 'progress' || s.mode === 'exploration') &&
    Number.isSafeInteger(s.potential_before) &&
    Number.isSafeInteger(s.potential_after) &&
    Number.isSafeInteger(s.charge) &&
    isStr(s.state_source) &&
    isStr(s.evidence_digest) &&
    isStr(s.prev) &&
    isStr(s.digest) &&
    'before' in s &&
    'after' in s
  );
}

/**
 * Stateless re-check of one step against the committed goal. Pure and deterministic: the same
 * inputs always give the same verdict; never throws. Nothing the step claims is trusted: the state
 * digests, both potentials, the mode and the charge are all recomputed.
 */
export function verifyProgressStep(
  goal: Goal,
  commitment: string,
  step: ProgressStep,
  opts: VerifyStepOptions = {},
): VerifyStepResult {
  try {
    if (!verifyGoalCommitment(goal, commitment)) return fail('goal-mismatch');
    if (!isStep(step)) return fail('malformed');
    if (step.goal_commitment !== commitment) return fail('goal-mismatch');
    if (opts.expectedSeq !== undefined && step.seq !== opts.expectedSeq) return fail('seq-mismatch');
    if (opts.expectedPrev !== undefined && step.prev !== opts.expectedPrev) return fail('chain-break');
    if (opts.expectedActionDigest !== undefined && step.action_digest !== opts.expectedActionDigest) {
      return fail('action-mismatch');
    }
    if (opts.expectedBeforeDigest !== undefined && step.before_digest !== opts.expectedBeforeDigest) {
      return fail('state-mismatch');
    }
    if (opts.expectedAfterDigest !== undefined && step.after_digest !== opts.expectedAfterDigest) {
      return fail('state-mismatch');
    }
    const { digest, ...body } = step;
    if (stepBodyDigest(body) !== digest) return fail('digest-mismatch');
    if (stateDigest(step.before) !== step.before_digest || stateDigest(step.after) !== step.after_digest) {
      return fail('state-digest-mismatch');
    }
    const reg = toRegistry(opts.registry);
    let pb: number, pa: number, cls: { mode: StepMode; charge: number };
    try {
      pb = potentialOf(goal, reg, step.before);
      pa = potentialOf(goal, reg, step.after);
      cls = classify(pb, pa, goal.epsilon);
    } catch (e) {
      return fail(denialOf(e));
    }
    if (pb !== step.potential_before || pa !== step.potential_after) return fail('potential-mismatch');
    if (step.mode !== cls.mode) return fail('mode-mismatch');
    if (step.charge !== cls.charge) return fail('charge-mismatch');
    if (opts.trustedStateSources && !opts.trustedStateSources.includes(step.state_source)) {
      return fail('untrusted-state-source');
    }
    if (opts.guard && !runGuard(opts.guard, { seq: step.seq, before: step.before, after: step.after, action_digest: step.action_digest })) {
      return fail('prohibited');
    }
    if (opts.attestation) {
      let ok = false;
      try {
        ok = opts.attestation(step) === true;
      } catch {
        ok = false;
      }
      if (!ok) return fail('attestation-failed');
    }
    return { ok: true, charge: cls.charge };
  } catch {
    return fail('malformed');
  }
}

export interface VerifyTrajectoryOptions extends Omit<VerifyStepOptions, 'expectedSeq' | 'expectedPrev' | 'expectedActionDigest' | 'expectedBeforeDigest' | 'expectedAfterDigest'> {
  /** Require the first step to start from this state. */
  initial?: unknown;
  /** Same, by digest (preferred when the state itself is not at hand). */
  initialDigest?: string;
  /** Require step[i].action_digest == expectedActionDigests[i] (and equal length). */
  expectedActionDigests?: readonly string[];
}

export type TrajectoryResult =
  | { ok: true; spent: number; remaining: number; reached: boolean; /** -1 if empty and no initial given */ finalPotential: number; steps: number; head: string }
  | { ok: false; reason: StepDenial; at: number };

/**
 * Verify a whole trajectory: goal binding, every step re-checked, hash-chained, states contiguous
 * (step[i].after_digest == step[i+1].before_digest), starting from `initial` if given, per-step
 * action binding if given, and the strict global invariant sum(charge) <= explorationBudget.
 * Recomputes charges itself; never trusts a claimed total.
 */
export function verifyTrajectory(
  goal: Goal,
  commitment: string,
  steps: readonly ProgressStep[],
  opts: VerifyTrajectoryOptions = {},
): TrajectoryResult {
  if (!verifyGoalCommitment(goal, commitment)) return { ok: false, reason: 'goal-mismatch', at: -1 };
  if (!Array.isArray(steps)) return { ok: false, reason: 'malformed', at: -1 };
  if (opts.expectedActionDigests && opts.expectedActionDigests.length !== steps.length) {
    return { ok: false, reason: 'action-mismatch', at: Math.min(opts.expectedActionDigests.length, steps.length) };
  }
  let anchor: string | undefined;
  try {
    anchor = opts.initialDigest ?? (opts.initial === undefined ? undefined : stateDigest(opts.initial));
  } catch {
    return { ok: false, reason: 'malformed', at: -1 };
  }
  let prev = GENESIS;
  let spent = 0;
  let finalPotential = -1;
  if (steps.length === 0 && opts.initial !== undefined) {
    try {
      finalPotential = potentialOf(goal, toRegistry(opts.registry), opts.initial);
    } catch (e) {
      return { ok: false, reason: denialOf(e), at: -1 };
    }
  }
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i]!;
    const r = verifyProgressStep(goal, commitment, s, {
      ...opts,
      expectedSeq: i,
      expectedPrev: prev,
      expectedActionDigest: opts.expectedActionDigests?.[i],
    });
    if (!r.ok) return { ok: false, reason: r.reason, at: i };
    if (anchor !== undefined && s.before_digest !== anchor) return { ok: false, reason: 'discontinuous-state', at: i };
    spent += r.charge;
    if (!Number.isSafeInteger(spent) || spent > goal.explorationBudget) return { ok: false, reason: 'budget-exceeded', at: i };
    anchor = s.after_digest;
    prev = s.digest;
    finalPotential = s.potential_after;
  }
  return {
    ok: true,
    spent,
    remaining: goal.explorationBudget - spent,
    reached: finalPotential === 0,
    finalPotential,
    steps: steps.length,
    head: prev,
  };
}

// ======================================================================================
// Signed proofs (Ed25519, domain-separated)
// ======================================================================================

/** A step plus the acting holder's signature binding it to goal, action and state transition. */
export interface SignedProgressStep {
  step: ProgressStep;
  /** Holder Ed25519 public key, base64url. */
  holder: string;
  /** base64url Ed25519 signature over the domain-separated binding message. */
  sig: string;
}

function sigMessage(step: ProgressStep, holder: string): Uint8Array {
  return canonicalBytes({
    d: PROGRESS_SIG_DOMAIN,
    b: {
      holder,
      goal_commitment: step.goal_commitment,
      action_digest: step.action_digest,
      before_digest: step.before_digest,
      after_digest: step.after_digest,
      seq: step.seq,
      prev: step.prev,
      step_digest: step.digest,
    },
  });
}

/** Sign a step. `holderPublicKey` is the b64u public key matching `secretKey` (committed in the message). */
export function signProgressStep(step: ProgressStep, secretKey: Uint8Array, holderPublicKey: string): SignedProgressStep {
  return { step, holder: holderPublicKey, sig: b64u(sign(secretKey, sigMessage(step, holderPublicKey))) };
}

export interface VerifySignedStepOptions extends Omit<VerifyStepOptions, 'expectedActionDigest'> {
  /** REQUIRED: the action this proof must be bound to (the PCActn's digest). */
  expectedActionDigest: string;
  /** REQUIRED: the holder key this proof must be signed by. */
  expectedHolder: string;
}

/**
 * Verify a signed step offline: signature (strict Ed25519, domain-separated) by the expected holder
 * over the binding fields, THEN the full deterministic step re-check. Rebinding to another action,
 * goal, state or holder fails.
 */
export function verifySignedProgressStep(
  goal: Goal,
  commitment: string,
  signed: SignedProgressStep,
  opts: VerifySignedStepOptions,
): VerifyStepResult {
  try {
    if (!isObj(signed) || !isStr(signed.holder) || !isStr(signed.sig) || !isStep(signed.step)) return fail('malformed');
    if (signed.holder !== opts.expectedHolder) return fail('holder-mismatch');
    // Cheap binding checks first so the precise reason surfaces, then the signature, then the recompute.
    if (signed.step.action_digest !== opts.expectedActionDigest) return fail('action-mismatch');
    if (signed.step.goal_commitment !== commitment) return fail('goal-mismatch');
    if (!verifyB64u(signed.holder, sigMessage(signed.step, signed.holder), signed.sig)) return fail('bad-signature');
    return verifyProgressStep(goal, commitment, signed.step, opts);
  } catch {
    return fail('malformed');
  }
}

export interface VerifySignedTrajectoryOptions extends Omit<VerifyTrajectoryOptions, 'expectedActionDigests'> {
  /** REQUIRED: step[i] must be bound to expectedActionDigests[i]. */
  expectedActionDigests: readonly string[];
  /** REQUIRED: every step must be signed by this holder. */
  expectedHolder: string;
}

/** Verify signatures on every step (see {@link verifySignedProgressStep}) and then the whole trajectory. */
export function verifySignedTrajectory(
  goal: Goal,
  commitment: string,
  signed: readonly SignedProgressStep[],
  opts: VerifySignedTrajectoryOptions,
): TrajectoryResult {
  if (!Array.isArray(signed)) return { ok: false, reason: 'malformed', at: -1 };
  if (opts.expectedActionDigests.length !== signed.length) {
    return { ok: false, reason: 'action-mismatch', at: Math.min(opts.expectedActionDigests.length, signed.length) };
  }
  for (let i = 0; i < signed.length; i++) {
    const sp = signed[i]!;
    try {
      if (!isObj(sp) || !isStr(sp.holder) || !isStr(sp.sig) || !isStep(sp.step)) return { ok: false, reason: 'malformed', at: i };
      if (sp.holder !== opts.expectedHolder) return { ok: false, reason: 'holder-mismatch', at: i };
      if (sp.step.action_digest !== opts.expectedActionDigests[i]) return { ok: false, reason: 'action-mismatch', at: i };
      if (!verifyB64u(sp.holder, sigMessage(sp.step, sp.holder), sp.sig)) return { ok: false, reason: 'bad-signature', at: i };
    } catch {
      return { ok: false, reason: 'malformed', at: i };
    }
  }
  const { expectedHolder: _h, ...rest } = opts;
  return verifyTrajectory(goal, commitment, signed.map((s) => s.step), rest);
}
