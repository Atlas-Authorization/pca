import fc from 'fast-check';
import {
  type ActionContext,
  type Capability,
  type CapabilityChain,
  type Caveat,
  type CaveatContext,
  type LeafCondition,
  type Predicate,
  admit,
  allocationsMonotone,
  cost,
  delegate,
  encodeKey,
  evaluateCaveats,
  evaluateCondition,
  evaluateConditionTri,
  evaluatePredicates,
  envelopeCaveatEvaluator,
  hashCanonical,
  requiredThreshold,
  riskScore,
  safetyBound,
  sign,
  validateRiskPolicy,
  verifyChain,
} from '@atlasauth/pca';
import {
  type EvalPoint,
  type GeneratedChain,
  arbChain,
  arbEvalPoint,
  arbPredicateList,
  arbRiskDeltas,
  arbRiskInputs,
  arbRiskPolicy,
  arbSeed32,
  arbTrustBudget,
  keyPairFromSeed,
  worsen,
} from './arbitraries';

/**
 * The PCA core safety invariants, each as a reusable fast-check property. A property returns `true`
 * for a passing case; any violation returns `false`, which fast-check shrinks to a minimal
 * counterexample and FAILS the enclosing `fc.assert`.
 */

const EPS = 1e-9;

// ============================ 1. ATTENUATION MONOTONICITY ===============================

/** Effective authority of a hop for a probe point: envelope predicates AND every caveat satisfied. */
function authAllowed(caveats: Caveat[], predicates: Predicate[], pt: EvalPoint): boolean {
  if (!evaluatePredicates(predicates, pt.action).allowed) return false;
  return evaluateCaveats(caveats, pt.cavCtx).ok;
}

/** Caveats of `child` must begin with the full caveat array of `parent` (append-only, order-preserving). */
function caveatsArePrefixExtension(parent: Capability, child: Capability): boolean {
  if (child.caveats.length < parent.caveats.length) return false;
  for (let j = 0; j < parent.caveats.length; j++) {
    const pj = parent.caveats[j];
    const cj = child.caveats[j];
    if (pj === undefined || cj === undefined) return false;
    if (hashCanonical(cj) !== hashCanonical(pj)) return false;
  }
  return true;
}

/** Numeric `budget_alloc.limit` values, in caveat order. */
function allocLimits(caveats: Caveat[]): number[] {
  const out: number[] = [];
  for (const cv of caveats) {
    if (cv !== null && typeof cv === 'object' && cv.type === 'budget_alloc') {
      const lim = (cv as { limit?: unknown }).limit;
      if (typeof lim === 'number') out.push(lim);
    }
  }
  return out;
}

/**
 * For any legal chain: (a) it verifies; (b) each hop's caveats are an append-only extension of its
 * parent's; (c) `budget_alloc` limits are monotone non-increasing; (d) for every probe point, the
 * per-hop "allowed" verdict is monotone non-increasing root->leaf — authority a delegate step can
 * only shrink or preserve, never widen. A (verb,resource,context) denied by an ancestor is never
 * allowed at the leaf.
 */
export function attenuationMonotonicityProperty(): fc.IPropertyWithHooks<[GeneratedChain, EvalPoint[]]> {
  return fc.property(arbChain, fc.array(arbEvalPoint, { minLength: 1, maxLength: 5 }), (chain, points) => {
    const caps: CapabilityChain = chain.caps;

    // (a) a legally built chain must verify against its root principal.
    if (!verifyChain(caps, chain.rootIssuer).ok) return false;

    // (b) structural append-only attenuation at every hop.
    for (let i = 1; i < caps.length; i++) {
      const parent = caps[i - 1];
      const child = caps[i];
      if (parent === undefined || child === undefined) return false;
      if (!caveatsArePrefixExtension(parent, child)) return false;
    }

    // (c) carried budget allocations monotone non-increasing (core + explicit numeric check on the leaf).
    const leaf = caps[caps.length - 1];
    if (leaf === undefined) return false;
    if (!allocationsMonotone(leaf.caveats).ok) return false;
    const limits = allocLimits(leaf.caveats);
    for (let i = 1; i < limits.length; i++) {
      const prev = limits[i - 1];
      const cur = limits[i];
      if (prev === undefined || cur === undefined) return false;
      if (cur > prev) return false;
    }

    // (d) authority monotone non-increasing down the chain, at every probe point.
    for (const pt of points) {
      let ancestorAllowed = true;
      for (const cap of caps) {
        const allowed = authAllowed(cap.caveats, chain.predicates, pt);
        // A `true` appearing after a `false` would be a widening — forbidden.
        if (allowed && !ancestorAllowed) return false;
        ancestorAllowed = allowed;
      }
    }
    return true;
  });
}

// ================================ 2. BUDGET SOUNDNESS ===================================

/**
 * Risk functional is well-formed: r is always clamped to [0,1] (= [0,S]), and the functional is
 * MONOTONE — a pointwise-worse input never yields a lower r.
 */
export function riskMonotoneProperty() {
  return fc.property(arbRiskPolicy, arbRiskInputs, arbRiskDeltas, (policy, inputs, deltas) => {
    const r = riskScore(inputs, policy.weights);
    if (!(r >= 0 && r <= 1)) return false; // clamped to [0, S=1]
    const worse = worsen(inputs, deltas);
    const rWorse = riskScore(worse, policy.weights);
    if (!(r >= 0 && r <= 1 && rWorse >= 0 && rWorse <= 1)) return false;
    // higher (worse) inputs never yield a lower r
    return rWorse + EPS >= r;
  });
}

/**
 * Single-action admission soundness: whenever `admit` lets an action proceed without a human
 * (admit, or any metered t<3 path), the admitted cost kappa*r is covered by the budget. And
 * `safetyBound` equals bMax/kappa exactly.
 */
export function admissionSoundnessProperty() {
  return fc.property(arbRiskPolicy, arbRiskInputs, arbTrustBudget, (policy, inputs, budget) => {
    // generated policy must be well-formed (self-check of the arbitrary).
    if (validateRiskPolicy(policy) !== null) return false;
    const r = riskScore(inputs, policy.weights);
    const c = cost(r, policy.kappa);
    const adm = admit(r, budget, policy);
    // metered <=> machine-only (t<3) proceed, which the core only returns once B >= c.
    if (adm.metered) {
      if (adm.t >= 3) return false;
      if (!(budget.B + EPS >= c)) return false;
    }
    if (adm.admit) {
      // auto-admit is t=1 and always metered and always covered.
      if (adm.t !== 1 || !adm.metered) return false;
      if (!(budget.B + EPS >= c)) return false;
    }
    // safetyBound is exactly bMax/kappa (kappa>0 for a valid policy).
    const expected = policy.kappa > 0 ? Math.max(0, policy.bMax) / policy.kappa : 0;
    return Math.abs(safetyBound(policy) - expected) <= EPS;
  });
}

/**
 * Cumulative-risk bound: starting from a full budget and performing a sequence of machine-only
 * (metered t<3) actions, debiting kappa*r each time, the budget never goes negative and the total
 * admitted risk obeys Sum(r) <= bMax/kappa — whatever the sequence of actions.
 */
export function cumulativeBudgetBoundProperty() {
  return fc.property(arbRiskPolicy, fc.array(arbRiskInputs, { minLength: 1, maxLength: 40 }), (policy, seq) => {
    const bound = safetyBound(policy); // bMax/kappa
    let B = Math.max(0, policy.bMax); // fresh recharge: B0 = bMax
    let sumR = 0;
    for (const inputs of seq) {
      const r = riskScore(inputs, policy.weights);
      const adm = admit(r, { B, tau: 0, asOf: 0 }, policy);
      if (adm.metered && adm.t < 3) {
        const c = cost(r, policy.kappa);
        // admit() only returns metered once B >= c, so the debit cannot drive B negative.
        if (!(B + EPS >= c)) return false;
        B = Math.max(0, B - c);
        sumR += r;
        if (B < -EPS) return false;
        // The core bound: kappa * Sum(r) <= bMax, i.e. Sum(r) <= bMax/kappa = safetyBound.
        if (!(policy.kappa * sumR <= policy.bMax + 1e-6)) return false;
        if (!(sumR <= bound + 1e-6)) return false;
      }
    }
    return true;
  });
}

// ================================== 3. FAIL-CLOSED ======================================

const KNOWN_CAVEAT_TYPES = new Set([
  'expires', 'not_before', 'rate', 'max_blast_radius', 'reversibility_max', 'delegation_depth', 'budget_alloc',
]);

/**
 * Every structurally-undecidable (but well-typed) leaf condition — a missing field, an
 * incomparable-type comparison, a non-array `in`/`nin` operand, a missing operand, a `member_of`
 * with no resolvable collection — evaluates to `'unknown'` (never `'true'`), so a predicate that
 * carries it NEVER grants. (This is the same `'unknown'` verdict the evaluator's `default` branch
 * returns for an unrecognized operator: undecidable ⇒ not-granted.)
 */
export function undecidableLeafFailsClosedProperty() {
  // Each builder makes a well-typed LeafCondition that cannot be cleanly decided against `ctx`.
  const undecidables: readonly ((f: string) => LeafCondition)[] = [
    (f) => ({ field: `${f}.definitely_absent`, op: 'eq', value: 'x' }), // missing field
    (f) => ({ field: f, op: 'lt', value: 5 }), // string field vs number => incomparable
    (f) => ({ field: f, op: 'in', value: 'not-an-array' }), // non-array operand
    (f) => ({ field: f, op: 'eq' }), // no value and no ref
    (f) => ({ field: f, op: 'member_of', value: 'g', collection: 'env.no_such_collection' }), // missing collection
  ];
  return fc.property(
    fc.nat({ max: undecidables.length - 1 }),
    fc.constantFrom('read', 'write', 'delete'),
    fc.constant('/x'),
    (pick, verb, resource) => {
      const make = undecidables[pick];
      if (make === undefined) return false;
      const ctx: ActionContext = { action: { verb, resource }, subject: { role: 'admin' } };
      const leaf = make('subject.role');
      // Undecidable => never cleanly 'true'.
      if (evaluateConditionTri(leaf, ctx) === 'true') return false;
      if (evaluateCondition(leaf, ctx) !== false) return false;
      // The same leaf inside a predicate's `where` must therefore DENY the action.
      return evaluatePredicates([{ verb, resource, where: [leaf] }], ctx).allowed === false;
    },
  );
}

/** A `not`/`all_of`/`any_of` built over undecidable or empty children fails closed (never `true`). */
export function undecidableGroupsFailClosedProperty() {
  return fc.property(fc.constant(0), () => {
    const ctx: ActionContext = { action: { verb: 'read', resource: '/x' }, subject: { role: 'admin' } };
    // A well-typed but undecidable child (string compared with `lt` to a number => 'unknown').
    const undecidableChild: LeafCondition = { field: 'subject.role', op: 'lt', value: 5 };
    // not(unknown) => unknown (not 'true'): fail-closed negation.
    if (evaluateConditionTri({ not: undecidableChild }, ctx) === 'true') return false;
    // empty all_of / any_of => unknown, never 'true'.
    if (evaluateConditionTri({ all_of: [] }, ctx) === 'true') return false;
    if (evaluateConditionTri({ any_of: [] }, ctx) === 'true') return false;
    // an all_of containing an undecidable child cannot complete.
    if (evaluateConditionTri({ all_of: [undecidableChild] }, ctx) === 'true') return false;
    // an any_of of only-undecidable children cannot carry.
    if (evaluateConditionTri({ any_of: [undecidableChild] }, ctx) === 'true') return false;
    return true;
  });
}

/**
 * `member_of` over a CYCLIC adjacency terminates and yields a clean, correct verdict (never hangs,
 * never throws, fails closed on an unreachable target).
 */
export function memberOfCycleSafeProperty() {
  return fc.property(fc.constantFrom('a', 'b', 'c', 'z'), (target) => {
    // a -> b -> a is a cycle; c hangs off b; z is absent.
    const rel: Record<string, string[]> = { a: ['b'], b: ['a', 'c'] };
    const ctx: ActionContext = { action: { verb: 'read', resource: '/x' }, subject: { g: 'a' }, env: { rel } };
    const tri = evaluateConditionTri(
      { field: 'subject.g', op: 'member_of', value: target, collection: 'env.rel' },
      ctx,
    );
    // Closure of 'a' over the cycle is {a,b,c}. Reachable targets decide 'true'; 'z' fails closed.
    const reachable = new Set(['a', 'b', 'c']);
    const expected = reachable.has(target) ? 'true' : 'false';
    return tri === expected;
  });
}

/** An unknown caveat TYPE is never satisfied; so a caveat set containing it is never `ok`. */
export function unknownCaveatTypeDeniesProperty() {
  return fc.property(
    fc.string({ minLength: 1, maxLength: 12 }).filter((s) => !KNOWN_CAVEAT_TYPES.has(s)),
    fc.integer({ min: 0, max: 10_000_000 }),
    (type, now) => {
      const cav: Caveat = { type };
      const ctx: CaveatContext = { now };
      if (envelopeCaveatEvaluator(cav, ctx) !== false) return false;
      return evaluateCaveats([cav], ctx).ok === false;
    },
  );
}

type ChainMutation =
  | 'tamper-caveat'
  | 'drop-leaf-caveat'
  | 'swap-holder'
  | 'break-parent'
  | 'bad-sig'
  | 'wrong-root-issuer'
  | 'suite-mismatch'
  | 'break-id'
  | 'append-forged-hop';

const ALL_MUTATIONS: ChainMutation[] = [
  'tamper-caveat', 'drop-leaf-caveat', 'swap-holder', 'break-parent',
  'bad-sig', 'wrong-root-issuer', 'suite-mismatch', 'break-id', 'append-forged-hop',
];

/** Deep structural clone, type-preserving (no `any`/cast). */
function cloneCaps(caps: CapabilityChain): Capability[] {
  return structuredClone(caps);
}

/**
 * Any forged/invalid chain fails verification. A legal chain is mutated by one of nine distinct
 * attacks (tampered/dropped caveats, swapped holder, broken parent link, bad signature, wrong root
 * issuer, mismatched signature suite, broken content-address id, appended unsigned hop) and
 * `verifyChain` must reject every one.
 */
export function forgedChainRejectedProperty() {
  return fc.property(
    arbChain,
    fc.constantFrom(...ALL_MUTATIONS),
    fc.nat({ max: 1_000_000 }),
    arbSeed32,
    (chain, mutation, pick, auxSeed) => {
      const caps = chain.caps;
      // Precondition: the pristine chain verifies.
      if (!verifyChain(caps, chain.rootIssuer).ok) return false;
      const n = caps.length;
      const idx = n > 0 ? pick % n : 0;
      const aux = keyPairFromSeed(auxSeed);

      switch (mutation) {
        case 'tamper-caveat': {
          const m = cloneCaps(caps);
          const hop = m[idx];
          if (hop === undefined) return true;
          hop.caveats = [...hop.caveats, { type: 'expires', at: 999 }];
          return verifyChain(m, chain.rootIssuer).ok === false;
        }
        case 'drop-leaf-caveat': {
          const m = cloneCaps(caps);
          const hop = m[n - 1];
          if (hop === undefined || hop.caveats.length === 0) return true; // inapplicable: trivially pass
          hop.caveats = hop.caveats.slice(0, hop.caveats.length - 1);
          return verifyChain(m, chain.rootIssuer).ok === false;
        }
        case 'swap-holder': {
          const m = cloneCaps(caps);
          const hop = m[idx];
          if (hop === undefined) return true;
          hop.holder = aux.pub; // changes the signed body => digest mismatch
          return verifyChain(m, chain.rootIssuer).ok === false;
        }
        case 'break-parent': {
          if (n < 2) return true; // no non-root hop to detach
          const m = cloneCaps(caps);
          const hop = m[Math.max(1, idx)];
          if (hop === undefined) return true;
          hop.parent = hashCanonical({ bogus: auxSeed.length, tag: 'not-a-real-parent' });
          return verifyChain(m, chain.rootIssuer).ok === false;
        }
        case 'bad-sig': {
          const m = cloneCaps(caps);
          const hop = m[idx];
          if (hop === undefined) return true;
          // A well-formed but wrong signature (over different bytes, by a different key).
          hop.sig = encodeKey(sign(aux.secretKey, Uint8Array.of(1, 2, 3, 4)));
          return verifyChain(m, chain.rootIssuer).ok === false;
        }
        case 'wrong-root-issuer': {
          // Pristine chain, but asserted against the WRONG principal.
          if (aux.pub === chain.rootIssuer) return true; // negligibly rare key collision: skip
          return verifyChain(caps, aux.pub).ok === false;
        }
        case 'suite-mismatch': {
          const m = cloneCaps(caps);
          const hop = m[idx];
          if (hop === undefined) return true;
          // Claim a different (PQ) suite than the body was signed under: the suite fields are bound
          // into body_digest, so this breaks the content-address / signature => must be rejected.
          hop.alg = 'ml-dsa-65';
          return verifyChain(m, chain.rootIssuer).ok === false;
        }
        case 'break-id': {
          const m = cloneCaps(caps);
          const hop = m[idx];
          if (hop === undefined) return true;
          hop.id = hashCanonical({ not: 'the-body-digest', n: idx });
          return verifyChain(m, chain.rootIssuer).ok === false;
        }
        case 'append-forged-hop': {
          const leaf = caps[n - 1];
          if (leaf === undefined) return true;
          // A hop issued as if from the leaf, but signed by a key that is NOT the leaf's holder.
          const forged = delegate(leaf, aux.pub, [], aux.secretKey);
          return verifyChain([...caps, forged], chain.rootIssuer).ok === false;
        }
      }
    },
  );
}

/** Well-typed but never-signed "capabilities" (random fields) never verify. */
const arbUnsignedCapability: fc.Arbitrary<Capability> = fc
  .record({
    id: fc.string(),
    issuer: fc.string(),
    holder: fc.string(),
    caveats: fc.array(fc.record({ type: fc.string() }), { maxLength: 3 }),
    body_digest: fc.string(),
    sig: fc.string(),
  })
  .map((r): Capability => ({
    id: r.id,
    issuer: r.issuer,
    holder: r.holder,
    caveats: r.caveats.map((c): Caveat => ({ type: c.type })),
    body_digest: r.body_digest,
    sig: r.sig,
  }));

/** Arbitrary never-signed chains (including the empty chain) never verify. */
export function garbageChainRejectedProperty() {
  return fc.property(fc.array(arbUnsignedCapability, { maxLength: 4 }), (garbage) => {
    // None of these were ever signed, so none can verify (and an empty array is an empty chain).
    return verifyChain(garbage).ok === false;
  });
}

// =================================== 4. DETERMINISM =====================================

/** verifyChain, evaluatePredicates, evaluateCaveats, riskScore/admit/threshold are all deterministic. */
export function determinismProperty() {
  return fc.property(
    arbChain,
    arbEvalPoint,
    arbPredicateList,
    arbRiskPolicy,
    arbRiskInputs,
    arbTrustBudget,
    (chain, pt, preds, policy, inputs, budget) => {
      const v1 = verifyChain(chain.caps, chain.rootIssuer);
      const v2 = verifyChain(chain.caps, chain.rootIssuer);
      if (v1.ok !== v2.ok || v1.reason !== v2.reason) return false;

      const p1 = evaluatePredicates(preds, pt.action);
      const p2 = evaluatePredicates(preds, pt.action);
      if (p1.allowed !== p2.allowed || p1.reason !== p2.reason) return false;

      const leaf = chain.caps[chain.caps.length - 1];
      if (leaf !== undefined) {
        const c1 = evaluateCaveats(leaf.caveats, pt.cavCtx);
        const c2 = evaluateCaveats(leaf.caveats, pt.cavCtx);
        if (c1.ok !== c2.ok || c1.failed.join('|') !== c2.failed.join('|')) return false;
      }

      const r1 = riskScore(inputs, policy.weights);
      const r2 = riskScore(inputs, policy.weights);
      if (!Object.is(r1, r2)) return false;

      const t1 = requiredThreshold(r1, policy);
      const t2 = requiredThreshold(r1, policy);
      if (t1.t !== t2.t || t1.proof !== t2.proof || t1.optimisticAllowed !== t2.optimisticAllowed) return false;

      const a1 = admit(r1, budget, policy);
      const a2 = admit(r1, budget, policy);
      return a1.admit === a2.admit && a1.needStepUp === a2.needStepUp && a1.t === a2.t && a1.metered === a2.metered;
    },
  );
}

// =================================== runner / registry ==================================

/** A named invariant whose `run` executes its property-based check at the given runs/seed. */
export interface Invariant {
  readonly name: string;
  readonly run: (numRuns: number, seed: number) => void;
}

/** Every PCA safety invariant as a named, runnable check. Each `run` captures its own typed property. */
export const INVARIANTS: readonly Invariant[] = [
  { name: 'attenuation-monotonicity', run: (nr, s) => fc.assert(attenuationMonotonicityProperty(), { numRuns: nr, seed: s }) },
  { name: 'risk-wellformed-and-monotone', run: (nr, s) => fc.assert(riskMonotoneProperty(), { numRuns: nr, seed: s }) },
  { name: 'admission-soundness', run: (nr, s) => fc.assert(admissionSoundnessProperty(), { numRuns: nr, seed: s }) },
  { name: 'cumulative-budget-bound', run: (nr, s) => fc.assert(cumulativeBudgetBoundProperty(), { numRuns: nr, seed: s }) },
  { name: 'fail-closed:undecidable-leaf', run: (nr, s) => fc.assert(undecidableLeafFailsClosedProperty(), { numRuns: nr, seed: s }) },
  { name: 'fail-closed:undecidable-groups', run: (nr, s) => fc.assert(undecidableGroupsFailClosedProperty(), { numRuns: nr, seed: s }) },
  { name: 'fail-closed:member-of-cycle-safe', run: (nr, s) => fc.assert(memberOfCycleSafeProperty(), { numRuns: nr, seed: s }) },
  { name: 'fail-closed:unknown-caveat-type', run: (nr, s) => fc.assert(unknownCaveatTypeDeniesProperty(), { numRuns: nr, seed: s }) },
  { name: 'fail-closed:forged-chain-rejected', run: (nr, s) => fc.assert(forgedChainRejectedProperty(), { numRuns: nr, seed: s }) },
  { name: 'fail-closed:garbage-chain-rejected', run: (nr, s) => fc.assert(garbageChainRejectedProperty(), { numRuns: nr, seed: s }) },
  { name: 'determinism', run: (nr, s) => fc.assert(determinismProperty(), { numRuns: nr, seed: s }) },
];

export interface InvariantResult {
  name: string;
  ok: boolean;
  numRuns: number;
  seed: number;
  error?: string;
}

export interface CheckInvariantsOptions {
  /** Property-test iterations per invariant (default 1000). */
  numRuns?: number;
  /** Fixed PRNG seed for reproducibility (default 20260108). */
  seed?: number;
  /** Stop at the first failing invariant (default false — run them all). */
  bail?: boolean;
}

export const DEFAULT_SEED = 20260108;
export const DEFAULT_NUM_RUNS = 1000;

/**
 * Machine-check every PCA safety invariant with property-based testing. Returns a per-invariant
 * result; `ok: false` with an `error` is a surfaced counterexample (a candidate core bug). This is
 * the reusable API that lets other packages run the same universal checks.
 */
export function checkInvariants(opts: CheckInvariantsOptions = {}): InvariantResult[] {
  const numRuns = opts.numRuns ?? DEFAULT_NUM_RUNS;
  const seed = opts.seed ?? DEFAULT_SEED;
  const results: InvariantResult[] = [];
  for (const inv of INVARIANTS) {
    try {
      inv.run(numRuns, seed);
      results.push({ name: inv.name, ok: true, numRuns, seed });
    } catch (e) {
      results.push({ name: inv.name, ok: false, numRuns, seed, error: e instanceof Error ? e.message : String(e) });
      if (opts.bail) break;
    }
  }
  return results;
}
