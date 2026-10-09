import fc from 'fast-check';
import {
  type ActionContext,
  type Capability,
  type CapabilityChain,
  type Caveat,
  type CaveatContext,
  type Condition,
  type LeafCondition,
  type Predicate,
  type RiskInputs,
  type RiskPolicy,
  type RiskWeights,
  type TrustBudget,
  delegate,
  encodeKey,
  mintRoot,
  publicKeyOf,
} from '@atlasauth/pca';

/**
 * fast-check arbitraries that generate WELL-FORMED random inputs for the PCA core: Ed25519 key
 * pairs (deterministically derived from the generator's bytes, so every run is reproducible from a
 * seed), multi-hop delegation chains whose every hop legally attenuates, risk policies / inputs /
 * budgets, predicates, actions and caveat-evaluation contexts.
 *
 * Everything here is PURE DATA fed to the real exported core functions — nothing re-implements the
 * model it is meant to check.
 */

// ---- keys ------------------------------------------------------------------------------

/** An Ed25519 key pair whose 32-byte secret IS the generator's bytes (any 32 bytes is a valid secret). */
export interface GenKeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  /** b64u public key — the string form used as `issuer` / `holder`. */
  pub: string;
}

/** 32 random bytes — a reproducible Ed25519 secret seed. */
export const arbSeed32: fc.Arbitrary<Uint8Array> = fc.uint8Array({ minLength: 32, maxLength: 32 });

export function keyPairFromSeed(seed: Uint8Array): GenKeyPair {
  const publicKey = publicKeyOf(seed);
  return { secretKey: seed, publicKey, pub: encodeKey(publicKey) };
}

export const arbKeyPair: fc.Arbitrary<GenKeyPair> = arbSeed32.map(keyPairFromSeed);

// ---- predicates ------------------------------------------------------------------------

const VERBS = ['read', 'write', 'delete', 'transfer', 'list', 'admin'] as const;
const RESOURCES = ['/acct/a', '/acct/b', '/docs/1', '/docs/2', '/x/y', '/'] as const;

export const arbVerb: fc.Arbitrary<string> = fc.constantFrom(...VERBS);
export const arbResource: fc.Arbitrary<string> = fc.oneof(fc.constantFrom(...RESOURCES), fc.string());

/** Known leaf operators (so a generated leaf is a decidable, well-formed comparison). */
const LEAF_OPS = ['eq', 'ne', 'in', 'nin', 'lt', 'lte', 'gt', 'gte', 'prefix', 'exists'] as const;
const LEAF_FIELDS = ['subject.role', 'subject.tier', 'env.ip', 'action.verb', 'action.resource', 'action.params.amount'] as const;

export const arbLeafCondition: fc.Arbitrary<LeafCondition> = fc
  .record({
    field: fc.constantFrom(...LEAF_FIELDS),
    op: fc.constantFrom(...LEAF_OPS),
    value: fc.oneof(
      fc.string(),
      fc.integer({ min: -10, max: 10 }),
      fc.boolean(),
      fc.array(fc.string(), { maxLength: 3 }),
    ),
  })
  .map(({ field, op, value }) => ({ field, op, value }));

export const arbCondition: fc.Arbitrary<Condition> = arbLeafCondition;

export const arbPredicate: fc.Arbitrary<Predicate> = fc
  .record({
    verb: fc.oneof(arbVerb, fc.array(arbVerb, { minLength: 1, maxLength: 3 }), fc.constant('*')),
    resource: fc.oneof(
      fc.constant<string | undefined>(undefined),
      fc.constant('*'),
      fc.constantFrom('/acct/*', '/docs/*'),
      arbResource,
    ),
    where: fc.oneof(
      fc.constant<Condition[] | undefined>(undefined),
      fc.array(arbCondition, { maxLength: 2 }),
    ),
  })
  .map(({ verb, resource, where }) => {
    const p: Predicate = { verb };
    if (resource !== undefined) p.resource = resource;
    if (where !== undefined) p.where = where;
    return p;
  });

export const arbPredicateList: fc.Arbitrary<Predicate[]> = fc.array(arbPredicate, { minLength: 1, maxLength: 4 });

// ---- action + caveat contexts ----------------------------------------------------------

export const arbActionContext: fc.Arbitrary<ActionContext> = fc
  .record({
    verb: arbVerb,
    resource: arbResource,
    params: fc.oneof(
      fc.constant<Record<string, unknown> | undefined>(undefined),
      fc.dictionary(
        fc.constantFrom('amount', 'target', 'reason'),
        fc.oneof(fc.string(), fc.integer({ min: -5, max: 100 }), fc.boolean()),
        { maxKeys: 3 },
      ),
    ),
    role: fc.constantFrom('admin', 'user', 'guest'),
    tier: fc.integer({ min: 0, max: 5 }),
    ip: fc.string(),
    withSubject: fc.boolean(),
    withEnv: fc.boolean(),
  })
  .map((r) => {
    const action: ActionContext['action'] = { verb: r.verb, resource: r.resource };
    if (r.params !== undefined) action.params = r.params;
    const ctx: ActionContext = { action };
    if (r.withSubject) ctx.subject = { role: r.role, tier: r.tier };
    if (r.withEnv) ctx.env = { ip: r.ip };
    return ctx;
  });

const REVERSIBILITY = ['reversible', 'rate_limited', 'irreversible', 'teleport'] as const;

export const arbCaveatContext: fc.Arbitrary<CaveatContext> = fc
  .record({
    now: fc.integer({ min: 0, max: 10_000_000 }),
    blastRadius: fc.oneof(fc.constant<number | undefined>(undefined), fc.double({ min: 0, max: 1, noNaN: true })),
    reversibilityClass: fc.oneof(fc.constant<string | undefined>(undefined), fc.constantFrom(...REVERSIBILITY)),
    delegationDepth: fc.oneof(fc.constant<number | undefined>(undefined), fc.nat({ max: 20 })),
    recentActionTimes: fc.oneof(
      fc.constant<number[] | undefined>(undefined),
      fc.array(fc.integer({ min: 0, max: 10_000_000 }), { maxLength: 6 }),
    ),
  })
  .map((r) => {
    const ctx: CaveatContext = { now: r.now };
    if (r.blastRadius !== undefined) ctx.blastRadius = r.blastRadius;
    if (r.reversibilityClass !== undefined) ctx.reversibilityClass = r.reversibilityClass;
    if (r.delegationDepth !== undefined) ctx.delegationDepth = r.delegationDepth;
    if (r.recentActionTimes !== undefined) ctx.recentActionTimes = r.recentActionTimes;
    return ctx;
  });

/** An action + caveat context together — one point at which to probe a chain's effective authority. */
export interface EvalPoint {
  action: ActionContext;
  cavCtx: CaveatContext;
}

export const arbEvalPoint: fc.Arbitrary<EvalPoint> = fc.record({ action: arbActionContext, cavCtx: arbCaveatContext });

// ---- attenuating delegation chains -----------------------------------------------------

/**
 * A caveat "spec": a well-formed, built-in, evaluator-decidable caveat (so `evaluateCaveats` gives a
 * meaningful verdict). `budget_frac` is materialised in chain order into a MONOTONE non-increasing
 * `budget_alloc.limit`, so the generated chain always satisfies `allocationsMonotone`.
 */
export type CaveatSpec =
  | { k: 'expires'; at: number }
  | { k: 'not_before'; at: number }
  | { k: 'rate'; max: number; per_secs: number }
  | { k: 'max_blast_radius'; max: number }
  | { k: 'reversibility_max'; cls: string }
  | { k: 'delegation_depth'; max: number }
  | { k: 'budget_frac'; frac: number };

export const arbCaveatSpec: fc.Arbitrary<CaveatSpec> = fc.oneof(
  fc.record({ k: fc.constant('expires' as const), at: fc.integer({ min: 0, max: 10_000_000 }) }),
  fc.record({ k: fc.constant('not_before' as const), at: fc.integer({ min: 0, max: 10_000_000 }) }),
  fc.record({
    k: fc.constant('rate' as const),
    max: fc.integer({ min: 1, max: 10 }),
    per_secs: fc.integer({ min: 1, max: 3600 }),
  }),
  // Quantized to 3 decimals so the limit is canonical-wire-safe (>= 1e-6, <= 15 significant digits).
  fc.record({ k: fc.constant('max_blast_radius' as const), max: fc.integer({ min: 0, max: 1000 }).map((n) => n / 1000) }),
  fc.record({ k: fc.constant('reversibility_max' as const), cls: fc.constantFrom('reversible', 'rate_limited', 'irreversible') }),
  fc.record({ k: fc.constant('delegation_depth' as const), max: fc.nat({ max: 20 }) }),
  fc.record({ k: fc.constant('budget_frac' as const), frac: fc.double({ min: 0, max: 1, noNaN: true }) }),
);

const BUDGET_ALLOC_BASE = 1_000_000;

/** Materialise one spec into a concrete `Caveat`, threading the running budget allocation (monotone). */
function specToCaveat(spec: CaveatSpec, alloc: { running: number }): Caveat {
  switch (spec.k) {
    case 'expires':
      return { type: 'expires', at: spec.at };
    case 'not_before':
      return { type: 'not_before', at: spec.at };
    case 'rate':
      return { type: 'rate', max: spec.max, per_secs: spec.per_secs };
    case 'max_blast_radius':
      return { type: 'max_blast_radius', max: spec.max };
    case 'reversibility_max':
      return { type: 'reversibility_max', class: spec.cls };
    case 'delegation_depth':
      return { type: 'delegation_depth', max: spec.max };
    case 'budget_frac': {
      const base = Number.isFinite(alloc.running) ? alloc.running : BUDGET_ALLOC_BASE;
      // frac in [0,1] and base a non-negative integer => floor is an integer in [0, base] <= the
      // previous allocation: monotone non-increasing AND canonical-wire-safe (a safe integer).
      const limit = Math.floor(base * spec.frac);
      alloc.running = limit;
      return { type: 'budget_alloc', limit };
    }
  }
}

/** A generated, signed, legally-attenuating chain, plus the fixed envelope authority alongside it. */
export interface GeneratedChain {
  caps: CapabilityChain;
  /** Envelope predicates — fixed by the root principal; the same at every hop (model of the envelope). */
  predicates: Predicate[];
  /** The root principal's b64u public key (the expected root issuer). */
  rootIssuer: string;
  /** b64u holder key at each hop (root holder first). */
  holders: string[];
}

interface ChainModel {
  principalSeed: Uint8Array;
  holder0Seed: Uint8Array;
  rootSpecs: CaveatSpec[];
  hops: { holderSeed: Uint8Array; addedSpecs: CaveatSpec[] }[];
  predicates: Predicate[];
}

export function buildChain(m: ChainModel): GeneratedChain {
  const alloc = { running: Number.POSITIVE_INFINITY };
  const principal = keyPairFromSeed(m.principalSeed);
  const holder0 = keyPairFromSeed(m.holder0Seed);

  const rootCaveats = m.rootSpecs.map((s) => specToCaveat(s, alloc));
  const root: Capability = mintRoot({
    principalSecret: principal.secretKey,
    principalPublic: principal.pub,
    holder: holder0.pub,
    caveats: rootCaveats,
  });

  const caps: Capability[] = [root];
  const holders: string[] = [holder0.pub];
  let prev = root;
  // The next hop is signed by the key the parent is bound to (issuer == parent.holder).
  let signerSecret = holder0.secretKey;

  for (const hop of m.hops) {
    const toHolder = keyPairFromSeed(hop.holderSeed);
    const added = hop.addedSpecs.map((s) => specToCaveat(s, alloc));
    const cap = delegate(prev, toHolder.pub, added, signerSecret);
    caps.push(cap);
    holders.push(toHolder.pub);
    prev = cap;
    signerSecret = toHolder.secretKey;
  }

  return { caps, predicates: m.predicates, rootIssuer: principal.pub, holders };
}

export const arbChain: fc.Arbitrary<GeneratedChain> = fc
  .record({
    principalSeed: arbSeed32,
    holder0Seed: arbSeed32,
    rootSpecs: fc.array(arbCaveatSpec, { minLength: 1, maxLength: 4 }),
    hops: fc.array(
      fc.record({ holderSeed: arbSeed32, addedSpecs: fc.array(arbCaveatSpec, { maxLength: 3 }) }),
      { maxLength: 5 },
    ),
    predicates: arbPredicateList,
  })
  .map(buildChain);

// ---- risk policy / inputs / budget -----------------------------------------------------

const nonNegWeight = fc.double({ min: 0, max: 2, noNaN: true });

export const arbRiskWeights: fc.Arbitrary<RiskWeights> = fc.record({
  alpha: nonNegWeight,
  beta: nonNegWeight,
  gamma: nonNegWeight,
  delta: nonNegWeight,
  epsilon: nonNegWeight,
  zeta: nonNegWeight,
});

/** A well-formed `RiskPolicy` (passes `validateRiskPolicy`): kappa > 0, 0 <= theta1 <= theta2, the rest finite >= 0. */
export const arbRiskPolicy: fc.Arbitrary<RiskPolicy> = fc
  .record({
    weights: arbRiskWeights,
    theta1: fc.double({ min: 0, max: 1, noNaN: true }),
    theta2Gap: fc.double({ min: 0, max: 1, noNaN: true }),
    kappa: fc.double({ min: 0.001, max: 5, noNaN: true }),
    lambda: fc.double({ min: 0, max: 0.01, noNaN: true }),
    rho: fc.double({ min: 0, max: 2, noNaN: true }),
    bMax: fc.double({ min: 0, max: 10, noNaN: true }),
  })
  .map((r) => ({
    weights: r.weights,
    theta1: r.theta1,
    theta2: r.theta1 + r.theta2Gap,
    kappa: r.kappa,
    lambda: r.lambda,
    rho: r.rho,
    bMax: r.bMax,
  }));

const unit = fc.double({ min: 0, max: 1, noNaN: true });

export const arbRiskInputs: fc.Arbitrary<RiskInputs> = fc.record({
  semanticDistance: unit,
  reversibility: unit,
  blastRadius: unit,
  taint: unit,
  confidence: unit,
  age: unit,
});

export const arbTrustBudget: fc.Arbitrary<TrustBudget> = fc
  .record({
    B: fc.double({ min: 0, max: 10, noNaN: true }),
    tau: fc.integer({ min: 0, max: 10_000_000 }),
    asOf: fc.oneof(fc.constant<number | undefined>(undefined), fc.integer({ min: 0, max: 10_000_000 })),
  })
  .map((r) => {
    const b: TrustBudget = { B: r.B, tau: r.tau };
    if (r.asOf !== undefined) b.asOf = r.asOf;
    return b;
  });

/** Non-negative deltas used to build a pointwise-WORSE risk input (for the monotonicity property). */
export interface RiskDeltas {
  dSem: number;
  dBlast: number;
  dTaint: number;
  dAge: number;
  dRev: number;
  dConf: number;
}

export const arbRiskDeltas: fc.Arbitrary<RiskDeltas> = fc.record({
  dSem: unit,
  dBlast: unit,
  dTaint: unit,
  dAge: unit,
  dRev: unit,
  dConf: unit,
});

const clamp01 = (x: number): number => (x < 0 ? 0 : x > 1 ? 1 : x);

/** A risk input that is >= `base` in every risk-INCREASING axis and <= in every PROTECTIVE axis. */
export function worsen(base: RiskInputs, d: RiskDeltas): RiskInputs {
  return {
    semanticDistance: clamp01(base.semanticDistance + d.dSem),
    blastRadius: clamp01(base.blastRadius + d.dBlast),
    taint: clamp01(base.taint + d.dTaint),
    age: clamp01(base.age + d.dAge),
    reversibility: clamp01(base.reversibility - d.dRev),
    confidence: clamp01(base.confidence - d.dConf),
  };
}
