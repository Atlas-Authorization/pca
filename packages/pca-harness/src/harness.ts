import {
  type Capability,
  type CapabilityChain,
  type InclusionProof,
  type PCActn,
  type PlanNode,
  type RiskInputs,
  type RiskPolicy,
  type RiskWeights,
  type TrustBudget,
  DEFAULT_RISK_POLICY,
  buildPCActn,
  commitPlan,
  cost,
  debit,
  hashCanonical,
  leak,
  requiredThreshold,
  riskScore,
} from '@atlasauth/pca';

/**
 * PCA framework-evolution item **B1 — "attest the mediator, not the weights"** (reference prototype).
 *
 * The spec's L0 rung derives the agent's identity key inside a TEE from an attestation quote that measures
 * *the model weights*. That is unshippable against the real landscape: agents are black-box API models,
 * client-side and multi-model, whose weights can never be measured. B1 pivots the trusted computing base
 * (TCB) away from the opaque model and onto a **small, auditable orchestration harness** — the code in this
 * file. The model becomes an UNTRUSTED ORACLE: the harness asks it for a candidate action, then enforces the
 * PCA invariants (plan-inclusion, taint provenance, trust-budget) itself, BEFORE any candidate is allowed to
 * become a signed PCActn. What an attestation would measure is therefore this harness (see
 * {@link Harness.harnessMeasurement}), not the weights — a smaller, honest, actually-attestable TCB.
 *
 * Security claim realised here: *a compromised model cannot form an out-of-policy action.* Even if the
 * oracle is fully adversarial (prompt-injected into proposing "wire the money"), the candidate never
 * acquires a signature unless it (1) is a node of the principal-authorised committed plan, (2) survives the
 * taint-folded risk gate, and (3) is covered by the trust budget. The oracle holds no signing key; only the
 * harness signs, and only after the checks pass.
 */

/** Declared provenance of one input the model consumed to form its candidate. */
export type Provenance = 'trusted' | 'untrusted';

export interface CandidateInput {
  /** An opaque reference to the input (tool id, URL, doc id, …). Carried into provenance.trusted_refs. */
  ref: string;
  /** `untrusted` = attacker-influenceable lineage (web content, inbound email, tool output). */
  provenance: Provenance;
}

/**
 * What the UNTRUSTED oracle (the model) returns. It is just a *proposal*: the harness treats every field as
 * adversary-controlled and verifies it against the committed plan before trusting any of it.
 */
export interface Candidate {
  verb: string;
  resource: string;
  params?: Record<string, unknown>;
  /** The plan node the oracle claims this action corresponds to. Verified, never trusted. */
  nodeId: string;
  inputs?: CandidateInput[];
}

/** The untrusted model, wrapped as a callback. May be async (a real API call). */
export type ProposeAction = () => Candidate | Promise<Candidate>;

/** Why the harness refused to emit a PCActn. No signed object is produced for any of these. */
export type RefusalReason = 'out_of_plan' | 'over_budget' | 'bad_candidate';

export interface RiskReport {
  r: number;
  inputs: RiskInputs;
  /** Derived taint label: 1 if any input had untrusted lineage, else 0. */
  taint: number;
  /** Required threshold rung for this risk under the policy. */
  t: 1 | 2 | 3;
}

export type StepResult =
  | {
      ok: true;
      pcactn: PCActn;
      inclusionProof: InclusionProof;
      risk: RiskReport;
      budget: TrustBudget;
    }
  | {
      ok: false;
      reason: RefusalReason;
      detail: string;
      /** For `over_budget`, the rung the principal must step up to. */
      requiredT?: 1 | 2 | 3;
      /** For `over_budget`, the budget after leak (unchanged; nothing was debited). */
      budget?: TrustBudget;
    };

/**
 * The ordered manifest of checks this harness ENFORCES before signing. It is policy-relevant code/config,
 * so it is folded into {@link Harness.harnessMeasurement}: changing what the harness enforces changes what an
 * attestation of the harness measures. The default is the B1 invariant set.
 */
export const ENFORCED_CHECKS: readonly string[] = [
  'plan_inclusion_before_signing',
  'taint_provenance_fold',
  'trust_budget_debit',
  'pcactn_sign',
] as const;

/** Semantic version of the harness's policy-relevant surface. Bump ⇒ measurement changes. */
export const HARNESS_VERSION = '0.1.0';

/**
 * The stable model-identifier this harness stamps into an emitted PCActn's `attestation.model_id` when
 * {@link HarnessOptions.attestation} is enabled. In B1 the "model" the attestation names is the AUDITABLE
 * MEDIATOR, not an opaque LLM: a resource server that pins this id (and allowlists the measurement) is
 * trusting the harness TCB, not the oracle. Distinct from the `'unattested'` stub `buildPCActn` defaults to.
 */
export const HARNESS_MODEL_ID = '@atlasauth/pca-harness';

/**
 * Pure, deterministic self-measurement: a SHA-256 digest (b64u) over the harness version + the enforced-checks
 * manifest + the risk-policy identity. This is a STUB for what a real attestation would measure about the
 * mediator (B1): a hash over the harness binary / policy config rather than over model weights. Two harnesses
 * with the same policy-relevant surface measure identically; any change to the enforced checks changes it.
 */
export function computeHarnessMeasurement(
  version: string,
  enforcedChecks: readonly string[],
  policy: RiskPolicy,
): string {
  return hashCanonical({
    harness: '@atlasauth/pca-harness',
    version,
    enforces: enforcedChecks,
    // The risk weights + thresholds are policy-relevant: a mediator that gates differently is a different TCB.
    risk_policy: {
      weights: policy.weights,
      theta1: policy.theta1,
      theta2: policy.theta2,
      kappa: policy.kappa,
    },
  });
}

/** Base risk inputs for an in-plan action; `taint` is overwritten per-step from input provenance. */
const DEFAULT_BASE_RISK: RiskInputs = {
  semanticDistance: 0.1,
  reversibility: 1, // reversible ⇒ low risk
  blastRadius: 0.1,
  taint: 0,
  confidence: 1,
  age: 0,
};

export interface HarnessOptions {
  /** The principal-signed root capability (the grant the chain roots at). */
  grant: Capability;
  /** The capability chain ending at the leaf the harness signs for; defaults to `[grant]`. */
  chain?: CapabilityChain;
  /** Ed25519 secret key of the leaf holder. The ORACLE never sees this: only the harness signs. */
  agentSecret: Uint8Array;
  /** The principal-authorised, committed plan. The harness only ever emits actions that are nodes of it. */
  plan: PlanNode[];
  /** Audience the PCActns are for (resource-server / Atlas instance id). */
  audience: string;
  /** Decaying trust budget. Machine-only actions (t<3) are metered against it. */
  budget: TrustBudget;
  /** Risk policy (weights, thresholds, κ, λ). Defaults to {@link DEFAULT_RISK_POLICY}. */
  policy?: RiskPolicy;
  /** Base risk inputs before taint folding. Defaults to a low, reversible profile. */
  baseRisk?: Partial<RiskInputs>;
  /** Clock (epoch ms); default `Date.now`. */
  now?: () => number;
  /** TTL stamped into each PCActn. */
  ttlMs?: number;
  /**
   * Override the enforced-checks manifest that feeds {@link Harness.harnessMeasurement}. For demonstrating
   * that the measurement tracks the mediator's policy surface; defaults to {@link ENFORCED_CHECKS}.
   */
  measurementManifest?: readonly string[];
  /** Deterministic nonce source (for tests); default a random 16-byte hex. */
  nonce?: () => string;
  /**
   * When set, STAMP this harness's B1 self-measurement into every emitted PCActn's `attestation` block
   * (`measurement = {@link Harness.harnessMeasurement}()`, `model_id = {@link HARNESS_MODEL_ID}`,
   * `operator`), so a resource server that allowlists the mediator (see `createHarnessAttestationVerifier`)
   * can verify the action was emitted by an attested harness — the B1 "attest the mediator" wire carrier.
   * The whole `attestation` block is covered by the leaf signature `buildPCActn` applies, so the stamped
   * measurement is tamper-evident and bound to the signing harness. `quote_digest` is left EMPTY: a harness
   * carries no server-issued TEE nonce (that is the distinct TEE/software attestation path).
   *
   * Default OFF: absent ⇒ the `attestation` block stays the empty stub `buildPCActn` defaults to, so an
   * emitted PCActn is byte-identical to the pre-B1-wiring prototype.
   */
  attestation?: { operator: string; epoch?: number };
}

const defaultNonce = (): string => {
  const b = new Uint8Array(16);
  (globalThis as unknown as { crypto: { getRandomValues(a: Uint8Array): Uint8Array } }).crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
};

/**
 * The attested mediator. Holds the principal's grant + committed plan + signing key + trust budget, and wraps
 * an untrusted model oracle. {@link Harness.step} is the ONLY path from an oracle proposal to a signed PCActn,
 * and it enforces plan-inclusion → taint fold → budget → sign, in that order.
 */
export class Harness {
  private readonly grant: Capability;
  private readonly chain: CapabilityChain;
  private readonly agentSecret: Uint8Array;
  private readonly plan: PlanNode[];
  private readonly planIndex: Map<string, PlanNode>;
  private readonly committed: ReturnType<typeof commitPlan>;
  private readonly audience: string;
  private readonly policy: RiskPolicy;
  private readonly baseRisk: RiskInputs;
  private readonly now: () => number;
  private readonly ttlMs: number | undefined;
  private readonly manifest: readonly string[];
  private readonly nonce: () => string;
  private readonly attest: { operator: string; epoch?: number } | undefined;

  private _budget: TrustBudget;
  private _counter = 0;

  constructor(opts: HarnessOptions) {
    if (typeof opts.audience !== 'string' || opts.audience.length === 0) {
      throw new Error('Harness: `audience` is required (the resource-server / instance id PCActns are for)');
    }
    this.grant = opts.grant;
    this.chain = opts.chain ?? [opts.grant];
    this.agentSecret = opts.agentSecret;
    this.plan = opts.plan;
    this.planIndex = new Map(opts.plan.map((n) => [n.id, n]));
    // Commit the principal-authorised plan ONCE; every emitted action carries an inclusion proof under this root.
    this.committed = commitPlan(opts.plan);
    this.audience = opts.audience;
    this.policy = opts.policy ?? DEFAULT_RISK_POLICY;
    this.baseRisk = { ...DEFAULT_BASE_RISK, ...(opts.baseRisk ?? {}) };
    this.now = opts.now ?? Date.now;
    this.ttlMs = opts.ttlMs;
    this.manifest = opts.measurementManifest ?? ENFORCED_CHECKS;
    this.nonce = opts.nonce ?? defaultNonce;
    this.attest = opts.attestation;
    this._budget = opts.budget;
  }

  /** The committed plan root the principal authorised. */
  get planRoot(): string {
    return this.committed.root;
  }

  /** Current (leaked-to-last-touch) trust budget. */
  get budget(): TrustBudget {
    return this._budget;
  }

  /** Monotonic action counter: the number of PCActns this harness has emitted. */
  get counter(): number {
    return this._counter;
  }

  /**
   * B1 self-measurement. A SHA-256 digest over the harness's own policy-relevant surface — what a remote
   * attestation of the MEDIATOR would cover, in place of the (unmeasurable) model weights of L0. Stable for a
   * given policy surface; changes iff the version, enforced-checks manifest, or gating policy changes.
   */
  harnessMeasurement(): string {
    return computeHarnessMeasurement(HARNESS_VERSION, this.manifest, this.policy);
  }

  /**
   * Ask the untrusted oracle for a candidate action and, only if it survives the invariant gate, emit a signed
   * PCActn. Enforcement order (B1):
   *   1. PLAN INCLUSION — the candidate must correspond to a node of the committed plan (same verb/resource,
   *      and params matching the node's committed params_digest). An out-of-plan candidate (injection, e.g.
   *      "wire the money") is refused HERE, before anything is signed, and no PCActn is produced.
   *   2. TAINT FOLD — a taint label is derived from the declared input provenance (any `untrusted` lineage ⇒
   *      taint=1) and folded into the risk inputs, raising r.
   *   3. TRUST BUDGET — the (leaked) budget must cover the risk cost κ·r for a machine-only (t<3) action;
   *      otherwise the action is refused and must step up to a human (no budget is debited, no PCActn).
   *   4. SIGN — only now is the PCActn built and signed with the leaf holder key.
   */
  async step(proposeAction: ProposeAction): Promise<StepResult> {
    const candidate = await proposeAction();

    // (0) Shape check — the oracle is untrusted, so validate before use.
    if (
      candidate === null ||
      typeof candidate !== 'object' ||
      typeof candidate.nodeId !== 'string' ||
      typeof candidate.verb !== 'string' ||
      typeof candidate.resource !== 'string'
    ) {
      return { ok: false, reason: 'bad_candidate', detail: 'oracle returned a malformed candidate' };
    }

    // (1) PLAN INCLUSION — reject out-of-plan BEFORE signing. This is the core B1 claim.
    const node = this.planIndex.get(candidate.nodeId);
    if (!node) {
      return { ok: false, reason: 'out_of_plan', detail: `node '${candidate.nodeId}' is not in the committed plan` };
    }
    if (node.verb !== candidate.verb || node.resource !== candidate.resource) {
      // The oracle named a real node but tried to smuggle a different action under it (e.g. same node id,
      // verb swapped to "transfer"): the committed leaf would not match, so refuse before signing.
      return {
        ok: false,
        reason: 'out_of_plan',
        detail: `action ${candidate.verb} ${candidate.resource} does not match committed node '${node.id}' (${node.verb} ${node.resource})`,
      };
    }
    // Build the Merkle inclusion proof against the committed root (recomputable by any verifier).
    let inclusionProof: InclusionProof;
    try {
      inclusionProof = this.committed.proofFor(node.id);
    } catch (e) {
      return { ok: false, reason: 'out_of_plan', detail: `no inclusion proof for '${node.id}': ${(e as Error).message}` };
    }

    // (2) TAINT FOLD — untrusted input lineage raises risk.
    const inputs = Array.isArray(candidate.inputs) ? candidate.inputs : [];
    const taint = inputs.some((i) => i && i.provenance === 'untrusted') ? 1 : 0;
    const trustedRefs = inputs.filter((i) => i && i.provenance === 'trusted').map((i) => i.ref);
    const riskInputs: RiskInputs = { ...this.baseRisk, taint };
    // Round to 6 d.p.: riskScore is a float sum whose full precision can exceed the 15-significant-digit
    // plain-decimal bound the canonical wire form requires for fractional fields. Rounding once here keeps the
    // reported r, the signed risk_claim.r, and the budget cost all consistent.
    const r = Math.round(riskScore(riskInputs, this.policy.weights satisfies RiskWeights) * 1e6) / 1e6;
    const rt = requiredThreshold(r, this.policy, { irreversible: node.reversibility_class === 'irreversible' });

    // (3) TRUST BUDGET — meter machine-only actions. Leak to now first.
    const nowMs = this.now();
    const leaked = leak(this._budget, nowMs, this.policy.lambda);
    const c = cost(r, this.policy.kappa);
    if (rt.t < 3 && !(leaked.B >= c)) {
      // Budget cannot cover even this (possibly low-risk) in-plan action ⇒ escalate to a human step-up.
      // Nothing is debited and NO PCActn is produced.
      this._budget = leaked;
      return {
        ok: false,
        reason: 'over_budget',
        detail: `budget ${leaked.B.toFixed(4)} < cost ${c.toFixed(4)}; step up to a human co-sign`,
        requiredT: 3,
        budget: leaked,
      };
    }

    // (4) SIGN — build + sign the PCActn via @atlasauth/pca. buildPCActn re-derives the SAME inclusion proof
    // internally; passing our committed plan guarantees the root it stamps equals `this.planRoot`.
    const provenance: PCActn['provenance'] = {
      causal_hash: hashCanonical(inputs.map((i) => ({ ref: i.ref, provenance: i.provenance }))),
      taint_level: taint,
      trusted_refs: trustedRefs,
    };
    // B1 attestation stamp (opt-in): carry THIS mediator's self-measurement in the signed `attestation`
    // block so an allowlisting resource server can verify the action came from an attested harness. Empty
    // `quote_digest`: a harness carries no server-issued TEE nonce (the distinct TEE/software path).
    const attestation: PCActn['attestation'] | undefined = this.attest
      ? {
          quote_digest: '',
          epoch: this.attest.epoch ?? 0,
          model_id: HARNESS_MODEL_ID,
          measurement: this.harnessMeasurement(),
          operator: this.attest.operator,
        }
      : undefined;
    let pcactn: PCActn;
    try {
      pcactn = buildPCActn({
        grant: this.grant,
        chain: this.chain,
        plan: this.plan,
        nodeId: node.id,
        params: candidate.params,
        counter: this._counter + 1,
        signerSecret: this.agentSecret,
        aud: this.audience,
        now: nowMs,
        provenance,
        riskClaim: { r, inputs: { ...riskInputs } },
        nonce: this.nonce(),
        ...(attestation ? { attestation } : {}),
        ...(this.ttlMs !== undefined ? { ttlMs: this.ttlMs } : {}),
      });
    } catch (e) {
      // e.g. params do not match the node's committed params_digest — still never emits an out-of-plan action.
      return { ok: false, reason: 'bad_candidate', detail: `could not build PCActn: ${(e as Error).message}` };
    }

    // Debit only for a metered (machine-only, t<3) action; commit the counter.
    const debited = rt.t < 3 ? debit(leaked, c) : leaked;
    this._budget = debited;
    this._counter += 1;

    return {
      ok: true,
      pcactn,
      inclusionProof,
      risk: { r, inputs: riskInputs, taint, t: rt.t },
      budget: this._budget,
    };
  }
}
