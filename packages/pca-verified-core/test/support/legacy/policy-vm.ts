// FROZEN SNAPSHOT of packages/pca/src/policy-vm.ts BEFORE the verified-core wiring of the decide() kernels (git f0991ade). Legacy reference for the differential tests; never edit.
import { type Capability, type CapabilityChain, verifyChain } from '../../../../pca/src/capability';
import type { PCActn } from '../../../../pca/src/pcactn';
import type { PlanNode } from '../../../../pca/src/merkle';
import { ENVELOPE_CAVEAT, readEnvelope } from '../../../../pca/src/envelope';
import { withRegexBudget } from '../../../../pca/src/regex-budget';
import { agentNativeCaveatEvaluator, type AgentCaveatContext } from '../../../../pca/src/agent-native';
import {
  evaluateCaveats,
  evaluatePredicates,
  type ActionContext,
  type CaveatContext,
} from '../../../../pca/src/predicates';
import {
  admit as admitBudget,
  ageSinceTouch,
  cost,
  debit,
  leak,
  planGeodesic,
  escalateThreshold,
  requiredThreshold,
  riskScore,
  type RequiredThreshold,
  type RiskInputs,
  type TrustBudget,
} from '../../../../pca/src/risk';

/**
 * Deterministic Policy VM (L2 "policy-as-cosigner"): the DECISION of whether the Guardian share
 * may be released for an action, and what threshold/proof the action then needs. The actual
 * threshold signing is M2/M4. Pure, total, never throws; every denial carries a reason.
 *
 * Not enforced here (later milestones): grant signature (`verifyChain`), `agent_binding` (L0).
 */

export interface DecideInput {
  grant: Capability;
  /**
   * R3-01: verifier-side PQ pins by Ed25519 identity (from the instance's pin registry, NEVER from the request or the
   * artifact). A pure-PQ / hybrid ROOT is refused unless its issuer has a pin equal to its `pq_pk`.
   */
  pqPins?: Readonly<Record<string, string>>;
  /**
   * The verifier's OWN stored copy of the grant (never the presented artifact's root). A pure-PQ / hybrid ROOT whose
   * capability is byte-identical to it is authorised on its own `pq_pk` (R3-01 `ChainPolicy.trustedRoot`), exactly as
   * `verifyPCActnCore` authorises it; a pin in `pqPins` that disagrees still refuses. Without it (and without a pin) a
   * pure-PQ / hybrid root is refused (fail closed). `verifyPCActn` and `deriveDecideInput` pass their stored grant here.
   */
  trustedRoot?: Capability;
  /**
   * Optional delegation chain (root = grant ... leaf). When given: delegationDepth is derived as
   * chain.length-1 (overriding caveatContext.delegationDepth) and caveats added beyond the
   * grant's by the hops are evaluated too. Omitted => legacy behaviour.
   */
  chain?: CapabilityChain;
  action: ActionContext;
  plan?: PlanNode[];
  /** Missing risk inputs fail closed (worst case), except `age`, derived from the budget's τ. */
  risk: Partial<RiskInputs>;
  budget: TrustBudget;
  /** epoch ms */
  now: number;
  /**
   * Plan node id the action is bound to (the signed `pcactn.plan.node_id`). Absent: no node is assumed (worst-case semantic
   * distance; the reversibility class is the action's own, else unknown, which reversibility_max caveats refuse).
   */
  nodeId?: string;
  /** Plan goal node (default: last plan node). */
  goalNodeId?: string;
  /** Extra caveat data the VM cannot derive: delegationDepth, recentActionTimes, reversibilityClass. */
  caveatContext?: Partial<Omit<CaveatContext, 'now'>>;
  /** Horizon for deriving `age` from the budget when not given (default 1h). */
  ageHorizonMs?: number;
  /**
   * Monotone risk floor (the PCActn's signed `caution`): `r = max(computed r, rFloor)`. Can only RAISE risk
   * (so the required threshold and budget cost), never lower it. Ignored unless a finite number in [0,1].
   */
  rFloor?: number;
  /**
   * A2h — ALREADY-VERIFIED MARKER. `decide()` fails closed on an unverified capability chain: unless this is
   * exactly `true`, `decide()` itself runs {@link verifyChain} over `chain` (or `[grant]` when no chain is
   * given), rooted at `grant.issuer`, and DENIES if the signatures / lineage do not verify. Set it to `true`
   * ONLY when an upstream verifier (e.g. `verifyPCActnCore`'s `cap_chain` check) has ALREADY run `verifyChain`
   * on this exact chain in this request, to skip the redundant re-verification. A forged/absent signature can
   * thus never be laundered through `decide()` by an SDK that forgot to verify first.
   */
  chainVerified?: boolean;
}

export interface PolicyDecision {
  /** Guardian participates in signing this action (policy + caveats satisfied). */
  releaseGuardianShare: boolean;
  /** Threshold/proof the resulting signature must meet. */
  requiredThreshold: RequiredThreshold;
  r: number;
  /** Auto path admitted (r <= θ1 and budget covers cost): no human needed. */
  admit: boolean;
  /** A higher threshold / human co-sign (recharge) is required. */
  needStepUp: boolean;
  reasons: string[];
  /** Budget after leak (and debit if the action was auto-admitted AND released). */
  budget: TrustBudget;
}

/**
 * The tool call an action denotes, for `tool_schema` caveats: tool = the signed action verb, args = the
 * (digest-checked) action params. Both are bound by the PCActn signature, so the agent cannot present a
 * different tool/args than the ones it signed. Missing params => `{}` (a schema with required args then
 * fails closed).
 */
export function toolCallOf(action: ActionContext): { tool: string; args: Record<string, unknown>; toolSignatureDigest?: string } {
  const a = action?.action;
  const params = a?.params;
  return {
    tool: typeof a?.verb === 'string' ? a.verb : '',
    args: params !== null && typeof params === 'object' && !Array.isArray(params) ? (params as Record<string, unknown>) : {},
    ...(typeof action?.toolBinding === 'string' ? { toolSignatureDigest: action.toolBinding } : {}),
  };
}

/**
 * Extend a stock caveat context with the action + derived tool call so `predicates` / `tool_schema`
 * caveats can be evaluated. The derived fields are applied LAST: a caller-supplied context can never
 * substitute a different action or tool call.
 */
export function agentCaveatContext(base: CaveatContext, action: ActionContext): CaveatContext & AgentCaveatContext {
  return { ...base, action, toolCall: toolCallOf(action) };
}

/** Evaluate caveats with the agent-native evaluator (stock types unchanged; `predicates`/`tool_schema` enforced; unknown => fail closed). */
export function evaluateAgentCaveats(caveats: Capability['caveats'], base: CaveatContext, action: ActionContext) {
  return evaluateCaveats(caveats, agentCaveatContext(base, action), agentNativeCaveatEvaluator);
}

/**
 * THE reversibility class of an action, shared by every path that evaluates `reversibility_max` caveats (decide() for the
 * envelope caveats, verifyPCActn for the delegated ones) and by the optimistic fast-path gate: the action's own class, else the
 * class of the plan node the action is bound to (`nodeId`, the SIGNED `pcactn.plan.node_id` on the server path), else
 * undefined, which no `reversibility_max` caveat accepts and which is not fast-path eligible (fail closed).
 */
export function resolveReversibilityClass(action: ActionContext | undefined, plan: readonly PlanNode[] | undefined, nodeId: string | undefined): string | undefined {
  const own = action?.action?.reversibility_class;
  if (own !== undefined && own !== null) return own;
  if (typeof nodeId !== 'string') return undefined; // no node named: never a guess (not even a plan node that lacks an id)
  return plan?.find((n) => n.id === nodeId)?.reversibility_class;
}

/**
 * The caveats on the ROOT grant that the policy layer evaluates as caveats: every entry of `grant.caveats` except the
 * first `envelope` caveat (the one `readEnvelope` reads; its predicates and inner caveats are evaluated separately).
 * A non-array list is returned as is, and `evaluateCaveats` refuses it (fail closed).
 */
export function rootCaveats(grant: Capability): Capability['caveats'] {
  const cs = grant?.caveats;
  if (!Array.isArray(cs)) return cs;
  const i = cs.findIndex((c) => c?.type === ENVELOPE_CAVEAT);
  return i < 0 ? cs.slice() : [...cs.slice(0, i), ...cs.slice(i + 1)];
}

/**
 * Every caveat the policy layer evaluates as a caveat for an action under `grant` delegated along `chain` (root first):
 * {@link rootCaveats} of the grant, then the caveats the hops appended (`leaf.caveats` beyond the grant's). This is the
 * list the conformance `caveat_eval` vectors evaluate; `decide()` / `verifyPCActn` evaluate the same two parts (and the
 * envelope's own caveats and predicates besides).
 */
export function policyCaveats(grant: Capability, chain?: CapabilityChain): Capability['caveats'] {
  const root = rootCaveats(grant);
  const leaf = Array.isArray(chain) ? chain[chain.length - 1] : undefined; // [] -> undefined
  const appended = leaf && Array.isArray(leaf.caveats) && Array.isArray(grant?.caveats) ? leaf.caveats.slice(grant.caveats.length) : [];
  return Array.isArray(root) ? [...root, ...appended] : root;
}

const WORST: RiskInputs = {
  semanticDistance: 1,
  reversibility: 0,
  blastRadius: 1,
  taint: 1,
  confidence: 0,
  age: 1,
};

/**
 * Reversibility classes RECOGNIZED as non-irreversible (so the optimistic/bonded fast-path may be
 * offered). The union of the classes the codebase recognizes as reversible-ish: `reversible`
 * (the merkle commitment default), `rate_limited` (the caveat enum), and `costly` (the RS
 * strictness enum). Anything NOT in this set — an ABSENT (undefined) or UNRECOGNIZED class — fails
 * CLOSED: it is treated as irreversible, so `optimisticAllowed` is denied. This is symmetric with
 * risk inputs, which also fail to the worst case when missing/unknown; it only tightens the
 * fast-path gate and never loosens the server-authoritative risk derivation.
 */
const FAST_PATH_ELIGIBLE_CLASSES: ReadonlySet<string> = new Set(['reversible', 'rate_limited', 'costly']);

function denied(reason: string, budget: TrustBudget): PolicyDecision {
  return {
    releaseGuardianShare: false,
    requiredThreshold: { t: 3, proof: 'strong', optimisticAllowed: false },
    r: 1,
    admit: false,
    needStepUp: true,
    reasons: [reason],
    budget,
  };
}

export function decide(input: DecideInput): PolicyDecision {
  // R4-05: ONE regex work budget for the whole decision (envelope predicates + every caveat of every hop).
  return withRegexBudget(() => decideInner(input));
}

function decideInner(input: DecideInput): PolicyDecision {
  const fallbackBudget: TrustBudget = input?.budget ?? { B: 0, tau: 0 };
  try {
    const { grant, action, plan, risk, budget, now } = input;
    const env = readEnvelope(grant);
    if (!env) return denied('grant carries no valid envelope', budget);
    if (!Number.isFinite(now)) return denied('invalid decision time', budget);

    // A2h — fail closed on an UNVERIFIED capability chain. Unless the caller passed the already-verified
    // marker, `decide()` itself re-runs `verifyChain` (over the supplied chain, or `[grant]` as a single-hop
    // when none is given) rooted at the grant's issuer. A grant/chain whose signatures or attenuation lineage
    // do not verify is DENIED here — SDK misuse that skipped verification can no longer reach a release. A
    // chain that IS present but empty/malformed is left to the existing `chainOk` handling below (so the
    // precise "delegation chain is empty or malformed" reason is preserved); the single grant is still checked.
    if (input.chainVerified !== true) {
      const toVerify: CapabilityChain =
        Array.isArray(input.chain) && input.chain.length > 0 ? input.chain : [grant];
      const cr = verifyChain(toVerify, grant?.issuer, { pqPins: input.pqPins, ...(input.trustedRoot !== undefined ? { trustedRoot: input.trustedRoot } : {}) });
      if (!cr.ok) return denied(`capability chain unverified: ${cr.reason ?? 'invalid'}`, budget);
    }

    const pol = env.risk_policy;
    const reasons: string[] = [];

    // 1. semantic predicates (default deny)
    const pr = evaluatePredicates(env.predicates, action);
    if (!pr.allowed) reasons.push(pr.reason ?? 'action not permitted by envelope predicates');

    // The plan node is the one the caller names (on the server path: the SIGNED pcactn.plan.node_id). There is no
    // verb/resource guess: without a node id the distance is the worst case and the class comes from the action alone.
    const nodeId = input.nodeId;

    // 2. envelope caveats
    const chain = input.chain;
    const cctx: CaveatContext = {
      now,
      blastRadius: risk?.blastRadius,
      reversibilityClass: resolveReversibilityClass(action, plan, nodeId),
      ...input.caveatContext,
    };
    let chainOk = true;
    let extra: typeof grant.caveats = [];
    if (chain !== undefined) {
      if (!Array.isArray(chain) || chain.length === 0) {
        chainOk = false;
        reasons.push('delegation chain is empty or malformed');
      } else {
        cctx.delegationDepth = chain.length - 1;
        extra = chain[chain.length - 1]!.caveats.slice(grant.caveats.length);
      }
    }
    const ecv = evaluateAgentCaveats(env.caveats, cctx, action);
    if (!ecv.ok) reasons.push(`caveat(s) not satisfied: ${ecv.failed.join(', ')}`);
    // 0.4.1 (security): caveats placed directly on the ROOT grant, outside the envelope, are signed authority too and are
    // enforced exactly like the caveats delegation hops append (attenuation applies from the root). Only the envelope
    // caveat that `readEnvelope` reads is excluded (its predicates and inner caveats are evaluated above); a second
    // `envelope` caveat, or any type this evaluator does not implement, is unsatisfied (fail closed).
    const rcv = evaluateAgentCaveats(rootCaveats(grant), cctx, action);
    if (!rcv.ok) reasons.push(`root caveat(s) not satisfied: ${rcv.failed.join(', ')}`);
    const cv = { ok: ecv.ok && rcv.ok };
    const dcv = evaluateAgentCaveats(extra, cctx, action);
    if (!dcv.ok) reasons.push(`delegated caveat(s) not satisfied: ${dcv.failed.join(', ')}`);

    // 3. risk
    const leaked = leak(budget, now, pol.lambda);
    const inputs: RiskInputs = { ...WORST, ...stripUndef(risk) };
    const missing = (Object.keys(WORST) as (keyof RiskInputs)[]).filter(
      (k) => k !== 'age' && (risk?.[k] === undefined || !Number.isFinite(risk[k])),
    );
    if (plan && risk?.semanticDistance === undefined) {
      const goal = input.goalNodeId ?? plan[plan.length - 1]?.id;
      inputs.semanticDistance =
        nodeId !== undefined && goal !== undefined ? planGeodesic(plan, nodeId, goal) : 1;
      const i = missing.indexOf('semanticDistance');
      if (i >= 0) missing.splice(i, 1);
    }
    if (risk?.age === undefined) inputs.age = ageSinceTouch(leaked, now, input.ageHorizonMs);
    if (missing.length) reasons.push(`risk input(s) missing, assumed worst case: ${missing.join(', ')}`);
    const rFloor = typeof input.rFloor === 'number' && Number.isFinite(input.rFloor) ? Math.min(1, Math.max(0, input.rFloor)) : 0;
    const r = Math.max(riskScore(inputs, pol.weights), rFloor);

    // Reversibility fails CLOSED for the optimistic fast-path: only a RECOGNIZED non-irreversible
    // class is fast-path eligible. A missing (undefined) or unrecognized class is treated as
    // irreversible (NOT optimistic-eligible) — never fail-open.
    const rc = cctx.reversibilityClass;
    const irreversible = !(typeof rc === 'string' && FAST_PATH_ELIGIBLE_CLASSES.has(rc));
    const rt = requiredThreshold(r, pol, { irreversible });

    // 4. budget admission
    const adm = admitBudget(r, leaked, pol);
    if (adm.needStepUp) {
      reasons.push(
        rt.t < 3 && adm.t === 3
          ? 'trust budget depleted: human recharge required'
          : `risk ${r.toFixed(3)} exceeds auto threshold: step-up to t=${adm.t}`,
      );
    }

    // 5. guardian release: policy AND caveats; the human/step-up path stays available otherwise
    const policyOk = pr.allowed && cv.ok && dcv.ok && chainOk;
    const release = policyOk;
    const autoAdmit = release && adm.admit;
    const outBudget = release && adm.metered ? debit(leaked, cost(r, pol.kappa)) : leaked;
    return {
      releaseGuardianShare: release,
      requiredThreshold: escalateThreshold(rt, adm.t),
      r,
      admit: autoAdmit,
      needStepUp: release ? adm.needStepUp : true,
      reasons,
      budget: outBudget,
    };
  } catch (e) {
    return denied(`policy evaluation error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`, fallbackBudget);
  }
}

function stripUndef(r: Partial<RiskInputs> | undefined): Partial<RiskInputs> {
  const out: Partial<RiskInputs> = {};
  if (!r) return out;
  for (const k of Object.keys(WORST) as (keyof RiskInputs)[]) {
    if (typeof r[k] === 'number' && Number.isFinite(r[k])) out[k] = r[k];
  }
  return out;
}

/**
 * Assemble a DecideInput from a PCActn plus RS-supplied context, so caller and verifier derive
 * action / nodeId / chain identically. The action context comes from the PCActn's own action
 * (params from `ctx.params`, which the caller must have checked against action.params_digest).
 */
/** `deriveDecideInput` was called without `ctx.grant` (the verifier's own stored grant). Never defaulted from the artifact. */
export class DecideInputGrantRequired extends Error {
  readonly code = 'grant_required' as const;
  constructor() {
    super('deriveDecideInput: ctx.grant (the grant from your own store) is required; the presented chain root is never used as the grant');
    this.name = 'DecideInputGrantRequired';
  }
}

export function deriveDecideInput(
  p: PCActn,
  ctx: {
    plan?: PlanNode[];
    params?: Record<string, unknown>;
    risk: Partial<RiskInputs>;
    budget: TrustBudget;
    chain?: CapabilityChain;
    now: number;
    /** REQUIRED: the grant from the verifier's own store (by the PCActn's grant_ref). */
    grant: Capability;
    goalNodeId?: string;
    subject?: Record<string, unknown>;
    env?: Record<string, unknown>;
    caveatContext?: Partial<Omit<CaveatContext, 'now'>>;
    ageHorizonMs?: number;
  },
): DecideInput {
  // Fail closed (R6-CORE-04 follow-up): the grant is the verifier's OWN stored grant. It is never taken from the presented
  // artifact's chain root, whose predicates an attacker can mint for itself.
  if (ctx.grant === undefined || ctx.grant === null || typeof ctx.grant !== 'object') throw new DecideInputGrantRequired();
  const chain = ctx.chain ?? p.cap_chain;
  return {
    grant: ctx.grant,
    chain,
    action: {
      action: {
        verb: p.action?.verb,
        resource: p.action?.resource,
        params: ctx.params ?? {},
        reversibility_class: p.action?.reversibility_class,
      },
      ...(ctx.subject ? { subject: ctx.subject } : {}),
      ...(ctx.env ? { env: ctx.env } : {}),
    },
    plan: ctx.plan,
    nodeId: p.plan?.node_id,
    goalNodeId: ctx.goalNodeId,
    risk: ctx.risk,
    budget: ctx.budget,
    now: ctx.now,
    caveatContext: ctx.caveatContext,
    ageHorizonMs: ctx.ageHorizonMs,
  };
}
