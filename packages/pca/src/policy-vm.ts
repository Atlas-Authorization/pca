import { type Capability, type CapabilityChain, verifyChain } from './capability';
import type { PCActn } from './pcactn';
import type { PlanNode } from './merkle';
import { readEnvelope } from './envelope';
import { agentNativeCaveatEvaluator, type AgentCaveatContext } from './agent-native';
import {
  evaluateCaveats,
  evaluatePredicates,
  type ActionContext,
  type CaveatContext,
} from './predicates';
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
} from './risk';

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
  /** Plan node id that the action corresponds to (default: first node matching verb+resource). */
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
      const cr = verifyChain(toVerify, grant?.issuer);
      if (!cr.ok) return denied(`capability chain unverified: ${cr.reason ?? 'invalid'}`, budget);
    }

    const pol = env.risk_policy;
    const reasons: string[] = [];

    // 1. semantic predicates (default deny)
    const pr = evaluatePredicates(env.predicates, action);
    if (!pr.allowed) reasons.push(pr.reason ?? 'action not permitted by envelope predicates');

    // plan node lookup (semantic distance + reversibility class)
    let nodeId = input.nodeId;
    if (plan && nodeId === undefined) {
      nodeId = plan.find((n) => n.verb === action?.action?.verb && n.resource === action?.action?.resource)?.id;
    }
    const node = plan?.find((n) => n.id === nodeId);

    // 2. envelope caveats
    const chain = input.chain;
    const cctx: CaveatContext = {
      now,
      blastRadius: risk?.blastRadius,
      reversibilityClass: action?.action?.reversibility_class ?? node?.reversibility_class,
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
    const cv = evaluateAgentCaveats(env.caveats, cctx, action);
    if (!cv.ok) reasons.push(`caveat(s) not satisfied: ${cv.failed.join(', ')}`);
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
export function deriveDecideInput(
  p: PCActn,
  ctx: {
    plan?: PlanNode[];
    params?: Record<string, unknown>;
    risk: Partial<RiskInputs>;
    budget: TrustBudget;
    chain?: CapabilityChain;
    now: number;
    grant?: Capability;
    goalNodeId?: string;
    subject?: Record<string, unknown>;
    env?: Record<string, unknown>;
    caveatContext?: Partial<Omit<CaveatContext, 'now'>>;
    ageHorizonMs?: number;
  },
): DecideInput {
  const chain = ctx.chain ?? p.cap_chain;
  const grant = ctx.grant ?? chain?.[0];
  return {
    grant: grant as Capability,
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
