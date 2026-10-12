/* eslint-disable @typescript-eslint/no-explicit-any */
// Reference drop-in for policy-vm.ts `decide()` whose predicate evaluation, caveat evaluation, threshold map, admission and release
// decision run the PROVED code (src/ext-policyvm.ts). Everything else is copied verbatim from the production function. Used by the
// differential tests; it is NOT wired into production (see docs/pca/security/verified-core.md, "Not wired").
import type { CapabilityChain } from '../../../pca/src/capability';
import { readEnvelope } from '../../../pca/src/envelope';
import { agentCaveatContext, resolveReversibilityClass, type DecideInput, type PolicyDecision } from '../../../pca/src/policy-vm';
import { type CaveatContext } from '../../../pca/src/predicates';
import { ageSinceTouch, cost, debit, leak, planGeodesic, type RiskInputs, type TrustBudget, riskScore } from '../../../pca/src/risk';
import { verifyChain } from '../../../pca/src/capability';
import {
  admitVerified,
  decideCoreVerified,
  requiredThresholdVerified,
  type PolicyVm,
} from '../../src/ext-policyvm';

const WORST: RiskInputs = { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 };
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
function stripUndef(r: Partial<RiskInputs> | undefined): Partial<RiskInputs> {
  const out: Partial<RiskInputs> = {};
  if (!r) return out;
  for (const k of Object.keys(WORST) as (keyof RiskInputs)[]) {
    if (typeof r[k] === 'number' && Number.isFinite(r[k])) out[k] = r[k];
  }
  return out;
}

export function decideVerified(input: DecideInput, vm: PolicyVm): PolicyDecision {
  const fallbackBudget: TrustBudget = input?.budget ?? { B: 0, tau: 0 };
  try {
    const { grant, action, plan, risk, budget, now } = input;
    const env = readEnvelope(grant);
    if (!env) return denied('grant carries no valid envelope', budget);
    if (!Number.isFinite(now)) return denied('invalid decision time', budget);
    if (input.chainVerified !== true) {
      const toVerify: CapabilityChain = Array.isArray(input.chain) && input.chain.length > 0 ? input.chain : [grant];
      const cr = verifyChain(toVerify, grant?.issuer, { pqPins: input.pqPins });
      if (!cr.ok) return denied(`capability chain unverified: ${cr.reason ?? 'invalid'}`, budget);
    }
    const pol = env.risk_policy;
    const reasons: string[] = [];

    // 1. semantic predicates (default deny) -- PROVED evaluator
    const pr = vm.evaluatePredicates(env.predicates, action);
    if (!pr.allowed) reasons.push(pr.reason ?? 'action not permitted by envelope predicates');

    const nodeId = input.nodeId;

    // 2. envelope caveats -- PROVED evaluator
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
    const agentCtx = agentCaveatContext(cctx, action);
    const ecv = vm.evaluateCaveats(env.caveats, agentCtx, 'agent');
    if (!ecv.ok) reasons.push(`caveat(s) not satisfied: ${ecv.failed.join(', ')}`);
    // 0.4.1: the root's caveats outside the envelope -- PROVED selection (RootCaveats) and evaluator
    const rcv = vm.evaluateCaveats(vm.rootCaveats(grant.caveats), agentCtx, 'agent');
    if (!rcv.ok) reasons.push(`root caveat(s) not satisfied: ${rcv.failed.join(', ')}`);
    const cv = { ok: ecv.ok && rcv.ok };
    const dcv = vm.evaluateCaveats(extra, agentCtx, 'agent');
    if (!dcv.ok) reasons.push(`delegated caveat(s) not satisfied: ${dcv.failed.join(', ')}`);

    // 3. risk (floating-point glue, unchanged)
    const leaked = leak(budget, now, pol.lambda);
    const inputs: RiskInputs = { ...WORST, ...stripUndef(risk) };
    const missing = (Object.keys(WORST) as (keyof RiskInputs)[]).filter(
      (k) => k !== 'age' && (risk?.[k] === undefined || !Number.isFinite(risk[k])),
    );
    if (plan && risk?.semanticDistance === undefined) {
      const goal = input.goalNodeId ?? plan[plan.length - 1]?.id;
      inputs.semanticDistance = nodeId !== undefined && goal !== undefined ? planGeodesic(plan, nodeId, goal) : 1;
      const i = missing.indexOf('semanticDistance');
      if (i >= 0) missing.splice(i, 1);
    }
    if (risk?.age === undefined) inputs.age = ageSinceTouch(leaked, now, input.ageHorizonMs);
    if (missing.length) reasons.push(`risk input(s) missing, assumed worst case: ${missing.join(', ')}`);
    const rFloor = typeof input.rFloor === 'number' && Number.isFinite(input.rFloor) ? Math.min(1, Math.max(0, input.rFloor)) : 0;
    const r = Math.max(riskScore(inputs, pol.weights), rFloor);

    const rc = cctx.reversibilityClass;
    const irreversible = !(typeof rc === 'string' && FAST_PATH_ELIGIBLE_CLASSES.has(rc));
    // thresholds / admission / release: PROVED kernels
    const rt = requiredThresholdVerified(r, pol.theta1, pol.theta2, irreversible);
    const adm = admitVerified(requiredThresholdVerified(r, pol.theta1, pol.theta2, false).t, leaked.B >= cost(r, pol.kappa));
    if (adm.needStepUp) {
      reasons.push(
        rt.t < 3 && adm.t === 3
          ? 'trust budget depleted: human recharge required'
          : `risk ${r.toFixed(3)} exceeds auto threshold: step-up to t=${adm.t}`,
      );
    }
    const dec = decideCoreVerified(pr.allowed, cv.ok, dcv.ok, chainOk, rt, adm);
    const outBudget = dec.debit ? debit(leaked, cost(r, pol.kappa)) : leaked;
    return {
      releaseGuardianShare: dec.release,
      requiredThreshold: dec.threshold,
      r,
      admit: dec.admit,
      needStepUp: dec.needStepUp,
      reasons,
      budget: outBudget,
    };
  } catch (e) {
    return denied(`policy evaluation error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`, fallbackBudget);
  }
}
