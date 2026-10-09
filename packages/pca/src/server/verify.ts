import { requiresAttestation } from '../attestation';
import { beaconRef, verifyLivenessBeacon, type LivenessBeacon } from '../beacons';
import { type Capability } from '../capability';
import { readEnvelope } from '../envelope';
import { hashCanonical } from '../hash';
import { merkleRoot, planNodeLeaf, type PlanNode } from '../merkle';
import { decodePCActn, verifyPCActnCore, type CheckStatus, type PCActn, type VerifyHooks } from '../pcactn';
import { decide, evaluateAgentCaveats } from '../policy-vm';
import { checkRevocationEpoch, type RevocationEpoch } from '../revocation';
import { type RequiredThreshold, type RiskInputs, type TrustBudget } from '../risk';


/**
 * Resource-server side Proof-Carrying Authority verifier (spec §4, §7, Appendix A).
 * Deterministic and offline; never throws (any internal error becomes a fail-closed verdict).
 */

export interface PcaContext {
  /** Plaintext action params. If given they MUST hash to `action.params_digest`; needed by predicates. */
  params?: Record<string, unknown>;
  subject?: Record<string, unknown>;
  env?: Record<string, unknown>;
  /** The committed plan, if the RS knows it. Its Merkle root must equal `plan.root`. */
  plan?: PlanNode[];
  /**
   * Whether the RS's copy of the plan root has been AUTHORIZED by the principal (App. A step 2).
   * `true` -> `plan_root_authorized` passes; `false` -> it FAILS; absent -> `not-enforced`.
   */
  planAuthorized?: boolean;
  /**
   * The RS's authoritative reversibility class for this action (from the principal-authorized plan node or
   * a verb->class catalog). The agent's self-declared `action.reversibility_class` can only make it STRICTER;
   * declaring a less-restrictive class than this is a hard failure (`reversibility`).
   */
  reversibilityClass?: string;
  /**
   * Risk inputs the RS can vouch for. Missing ones fail closed (worst case), INCLUDING `taint`: the agent's
   * own `provenance.taint_level` is never used as an input (it could only ever lower risk).
   */
  risk?: Partial<RiskInputs>;
  /**
   * Current trust budget for the leaf holder. Absent fails CLOSED to a DENY-METERED budget (B=0): any
   * machine-only (t<3) action with cost κ·r > 0 is forced to step-up / recharge (a zero-risk action is
   * still admitted). The `budget` check reports not-enforced when absent (visibility is preserved).
   */
  budget?: TrustBudget;
  recentActionTimes?: number[];
  /**
   * The guardian-signed revocation epoch for the grant (P2-3). When present the verifier REQUIRES it to
   * be genuine (signature by `guardianPublic`), unexpired (`now <= not_after`), not older than
   * `lastAcceptedEpoch`, and bound to the PCActn's signed `freshness.epoch` (an action that predates the
   * epoch is rejected). Reported as the `freshness` check; absent = `not-enforced`.
   */
  revocationEpoch?: { epoch: RevocationEpoch; guardianPublic: string; lastAcceptedEpoch?: number };
  /**
   * The dead-man liveness beacon for the grant (P2-4). When present the verifier REQUIRES it to be genuine
   * (signed by one of the pinned `issuers`: the grant principal and/or operator), for this `instance`, covering
   * the grant, within its validity (hard-max enforced), not rolled back past `lastAcceptedSeq`, and bound by the
   * PCActn's signed `freshness.beacon_ref`. Reported as the `beacon` check; absent = `not-enforced`.
   */
  beacon?: { beacon: LivenessBeacon; issuers: string[]; instance: string; lastAcceptedSeq?: number };
}

export interface VerifyPCActnOptions {
  grant: Capability;
  /**
   * THIS verifier's audience id (resource server / Atlas instance id). The PCActn's signed `aud` must equal
   * it (audit P0-5: kills cross-server / cross-instance replay). FAIL-CLOSED: if the PCActn carries a signed
   * `aud` but no audience is supplied here, the `audience` check FAILS (a verifier must not silently lose its
   * cross-instance binding). Pass `null` to deliberately accept any audience (reported 'not-enforced'); an
   * absent audience is only 'not-enforced' when the PCActn itself carries no `aud`.
   */
  audience?: string | null;
  hooks?: VerifyHooks;
  /** epoch ms (default Date.now()) */
  now?: number;
  context?: PcaContext;
  /**
   * Minimum enforcement rung: every named check MUST be 'pass'; one that is 'not-enforced' (or absent)
   * is treated as a failure (default-deny). Default: none (the library verifier reports, the caller
   * decides) - `requirePCA` defaults this to {@link DEFAULT_REQUIRED_CHECKS}.
   */
  require?: string[];
}

/** The minimum enforcement profile a resource server should demand (see `requirePCA`). */
export const DEFAULT_REQUIRED_CHECKS = ['counter', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound'] as const;

/** Who the verdict says authorized this: the registry-resolved principal behind the grant. */
export interface PcaPrincipalInfo {
  pub: string;
  subject_type: 'user' | 'org' | 'machine' | 'unverified';
  subject_id: string | null;
  /** true only when the key is an active, authenticated, enrolled principal. */
  verified: boolean;
}

const CLASS_RANK: Record<string, number> = { reversible: 0, costly: 1, irreversible: 2 };
/** Unknown class strings are the most restrictive (fail closed). */
const classRank = (c: unknown): number => (typeof c === 'string' && c in CLASS_RANK ? CLASS_RANK[c]! : 2);

/**
 * Default-deny: turn every required check that is not 'pass' into a failure. Mutates + returns the verdict.
 * Exported so framework adapters that finish checks after `verifyPCActn` (e.g. the replay counter) can apply it last.
 */
export function enforceRequired(v: PcaVerdict, required: readonly string[]): PcaVerdict {
  for (const name of required) {
    const c = v.checks[name];
    if (c === 'pass') continue;
    v.allow = false;
    if (c !== 'fail') {
      v.checks[name] = 'fail';
      v.reasons.push(`${name}: required check is ${c ?? 'absent'} (default-deny: not enforced by this resource server)`);
    }
  }
  return v;
}

export interface PcaVerdict {
  allow: boolean;
  /** Recomputed risk score in [0,1]. */
  r: number;
  requiredThreshold: RequiredThreshold;
  checks: Record<string, CheckStatus>;
  reasons: string[];
  /** Budget after the decision (leaked, and debited when auto-admitted). Persist it on allow. */
  budget?: TrustBudget;
  /** Registry-resolved principal behind the grant (attached by the server / `requirePCA({ resolvePrincipal })`). */
  principal?: PcaPrincipalInfo;
}

const WORST_THRESHOLD: RequiredThreshold = { t: 3, proof: 'strong', optimisticAllowed: false };

function failClosed(reason: string, checks: Record<string, CheckStatus> = {}): PcaVerdict {
  return {
    allow: false,
    r: 1,
    requiredThreshold: WORST_THRESHOLD,
    checks: { ...checks, malformed: 'fail' },
    reasons: [reason],
  };
}

export async function verifyPCActn(pcactn: PCActn | string, opts: VerifyPCActnOptions): Promise<PcaVerdict> {
  try {
    let p: PCActn;
    try {
      p = typeof pcactn === 'string' ? decodePCActn(pcactn) : pcactn;
    } catch (e) {
      return failClosed(`undecodable PCActn: ${(e as Error).message}`);
    }
    if (p === null || typeof p !== 'object') return failClosed('PCActn is not an object');

    const now = opts.now ?? Date.now();
    const ctx = opts.context ?? {};
    const core = await verifyPCActnCore(p, { grant: opts.grant, nowEpoch: now, audience: opts.audience, hooks: opts.hooks });
    // A wire-form failure is terminal (normative): nothing else is evaluated on a malformed object.
    if (core.checks.wire === 'fail') return failClosed(core.reason ?? 'wire: malformed PCActn', { wire: 'fail' });
    const checks: Record<string, CheckStatus> = { ...core.checks };
    const reasons: string[] = [];
    if (!core.allow && core.reason) reasons.push(core.reason);
    const fail = (name: string, why: string) => {
      checks[name] = 'fail';
      reasons.push(`${name}: ${why}`);
    };

    // grant_ref binds the object to this grant
    if (p.grant_ref === opts.grant.id) checks.grant_ref = 'pass';
    else fail('grant_ref', 'does not reference the supplied grant');

    // params plaintext must open the committed digest
    if (ctx.params !== undefined) {
      if (hashCanonical(ctx.params) === p.action?.params_digest) checks.params_digest = 'pass';
      else fail('params_digest', 'supplied params do not hash to action.params_digest');
    } else checks.params_digest = 'not-enforced';

    // the RS's own copy of the plan must be the committed one
    if (ctx.plan) {
      if (merkleRoot(ctx.plan.map(planNodeLeaf)) !== p.plan?.root) {
        fail('plan_root_authorized', 'known plan does not match plan.root');
      } else if (ctx.planAuthorized === true) checks.plan_root_authorized = 'pass';
      else if (ctx.planAuthorized === false) fail('plan_root_authorized', 'the plan root has not been authorized by the principal');
      else checks.plan_root_authorized = 'not-enforced';
    } else checks.plan_root_authorized = 'not-enforced';

    if (ctx.revocationEpoch) {
      const r = checkRevocationEpoch(ctx.revocationEpoch.epoch, {
        guardianPublic: ctx.revocationEpoch.guardianPublic,
        now,
        grantRef: opts.grant.id,
        lastAcceptedEpoch: ctx.revocationEpoch.lastAcceptedEpoch,
        pcactnEpoch: p.freshness?.epoch,
      });
      if (r.ok) checks.freshness = 'pass';
      else fail('freshness', r.reason ?? 'revocation epoch rejected');
    } else checks.freshness = 'not-enforced';

    if (ctx.beacon) {
      const bc = ctx.beacon;
      const r = verifyLivenessBeacon(bc.beacon, { issuers: bc.issuers, now, instance: bc.instance, scope: opts.grant.id });
      if (!r.ok) fail('beacon', r.reason ?? 'beacon rejected');
      else if (bc.lastAcceptedSeq !== undefined && bc.beacon.seq < bc.lastAcceptedSeq) {
        fail('beacon', `beacon seq ${bc.beacon.seq} is older than the last accepted ${bc.lastAcceptedSeq} (replay)`);
      } else if (p.freshness?.beacon_ref !== beaconRef(bc.beacon)) {
        fail('beacon', 'PCActn freshness.beacon_ref does not bind the presented beacon');
      } else checks.beacon = 'pass';
    } else checks.beacon = 'not-enforced';

    // Require-when-bound (audit finding 3): a grant whose agent_binding constrains the model / measurement /
    // operator / weights REQUIRES a bound attestation. Absent, unbound or unenforced => DENY, never skipped.
    if (requiresAttestation(readEnvelope(opts.grant)?.agent_binding) && checks.attestation !== 'pass') {
      fail('attestation', 'the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED');
    }

    const chain = Array.isArray(p.cap_chain) ? p.cap_chain : [];
    const leaf = chain[chain.length - 1];
    const depth = Math.max(0, chain.length - 1);
    const now0 = now;
    // Fail-closed default: an ABSENT budget becomes a DENY-METERED budget (B=0) in `decideBudget`,
    // so a caller that forgets `ctx.budget` cannot silently get unlimited machine-only authority.
    const budgetIn: TrustBudget = ctx.budget ?? { B: 0, tau: now0, asOf: now0 };
    checks.budget = ctx.budget ? 'pass' : 'not-enforced';
    if (ctx.budget === undefined) {
      reasons.push(
        'budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge',
      );
    }

    // Taint: ONLY an RS-supplied value counts. The agent's `provenance.taint_level` is untrusted (it can only
    // lower risk), so a missing RS taint fails closed to the worst case in the Policy VM.
    const risk: Partial<RiskInputs> = { ...ctx.risk };

    // Reversibility: the RS's authoritative class wins; the agent may only be STRICTER.
    const declared = p.action?.reversibility_class;
    let reversibility = declared;
    if (ctx.reversibilityClass !== undefined) {
      if (classRank(declared) < classRank(ctx.reversibilityClass)) {
        fail('reversibility', `declared class '${String(declared)}' is less restrictive than the authoritative '${ctx.reversibilityClass}'`);
      } else checks.reversibility = 'pass';
      reversibility = classRank(declared) > classRank(ctx.reversibilityClass) ? declared : ctx.reversibilityClass;
    }
    const budgetForDecide = decideBudget(budgetIn, ctx.budget === undefined);
    const actionCtx = {
      action: { verb: p.action?.verb, resource: p.action?.resource, params: ctx.params, reversibility_class: reversibility },
      subject: ctx.subject,
      env: ctx.env,
      // Signed `tool_binding` (D): binds the semantic firewall (`tool_schema` caveats) to the tool the agent signed.
      ...(typeof p.tool_binding === 'string' ? { toolBinding: p.tool_binding } : {}),
    };
    const d = decide({
      grant: opts.grant,
      action: actionCtx,
      plan: ctx.plan,
      nodeId: p.plan?.node_id,
      risk,
      budget: budgetForDecide,
      now,
      caveatContext: { delegationDepth: depth, recentActionTimes: ctx.recentActionTimes },
      // Signed `caution` (D): monotone uncertainty attestation, combined with the server r via max.
      rFloor: typeof p.caution === 'number' ? p.caution : undefined,
    });

    // Caveats added by delegation hops (beyond the root's) are conjunctive too.
    if (leaf) {
      const extra = leaf.caveats.slice(opts.grant.caveats.length);
      // Agent-native evaluator: delegated `predicates` / `tool_schema` caveats are ENFORCED against the signed action.
      const cv = evaluateAgentCaveats(
        extra,
        {
          now,
          blastRadius: risk.blastRadius,
          reversibilityClass: reversibility,
          delegationDepth: depth,
          recentActionTimes: ctx.recentActionTimes,
        },
        actionCtx,
      );
      if (cv.ok) checks.delegated_caveats = 'pass';
      else fail('delegated_caveats', `delegation caveat(s) not satisfied: ${cv.failed.join(', ')}`);
    }

    if (d.releaseGuardianShare) checks.policy = 'pass';
    else {
      checks.policy = 'fail';
      reasons.push(...d.reasons.map((x) => `policy: ${x}`));
    }
    if (d.releaseGuardianShare) {
      // informational reasons (step-up, assumed worst case) are kept even when released
      reasons.push(...d.reasons.map((x) => `policy: ${x}`));
    }

    // Threshold: t > 1 needs a proof we can only get from an enforced threshold hook.
    const th = checks.threshold;
    if (d.requiredThreshold.t > 1 && d.releaseGuardianShare && th !== 'pass') {
      fail(
        'threshold',
        th === 'fail'
          ? `t=${d.requiredThreshold.t} required and the threshold proof was rejected`
          : `t=${d.requiredThreshold.t} (${d.requiredThreshold.proof}) required but no threshold verifier is enforced`,
      );
    }

    const allow =
      !Object.values(checks).includes('fail') && d.releaseGuardianShare && core.allow;
    const out: PcaVerdict = allow
      ? { allow, r: d.r, requiredThreshold: d.requiredThreshold, checks, reasons, budget: ctx.budget ? d.budget : undefined }
      : { allow: false, r: d.r, requiredThreshold: d.requiredThreshold, checks, reasons };
    if (opts.require?.length) enforceRequired(out, opts.require);
    if (!out.allow && out.reasons.length === 0) out.reasons.push('denied');
    return out;
  } catch (e) {
    return failClosed(`verifier error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
  }
}

/**
 * An ABSENT budget fails CLOSED. A caller that omits `ctx.budget` would otherwise be handed unlimited
 * machine-only authority, so the safe default is a DENY-METERED budget (B=0): any machine-only (t<3)
 * cost `κ·r > 0` cannot be afforded and the action is forced to human step-up / recharge. The hosted
 * Atlas server path always supplies `ctx.budget` (seeded from the budget store / context), so it is
 * unaffected; only the omitted-budget default changes. A zero-risk (r=0 ⇒ cost 0) action is still
 * admitted at B=0, which keeps it backward-compatible for genuinely free machine actions.
 */
function decideBudget(b: TrustBudget, absent: boolean): TrustBudget {
  return absent ? { ...b, B: 0 } : b;
}
