import { hookTInt } from '../verified-decision';
import { requiresAttestation } from '../attestation';
import { VerdictState, beaconDecision, enforceRequired as enforceRequiredVerified, planDecision, reversibilityDecision, useDeclaredClass, withDeniedFallback } from '@atlasauth/pca-verified-core';
import { beaconRef, verifyLivenessBeacon, type LivenessBeacon } from '../beacons';
import { type Capability } from '../capability';
import { readEnvelope } from '../envelope';
import { hashCanonical } from '../hash';
import { merkleRoot, planNodeLeaf, type PlanNode } from '../merkle';
import { decodePCActn, type CheckStatus, type EnforcementGates, type PCActn, type VerifyHooks } from '../pcactn';
import { verifyPCActnCore } from '../pcactn-full';
import { decide, evaluateAgentCaveats, resolveReversibilityClass } from '../policy-vm';
import type { SigAlg } from '../pq';
import type { IntentPolicy } from '../intent-binding';
import { type IntentV2Context, decideIntentV2 } from '../intent-v2';
import { decisionOf, foldV2Reasons, modelPathsRead } from '../decision';
import { checkRevocationEpoch, type RevocationEpoch } from '../revocation';
import { classRank } from '../reversibility';
import { type AssuranceReport, type AssuranceRequirement, assuranceReport, refreshAssurance, unmetAssurance } from '../assurance';
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
  revocationEpoch?: {
    epoch: RevocationEpoch;
    guardianPublic: string;
    lastAcceptedEpoch?: number;
    /** Verifier-side maximum age of the epoch (`now - issued_at`), on top of its signed `not_after`. Absent: no age cap. */
    maxAgeMs?: number;
  };
  /**
   * The dead-man liveness beacon for the grant (P2-4). When present the verifier REQUIRES it to be genuine
   * (signed by one of the pinned `issuers`: the grant principal and/or operator), for this `instance`, covering
   * the grant, within its validity (hard-max enforced), not rolled back past `lastAcceptedSeq`, and bound by the
   * PCActn's signed `freshness.beacon_ref`. Reported as the `beacon` check; absent = `not-enforced`.
   */
  beacon?: { beacon: LivenessBeacon; issuers: string[]; instance: string; lastAcceptedSeq?: number; /** R2-01: PQ pins by issuer identity; a pure-PQ / hybrid beacon verifies only under these. */ pqPins?: Readonly<Record<string, string>> };
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
   * Minimum enforcement rung: every named check MUST be 'pass'; one that is 'not-enforced', 'unsupported' (or absent)
   * is treated as a failure (default-deny). Default (0.5): {@link DEFAULT_REQUIRED_CHECKS}, so a verdict is an allow only
   * when the replay counter, revocation, plan authorization, audience, validity and grant binding all passed. Pass `[]`
   * to get the report alone and decide yourself (the 0.4 behaviour).
   */
  require?: readonly string[];
  /**
   * Suite policy (F-4): the only signature suites accepted for the PCActn leaf and every delegation hop
   * (absent `alg` == `'ed25519'`). Unset: every registered suite, with the PQ key of any hybrid / pure-PQ signer
   * required to be bound to its holder (`holder_pq`, F-2).
   */
  allowedSuites?: readonly SigAlg[];
  /** LEGACY: accept PQ keys read from the artifact (no `holder_pq` binding). Voids the hybrid's PQ protection (F-2). Default false. */
  allowUnboundPq?: boolean;
  /** Intent Layer M2 policy, passed to the core `intent` check (see intent-binding.ts). */
  intent?: IntentPolicy;
  /**
   * Intent Layer v2 state + policy (rules 13–18, see intent-v2.ts). `params` defaults to `context.params`. For a PCActn
   * with `intent_session`, the verifier-computed `env.acc` / `env.mon` (accumulators passed), `env.canon` (schema
   * passed) and `env.world` / `env.prov` / `env.class` (W-B passed) REPLACE those members of `context.env` for the grant
   * predicates: only the verifier computes them.
   */
  intentV2?: IntentV2Context;
  /**
   * Server-side PQ pins `issuer -> pq_pk` (b64u). When set, a grant whose root suite is not Ed25519 must carry a `pq_pk`
   * byte-equal to `pqPins[grant.issuer]`; a missing or different pin FAILS the `pq_pin` check (fail closed). An Ed25519
   * grant has no PQ key to pin and passes. Unset: `pq_pin` is not reported (the stored grant alone roots the key).
   */
  pqPins?: Readonly<Record<string, string>>;
  /**
   * The operation the caller WILL EXECUTE, taken from the server's own routing / handler (never from the PCActn). When
   * set, the `operation` check passes only if the signed `action.verb` and `action.resource` equal it and, when `params`
   * is given, the signed `params_digest` opens to exactly these params. Those params are then the action params the
   * predicates and caveats read (a `context.params` that hashes differently fails `operation`). Absent: no `operation`
   * check (unchanged).
   */
  operation?: PcaOperation;
  /**
   * Opt-in enforcement gates forwarded to the core verifier (M1 taint / M3 freshness / M5 attestation; see
   * `EnforcementGates`). Each gate that is set FAILS CLOSED. Absent: unchanged ('not-enforced').
   */
  enforce?: EnforcementGates;
  /**
   * Risk inputs the server MUST supply in `context.risk` (finite numbers). A missing one fails the `risk_inputs` check
   * with its name, instead of being priced at the worst case. `semanticDistance` also counts as supplied when
   * `context.plan` is given (the Policy VM derives it from the server's plan). Absent or empty: no `risk_inputs` check.
   */
  requireRiskInputs?: readonly (keyof RiskInputs)[];
  /** Attach the per-check assurance report (`verdict.assurance`, see `assurance.ts`). Absent: no report (unchanged). */
  assurance?: boolean;
  /**
   * High-assurance policy (0.5, additive): e.g. `{ attestation: 'hardware', zk: 'snark', signature: 'pq' }`. Adds an
   * `assurance` check that fails, and denies, when the evidence for a listed dimension is weaker, missing, failed
   * (invalid / expired), unlabelled, preview (FROST / DKG / MPC) or unsupported. Implies `assurance: true`.
   */
  requireAssurance?: AssuranceRequirement;
  /**
   * Checks whose status may be `unsupported` without denying (0.5). A PCActn that carries a feature this verifier does
   * not implement (today: `bond_ref`, check `bond`) reports that check as `unsupported`, never `pass`, and is denied
   * unless the check is listed here.
   */
  allowUnsupported?: readonly string[];
}

/** An operation as the resource server will execute it: verb, resource and the exact params. */
export interface PcaOperation {
  verb: string;
  resource: string;
  params?: Record<string, unknown>;
}

/** The minimum enforcement profile a resource server should demand (see `requirePCA`). */
export const DEFAULT_REQUIRED_CHECKS = ['counter_format', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound'] as const;

/**
 * The profile a STATEFUL resource server demands (`requirePCA`, `authorize`): the stateless profile plus `replay`, the
 * strictly-increasing-counter check against stored state (it is `not-enforced`, so the request is denied, without a store).
 * 0.5 (B6): the old `counter` check is split into `counter_format` (stateless, well-formed counter) and `replay`.
 */
export const STATEFUL_REQUIRED_CHECKS = ['counter_format', 'replay', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound'] as const;

/** Old check names a `require` list may still use. `counter` meant the format check statelessly and the replay check with a store. */
function resolveRequiredName(name: string, checks: Record<string, CheckStatus>): string {
  return name === 'counter' && !('counter' in checks) ? ('replay' in checks ? 'replay' : 'counter_format') : name;
}

/** Who the verdict says authorized this: the registry-resolved principal behind the grant. */
export interface PcaPrincipalInfo {
  pub: string;
  subject_type: 'user' | 'org' | 'machine' | 'unverified';
  subject_id: string | null;
  /** true only when the key is an active, authenticated, enrolled principal. */
  verified: boolean;
}


/** The proved decision core knows three statuses; `unsupported` is carried beside its fold and read back as `not-enforced` there. */
type Proved = Exclude<CheckStatus, 'unsupported'>;
const provedOf = (s: CheckStatus): Proved => (s === 'unsupported' ? 'not-enforced' : s);

/**
 * Default-deny: turn every required check that is not 'pass' into a failure. Mutates + returns the verdict.
 * Exported so framework adapters that finish checks after `verifyPCActn` (e.g. the replay counter) can apply it last.
 */
export function enforceRequired(v: PcaVerdict, required: readonly string[]): PcaVerdict {
  const r = enforceRequiredVerified<string, string>(v.allow, Object.entries(v.checks).map(([k, c]) => [k, provedOf(c)] as [string, Proved]), v.reasons, required.map((n) => resolveRequiredName(n, v.checks)), (name, was) => `${name}: required check is ${v.checks[name] === 'unsupported' ? 'unsupported' : (was ?? 'absent')} (default-deny: not enforced by this resource server)`);
  v.allow = r.allow;
  for (const [k, c] of r.checks) v.checks[k] = v.checks[k] === 'unsupported' && c === 'not-enforced' ? 'unsupported' : c;
  v.reasons.splice(0, v.reasons.length, ...r.reasons);
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
  /**
   * What each check rests on (0.5, additive; see `assurance.ts`): per check, its outcome (`unsupported` for a feature
   * this verifier does not implement, never a pass) and, on a pass, the level of the evidence. Present only when asked
   * for (`assurance: true` or `requireAssurance`); `authorize()` always reports it.
   */
  assurance?: AssuranceReport;
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
  const v = await verifyPCActnChecks(pcactn, opts);
  // a verdict that stopped before the checks ran (undecodable, wire, verifier error) still reports its outcomes when asked
  if ((opts.assurance === true || opts.requireAssurance !== undefined) && v.assurance === undefined) v.assurance = assuranceReport({ checks: v.checks });
  return v;
}

async function verifyPCActnChecks(pcactn: PCActn | string, opts: VerifyPCActnOptions): Promise<PcaVerdict> {
  try {
    let p: PCActn;
    try {
      p = typeof pcactn === 'string' ? decodePCActn(pcactn) : pcactn;
    } catch (e) {
      return failClosed(`undecodable PCActn: ${(e as Error).message}`);
    }
    if (p === null || typeof p !== 'object') return failClosed('PCActn is not an object');

    const now = opts.now ?? Date.now();
    const op = opts.operation;
    // The operation's params are the action params (predicates, caveats, digest); a context that disagrees is flagged below.
    const ctxParams = opts.context?.params;
    const ctx: PcaContext = op?.params !== undefined ? { ...opts.context, params: op.params } : (opts.context ?? {});
    // F-1: remember the threshold the hook says it enforced, so it can be compared with the SERVER-derived t below.
    let hookT: number | undefined;
    const userThreshold = opts.hooks?.threshold;
    const hooks = userThreshold
      ? {
          ...opts.hooks,
          threshold: async (hctx: Parameters<typeof userThreshold>[0]) => {
            const r = await userThreshold(hctx);
            if (r.enforced) hookT = r.t;
            return r;
          },
        }
      : opts.hooks;
    // Rules 20 and 21 read the signed envelope of the stored grant (`units`, `tighten`, model-derived paths in `where`): when it
    // carries any, the v2 pipeline needs the plaintext params and the host env even if the host configured no v2 context.
    const grantEnv = readEnvelope(opts.grant);
    const needsModelRules = grantEnv !== null && (grantEnv.units !== undefined || grantEnv.tighten !== undefined || grantEnv.model_polarity !== undefined || modelPathsRead([grantEnv.predicates]).length > 0);
    const intentV2: IntentV2Context | undefined =
      opts.intentV2 || needsModelRules ? { ...(opts.intentV2 ?? {}), params: opts.intentV2?.params ?? ctx.params, env: opts.intentV2?.env ?? ctx.env } : undefined;
    // one run of the v2 pipeline feeds the predicate env (below) and the degraded-polarity report
    const v2d = p.intent_session !== undefined || needsModelRules ? decideIntentV2(p, opts.grant, intentV2, now) : undefined;
    // pca-unsafe-root: allow the full verifier's own grant parameter; callers pass their stored grant (pca-a2a's pinned-issuer root is admitted only with pqPins)
    const core = await verifyPCActnCore(p, { grant: opts.grant, nowEpoch: now, audience: opts.audience, hooks, allowedSuites: opts.allowedSuites, allowUnboundPq: opts.allowUnboundPq, intent: opts.intent, intentV2, ...(opts.enforce !== undefined ? { enforce: opts.enforce } : {}) });
    // A wire-form failure is terminal (normative): nothing else is evaluated on a malformed object.
    if (core.checks.wire === 'fail') return failClosed(core.reason ?? 'wire: malformed PCActn', { wire: 'fail' });
    const unsupported = Object.entries(core.checks).filter(([, c]) => c === 'unsupported').map(([n]) => n);
    let vs = VerdictState.init<string, string>(Object.entries(core.checks).map(([n, c]) => [n, provedOf(c)] as [string, Proved]), !core.allow && core.reason ? [core.reason] : []);
    // the core keeps only its FIRST failure reason; the v2 checks are the escalate-class ones, so every failed one is reported
    // (a failing check with no reason of its own is read as a hard failure, never as an escalation)
    if (v2d) for (const r of foldV2Reasons(vs.reasons, v2d.checks).slice(vs.reasons.length)) vs = vs.push(r);
    const fail = (name: string, why: string) => {
      vs = vs.fail(name, () => `${name}: ${why}`);
    };
    const mark = (name: string, s: Proved) => {
      vs = vs.set(name, s);
    };

    // server-side PQ pin for a non-Ed25519 grant (fail closed: no pin for the issuer, or a different key, denies)
    if (opts.pqPins !== undefined) {
      const alg = opts.grant.alg ?? 'ed25519';
      const pin = Object.prototype.hasOwnProperty.call(opts.pqPins, opts.grant.issuer) ? opts.pqPins[opts.grant.issuer] : undefined;
      if (alg === 'ed25519') mark('pq_pin', 'pass');
      else if (typeof pin === 'string' && typeof opts.grant.pq_pk === 'string' && pin === opts.grant.pq_pk) mark('pq_pin', 'pass');
      else fail('pq_pin', pin === undefined ? `no server-side PQ pin for the grant issuer (suite ${alg})` : 'the grant pq_pk does not match the server-side pin');
    }

    // grant_ref binds the object to this grant
    if (p.grant_ref === opts.grant.id) mark('grant_ref', 'pass');
    else fail('grant_ref', 'does not reference the supplied grant');

    // the proof must be for the operation the server will execute: verb, resource and (when given) the exact params
    if (op) {
      const signed = `${String(p.action?.verb)} on ${String(p.action?.resource)}`;
      if (typeof op.verb !== 'string' || typeof op.resource !== 'string') fail('operation', 'the server operation has no verb / resource (fail closed)');
      else if (p.action?.verb !== op.verb || p.action?.resource !== op.resource) fail('operation', `the proof is for ${signed}, but this operation is ${op.verb} on ${op.resource}`);
      else if (op.params !== undefined && hashCanonical(op.params) !== p.action?.params_digest) fail('operation', `the proof's params_digest does not match the params of this ${op.verb} operation`);
      else if (op.params !== undefined && ctxParams !== undefined && hashCanonical(ctxParams) !== hashCanonical(op.params)) fail('operation', 'context.params differ from the operation params');
      else mark('operation', 'pass');
    }

    // params plaintext must open the committed digest
    if (ctx.params !== undefined) {
      if (hashCanonical(ctx.params) === p.action?.params_digest) mark('params_digest', 'pass');
      else fail('params_digest', 'supplied params do not hash to action.params_digest');
    } else mark('params_digest', 'not-enforced');

    // the RS's own copy of the plan must be the committed one
    switch (planDecision(!!ctx.plan, ctx.plan ? merkleRoot(ctx.plan.map(planNodeLeaf)) === p.plan?.root : false, ctx.planAuthorized)) {
      case 'mismatch':
        fail('plan_root_authorized', 'known plan does not match plan.root');
        break;
      case 'unauthorized':
        fail('plan_root_authorized', 'the plan root has not been authorized by the principal');
        break;
      case 'pass':
        mark('plan_root_authorized', 'pass');
        break;
      case 'not-enforced':
        mark('plan_root_authorized', 'not-enforced');
        break;
    }

    if (ctx.revocationEpoch) {
      const r = checkRevocationEpoch(ctx.revocationEpoch.epoch, {
        guardianPublic: ctx.revocationEpoch.guardianPublic,
        now,
        grantRef: opts.grant.id,
        lastAcceptedEpoch: ctx.revocationEpoch.lastAcceptedEpoch,
        pcactnEpoch: p.freshness?.epoch,
        ...(ctx.revocationEpoch.maxAgeMs !== undefined ? { maxAgeMs: ctx.revocationEpoch.maxAgeMs } : {}),
      });
      // an `enforce.freshness` failure from the core stands (a passing epoch never overwrites it)
      if (r.ok) {
        if (vs.get('freshness') !== 'fail') mark('freshness', 'pass');
      } else fail('freshness', r.reason ?? 'revocation epoch rejected');
    } else if (vs.get('freshness') === undefined) mark('freshness', 'not-enforced');

    {
      const bc = ctx.beacon;
      const r = bc ? verifyLivenessBeacon(bc.beacon, { issuers: bc.issuers, now, instance: bc.instance, scope: opts.grant.id, ...(bc.pqPins ? { pqPins: bc.pqPins } : {}) }) : undefined;
      const replayed = !!bc && !!r?.ok && bc.lastAcceptedSeq !== undefined && bc.beacon.seq < bc.lastAcceptedSeq;
      const refBinds = !!bc && !!r?.ok && !replayed && p.freshness?.beacon_ref === beaconRef(bc.beacon);
      switch (beaconDecision(!!bc, !!r?.ok, replayed, refBinds)) {
        case 'rejected':
          fail('beacon', r?.reason ?? 'beacon rejected');
          break;
        case 'replayed':
          fail('beacon', `beacon seq ${bc!.beacon.seq} is older than the last accepted ${bc!.lastAcceptedSeq} (replay)`);
          break;
        case 'unbound':
          fail('beacon', 'PCActn freshness.beacon_ref does not bind the presented beacon');
          break;
        case 'pass':
          mark('beacon', 'pass');
          break;
        case 'not-enforced':
          mark('beacon', 'not-enforced');
          break;
      }
    }

    // Require-when-bound (audit finding 3): a grant whose agent_binding constrains the model / measurement /
    // operator / weights REQUIRES a bound attestation. Absent, unbound or unenforced => DENY, never skipped.
    if (vs.attestationRequiredFails(requiresAttestation(readEnvelope(opts.grant)?.agent_binding), 'attestation')) {
      fail('attestation', 'the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED');
    }

    const chain = Array.isArray(p.cap_chain) ? p.cap_chain : [];
    const leaf = chain[chain.length - 1];
    const depth = Math.max(0, chain.length - 1);
    const now0 = now;
    // Fail-closed default: an ABSENT budget becomes a DENY-METERED budget (B=0) in `decideBudget`,
    // so a caller that forgets `ctx.budget` cannot silently get unlimited machine-only authority.
    const budgetIn: TrustBudget = ctx.budget ?? { B: 0, tau: now0, asOf: now0 };
    mark('budget', ctx.budget ? 'pass' : 'not-enforced');
    if (ctx.budget === undefined) {
      vs = vs.push(
        'budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge',
      );
    }

    // Taint: ONLY an RS-supplied value counts. The agent's `provenance.taint_level` is untrusted (it can only
    // lower risk), so a missing RS taint fails closed to the worst case in the Policy VM.
    const risk: Partial<RiskInputs> = { ...ctx.risk };
    if (opts.requireRiskInputs?.length) {
      const supplied = (k: keyof RiskInputs) => (typeof risk[k] === 'number' && Number.isFinite(risk[k])) || (k === 'semanticDistance' && ctx.plan !== undefined);
      const missing = opts.requireRiskInputs.filter((k) => !supplied(k));
      if (missing.length) fail('risk_inputs', `required risk input(s) not supplied by the server: ${missing.join(', ')}`);
      else mark('risk_inputs', 'pass');
    }

    // Reversibility: the RS's authoritative class wins; the agent may only be STRICTER.
    const declared = p.action?.reversibility_class;
    let reversibility = declared;
    if (ctx.reversibilityClass !== undefined) {
      const dr = classRank(declared);
      const sr = classRank(ctx.reversibilityClass);
      if (reversibilityDecision(dr, sr) === 'less-restrictive') {
        fail('reversibility', `declared class '${String(declared)}' is less restrictive than the authoritative '${ctx.reversibilityClass}'`);
      } else mark('reversibility', 'pass');
      reversibility = useDeclaredClass(dr, sr) ? declared : ctx.reversibilityClass;
    }
    const budgetForDecide = decideBudget(budgetIn, ctx.budget === undefined);
    const actionCtx = {
      action: { verb: p.action?.verb, resource: p.action?.resource, params: ctx.params, reversibility_class: reversibility },
      subject: ctx.subject,
      env: v2Env(p, v2d, ctx.env),
      // Signed `tool_binding` (D): binds the semantic firewall (`tool_schema` caveats) to the tool the agent signed.
      ...(typeof p.tool_binding === 'string' ? { toolBinding: p.tool_binding } : {}),
    };
    const d = decide({
      // pca-unsafe-root: allow decide() runs under the same grant parameter as the core verifier above
      grant: opts.grant,
      // the SAME authority the core verifier used for a pure-PQ / hybrid root: the stored grant and the server-side pins.
      // pca-unsafe-root: allow mirrors the core's own trustedRoot: opts.grant (pcactn.ts), so decide() accepts no root the core refused; a non-Ed25519 pinned-issuer root from pca-a2a still needs a matching pqPins entry (pq_pin check above, fail closed)
      trustedRoot: opts.grant,
      ...(opts.pqPins !== undefined ? { pqPins: opts.pqPins } : {}),
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
          // the SAME class decide() used for the envelope caveats: the action's own, else the signed plan node's
          reversibilityClass: resolveReversibilityClass(actionCtx, ctx.plan, p.plan?.node_id),
          delegationDepth: depth,
          recentActionTimes: ctx.recentActionTimes,
        },
        actionCtx,
      );
      if (cv.ok) mark('delegated_caveats', 'pass');
      else fail('delegated_caveats', `delegation caveat(s) not satisfied: ${cv.failed.join(', ')}`);
    }

    // policy: the check mirrors the Policy VM's release decision; its reasons (also the informational step-up /
    // assumed-worst-case ones when released) are kept in order.
    mark('policy', d.releaseGuardianShare ? 'pass' : 'fail');
    vs = vs.pushAll(d.reasons.map((x) => `policy: ${x}`));

    // Threshold: t > 1 needs a proof we can only get from an enforced threshold hook (F-1: the hook must report
    // having enforced at least the SERVER-derived t; below it, or silent, the check fails).
    vs = vs.applyThreshold('threshold', d.requiredThreshold.t, d.releaseGuardianShare, vs.get('threshold'), hookTInt(hookT), (r) => {
      const t = d.requiredThreshold.t;
      if (r === 'below') {
        return `threshold: threshold hook enforced t=${hookT === undefined ? 'unreported' : String(hookT)} but the server requires t=${t} (below the server-derived threshold; derive t from server-held data)`;
      }
      if (r === 'rejected') return `threshold: t=${t} required and the threshold proof was rejected`;
      return `threshold: t=${t} (${d.requiredThreshold.proof}) required but no threshold verifier is enforced`;
    });

    const required = opts.require ?? DEFAULT_REQUIRED_CHECKS;
    const wantAssurance = opts.assurance === true || opts.requireAssurance !== undefined;
    // pca-unsafe-root: allow the verifier's own grant parameter (opts.grant), read only to label the assurance report
    const assuranceSrc = { pcactn: p, grant: opts.grant, hooks: opts.hooks, attestationHook: opts.enforce?.attestation?.verifier ?? opts.hooks?.attestation, thresholdT: hookT, allowUnboundPq: opts.allowUnboundPq, ...(v2d?.legacy_model_polarity === true ? { degraded: { tighten: "model_polarity 'legacy': a grant reads a model-derived value in where (rule 21)" } } : {}) };
    if (opts.requireAssurance) {
      const unmet = unmetAssurance(assuranceReport({ ...assuranceSrc, checks: Object.fromEntries(vs.checks) as Record<string, CheckStatus> }), opts.requireAssurance);
      if (unmet === undefined) mark('assurance', 'pass');
      else vs = vs.fail('assurance', () => unmet);
    }

    const allow = vs.finalAllow(d.releaseGuardianShare, core.allow);
    const checks = Object.fromEntries(vs.checks) as Record<string, CheckStatus>;
    for (const n of unsupported) if (checks[n] === 'not-enforced') checks[n] = 'unsupported';
    const reasons = vs.reasons;
    // B7: a feature the PCActn carries but this verifier does not implement is never a pass, and denies unless allowed.
    const refused = unsupported.filter((n) => !(opts.allowUnsupported ?? []).includes(n));
    if (refused.length > 0) {
      const out: PcaVerdict = { allow: false, r: d.r, requiredThreshold: d.requiredThreshold, checks, reasons: [...reasons, ...refused.map((n) => `${n}: unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)`)] };
      enforceRequired(out, required);
      if (wantAssurance) out.assurance = refreshAssurance(assuranceReport({ ...assuranceSrc, checks }), out.checks);
      return out;
    }
    const out: PcaVerdict = allow
      ? { allow, r: d.r, requiredThreshold: d.requiredThreshold, checks, reasons, budget: ctx.budget ? d.budget : undefined }
      : { allow: false, r: d.r, requiredThreshold: d.requiredThreshold, checks, reasons };
    enforceRequired(out, required);
    // an escalation keeps the post-decision budget: an answered escalation (requirePCA) is admitted with it, never free
    if (!out.allow && ctx.budget && decisionOf(out) === 'escalate') out.budget = d.budget;
    out.reasons = withDeniedFallback(out.allow, out.reasons, 'denied');
    if (wantAssurance) out.assurance = refreshAssurance(assuranceReport({ ...assuranceSrc, checks }), out.checks);
    return out;
  } catch (e) {
    return failClosed(`verifier error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
  }
}

/** The predicate `env`: the host's, with the verifier-computed v2 members (see intent-v2.ts IntentV2Env). */
function v2Env(p: PCActn, v2d: ReturnType<typeof decideIntentV2> | undefined, env: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (p.intent_session === undefined) return env;
  // only the verifier computes these members: whatever the host passed under these names is dropped
  const rest: Record<string, unknown> = { ...(env ?? {}) };
  for (const k of ['acc', 'mon', 'canon', 'world', 'prov', 'class']) delete rest[k];
  const d = v2d?.env ?? {};
  for (const [k, v] of Object.entries(d)) if (v !== undefined) rest[k] = v;
  return rest;
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
