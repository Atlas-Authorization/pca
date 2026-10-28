/**
 * `authorizeExecution`: the full-policy check for one local execution (an agent framework tool call, a gateway
 * request), for verifiers that have the PCActn in hand rather than an HTTP request.
 *
 * `verifyPCActnCore` alone checks that a proof is genuine (signatures, chain, plan, audience, validity, counter format).
 * It does not read the grant's limits, so a validly signed $400 payment under a $100 grant passes it. This function runs,
 * in order:
 *
 *   1. configuration: the audience, a grant source, the replay / budget store and the revocation check are REQUIRED;
 *      a missing one denies every call (fail closed, never a downgrade to signature-only);
 *   2. operation binding: the PCActn's signed verb (and resource, when the caller names one) must be the operation
 *      that is about to execute;
 *   3. the full server verifier, through `authorize` (the one pipeline): the grant from the caller's store, the operation's params
 *      against the signed params digest, the grant's predicates, limits and caveats (root, envelope and delegated),
 *      revocation, the replay counter and the trust budget, with risk priced from server-side inputs.
 *
 * It is the shared engine of the full-policy mode of `@atlasauth/pca-gateway`, `@atlasauth/pca-mastra`,
 * `@atlasauth/pca-vercel-ai` and `@atlasauth/pca-openai-agents`.
 */

import { type Capability } from '../capability';
import { readEnvelope } from '../envelope';
import { merkleRoot, planNodeLeaf, type PlanNode } from '../merkle';
import { type CheckStatus, type EnforcementGates, type PCActn, type VerifyHooks } from '../pcactn';
import type { SigAlg } from '../pq';
import type { K1Input } from '../caveat-lang';
import type { ReplayStore } from '../replay';
import { type RiskInputs } from '../risk';
import type { AssuranceReport, AssuranceRequirement } from '../assurance';
import { authorize } from './authorize';
import type { PcaStateStore, RequirePcaOptions } from './require-pca';
import { STATEFUL_REQUIRED_CHECKS, type PcaVerdict } from './verify';

/** The operation that is about to execute: what the PCActn must have been signed for. */
export interface ExecutionOperation {
  /** The PCA verb of this operation (e.g. `stripe.refund`). Must equal the signed `action.verb`. */
  verb: string;
  /** The PCA resource of this operation. When given it must equal the signed `action.resource`. */
  resource?: string;
  /** The parameters the operation will execute with. They must hash to the signed `action.params_digest`. */
  params: Record<string, unknown>;
}

export interface AuthorizeExecutionOptions {
  /** REQUIRED: this verifier's audience id. A PCActn whose signed `aud` differs is denied. */
  audience: string;
  /** The grant the PCActn must chain to. Give this or `resolveGrant` (one is required). */
  grant?: Capability;
  /** Look the grant up in YOUR store by the PCActn's signed `grant_ref`. Never return a grant taken from the call. */
  resolveGrant?: (grantRef: string, pcactn: PCActn) => Capability | null | undefined | Promise<Capability | null | undefined>;
  /** REQUIRED: replay counters and trust budgets per agent. Share one store across processes (Redis or your DB). */
  state: PcaStateStore;
  /** REQUIRED: is this grant revoked? A verifier that cannot answer this must not authorize. */
  isRevoked: (grant: Capability, pcactn: PCActn) => boolean | Promise<boolean>;
  /**
   * Has the principal authorized this plan root for this grant? Default: a one-step plan is authorized when it is exactly
   * the step that was signed (the grant's permissions are the policy).
   */
  isPlanAuthorized?: (grantRef: string, planRoot: string) => boolean | Promise<boolean>;
  /**
   * Server-side risk inputs for this operation. Default {@link amountRisk}: `blastRadius = amount / kappa` from the
   * verified `params.amount` and the grant's risk policy. Inputs not supplied are priced at the worst case by the verifier.
   */
  risk?: (grant: Capability, params: Record<string, unknown>, pcactn: PCActn) => Partial<RiskInputs> | undefined;
  /** Attestation / threshold / zk hooks forwarded to the verifier (revocation comes from `isRevoked`). */
  hooks?: Omit<VerifyHooks, 'revocation'>;
  /** Further checks that must report `pass`, on top of the full-mode defaults. */
  require?: readonly string[];
  /**
   * Caveat language v2 input (pins, presented discharges and narrow block, revoked discharges, SPIFFE id, history), as on
   * `requirePCA`. Absent: every K1 caveat in the chain refuses (fail closed).
   */
  k1?: K1Input;
  /** The consume-once store `max_uses` caveats spend from (as on `requirePCA`). */
  usesStore?: ReplayStore;
  /** Accepted signature suites. Default `['ed25519']`. */
  allowedSuites?: readonly SigAlg[];
  /** Server-side PQ pins `issuer -> pq_pk`, needed only if you accept a post-quantum suite. */
  pqPins?: Readonly<Record<string, string>>;
  /** Verifier clock (epoch ms). Default `Date.now`. */
  now?: () => number;
  /**
   * High-assurance policy (see `AssuranceRequirement`), forwarded to `authorize`: weaker, missing, failed, unlabelled,
   * awaiting-audit or unsupported evidence denies (`assurance` check, kind `policy`).
   */
  requireAssurance?: AssuranceRequirement;
  /** Opt-in core gates (taint / freshness / attestation), as on `requirePCA`. Each gate that is set fails closed. */
  enforce?: EnforcementGates;
  /**
   * More than one process or node shares `state` (as on `requirePCA`): a store that only the in-process lock can
   * serialise (no `claim`, no `withKeyLock`, or `scope: 'process'`) is refused, and every call is denied with the reason.
   */
  multiInstance?: boolean;
  /** Replay-state scope (as on `requirePCA`). `'audience-grant-holder'` keeps a separate counter stream per audience. */
  replayScope?: RequirePcaOptions['replayScope'];
  /** Re-verifications after an atomic `claim` budget conflict before the call is denied (as on `requirePCA`; default 3). */
  claimRetries?: number;
}

/** Why a full-policy check refused. */
export type ExecutionDenialKind = 'config' | 'binding' | 'authn' | 'policy' | 'replay' | 'revoked';

export type ExecutionDecision =
  | { allow: true; pcactn: PCActn; grant: Capability; verdict: PcaVerdict; /** What each check rested on (see `assurance.ts`). */ assurance?: AssuranceReport }
  | {
      allow: false;
      kind: ExecutionDenialKind;
      /** What each check rested on, when the verifier ran (see `assurance.ts`). */
      assurance?: AssuranceReport;
      status: 401 | 403;
      /** The decisive reason, in the verifier's words (e.g. `policy: no predicate permits ...`, `replay: ... (replay)`). */
      reason: string;
      checks?: Record<string, CheckStatus>;
      verdict?: PcaVerdict;
    };

/**
 * The checks a full-policy decision must PASS: the `requirePCA` default profile (counter, revocation, plan root,
 * audience, validity, grant_ref binding) plus the params digest and the policy itself (`authorize` adds `operation`).
 */
export const EXECUTION_REQUIRED_CHECKS: readonly string[] = [...STATEFUL_REQUIRED_CHECKS, 'params_digest', 'policy'];

/** The required components that `opts` lacks (empty when the configuration is complete). */
export function missingExecutionComponents(opts: Partial<AuthorizeExecutionOptions> | null | undefined): string[] {
  const o = opts ?? {};
  const missing: string[] = [];
  if (typeof o.audience !== 'string' || o.audience === '') missing.push('audience');
  if (o.grant === undefined && typeof o.resolveGrant !== 'function') missing.push('grant or resolveGrant');
  if (o.state === null || typeof o.state !== 'object' || typeof o.state.get !== 'function' || typeof o.state.put !== 'function') missing.push('state');
  if (typeof o.isRevoked !== 'function') missing.push('isRevoked');
  return missing;
}

/**
 * The server's risk inputs for a money-moving operation: `blastRadius = amount / kappa` from the verified
 * `params[amountField]` and the grant's own risk policy. `undefined` when there is no numeric amount (the verifier then
 * prices the missing inputs at the worst case).
 */
export function amountRisk(grant: Capability, params: Record<string, unknown>, opts: { amountField?: string } = {}): Partial<RiskInputs> | undefined {
  const amount = params[opts.amountField ?? 'amount'];
  const kappa = readEnvelope(grant)?.risk_policy.kappa;
  if (typeof amount !== 'number' || !Number.isFinite(amount) || typeof kappa !== 'number' || !(kappa > 0)) return undefined;
  return { blastRadius: Math.min(1, Math.max(0, amount / kappa)) };
}

const RISK_NOISE = /risk input\(s\) missing/;

/**
 * The reason of the first failing check (the verifier also lists context such as worst-case risk inputs). The verb and
 * resource are bound before the verifier runs, so a failing `operation` check here is a params mismatch that
 * `params_digest` already reports: it is ranked last so the reason stays the established `params_digest` one.
 */
function decisiveReason(v: PcaVerdict): string {
  for (const [name, status] of [...Object.entries(v.checks)].sort(([a], [b]) => Number(a === 'operation') - Number(b === 'operation'))) {
    if (status !== 'fail') continue;
    const hit = v.reasons.find((x) => x.startsWith(`${name}:`) && !RISK_NOISE.test(x));
    if (hit) return hit;
  }
  return v.reasons.find((x) => !RISK_NOISE.test(x)) ?? v.reasons[0] ?? 'denied';
}

/** The PCActn's one-step plan, rebuilt from the signed action. */
function planOf(p: PCActn): PlanNode[] {
  return [{ id: p.plan.node_id, verb: p.action.verb, resource: p.action.resource, params_digest: p.action.params_digest, reversibility_class: p.action.reversibility_class }];
}

/** Authorize one execution completely: configuration, binding to the operation, and the full verifier. See the module doc. */
export async function authorizeExecution(pcactn: PCActn, operation: ExecutionOperation, opts: AuthorizeExecutionOptions): Promise<ExecutionDecision> {
  const missing = missingExecutionComponents(opts);
  if (missing.length > 0) {
    return { allow: false, kind: 'config', status: 403, reason: `full policy mode is missing ${missing.join(', ')} (fail closed)` };
  }
  try {
    const p = pcactn;
    // binding: checked before any state is read or written, so a proof presented for another operation is not spent.
    if (p?.action?.verb !== operation.verb || (operation.resource !== undefined && p.action.resource !== operation.resource)) {
      const want = operation.resource !== undefined ? `${operation.verb} on ${operation.resource}` : operation.verb;
      return { allow: false, kind: 'binding', status: 403, reason: `the proof is for ${String(p?.action?.verb)} on ${String(p?.action?.resource)}, but this call is ${want}` };
    }
    const grant = opts.grant ?? (await opts.resolveGrant!(p.grant_ref, p));
    if (!grant) return { allow: false, kind: 'authn', status: 401, reason: 'unknown grant_ref' };
    const now = opts.now ?? Date.now;
    const params = operation.params;

    // the one pipeline: `authorize()` (requirePCA with every component required and the proof bound to the operation,
    // including the atomic `claim` path when `state` has one). This wrapper only maps its option names, adds the principal's
    // plan gate and the amount-priced risk, and maps the result to an `ExecutionDecision`.
    const r = await authorize(
      { operation: { verb: operation.verb, resource: operation.resource ?? p.action.resource, params }, pcactn: p },
      {
        audience: opts.audience,
        allowedSuites: opts.allowedSuites ?? ['ed25519'],
        ...(opts.pqPins !== undefined ? { pqPins: opts.pqPins } : {}),
        now,
        ...(opts.requireAssurance !== undefined ? { requireAssurance: opts.requireAssurance } : {}),
        ...(opts.enforce !== undefined ? { enforce: opts.enforce } : {}),
        ...(opts.multiInstance !== undefined ? { multiInstance: opts.multiInstance } : {}),
        ...(opts.replayScope !== undefined ? { replayScope: opts.replayScope } : {}),
        ...(opts.claimRetries !== undefined ? { claimRetries: opts.claimRetries } : {}),
        ...(opts.k1 !== undefined ? { k1: opts.k1 } : {}),
        ...(opts.usesStore !== undefined ? { usesStore: opts.usesStore } : {}),
        resolveGrant: async () => grant,
        budgetStore: opts.state,
        hooks: { ...opts.hooks, revocation: async ({ grant: g }) => ({ enforced: true, ok: (await opts.isRevoked(g, p)) !== true }) },
        require: [...EXECUTION_REQUIRED_CHECKS, ...(opts.require ?? [])],
        // an agent with no stored budget starts at the grant's signed bMax (0 when the grant has none)
        seedBudget: (g, t) => ({ B: readEnvelope(g)?.risk_policy.bMax ?? 0, tau: t, asOf: t }),
        risk: (_op, g, pc) => (opts.risk ? opts.risk(g, params, pc) : amountRisk(g, params)),
        context: async (_req, pc) => {
          const plan = planOf(pc);
          const consistent = merkleRoot(plan.map(planNodeLeaf)) === pc.plan.root;
          const approved = opts.isPlanAuthorized ? (await opts.isPlanAuthorized(pc.grant_ref, pc.plan.root)) === true : true;
          return { params, plan, planAuthorized: consistent && approved };
        },
      },
    );
    if (r.allow) return { allow: true, pcactn: r.pcactn, grant, verdict: r.verdict, assurance: r.assurance };
    const v = r.verdict;
    const kind: ExecutionDenialKind =
      r.status === 401 ? 'authn' : v.checks['revocation'] === 'fail' ? 'revoked' : v.checks['replay'] === 'fail' ? 'replay' : 'policy';
    return { allow: false, kind, status: r.status, reason: decisiveReason(v), checks: v.checks, verdict: v, assurance: r.assurance };
  } catch (e) {
    return { allow: false, kind: 'policy', status: 403, reason: `authorization error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
  }
}
