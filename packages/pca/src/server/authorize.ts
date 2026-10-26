import { snapshotConfig } from '../config-snapshot';
import { readEnvelope } from '../envelope';
import { hashCanonical } from '../hash';
import { paramsDigest, type PlanNode } from '../merkle';
import { decodePCActn, type CheckStatus, type PCActn } from '../pcactn';
import type { AssuranceReport } from '../assurance';
import { passportAssurance, verifyPassport, type PassportVerdict, type SignedPassport, type VerifyPassportOptions } from '../passport';
import {
  defaultExtract,
  requirePCA,
  type AuthorizedOperation,
  type PcaGuardResult,
  type PcaRequestLike,
  type PcaStateStore,
  type RequirePcaOptions,
} from './require-pca';
import { STATEFUL_REQUIRED_CHECKS, type PcaContext, type PcaOperation, type PcaVerdict } from './verify';
import type { PlanRegistry, PlanStatus } from './plan-lifecycle';

/**
 * `authorize()`: the one authorization pipeline for a TypeScript resource server.
 *
 * It is `requirePCA` (the same code path: strict parse, proof and chain verification, audience, plan, the full policy
 * with root and delegated caveats, risk, budget, threshold, revocation, replay counter under the store's lock) with
 * every component that guard lets you leave out made REQUIRED, plus binding to the operation the handler will execute:
 *
 *   - `audience`, `resolveGrant`, `budgetStore` and a revocation source (`hooks.revocation`) must be configured, and the
 *     call must name its `operation` with params. A missing one DENIES with its name (it is never downgraded).
 *   - `insecureAllowUnenforced` is not accepted; the default required checks always apply, and `require` can only add.
 *   - The PCActn must be for exactly `operation` (verb, resource, params digest). The params given here are what the
 *     predicates and caveats evaluate, so a $400 operation under a $100 grant is refused even if the agent signed $50.
 *   - On success the result carries the bound operation (`verb`, `resource`, `params_digest`, `id`); `isAuthorizedFor`
 *     checks a result against the operation about to run.
 *
 * Intent Layer v2 (`intentV2`), the core gates (`enforce`), required risk inputs (`requireRiskInputs`), server risk
 * (`risk`, e.g. `catalogRisk`) and a high-assurance policy (`requireAssurance`) are forwarded exactly as `requirePCA`
 * forwards them.
 *
 * Every result carries `assurance`: per check, its outcome and, on a pass, what the evidence was (software or hardware
 * attestation, SNARK or attested-VM compliance, PQ or Ed25519 signatures, multisig or FROST threshold); `unsupported` for
 * a feature this verifier does not implement. It is on the result, not inside `verdict` (unless `assurance: true`).
 */

export interface AuthorizeOptions extends Omit<RequirePcaOptions, 'insecureAllowUnenforced' | 'insecureAllowUnboundOperation' | 'operation' | 'audience' | 'budgetStore'> {
  /** REQUIRED: this resource server's audience id. */
  audience: string;
  /** REQUIRED: replay counter + budget state (see `PcaStateStore`; multi-node deployments need `withKeyLock`). */
  budgetStore: PcaStateStore;
  /**
   * `'single-step'`: accept a one-node plan whose node is the bound operation (verb, resource, params digest) under the
   * PCActn's node id and class; the grant alone then limits what runs. Otherwise `context()` must return the
   * principal-authorized `plan` + `planAuthorized: true` (the `plan_root_authorized` check is required).
   */
  plan?: 'single-step';
  /**
   * Plan lifecycle (0.5, additive): when the PCActn's plan root is in this registry, the verifier gets the stored plan and
   * `planAuthorized` = executable now (authorized, approval unexpired, not revoked), and the verdict gains a
   * `plan_state` check that names the state on a denial (e.g. `plan_state: plan ... is committed but not authorized by the
   * principal`). A root the registry does not know falls back to `plan: 'single-step'` when set, else it is denied. A
   * `plan` returned by `context()` wins (the registry is not consulted).
   */
  plans?: PlanRegistry;
  /**
   * Optional: require a valid signed agent passport for the presenting agent. Absent => behaviour is unchanged. When set,
   * `trustedIssuers` and `revocation` are REQUIRED (missing => deny), the call must carry `passport`, and its `sub` must be the
   * PCActn's leaf holder key. `hardware: true` additionally demands a `hardware_rooted` passport whose evidence verified.
   * The passport is checked before the PCActn is verified or its replay counter advanced, so a refusal here never consumes the PCActn.
   */
  requirePassport?: Omit<VerifyPassportOptions, 'now' | 'subject'> & { hardware?: boolean; now?: () => number };
}

export interface AuthorizeInput {
  /** The operation the handler WILL execute, from the server (route, tool mapping, parsed body), never from the PCActn. */
  operation: PcaOperation;
  /** The request (headers / body), read by the extractor and handed to `context`, `intentV2`, ... */
  request?: PcaRequestLike;
  /** The presented PCActn, when the caller already extracted it (otherwise it is read from `request`). */
  pcactn?: PCActn | string;
  /** The presenting agent's signed passport (read only when `requirePassport` is configured). */
  passport?: SignedPassport;
}

export type AuthorizeResult =
  | { allow: true; status: 200; verdict: PcaVerdict; pcactn: PCActn; operation: AuthorizedOperation; assurance: AssuranceReport; passport?: Extract<PassportVerdict, { ok: true }> }
  | {
      allow: false;
      status: 401 | 403;
      verdict: PcaVerdict;
      /** What each check rested on (see `assurance.ts`); `{ <check>: { outcome: 'fail' } }` for a refusal before verification. */
      assurance: AssuranceReport;
      /** The decisive reason (the first failing check's). */
      reason: string;
      wwwAuthenticate?: string;
      /** Configuration components that are missing (the call was refused before any verification). */
      missing?: string[];
    };

const WORST = { t: 3, proof: 'strong', optimisticAllowed: false } as const;

function refuse(reason: string, check: string, missing?: string[]): Extract<AuthorizeResult, { allow: false }> {
  const checks: Record<string, CheckStatus> = { [check]: 'fail' };
  return { allow: false, status: 403, verdict: { allow: false, r: 1, requiredThreshold: { ...WORST }, checks, reasons: [reason] }, reason, assurance: { [check]: { outcome: 'fail' } }, ...(missing ? { missing } : {}) };
}

/** The reason of the first failing check (a binding failure first: it explains the others; then the plan state), else the first reason. */
const RANK: Readonly<Record<string, number>> = { operation: 2, plan_state: 1 };
function decisive(v: PcaVerdict): string {
  for (const [name, status] of [...Object.entries(v.checks)].sort(([a], [b]) => (RANK[b] ?? 0) - (RANK[a] ?? 0))) {
    if (status !== 'fail') continue;
    const hit = v.reasons.find((x) => x.startsWith(`${name}:`));
    if (hit) return hit;
  }
  return v.reasons[0] ?? 'denied';
}

type PassportRequirement = NonNullable<AuthorizeOptions['requirePassport']>;

/** The leaf holder named by a presented (unverified) PCActn, or undefined when it cannot be read. */
function presentedLeaf(read: () => unknown): string | undefined {
  let holder: unknown;
  try {
    const raw = read();
    const chain = ((typeof raw === 'string' ? decodePCActn(raw) : raw) as PCActn).cap_chain;
    holder = chain[chain.length - 1]!.holder;
  } catch {
    // unreadable (null, garbage, no chain): left to the guard, which denies it
  }
  return typeof holder === 'string' ? holder : undefined;
}

/** Names of the required components `opts` lacks (empty = complete). */
export function missingAuthorizeComponents(opts: Partial<AuthorizeOptions> & { insecureAllowUnenforced?: unknown; insecureAllowUnboundOperation?: unknown }): string[] {
  const missing: string[] = [];
  if (typeof opts.audience !== 'string' || opts.audience.length === 0) missing.push('audience');
  if (typeof opts.resolveGrant !== 'function') missing.push('resolveGrant');
  const st = opts.budgetStore as Partial<PcaStateStore> | undefined;
  if (!st || typeof st.get !== 'function' || typeof st.put !== 'function') missing.push('budgetStore');
  if (typeof opts.hooks?.revocation !== 'function') missing.push('hooks.revocation');
  if (opts.requirePassport !== undefined) {
    if (!Array.isArray(opts.requirePassport.trustedIssuers) || opts.requirePassport.trustedIssuers.length === 0) missing.push('requirePassport.trustedIssuers');
    if (typeof opts.requirePassport.revocation !== 'function') missing.push('requirePassport.revocation');
  }
  if (opts.insecureAllowUnenforced) missing.push('insecureAllowUnenforced is not accepted by authorize');
  if ((opts as { insecureAllowUnboundOperation?: unknown }).insecureAllowUnboundOperation) missing.push('insecureAllowUnboundOperation is not accepted by authorize');
  return missing;
}

const validOperation = (op: unknown): op is PcaOperation & { params: Record<string, unknown> } => {
  const o = op as Partial<PcaOperation> | null | undefined;
  return !!o && typeof o.verb === 'string' && o.verb.length > 0 && typeof o.resource === 'string' && o.resource.length > 0 && !!o.params && typeof o.params === 'object' && !Array.isArray(o.params);
};

/** Build an authorizer once (configuration is validated and frozen here) and call it per operation. */
export function createAuthorizer(opts: AuthorizeOptions): (input: AuthorizeInput) => Promise<AuthorizeResult> {
  const missing = missingAuthorizeComponents(opts);
  if (missing.length) {
    const reason = `authorize: missing required component(s): ${missing.join(', ')} (fail closed)`;
    return async () => refuse(reason, 'authorize_config', missing);
  }
  // per-call inputs, keyed by the request object requirePCA hands back to its callbacks
  const ops = new WeakMap<object, PcaOperation>();
  const presented = new WeakMap<object, PCActn | string>();
  const userContext = opts.context;
  const userExtract = opts.extract ?? defaultExtract;
  const singleStep = opts.plan === 'single-step';
  const plans = opts.plans;
  const planStates = new WeakMap<object, PlanStatus>();
  const { plans: _plans, ...guardOpts } = opts;
  const guard = requirePCA({
    ...guardOpts,
    insecureAllowUnenforced: false,
    assurance: true,
    // the defaults always apply; `require` can only add checks
    require: [
      ...STATEFUL_REQUIRED_CHECKS,
      ...(opts.revocationEpoch ? ['freshness'] : []),
      ...(opts.beacon ? ['beacon'] : []),
      ...(opts.require ?? []),
    ],
    operation: (req) => ops.get(req),
    extract: (req) => (presented.has(req) ? presented.get(req)! : userExtract(req)),
    seedBudget:
      opts.seedBudget ??
      ((grant, now) => {
        // readEnvelope validates the risk policy, so bMax is a finite number whenever an envelope is present
        const bMax = readEnvelope(grant)?.risk_policy.bMax;
        return bMax === undefined ? undefined : { B: bMax, tau: now, asOf: now };
      }),
    context: async (req, p): Promise<PcaContext> => {
      const base: PcaContext = { ...(await userContext?.(req, p)) };
      const op = ops.get(req);
      if (plans && base.plan === undefined) {
        const root = typeof p.plan?.root === 'string' ? p.plan.root : '';
        const pc = await plans.context(p.grant_ref, root, opts.now?.() ?? Date.now());
        if (pc) {
          base.plan = pc.plan;
          base.planAuthorized = pc.planAuthorized;
          planStates.set(req, pc.status);
        } else if (!singleStep) planStates.set(req, { state: 'unknown', executable: false, reason: `plan ${root} is unknown to the plan registry` });
      }
      if (singleStep && base.plan === undefined && op) {
        const plan: PlanNode[] = [{ id: String(p.plan.node_id), verb: op.verb, resource: op.resource, params_digest: paramsDigest(op.params), reversibility_class: p.action?.reversibility_class as PlanNode['reversibility_class'] }];
        base.plan = plan;
        base.planAuthorized = true; // the verifier compares this plan's root with plan.root; a mismatch denies plan_root_authorized
      }
      return base;
    },
  });
  return async (input) => {
    try {
      if (!input || !validOperation(input.operation)) return refuse('operation: authorize needs the operation to execute (verb, resource, params) (fail closed)', 'operation');
      // the caller's own request object reaches context() / intentV2() unchanged (framework fields included)
      const req: PcaRequestLike = input.request ?? { headers: {} };
      // a frozen copy: the params that are verified cannot change under the verifier
      ops.set(req, snapshotConfig(input.operation));
      if (input.pcactn !== undefined) presented.set(req, input.pcactn);
      else presented.delete(req);
      planStates.delete(req);
      // A passport is checked BEFORE the guard so a refusal never advances the PCActn's replay counter. The leaf is read from the
      // presented (unverified) PCActn only to pick the subject; the guard still verifies the chain, and the verified leaf must equal it.
      const rp = opts.requirePassport;
      let pre: { leaf: string; pv: Extract<PassportVerdict, { ok: true }> } | undefined;
      if (rp !== undefined) {
        const leaf = presentedLeaf(() => (presented.has(req) ? presented.get(req) : userExtract(req)));
        if (leaf !== undefined) {
          const pv = await verifyPassport(input.passport, { ...rp, now: (rp.now ?? Date.now)(), subject: leaf });
          if (!pv.ok) return refuse(`passport: ${pv.reason}`, 'passport');
          if (rp.hardware === true && !pv.hardware_verified) return refuse('passport: hardware_evidence_missing', 'passport');
          pre = { leaf, pv };
        }
      }
      const r: PcaGuardResult = await guard(req);
      const ps = planStates.get(req);
      if (ps) {
        r.verdict.checks.plan_state = ps.executable ? 'pass' : 'fail';
        if (!ps.executable) {
          r.verdict.reasons.push(`plan_state: ${ps.reason ?? `plan is ${ps.state}`}`);
          // never reached: a plan that is not executable fails plan_root_authorized; kept as the fail-closed backstop
          if (r.ok) return refuse(`plan_state: ${ps.reason ?? 'not executable'}`, 'plan_state');
        }
      }
      // the report goes on the result; the verdict keeps its shape unless the caller asked for it there too
      const { assurance: reported, ...bare } = r.verdict;
      const verdict: PcaVerdict = opts.assurance === true ? r.verdict : bare;
      const assurance: AssuranceReport = reported ?? Object.fromEntries(Object.entries(r.verdict.checks).map(([k, v]) => [k, { outcome: v }]));
      if (r.ok) {
        if (!r.operation) return refuse('operation: the decision is not bound to an operation (fail closed)', 'operation');
        if (rp === undefined) return { allow: true, status: 200, verdict, pcactn: r.pcactn, operation: r.operation, assurance };
        const chain = r.pcactn.cap_chain;
        // fail closed when the leaf could not be read up front, or the guard verified a different leaf than the passport was checked for
        if (!pre || pre.leaf !== chain[chain.length - 1]!.holder) return refuse('passport: subject_mismatch', 'passport');
        const pv = pre.pv;
        const a = passportAssurance(pv, rp.attestationVerifier);
        return { allow: true, status: 200, verdict, pcactn: r.pcactn, operation: r.operation, assurance: { ...assurance, passport: { outcome: 'pass', level: a.level, ...(a.vendor ? { vendor: a.vendor } : {}) } }, passport: pv };
      }
      return { allow: false, status: r.status, verdict, reason: decisive(r.verdict), assurance, ...(r.wwwAuthenticate ? { wwwAuthenticate: r.wwwAuthenticate } : {}) };
    } catch (e) {
      return refuse(`authorize error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`, 'authorize');
    }
  };
}

/** Authorize one operation (see the module doc). Prefer `createAuthorizer` to build the configuration once. */
export function authorize(input: AuthorizeInput, opts: AuthorizeOptions): Promise<AuthorizeResult> {
  return createAuthorizer(opts)(input);
}

/**
 * True only if `result` allowed exactly this operation: same verb and resource, and `operation.params` hashes to the
 * bound digest. Call it where the side effect runs, with the values it is about to use.
 */
export function isAuthorizedFor(result: AuthorizeResult | PcaGuardResult, operation: PcaOperation): boolean {
  const ok = 'allow' in result ? result.allow : result.ok;
  const bound = (result as { operation?: AuthorizedOperation }).operation;
  if (!ok || !bound || !validOperation(operation)) return false;
  try {
    return bound.verb === operation.verb && bound.resource === operation.resource && bound.params_digest === hashCanonical(operation.params);
  } catch {
    return false;
  }
}

/** Options for {@link requireAuthorized}: `authorize` options plus the request -> operation mapping. */
export interface RequireAuthorizedOptions extends AuthorizeOptions {
  /** The operation this request will execute, from the server's routing (never from the PCActn). null denies. */
  operation: (req: PcaRequestLike) => PcaOperation | null | undefined | Promise<PcaOperation | null | undefined>;
}

/**
 * A request guard over `authorize` with the `requirePCA` result shape (`ok`, `status`, `verdict`, `pcactn`,
 * `wwwAuthenticate`), plus the bound `operation` on success. The framework adapters use it when given `operation`.
 */
export function requireAuthorized(opts: RequireAuthorizedOptions): (req: PcaRequestLike) => Promise<PcaGuardResult> {
  const { operation: mapOperation, ...rest } = opts;
  const az = createAuthorizer(rest);
  return async (req) => {
    let op: PcaOperation | null | undefined;
    try {
      op = await mapOperation(req);
    } catch {
      // no operation: refused below
    }
    const r = await az({ request: req, operation: op as PcaOperation });
    if (r.allow) return { ok: true, verdict: r.verdict, pcactn: r.pcactn, operation: r.operation };
    return { ok: false, status: r.status, verdict: r.verdict, ...(r.wwwAuthenticate ? { wwwAuthenticate: r.wwwAuthenticate } : {}) };
  };
}
