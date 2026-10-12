/**
 * @atlasauth/pca-authzen — PCA behind the OpenID AuthZEN Authorization API.
 *
 * The OpenID AuthZEN Authorization API 1.0 (final, Jan 2026) standardises the PEP↔PDP wire: a Policy
 * Enforcement Point (an API gateway, a service mesh sidecar, an MCP host) asks a Policy Decision Point
 * `can this subject do this action on this resource in this context?` and gets back a boolean decision.
 * This package makes Proof-Carrying Authority (PCA) answer that call, so ANY AuthZEN-speaking PEP can
 * use the PCA verifier + Policy-VM as its decision point without knowing anything about PCActns,
 * capability chains, trust budgets or FROST — instant distribution across the AuthZEN ecosystem.
 *
 * It maps the AuthZEN quad onto PCA two ways:
 *   • when the `context` carries a signed PCActn, the PDP VERIFIES it (`verifyPCActnCore`) and then runs
 *     the deterministic Policy-VM decision (`decide`) — proof-carrying, runtime authority;
 *   • otherwise it evaluates the declared policy STATICALLY (`@atlasauth/pca-analyzer` exact admission) —
 *     "is this action admissible at all under the authority?".
 * Everything FAILS CLOSED: an unresolved policy, a malformed/foreign PCActn, a verifier rejection, a
 * policy denial, or any thrown error all yield `decision: false`.
 *
 * Three AuthZEN surfaces are exposed:
 *   • Access Evaluation  (`evaluate`)        — the single `{subject,action,resource,context}` call;
 *   • Access Evaluations (`evaluations`)     — the boxcar / batch endpoint with default-inheritance;
 *   • the COAZ profile    (`evaluateTool`)   — MCP-tool authorization (tool → required capability → decision);
 *   • the AARP profile    (step-up)          — when the Policy-VM needs a human/guardian co-sign, the
 *                                               decision carries an "approval required" reference that maps
 *                                               onto PCA's FROST/CIBA step-up.
 * A framework-agnostic `authzenHandler` turns all of this into the status + JSON a PEP expects.
 */

import {
  type Capability,
  type CapabilityChain,
  type EnforcementGates,
  type PCActn,
  type PlanNode,
  type RequiredThreshold,
  type RiskInputs,
  type TrustBudget,
  type VerifyResult,
  decide,
  decodePCActn,
  deriveDecideInput,
  hashCanonical,
  paramsDigest,
  readEnvelope,
  verifyPCActnCore,
} from '@atlasauth/pca';
import { type AnalyzerAction, type PolicyInput, admitsConcrete } from '@atlasauth/pca-analyzer';

// ===================================================================================================
// AuthZEN 1.0 core information model (§ Access Evaluation API)
// ===================================================================================================

/** AuthZEN Subject: the entity requesting access (a typed, identified principal + free-form properties). */
export interface AuthzenSubject {
  type: string;
  id: string;
  properties?: Record<string, unknown>;
}

/** AuthZEN Action: the operation the subject wants to take. `name` is the verb. */
export interface AuthzenAction {
  name: string;
  properties?: Record<string, unknown>;
}

/** AuthZEN Resource: the target the action is taken on (typed + identified + free-form properties). */
export interface AuthzenResource {
  type: string;
  id: string;
  properties?: Record<string, unknown>;
}

/** AuthZEN Context: environmental / request attributes. Carries the PCActn and/or PCA hints here. */
export type AuthzenContext = Record<string, unknown>;

/** The AuthZEN Access Evaluation request (the PDP's single-decision input). */
export interface AccessEvaluationRequest {
  subject: AuthzenSubject;
  action: AuthzenAction;
  resource: AuthzenResource;
  context?: AuthzenContext;
}

/** AuthZEN decision context: the OPTIONAL additional information a PDP returns with a decision. */
export interface DecisionContext {
  id?: string;
  /** Machine-readable rationale for operators / audit. */
  reason_admin?: Record<string, unknown>;
  /** Human-facing rationale a PEP may surface to the end user. */
  reason_user?: Record<string, unknown>;
  [k: string]: unknown;
}

/** The AuthZEN Access Evaluation response. `decision` is the boolean a PEP enforces. */
export interface AccessEvaluationResponse {
  decision: boolean;
  context?: DecisionContext;
}

// ---- boxcar / batch (§ Access Evaluations API) ----------------------------------------------------

/** How the PDP processes a boxcar: run everything, or short-circuit on the first deny / permit. */
export type EvaluationsSemantic = 'execute_all' | 'deny_on_first_deny' | 'permit_on_first_permit';

/**
 * The AuthZEN Access Evaluations (boxcar) request. Top-level `subject`/`action`/`resource`/`context` are
 * DEFAULTS each item inherits; a per-item field overrides the default for that item only.
 */
export interface AccessEvaluationsRequest {
  subject?: AuthzenSubject;
  action?: AuthzenAction;
  resource?: AuthzenResource;
  context?: AuthzenContext;
  evaluations: Array<Partial<AccessEvaluationRequest>>;
  options?: { evaluations_semantic?: EvaluationsSemantic };
}

/** The AuthZEN Access Evaluations (boxcar) response: decisions in request order. */
export interface AccessEvaluationsResponse {
  evaluations: AccessEvaluationResponse[];
}

// ---- COAZ profile: MCP-tool authorization ---------------------------------------------------------

/**
 * COAZ (MCP-tool authorization) request: an MCP host asking whether `subject` may invoke `tool` with the
 * given arguments. The PDP maps the tool to the PCA capability it requires and decides.
 */
export interface CoazToolAuthorizationRequest {
  subject: AuthzenSubject;
  tool: { name: string; arguments?: Record<string, unknown> };
  context?: AuthzenContext;
}

/** COAZ response: the decision plus which capability the tool required (tool → required capability → decision). */
export interface CoazToolAuthorizationResponse {
  decision: boolean;
  /** Echoed tool name. */
  tool: string;
  /** The PCA capability (verb) the tool was authorized against. */
  required_capability: string;
  context?: DecisionContext;
}

// ---- AARP profile: approval-required (step-up) ----------------------------------------------------

/** Well-known AuthZEN decision-context key under which the AARP pending-approval reference is carried. */
export const PCA_APPROVAL_KEY = 'pca_approval' as const;

/** Well-known AuthZEN context key under which a PEP forwards the signed PCActn (compact wire string). */
export const PCA_ACTION_KEY = 'pca_action' as const;

/**
 * AARP pending-approval reference. Produced when the Policy-VM decision needs a tier-2 (guardian) or
 * tier-3 (human) co-sign. It maps onto PCA's FROST / CIBA step-up: `tier` is the threshold `t`, and
 * `auth_req_id` is the CIBA-style handle a PEP polls / an approval inbox resolves. `goal_commit` carries
 * the grant's signed goal lineage so the approver sees which goal this action traces back to.
 */
export interface AarpPending {
  approval_required: true;
  /** CIBA-style reference the PEP uses to poll / resolve the pending approval. */
  auth_req_id: string;
  /** The threshold tier a guardian/human must satisfy (2 guardian, 3 human). */
  tier: 2 | 3;
  /** The full Policy-VM required threshold (t / proof / optimistic). */
  required_threshold: RequiredThreshold;
  /** Signed goal commitment from the grant this action is under (approval lineage). */
  goal_commit: string;
  /** The risk value the action carries. */
  risk: number;
  reason: string;
  requested_at: number;
}

/** True iff this decision is a step-up (deny now, approval pending) carrying an AARP reference. */
export function isApprovalRequired(resp: AccessEvaluationResponse): boolean {
  return approvalOf(resp) !== null;
}

/** Extract the AARP pending-approval reference from a decision, or null if none. */
export function approvalOf(resp: AccessEvaluationResponse): AarpPending | null {
  const ctx = resp.context;
  if (ctx === undefined) return null;
  const p = ctx[PCA_APPROVAL_KEY];
  if (isRecord(p) && p.approval_required === true && typeof p.auth_req_id === 'string') {
    // Structurally the pending reference the PDP itself wrote.
    const tier = p.tier === 3 ? 3 : 2;
    const rt = p.required_threshold;
    return {
      approval_required: true,
      auth_req_id: p.auth_req_id,
      tier,
      required_threshold: isRequiredThreshold(rt) ? rt : { t: tier, proof: tier === 3 ? 'strong' : 'standard', optimisticAllowed: false },
      goal_commit: typeof p.goal_commit === 'string' ? p.goal_commit : '',
      risk: typeof p.risk === 'number' ? p.risk : 1,
      reason: typeof p.reason === 'string' ? p.reason : 'approval required',
      requested_at: typeof p.requested_at === 'number' ? p.requested_at : 0,
    };
  }
  return null;
}

// ===================================================================================================
// PDP configuration — how an AuthZEN request resolves to PCA authority
// ===================================================================================================

/**
 * The PCA authority + evaluation inputs a resolved AuthZEN request decides against. The host supplies
 * this (keyed off the request's subject/resource/etc.) so the PDP stays stateless about where grants and
 * budgets live.
 */
export interface PdpDecisionContext {
  /** The signed Root Intent Grant (the capability-chain root the PCActn must chain from). */
  grant: Capability;
  /** The full capability chain (root first). Defaults to the PCActn's own `cap_chain`. */
  chain?: CapabilityChain;
  /** The policy to evaluate STATICALLY when no PCActn is present (the grant's compiled policy, usually). */
  policy: PolicyInput;
  /** Plan nodes for semantic-distance risk (optional). */
  plan?: PlanNode[];
  /**
   * Server-authoritative risk inputs for the Policy-VM. Omitted / missing fields fail safe to WORST
   * (which raises the required threshold), so a PDP that cannot score risk defaults to demanding step-up.
   */
  risk?: Partial<RiskInputs>;
  /** Trust budget to meter against. Defaults to a fresh budget at the grant's `bMax`. */
  budget?: TrustBudget;
  /** Optional opt-in verifier enforcement gates (M1 taint / M3 freshness / M5 attestation). */
  enforce?: EnforcementGates;
  /** Override the default AuthZEN→PCA action mapping for this request. */
  toAction?: (req: AccessEvaluationRequest) => AnalyzerAction;
}

export interface AuthzenPdpConfig {
  /**
   * Resolve the PCA authority for an AuthZEN request. Return `null`/`undefined` to DENY (fail closed:
   * no policy context => no authority => no access). May throw; a throw is caught and fails closed.
   */
  resolve: (req: AccessEvaluationRequest) => PdpDecisionContext | null | undefined;
  /**
   * This PDP's own audience id, compared to a PCActn's signed `aud` (cross-instance binding):
   *  - a string  => must equal the PCActn `aud`;
   *  - `null`    => accept any audience;
   *  - omitted   => FAIL CLOSED when a PCActn carries an `aud` (forwarded to `verifyPCActnCore`).
   */
  audience?: string | null;
  /** Clock (epoch ms). Defaults to `Date.now`. */
  now?: () => number;
  /** Map an MCP tool name to the PCA capability (verb) it requires. Default: identity (verb === tool). */
  toolCapability?: (toolName: string) => string;
}

export interface AuthzenPdp {
  /** AuthZEN Access Evaluation: one `{subject,action,resource,context}` → one decision. */
  evaluate(req: AccessEvaluationRequest): Promise<AccessEvaluationResponse>;
  /** AuthZEN Access Evaluations: the boxcar / batch endpoint with default-inheritance + semantics. */
  evaluations(req: AccessEvaluationsRequest): Promise<AccessEvaluationsResponse>;
  /** COAZ profile: authorize an MCP tool invocation (tool → required capability → decision). */
  evaluateTool(req: CoazToolAuthorizationRequest): Promise<CoazToolAuthorizationResponse>;
}

// ===================================================================================================
// small, cast-free guards & helpers
// ===================================================================================================

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

function isRequiredThreshold(x: unknown): x is RequiredThreshold {
  return isRecord(x) && (x.t === 1 || x.t === 2 || x.t === 3) && typeof x.proof === 'string' && typeof x.optimisticAllowed === 'boolean';
}

export function isAuthzenSubject(x: unknown): x is AuthzenSubject {
  return isRecord(x) && typeof x.type === 'string' && typeof x.id === 'string';
}
export function isAuthzenAction(x: unknown): x is AuthzenAction {
  return isRecord(x) && typeof x.name === 'string';
}
export function isAuthzenResource(x: unknown): x is AuthzenResource {
  return isRecord(x) && typeof x.type === 'string' && typeof x.id === 'string';
}
export function isAccessEvaluationRequest(x: unknown): x is AccessEvaluationRequest {
  return (
    isRecord(x) &&
    isAuthzenSubject(x.subject) &&
    isAuthzenAction(x.action) &&
    isAuthzenResource(x.resource) &&
    (x.context === undefined || isRecord(x.context))
  );
}
export function isAccessEvaluationsRequest(x: unknown): x is AccessEvaluationsRequest {
  return isRecord(x) && Array.isArray(x.evaluations);
}
export function isCoazToolAuthorizationRequest(x: unknown): x is CoazToolAuthorizationRequest {
  return isRecord(x) && isAuthzenSubject(x.subject) && isRecord(x.tool) && typeof x.tool.name === 'string';
}

/** A denial response with machine + human rationale. */
function deny(reason: string, id?: string): AccessEvaluationResponse {
  const context: DecisionContext = { reason_admin: { denied: true, reason }, reason_user: { message: reason } };
  if (id !== undefined) context.id = id;
  return { decision: false, context };
}

/** A permit response with optional rationale. */
function permit(reason: string): AccessEvaluationResponse {
  return { decision: true, context: { reason_admin: { reason } } };
}

/** Pull a string reversibility hint out of the request (action.properties / context), for static mapping. */
function pickReversibility(req: AccessEvaluationRequest): string | undefined {
  const fromAction = req.action.properties;
  if (isRecord(fromAction) && typeof fromAction.reversibility_class === 'string') return fromAction.reversibility_class;
  const fromCtx = req.context;
  if (isRecord(fromCtx) && typeof fromCtx.reversibility_class === 'string') return fromCtx.reversibility_class;
  return undefined;
}

/** The env witness a predicate's `env.*` conditions see: the context minus PCA-private keys. */
function envFromContext(context: AuthzenContext | undefined): Record<string, unknown> | undefined {
  if (!isRecord(context)) return undefined;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(context)) {
    if (k === PCA_ACTION_KEY || k === PCA_APPROVAL_KEY) continue;
    out[k] = v;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/**
 * Default AuthZEN→PCA action mapping:
 *   verb     = action.name
 *   resource = `${resource.type}:${resource.id}`  (or just the type when id is empty)
 *   params   = { ...resource.properties, ...action.properties }   (action wins on key collision)
 *   subject  = subject.properties   (witness for `subject.*` conditions)
 *   env      = context (minus PCA keys)  (witness for `env.*` conditions)
 */
export function defaultToAction(req: AccessEvaluationRequest): AnalyzerAction {
  const resource = req.resource.id.length > 0 ? `${req.resource.type}:${req.resource.id}` : req.resource.type;
  const params: Record<string, unknown> = {
    ...(isRecord(req.resource.properties) ? req.resource.properties : {}),
    ...(isRecord(req.action.properties) ? req.action.properties : {}),
  };
  const out: AnalyzerAction = { verb: req.action.name, resource, params };
  const rc = pickReversibility(req);
  if (rc !== undefined) out.reversibilityClass = rc;
  if (isRecord(req.subject.properties)) out.subject = req.subject.properties;
  const env = envFromContext(req.context);
  if (env !== undefined) out.env = env;
  return out;
}

/** Extract the forwarded PCActn (compact wire string) from the AuthZEN context, if any. */
function pcactnFromContext(context: AuthzenContext | undefined): PCActn | null | 'malformed' {
  if (!isRecord(context)) return null;
  const raw = context[PCA_ACTION_KEY];
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== 'string') return 'malformed';
  try {
    return decodePCActn(raw);
  } catch {
    return 'malformed';
  }
}

// ===================================================================================================
// the PDP
// ===================================================================================================

export function authzenPdp(config: AuthzenPdpConfig): AuthzenPdp {
  const clock = config.now ?? (() => Date.now());
  const toolCapability = config.toolCapability ?? ((name: string) => name);

  async function evaluate(req: AccessEvaluationRequest): Promise<AccessEvaluationResponse> {
    const now = clock();
    try {
      const ctx = config.resolve(req);
      if (ctx === null || ctx === undefined) return deny('no PCA authority resolved for this request');

      const mapped = (ctx.toAction ?? defaultToAction)(req);
      const carried = pcactnFromContext(req.context);
      if (carried === 'malformed') return deny('context carries a malformed PCActn');

      // ---- static path: no PCActn → "is this admissible under the declared authority at all?" ----
      if (carried === null) {
        const admissible = admitsConcrete(ctx.policy, mapped);
        return admissible
          ? permit('statically admissible under the declared authority')
          : deny('action is not admissible under the declared authority');
      }

      // ---- proof-carrying path: verify the PCActn, then run the Policy-VM decision ----
      const p = carried;

      // The proof must be FOR the action the PEP is asking about (bind the signed action to the request):
      // verb + resource, and the request's attributes must hash to the PCActn's signed `params_digest`
      // (so a valid proof for one set of args cannot be replayed against different ones).
      if (p.action.verb !== mapped.verb || p.action.resource !== mapped.resource) {
        return deny(
          `the PCActn authorizes ${p.action.verb} on ${p.action.resource}, not the requested ${mapped.verb} on ${mapped.resource}`,
        );
      }
      const reqParams = paramsOf(mapped);
      if (paramsDigest(reqParams) !== p.action.params_digest) {
        return deny("the request attributes do not match the PCActn's signed params_digest");
      }

      const verify: VerifyResult = await verifyPCActnCore(p, {
        grant: ctx.grant,
        nowEpoch: now,
        audience: config.audience,
        ...(ctx.enforce !== undefined ? { enforce: ctx.enforce } : {}),
      });
      if (!verify.allow) {
        return {
          decision: false,
          context: {
            reason_admin: { denied: true, stage: 'verify', checks: verify.checks, reason: verify.reason ?? 'PCActn verification failed' },
            reason_user: { message: 'the proof-carrying action did not verify' },
          },
        };
      }

      const budget: TrustBudget = ctx.budget ?? freshBudget(ctx.grant, now);
      const decision = decide(
        deriveDecideInput(p, {
          grant: ctx.grant,
          chain: ctx.chain ?? p.cap_chain,
          ...(ctx.plan !== undefined ? { plan: ctx.plan } : {}),
          params: reqParams,
          risk: ctx.risk ?? {},
          budget,
          now,
          ...(mapped.subject !== undefined ? { subject: mapped.subject } : {}),
          ...(mapped.env !== undefined ? { env: mapped.env } : {}),
        }),
      );

      if (!decision.releaseGuardianShare) {
        return {
          decision: false,
          context: {
            reason_admin: { denied: true, stage: 'policy', reasons: decision.reasons, risk: decision.r },
            reason_user: { message: 'the policy does not permit this action' },
          },
        };
      }

      if (decision.admit) {
        return {
          decision: true,
          context: { reason_admin: { stage: 'policy', risk: decision.r, threshold: decision.requiredThreshold } },
        };
      }

      // Admissible but needs a guardian/human co-sign → AARP approval-required (step-up).
      return approvalRequired(p, decision, ctx.grant, now);
    } catch (err) {
      return deny(`evaluation error (fail closed): ${err instanceof Error ? err.message : 'unknown'}`);
    }
  }

  async function evaluations(req: AccessEvaluationsRequest): Promise<AccessEvaluationsResponse> {
    if (!Array.isArray(req.evaluations)) return { evaluations: [] };
    const semantic: EvaluationsSemantic = req.options?.evaluations_semantic ?? 'execute_all';
    const merged = req.evaluations.map((item) => mergeEvaluation(req, item));

    if (semantic === 'execute_all') {
      const out = await Promise.all(merged.map((m) => (m === null ? Promise.resolve(deny('incomplete evaluation (missing subject/action/resource)')) : evaluate(m))));
      return { evaluations: out };
    }

    // Short-circuit modes: evaluate sequentially, stop at the first matching decision.
    const out: AccessEvaluationResponse[] = [];
    for (const m of merged) {
      const r = m === null ? deny('incomplete evaluation (missing subject/action/resource)') : await evaluate(m);
      out.push(r);
      if (semantic === 'deny_on_first_deny' && r.decision === false) break;
      if (semantic === 'permit_on_first_permit' && r.decision === true) break;
    }
    return { evaluations: out };
  }

  async function evaluateTool(req: CoazToolAuthorizationRequest): Promise<CoazToolAuthorizationResponse> {
    const capability = toolCapability(req.tool.name);
    const mappedReq: AccessEvaluationRequest = {
      subject: req.subject,
      action: { name: capability, ...(req.tool.arguments !== undefined ? { properties: req.tool.arguments } : {}) },
      resource: { type: 'mcp_tool', id: req.tool.name },
      ...(req.context !== undefined ? { context: req.context } : {}),
    };
    const resp = await evaluate(mappedReq);
    return {
      decision: resp.decision,
      tool: req.tool.name,
      required_capability: capability,
      ...(resp.context !== undefined ? { context: resp.context } : {}),
    };
  }

  return { evaluate, evaluations, evaluateTool };
}

// ---- internals ------------------------------------------------------------------------------------

function paramsOf(action: AnalyzerAction): Record<string, unknown> {
  return isRecord(action.params) ? action.params : {};
}

function freshBudget(grant: Capability, now: number): TrustBudget {
  const env = readEnvelope(grant);
  const bMax = env?.risk_policy.bMax;
  return { B: typeof bMax === 'number' && Number.isFinite(bMax) ? bMax : 0, tau: now, asOf: now };
}

/** Build the AARP approval-required decision from a step-up Policy-VM result. */
function approvalRequired(p: PCActn, decision: ReturnType<typeof decide>, grant: Capability, now: number): AccessEvaluationResponse {
  const tier: 2 | 3 = decision.requiredThreshold.t >= 3 ? 3 : 2;
  const reason = decision.reasons[0] ?? `requires tier-${tier} co-sign`;
  const auth_req_id = hashCanonical({
    d: 'atlas-pca/authzen/aarp/v1',
    verb: p.action.verb,
    resource: p.action.resource,
    params_digest: p.action.params_digest,
    counter: p.counter,
    at: now,
  });
  const pending: AarpPending = {
    approval_required: true,
    auth_req_id,
    tier,
    required_threshold: decision.requiredThreshold,
    goal_commit: readEnvelope(grant)?.goal_commit ?? '',
    risk: decision.r,
    reason,
    requested_at: now,
  };
  return {
    decision: false,
    context: {
      id: auth_req_id,
      reason_admin: { stage: 'step_up', risk: decision.r, threshold: decision.requiredThreshold, reasons: decision.reasons },
      reason_user: { message: 'approval required before this action can proceed' },
      [PCA_APPROVAL_KEY]: pending,
    },
  };
}

/** Merge boxcar defaults with one item; null when a required piece is still missing (→ fail closed). */
function mergeEvaluation(defaults: AccessEvaluationsRequest, item: Partial<AccessEvaluationRequest>): AccessEvaluationRequest | null {
  const subject = item.subject ?? defaults.subject;
  const action = item.action ?? defaults.action;
  const resource = item.resource ?? defaults.resource;
  const context = item.context ?? defaults.context;
  if (!isAuthzenSubject(subject) || !isAuthzenAction(action) || !isAuthzenResource(resource)) return null;
  return { subject, action, resource, ...(context !== undefined ? { context } : {}) };
}

// ===================================================================================================
// framework-agnostic HTTP handler
// ===================================================================================================

/** The AuthZEN 1.0 standard Access Evaluation path. */
export const EVALUATION_PATH = '/access/v1/evaluation' as const;
/** The AuthZEN 1.0 standard Access Evaluations (boxcar) path. */
export const EVALUATIONS_PATH = '/access/v1/evaluations' as const;
/** The COAZ (MCP-tool authorization) profile path. */
export const COAZ_TOOL_PATH = '/access/v1/mcp/tool/evaluation' as const;

export interface HandlerRequest {
  path: string;
  body: unknown;
}

export interface HandlerResponse {
  status: number;
  body: AccessEvaluationResponse | AccessEvaluationsResponse | CoazToolAuthorizationResponse | { error: string };
}

/**
 * A tiny, framework-agnostic handler: give it `{ path, body }` (body = the parsed JSON a PEP POSTed) and
 * it returns `{ status, body }` to serialize back. A malformed body is a 400 (which a PEP enforces as a
 * deny — fail closed); a decision endpoint always returns 200 with the AuthZEN decision JSON. Drop it
 * behind Express, Fastify, a Lambda, a service-mesh filter — anything that can hand it a path + JSON.
 */
export function authzenHandler(pdp: AuthzenPdp): (req: HandlerRequest) => Promise<HandlerResponse> {
  return async (req: HandlerRequest): Promise<HandlerResponse> => {
    switch (req.path) {
      case EVALUATION_PATH: {
        if (!isAccessEvaluationRequest(req.body)) return { status: 400, body: { error: 'invalid AuthZEN Access Evaluation request' } };
        return { status: 200, body: await pdp.evaluate(req.body) };
      }
      case EVALUATIONS_PATH: {
        if (!isAccessEvaluationsRequest(req.body)) return { status: 400, body: { error: 'invalid AuthZEN Access Evaluations request' } };
        return { status: 200, body: await pdp.evaluations(req.body) };
      }
      case COAZ_TOOL_PATH: {
        if (!isCoazToolAuthorizationRequest(req.body)) return { status: 400, body: { error: 'invalid COAZ MCP-tool authorization request' } };
        return { status: 200, body: await pdp.evaluateTool(req.body) };
      }
      default:
        return { status: 404, body: { error: `unknown AuthZEN path: ${req.path}` } };
    }
  };
}
