/**
 * `authorizeToolCall`: the complete authorization check for one MCP tool call, in one call.
 *
 * `admitRequest` is the low-level admission check (audience, issuer, signatures and chain, scopes, step-up). It does
 * not evaluate the grant's predicates or limits, does not bind the PCActn to the tool call, and keeps no replay counter.
 * Since 0.5 `authorizeRequest` is this complete check by default (it is `authorizeToolCall`); admission alone is the
 * explicit `authorizeRequest(req, { ...opts, admissionOnly: true })`.
 * `authorizeToolCall` runs, in order:
 *
 *   1. admission: `admitRequest` with the same options (401/403 + `WWW-Authenticate` as there);
 *   2. call binding: the PCActn's signed verb and resource must be what `toolAction(tool, args)` says this call is
 *      (a proof for another tool, another resource or an unmapped tool is refused before any state is touched);
 *   3. the full server verifier, `authorize` from `@atlasauth/pca` (the one pipeline, bound to this call as the
 *      operation): the grant from YOUR store, the tool arguments against the signed params digest, the grant's
 *      predicates, limits and caveats, revocation, the replay counter (the atomic `claim` path when `state` has one) and
 *      the trust budget (money-moving calls are priced by the server from the verified amount, see {@link toolCallRisk}).
 *
 * A denial carries a plain-language `reason` (for the model and your logs) and, for the common configuration mistakes,
 * a developer `hint`. The `WWW-Authenticate` challenge of a binding or policy denial carries only the static error code,
 * never request-derived text.
 */

import {
  authorize,
  merkleRoot,
  planNodeLeaf,
  readEnvelope,
  type AuthorizedOperation,
  type Capability,
  type CheckStatus,
  type EnforcementGates,
  type PCActn,
  type PcaStateStore,
  type PcaVerdict,
  type PlanNode,
  type RiskInputs,
  type SigAlg,
} from '@atlasauth/pca';
import {
  admitRequest,
  extractPCActn,
  wwwAuthenticateChallenge,
  type AdmissionOptions,
  type AuthorizeResult,
  type McpRequestLike,
  type StepUpChallenge,
} from './index';

/** Which PCA action an MCP tool call is: its verb and resource. `null` = this tool has no PCA mapping (refused). */
export type ToolActionMap = (tool: string, args: Record<string, unknown>) => { verb: string; resource: string } | null;

export interface AuthorizeToolCallOptions extends Omit<AdmissionOptions, 'tool' | 'resolveGrant' | 'now' | 'authorizationServers'> {
  /**
   * Trusted grant issuers (RFC 9207), as in `authorizeRequest`. Omit it when your grant store is the trust anchor (you
   * only store grants your principals registered): then a grant's own issuer is accepted, because the grant came from
   * your store, never from the request.
   */
  authorizationServers?: string[];
  /** The MCP tool being called (`params.name` of the `tools/call`). */
  tool: string;
  /** The tool arguments the server received (`params.arguments`). They must hash to the PCActn's signed params digest. */
  args: Record<string, unknown>;
  /** Map a tool call to the PCA verb and resource the PCActn must carry. Use the same mapping the agent signs with. */
  toolAction: ToolActionMap;
  /** Look the grant up in YOUR store by the PCActn's signed `grant_ref`. Never return a grant taken from the request. */
  resolveGrant: (grantRef: string, pcactn: PCActn) => Capability | null | Promise<Capability | null>;
  /** Replay counters and trust budgets per agent. Share one store across calls (Redis or your DB across processes). */
  state: PcaStateStore;
  /** Is this grant revoked? Required: a server that cannot answer this should not authorize. */
  isRevoked: (grant: Capability) => boolean | Promise<boolean>;
  /**
   * Has the principal authorized this plan root for this grant? Default: a one-step plan is authorized when it is exactly
   * the step that was signed (the grant's permissions are the policy). Supply this to require pre-approved plans.
   */
  isPlanAuthorized?: (grantRef: string, planRoot: string) => boolean | Promise<boolean>;
  /** Server-side risk inputs for this call. Default: {@link toolCallRisk} (prices `args[amountField]` against the grant). */
  risk?: (grant: Capability, args: Record<string, unknown>, pcactn: PCActn) => Partial<RiskInputs> | undefined;
  /** Accepted signature suites. Default `['ed25519']`. */
  allowedSuites?: readonly SigAlg[];
  /** Server-side PQ pins `issuer -> pq_pk`, needed only if you accept a post-quantum suite. */
  pqPins?: Readonly<Record<string, string>>;
  /** Verifier clock. Default `Date.now`. */
  now?: () => number;
  /** Opt-in core gates (taint / freshness / attestation), as on `requirePCA`. Each gate that is set fails closed. */
  enforce?: EnforcementGates;
  /** More than one process or node shares `state` (as on `requirePCA`): a process-local store denies every call. */
  multiInstance?: boolean;
  /** Replay-state scope (as on `requirePCA`). `'audience-grant-holder'` keeps a separate counter stream per audience. */
  replayScope?: 'grant-holder' | 'audience-grant-holder';
  /** Re-verifications after an atomic `claim` budget conflict before the call is denied (default 3). */
  claimRetries?: number;
}

export interface AuthorizeToolCallAllow {
  ok: true;
  status: 200;
  pcactn: PCActn;
  grant: Capability;
  grantedScopes: string[];
  /** The full verifier's verdict (checks, risk, budget after this call). */
  verdict: PcaVerdict;
  /** The operation this decision is bound to; its `id` is the operation id (e.g. for `executeAuthorized` records). */
  operation?: AuthorizedOperation;
}

export interface AuthorizeToolCallDeny {
  ok: false;
  status: 401 | 403;
  error: string;
  /** Plain-language reason: safe to return to the model as the tool error text, and to log. */
  reason: string;
  /** Developer hint for a common configuration mistake (logs only). */
  hint?: string;
  /** The ready-to-send `WWW-Authenticate` header value. */
  wwwAuthenticate: string;
  stepUp?: StepUpChallenge;
  checks?: Record<string, CheckStatus>;
}

export type AuthorizeToolCallResult = AuthorizeToolCallAllow | AuthorizeToolCallDeny;

/**
 * The server's risk inputs for a money-moving call: `blastRadius = amount / kappa` from the VERIFIED tool arguments and
 * the grant's own risk policy (for a grant from `agent({ limits: { refund: '$500/day' } })`, a $42 refund is 42/500).
 * Returns `undefined` when the arguments carry no numeric amount; missing inputs are then priced at the worst case by
 * the verifier. Never take the agent's own risk claim instead.
 */
export function toolCallRisk(
  grant: Capability,
  args: Record<string, unknown>,
  opts: { amountField?: string; /** An action definition (structural `ActionDef`): the amount is its one `money.amount` parameter. */ action?: { params: Record<string, { role?: string }> } } = {},
): Partial<RiskInputs> | undefined {
  const field = opts.action !== undefined ? moneyAmountParam(opts.action) : (opts.amountField ?? 'amount');
  // a dotted parameter name addresses a nested argument (`payment.amount`); a flat key wins when present
  const amount = field === undefined ? undefined : Object.prototype.hasOwnProperty.call(args, field) ? args[field] : field.split('.').reduce<unknown>((o, k) => (o !== null && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k) ? (o as Record<string, unknown>)[k] : undefined), args);
  const kappa = readEnvelope(grant)?.risk_policy.kappa;
  if (typeof amount !== 'number' || !Number.isFinite(amount) || typeof kappa !== 'number' || !(kappa > 0)) return undefined;
  return { blastRadius: Math.min(1, Math.max(0, amount / kappa)) };
}

/** The one parameter of an action definition with the role `money.amount`; none or several: undefined (priced at the worst case). */
export function moneyAmountParam(def: { params: Record<string, { role?: string }> }): string | undefined {
  const hits = Object.keys(def.params).filter((n) => def.params[n]!.role === 'money.amount');
  return hits.length === 1 ? hits[0] : undefined;
}

const OPS: Record<string, string> = { lte: '<=', lt: '<', gte: '>=', gt: '>', eq: '==', neq: '!=' };

const RISK_NOISE = /risk input\(s\) missing/;

/**
 * The reason of the first failing check (the verifier also lists context such as worst-case risk inputs). The tool and
 * resource are bound before the verifier runs, so a failing `operation` check is a params mismatch that `params_digest`
 * also reports: it is ranked last so the reason stays the `params_digest` one.
 */
function decisiveReason(v: PcaVerdict): string {
  for (const [name, status] of [...Object.entries(v.checks)].sort(([a], [b]) => Number(a === 'operation') - Number(b === 'operation'))) {
    if (status !== 'fail') continue;
    const hit = v.reasons.find((x) => x.startsWith(`${name}:`) && !RISK_NOISE.test(x));
    if (hit) return hit;
  }
  return v.reasons.find((x) => !RISK_NOISE.test(x)) ?? v.reasons[0] ?? 'denied';
}

/** The decisive reason in plain words. The verifier names an unmet limit itself (0.5); "no predicate permits" is split into "not permitted" and "outside limits" for the cases it still covers. */
function explainPolicy(v: PcaVerdict, grant: Capability | null, want: { verb: string; resource: string }): string {
  const first = decisiveReason(v).replace(/^policy: /, '');
  if (!first.startsWith('no predicate permits') || grant === null) return first;
  const predicates = readEnvelope(grant)?.predicates ?? [];
  const forVerb = predicates.filter((p) => p.verb === '*' || p.verb === want.verb || (Array.isArray(p.verb) && p.verb.includes(want.verb)));
  if (forVerb.length === 0) {
    const permitted = predicates.flatMap((p) => (Array.isArray(p.verb) ? p.verb : [p.verb]));
    return `the grant does not permit ${want.verb} (it permits: ${permitted.join(', ') || 'nothing'})`;
  }
  const limits = forVerb.flatMap((p) =>
    (p.where ?? []).flatMap((c) => ('field' in c && 'op' in c ? [`${c.field.replace(/^action\.params\./, '')} ${OPS[c.op] ?? c.op} ${JSON.stringify(c.value)}`] : [])),
  );
  return limits.length > 0 ? `${want.verb} on ${want.resource} is outside the grant's limits (${limits.join(', ')})` : first;
}

function policyHint(reason: string): string | undefined {
  if (/trust budget depleted/.test(reason)) return 'the agent spent its trust budget; for money-moving calls make sure the server prices them (toolCallRisk / the `risk` option), or recharge the budget';
  if (/^counter/.test(reason) || /replay/.test(reason)) return 'each PCActn is single-use: the agent must build a fresh one per call (pcaFetch / bridgeToolCall do)';
  if (/^plan_root_authorized/.test(reason)) return '`isPlanAuthorized` did not approve this plan root';
  if (/^revocation/.test(reason)) return '`isRevoked` reported the grant as revoked';
  if (/^audience/.test(reason)) return "mint the PCActn for this server: its aud must equal the `resource` option";
  return undefined;
}

/** The PCActn's one-step plan, rebuilt from the signed action. */
function planOf(p: PCActn): PlanNode[] {
  return [{ id: p.plan.node_id, verb: p.action.verb, resource: p.action.resource, params_digest: p.action.params_digest, reversibility_class: p.action.reversibility_class }];
}

/** Authorize one MCP tool call completely: admission, binding to the exact call, and the full verifier. See the module doc. */
export async function authorizeToolCall(req: McpRequestLike, opts: AuthorizeToolCallOptions): Promise<AuthorizeToolCallResult> {
  const realm = opts.realm ?? 'pca';
  const challenge = (error: string): string => wwwAuthenticateChallenge({ resourceMetadataUrl: opts.prmUrl, error, realm });
  const deny = (status: 401 | 403, error: string, reason: string, extra: { hint?: string; checks?: Record<string, CheckStatus> } = {}): AuthorizeToolCallDeny => ({
    ok: false,
    status,
    error,
    reason,
    wwwAuthenticate: challenge(error),
    ...(extra.hint !== undefined ? { hint: extra.hint } : {}),
    ...(extra.checks ? { checks: extra.checks } : {}),
  });

  try {
    // fail closed on a missing component (a JavaScript caller, or an old `authorizeRequest` call that never passed these)
    const missing = [
      typeof opts.tool === 'string' && opts.tool.length > 0 ? '' : 'tool',
      typeof opts.toolAction === 'function' ? '' : 'toolAction',
      typeof opts.resolveGrant === 'function' ? '' : 'resolveGrant',
      opts.state && typeof opts.state.get === 'function' && typeof opts.state.put === 'function' ? '' : 'state',
      typeof opts.isRevoked === 'function' ? '' : 'isRevoked',
    ].filter(Boolean);
    if (missing.length > 0) {
      return deny(403, 'forbidden', `authorization is not configured: missing ${missing.join(', ')} (fail closed)`, {
        hint: 'authorizeRequest and authorizeToolCall authorize the whole call; pass these, or call authorizeRequest with admissionOnly: true to check admission alone',
      });
    }
    const now = opts.now ?? Date.now;
    const args = opts.args !== null && typeof opts.args === 'object' ? opts.args : {};

    // 1. admission (audience, issuer, chain and signatures, scopes, step-up).
    const { args: _a, toolAction: _m, state: _s, isRevoked: _r, isPlanAuthorized: _p, risk: _k, allowedSuites: _as, pqPins: _pq, now: _n, enforce: _e, multiInstance: _mi, replayScope: _rs, claimRetries: _cr, ...admissionOpts } =
      opts;
    const issuerFromStore = 'pca:grant-from-store';
    const adm = await admitRequest(req, {
      ...admissionOpts,
      insecureSkipPlanRootCheck: true, // admission only; step 3 (`authorize`) enforces plan_root_authorized via isPlanAuthorized and never accepts a skip
      ...(opts.authorizationServers === undefined
        ? { authorizationServers: [issuerFromStore], resolveIssuer: () => issuerFromStore }
        : { authorizationServers: opts.authorizationServers }),
      now: now(),
    });
    if (!adm.ok) {
      const missing = adm.error === 'invalid_request' && adm.errorDescription.startsWith('no PCActn presented');
      return {
        ok: false,
        status: adm.status,
        error: adm.error,
        reason: missing ? `tool '${opts.tool}' requires a proof-carrying action: send it in the PCA-Action header` : adm.errorDescription,
        wwwAuthenticate: adm.wwwAuthenticate,
        ...(adm.hint !== undefined ? { hint: adm.hint } : {}),
        ...(adm.stepUp ? { stepUp: adm.stepUp } : {}),
        ...(adm.checks ? { checks: adm.checks } : {}),
      };
    }

    // 2. binding: the proof must be for THIS call, checked before the replay counter or budget is touched.
    const want = opts.toolAction(opts.tool, args);
    if (want === null) return deny(403, 'forbidden', `tool '${opts.tool}' has no PCA mapping on this server`, { hint: 'add the tool to your `toolAction` mapping' });
    const p = adm.pcactn;
    if (p.action?.verb !== want.verb || p.action?.resource !== want.resource) {
      return deny(403, 'forbidden', `the proof is for ${String(p.action?.verb)} on ${String(p.action?.resource)}, but this call is ${want.verb} on ${want.resource}`, {
        hint: 'the agent must sign the action this tool call maps to, with the same `toolAction` mapping (pcaFetch does this per call)',
      });
    }

    // 3. the full verifier (`authorize`, bound to this call), against the grant from the caller's store.
    const grant = adm.grant;
    const r = await authorize(
      { operation: { verb: want.verb, resource: want.resource, params: args } },
      {
        audience: opts.resource,
        allowedSuites: opts.allowedSuites ?? ['ed25519'],
        ...(opts.pqPins !== undefined ? { pqPins: opts.pqPins } : {}),
        now,
        ...(opts.enforce !== undefined ? { enforce: opts.enforce } : {}),
        ...(opts.multiInstance !== undefined ? { multiInstance: opts.multiInstance } : {}),
        ...(opts.replayScope !== undefined ? { replayScope: opts.replayScope } : {}),
        ...(opts.claimRetries !== undefined ? { claimRetries: opts.claimRetries } : {}),
        resolveGrant: async (ref, pc) => (await opts.resolveGrant(ref, pc)) ?? null,
        budgetStore: opts.state,
        hooks: { revocation: async ({ grant: g }) => ({ enforced: true, ok: (await opts.isRevoked(g)) !== true }) },
        extract: () => extractPCActn(req),
        // an agent with no stored budget starts at the grant's signed bMax (0 when the grant has none)
        seedBudget: (g, t) => ({ B: readEnvelope(g)?.risk_policy.bMax ?? 0, tau: t, asOf: t }),
        context: async (_req, pc) => {
          const plan = planOf(pc);
          const consistent = merkleRoot(plan.map(planNodeLeaf)) === pc.plan.root;
          const approved = opts.isPlanAuthorized ? (await opts.isPlanAuthorized(pc.grant_ref, pc.plan.root)) === true : true;
          const risk = opts.risk ? opts.risk(grant, args, pc) : toolCallRisk(grant, args);
          return { params: args, plan, planAuthorized: consistent && approved, ...(risk !== undefined ? { risk } : {}) };
        },
      },
    );
    if (r.allow) return { ok: true, status: 200, pcactn: r.pcactn, grant, grantedScopes: adm.grantedScopes, verdict: r.verdict, operation: r.operation };
    const coSign = r.verdict.checks['threshold'] === 'fail' && r.verdict.checks['policy'] !== 'fail';
    const reason = coSign
      ? `${want.verb} on ${want.resource} needs a co-sign at threshold t=${r.verdict.requiredThreshold.t} (risk ${r.verdict.r.toFixed(2)} under the grant's risk policy)` +
        (r.verdict.reasons.some((x) => RISK_NOISE.test(x)) ? '; risk inputs the server did not supply were priced at the worst case' : '')
      : explainPolicy(r.verdict, grant, want);
    const hint = coSign
      ? 'supply the risk inputs your server can vouch for in the `risk` option (a grant with money limits is priced by toolCallRisk), or collect the co-sign with the PCA step-up flow'
      : policyHint(reason);
    return deny(r.status, r.status === 401 ? 'invalid_token' : 'forbidden', reason, { ...(hint !== undefined ? { hint } : {}), checks: r.verdict.checks });
  } catch (e) {
    return deny(403, 'forbidden', `authorization error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
  }
}

/** Admission alone: `authorizeRequest` with `admissionOnly: true` (audience, issuer, chain and signatures, scopes, step-up). */
export type AdmissionOnlyOptions = AdmissionOptions & { admissionOnly: true };

/**
 * Authorize one MCP request. Since 0.5 this is the COMPLETE check by default, exactly `authorizeToolCall`: admission, the
 * binding to the tool call, and the full verifier (limits, revocation, replay, budget). Admission alone is an explicit
 * opt-in, `admissionOnly: true`: it checks the proof is genuine and in scope, and nothing about this call
 * (see {@link admitRequest}). A call that omits the components the full check needs is refused, never downgraded.
 */
export function authorizeRequest(req: McpRequestLike, opts: AdmissionOnlyOptions): Promise<AuthorizeResult>;
export function authorizeRequest(req: McpRequestLike, opts: AuthorizeToolCallOptions): Promise<AuthorizeToolCallResult>;
export function authorizeRequest(req: McpRequestLike, opts: AdmissionOnlyOptions | AuthorizeToolCallOptions): Promise<AuthorizeResult | AuthorizeToolCallResult> {
  return (opts as { admissionOnly?: unknown }).admissionOnly === true ? admitRequest(req, opts as AdmissionOnlyOptions) : authorizeToolCall(req, opts as AuthorizeToolCallOptions);
}
