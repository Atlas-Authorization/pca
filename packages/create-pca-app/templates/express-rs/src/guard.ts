/**
 * The verification core of the resource server, kept free of Express so it is easy to test.
 *
 * THE RULES THIS FILE EXISTS TO TEACH:
 *
 * 1. The root of trust is decided by the SERVER, never by the request.
 *    - The grant the action must chain back to is loaded from THIS server's own store, keyed by the
 *      action's signed `grant_ref`. It is never read from a header, a body, or the presented artifact's
 *      own `cap_chain[0]`. A grant the caller hands you proves nothing: an attacker can mint a root that
 *      names your principal as `issuer` but is signed with the attacker's own (e.g. post-quantum) key.
 *    - `allowedSuites` states which signature suites this server accepts (here: Ed25519 only), so a
 *      pure-PQ or hybrid artifact is refused outright. If you do accept a post-quantum suite, keep the
 *      grant in your store (as here) and pin the principal's PQ key on the server (`pqPins`).
 *    - The audience is this server's own id, and the clock is this server's clock.
 *
 * 2. A valid PROOF is not an AUTHORIZATION. The decision is made by `requirePCA`, the full server
 *    verifier: the grant's predicates and limits (a refund-only grant never authorizes
 *    `github.delete_repo`), its caveats, the plan the principal authorized, revocation, the replay
 *    counter, the trust budget and the threshold the server derives for the action. The structural core
 *    verifier only checks that the proof is well-formed and signed; it evaluates no predicate, limit or
 *    caveat, so it is never the thing that says "allow".
 *
 * 3. Default-deny: `requirePCA` requires every check in `DEFAULT_REQUIRED_CHECKS` (replay counter,
 *    revocation, plan authorization, audience, validity, grant binding) to PASS, not merely "not enforced".
 */

import {
  merkleRoot,
  planNodeLeaf,
  readEnvelope,
  requirePCA,
  type Capability,
  type PCActn,
  type PcaOperation,
  type PcaStateStore,
  type PlanNode,
  type SigAlg,
} from '@atlasauth/pca';

/** The server's own registry. In production: your database. The ONLY source of a trusted root. */
export interface GrantStore {
  /** The grant the principal registered with this server out-of-band, by id. */
  get(grantRef: string): Capability | null | undefined;
  /** Has the principal authorized this plan root for this grant (registered it out-of-band)? */
  isPlanAuthorized(grantRef: string, planRoot: string): boolean;
  /** Has the principal revoked this grant? */
  isRevoked(grantRef: string): boolean;
}

export interface GuardConfig {
  /** This server's own audience id. A PCActn minted for a different audience will not verify here. */
  audience: string;
  /** Grants, authorized plan roots and revocations the principal registered with this server. */
  grants: GrantStore;
  /** Per-holder replay counter + trust budget (in memory here: `memoryPcaStore()`; Redis / a DB in production). */
  state: PcaStateStore;
  /** Signature suites accepted for the leaf and every delegation hop. Default: Ed25519 only. */
  allowedSuites?: readonly SigAlg[];
  /** Server-side PQ pins `issuer -> pq_pk`, needed only if you accept a post-quantum suite. */
  pqPins?: Readonly<Record<string, string>>;
  /** This server's clock (epoch ms). Tests inject it; never take it from the request. */
  now?: () => number;
}

export interface GuardResult {
  status: 200 | 401 | 403;
  body: Record<string, unknown>;
  /** `WWW-Authenticate` challenge for a 401. */
  wwwAuthenticate?: string;
}

/**
 * What the guard reads from one request: the `PCA-Action` header and the operation the ROUTE will execute (its verb, the
 * resource named in the URL or body, and the plaintext params from the JSON body). The operation comes from your routing,
 * never from the proof: the proof must be for exactly it.
 */
interface ActionRequest {
  headers: Record<string, string | undefined>;
  body: Record<string, never>;
  operation: PcaOperation;
}

/** Rebuild the one-node plan from the SIGNED action; its Merkle root is bound inside the PCActn. */
function planOf(p: PCActn): PlanNode[] {
  return [{ id: p.plan.node_id, verb: p.action.verb, resource: p.action.resource, params_digest: p.action.params_digest, reversibility_class: p.action.reversibility_class }];
}

/** Build the guard once per server. It returns a function that decides one request. */
export function createGuard(cfg: GuardConfig): (actionHeader: string, operation: PcaOperation) => Promise<GuardResult> {
  const guard = requirePCA({
    audience: cfg.audience,
    allowedSuites: cfg.allowedSuites ?? ['ed25519'],
    ...(cfg.pqPins !== undefined ? { pqPins: cfg.pqPins } : {}),
    ...(cfg.now !== undefined ? { now: cfg.now } : {}),
    // The trusted root comes from OUR store, by the action's signed grant_ref. Unknown => deny.
    resolveGrant: async (ref) => cfg.grants.get(ref) ?? null,
    budgetStore: cfg.state,
    // The operation this route executes (from the route, not the proof): the proof must be for exactly this verb,
    // resource and params, so it cannot be reused for another resource or amount.
    operation: (req) => (req as ActionRequest).operation,
    // The trust budget starts at the ceiling the principal signed into the grant; the store carries the spent budget from then on.
    seedBudget: (grant, now) => ({ B: readEnvelope(grant)?.risk_policy.bMax ?? 0, tau: now, asOf: now }),
    hooks: { revocation: ({ grant }) => ({ enforced: true, ok: !cfg.grants.isRevoked(grant.id) }) },
    // The header carries the PCActn (JSON or base64url); requirePCA decodes it strictly.
    extract: (req) => (req as ActionRequest).headers['pca-action'] ?? null,
    context: async (req, p) => {
      const plan = planOf(p);
      const grant = cfg.grants.get(p.grant_ref);
      const policy = grant ? readEnvelope(grant)?.risk_policy : undefined;
      const params = (req as ActionRequest).operation.params;
      // The server prices a money-moving action itself, from the amount it verified: $42 under a $500 cap spends
      // 42/500 of the trust budget. Risk inputs the server does not supply are priced at the worst case, so without
      // this one refund would spend the whole budget.
      const amount = params?.['amount'];
      const risk = typeof amount === 'number' && policy && policy.kappa > 0 ? { blastRadius: Math.min(1, Math.max(0, amount / policy.kappa)) } : undefined;
      return {
        params,
        ...(risk !== undefined ? { risk } : {}),
        plan,
        planAuthorized: merkleRoot(plan.map(planNodeLeaf)) === p.plan.root && cfg.grants.isPlanAuthorized(p.grant_ref, p.plan.root),
      };
    },
  });

  return async (actionHeader, operation) => {
    const r = await guard({ headers: { 'pca-action': actionHeader }, body: {}, operation } as ActionRequest);
    if (r.ok) return { status: 200, body: { allow: true, verb: r.pcactn.action.verb, resource: r.pcactn.action.resource, checks: r.verdict.checks } };
    return { status: r.status, body: { allow: false, reasons: r.verdict.reasons, checks: r.verdict.checks }, ...(r.wwwAuthenticate ? { wwwAuthenticate: r.wwwAuthenticate } : {}) };
  };
}

const guards = new WeakMap<GuardConfig, ReturnType<typeof createGuard>>();

/**
 * Verify one `PCA-Action` header value and decide whether to perform `operation`: the verb and resource this route
 * executes and the plaintext params (sent in the request body). The proof must be for exactly that operation and the
 * verifier checks the params against the commitment and the grant's limits. The caller supplies NOTHING that is
 * trusted as a root.
 */
export async function verifyAction(actionHeader: string, cfg: GuardConfig, operation: PcaOperation): Promise<GuardResult> {
  let g = guards.get(cfg);
  if (!g) guards.set(cfg, (g = createGuard(cfg)));
  return g(actionHeader, operation);
}
