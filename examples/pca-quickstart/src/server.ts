/**
 * THE RESOURCE SERVER SIDE.
 *
 * One Express route, `POST /refunds`, guarded by `requirePCA()` (via `@atlasauth/pca-express`).
 * The guard verifies the inbound proof-carrying action OFFLINE and is default-deny: if a required
 * check cannot be enforced, the request is denied. On success it attaches the verdict and calls
 * your handler; otherwise it answers 401/403 with a `WWW-Authenticate` challenge.
 *
 * The client sends `{ pcactn, charge, params }` as JSON. `params` is the plaintext the proof committed by
 * hash — the verifier needs it to check the action against the grant's limits (e.g. "<= $500". The route
 * names the operation it will run (`stripe.refund` on `charge:<id>` with these params), and the proof must be
 * for exactly that operation.
 */

import express, { type RequestHandler } from 'express';
import { memoryPcaStore, pcaExpress } from '@atlasauth/pca-express';
import {
  merkleRoot,
  planNodeLeaf,
  readEnvelope,
  type Capability,
  type PCActn,
  type PlanNode,
} from '@atlasauth/pca';

export interface QuickstartServer {
  /** The configured Express app (not yet listening). */
  app: express.Express;
  /** The principal authorizes a plan root; actions on an un-authorized plan are denied. */
  authorize(planRoot: string): void;
}

export function createServer(opts: { grant: Capability; audience: string }): QuickstartServer {
  const { grant, audience } = opts;

  // Per-holder replay + budget state. In-memory here; back it with Redis/a DB in production.
  const store = memoryPcaStore();
  // The grant's risk policy: its per-call cap (kappa) prices a refund.
  const policy = readEnvelope(grant)?.risk_policy;
  // Plan roots the human principal has authorized. (App. A step 2: the RS must know them.)
  const authorizedPlanRoots = new Set<string>();

  const app = express();
  app.use(express.json());

  // `requirePCA()` for Express. The middleware reads only `headers` + `body`, so we hand it those
  // from Express's request at the boundary (keeps it typed with no casts and no `any`).
  const pcaGuard = pcaExpress({
    audience, // the PCActn's signed `aud` must equal this (no cross-server replay)
    // Look up the Root Intent Grant the action chains back to (by its signed grant_ref).
    resolveGrant: async (ref) => (ref === grant.id ? grant : null),
    budgetStore: store,
    // The operation this route executes, from the route and the body, never from the proof. The proof must be
    // for exactly this verb, resource and params, so it cannot be reused for another charge or amount.
    operation: (req) => {
      const body = (req.body ?? {}) as { charge?: string; params?: Record<string, unknown> };
      return { verb: 'stripe.refund', resource: `charge:${body.charge}`, params: body.params ?? {} };
    },
    // Confirm the grant is not revoked. Plug your revocation list in here.
    hooks: { revocation: () => ({ enforced: true, ok: true }) },
    // Hand the verifier the plaintext params + the authorized plan so it can judge the action.
    context: async (req, p: PCActn) => {
      const body = (req.body ?? {}) as { params?: Record<string, unknown> };
      // Rebuild the one-node plan from the SIGNED action. Its Merkle root is bound inside the
      // PCActn, so a tampered action cannot match an authorized root.
      const node: PlanNode = {
        id: p.plan.node_id,
        verb: p.action.verb,
        resource: p.action.resource,
        params_digest: p.action.params_digest,
        reversibility_class: p.action.reversibility_class,
      };
      const plan = [node];
      const rootMatches = merkleRoot(plan.map(planNodeLeaf)) === p.plan.root;
      // The server prices the refund itself, from the amount it verified: $42 under a $500 cap spends 42/500 of
      // the trust budget. (Risk inputs the server does not supply are priced at the worst case, so one call would
      // spend the whole budget.)
      const amount = body.params?.['amount'];
      const kappa = policy?.kappa ?? 0;
      const risk = typeof amount === 'number' && kappa > 0 ? { blastRadius: Math.min(1, Math.max(0, amount / kappa)) } : undefined;
      // The trust budget starts at the grant's bMax and the store keeps the debited budget from then on.
      return {
        params: body.params,
        plan,
        planAuthorized: rootMatches && authorizedPlanRoots.has(p.plan.root),
        ...(risk !== undefined ? { risk } : {}),
      };
    },
  });

  const guard: RequestHandler = (req, res, next) => {
    pcaGuard({ headers: req.headers, body: req.body }, res, next);
  };

  app.post('/refunds', guard, (_req, res) => {
    // Reached only when the proof verified and the policy allowed the action.
    res.json({ ok: true, status: 'refunded' });
  });

  return { app, authorize: (planRoot) => void authorizedPlanRoots.add(planRoot) };
}
