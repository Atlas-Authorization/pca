import type { Capability } from '../capability';
import { catalogRisk } from '../catalog-risk';
import type { RequireAuthorizedOptions } from './authorize';
import { memoryPcaStore } from './require-pca';

/**
 * `protect()`: the secure defaults for a resource server, in one call.
 *
 *   const p = protect({ audience: 'ins_acme', grants: [grant], operation: (req) => ({ verb: 'stripe.refund', resource: `charge:${req.body.charge}`, params: req.body.params }) });
 *   app.post('/refunds', pcaExpress(p.options), handler);     // or requireAuthorized(p.options), pcaFastify(...), ...
 *   p.revoke(grant.id);                                       // later: every action under that grant is refused
 *
 * It fills in the parts every server otherwise wires by hand, and nothing else: the grant lookup (your own list or
 * function, never the request), a replay/budget store (in memory unless you pass `budgetStore`), a revocation source,
 * `plan: 'single-step'` (the grant alone limits what runs), and server-side risk from the connector catalog
 * (`catalogRisk`). Everything is still `authorize()`: bound to the operation your route executes, default-deny.
 * Any option you pass wins over the default.
 */
export type ProtectOptions = Pick<RequireAuthorizedOptions, 'audience' | 'operation'> &
  Partial<Omit<RequireAuthorizedOptions, 'audience' | 'operation' | 'resolveGrant'>> & {
    /** The grants this server accepts (looked up by `id`), or a function from `grant_ref` to a grant. */
    grants: Capability[] | RequireAuthorizedOptions['resolveGrant'];
    /** Extra revocation source, consulted in addition to `revoke()`. */
    isRevoked?: (grant: Capability) => boolean | Promise<boolean>;
  };

export interface Protected {
  /** Pass to `requireAuthorized`, `pcaExpress`, `pcaFastify`, `pcaHono`, `pcaNext`, `pcaFetch`-style guards. */
  options: RequireAuthorizedOptions;
  /** Refuse every further action under this grant id. */
  revoke(grantId: string): void;
}

export function protect(opts: ProtectOptions): Protected {
  const { grants, isRevoked, ...rest } = opts;
  const revoked = new Set<string>();
  const byId = Array.isArray(grants) ? new Map(grants.map((g) => [g.id, g] as const)) : undefined;
  const resolveGrant: RequireAuthorizedOptions['resolveGrant'] = byId ? async (ref) => byId.get(ref) ?? null : (grants as RequireAuthorizedOptions['resolveGrant']);
  const options: RequireAuthorizedOptions = {
    plan: 'single-step',
    risk: (op, grant) => (op ? catalogRisk(op.verb, op.params, grant) : undefined),
    budgetStore: memoryPcaStore(),
    ...rest,
    // your own hooks win; the revocation hook stays unless you replace it
    hooks: { revocation: async ({ grant }) => ({ enforced: true, ok: !revoked.has(grant.id) && (await isRevoked?.(grant)) !== true }), ...rest.hooks },
    resolveGrant,
  };
  return { options, revoke: (id) => void revoked.add(id) };
}
