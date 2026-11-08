import { checkLease, type LeaseAcceptCode, type LeaseRegistry } from './lease';
import type { GrantHttpRequest, GrantHttpResponse } from './http';
import { isObj } from './sig';

/**
 * Hosted lease routes (framework-neutral, same shape as the grant resource). The server only stores records the lease
 * authority already signed; it never mints one, so a compromised host cannot extend a lease.
 *   POST   /pca/leases              body {lease, chain?}        issue (seq 1) or renew (seq n+1)
 *   GET    /pca/leases/:id                                      the newest record and its renewal ledger
 *   POST   /pca/leases/:id/check   body {lease, now?}           is this record a live lease
 *   POST   /pca/leases/revoke      body {revocation}            a signed revoke by lease, prefix or grant
 */
export const LEASES_PATH = '/pca/leases';
export interface LeaseCaller { admin?: boolean; principal?: string }
export interface LeaseHttpOptions {
  authenticate: (req: GrantHttpRequest) => LeaseCaller | null | Promise<LeaseCaller | null>;
  now?: () => number;
}
const STATUS: Partial<Record<LeaseAcceptCode, number>> = {
  bad_record: 400, bad_seq: 409, stale_seq: 409, lease_fork: 409, renewal_mismatch: 422, over_max_ttl: 422, ttl_ceiling: 422, not_extending: 422, stale_justification: 422,
  expired_lease: 409, revoked: 409, sod: 403, unknown_authority: 403, store_unreachable: 503,
};

export const leaseManagementMetadata = (base: string) => ({ leases: { leases_endpoint: `${base}${LEASES_PATH}`, revoke_targets: ['lease', 'prefix', 'grant'] } });

export function leaseResourceHandler(reg: LeaseRegistry, o: LeaseHttpOptions): (req: GrantHttpRequest) => Promise<GrantHttpResponse> {
  const clock = o.now ?? (() => Date.now());
  return async (req) => {
    try {
      const who = await o.authenticate(req);
      if (!who || (!who.admin && !who.principal)) return { status: 401, body: { error: 'unauthenticated' } };
      const seg = req.path.split('/').filter(Boolean); // ['pca','leases',id?,verb?]
      const b = isObj(req.body) ? req.body : {};
      if (seg[0] !== 'pca' || seg[1] !== 'leases') return { status: 404, body: { error: 'not_found' } };
      // a lease belongs to its holder: a non-admin sees and checks only leases it holds
      const visible = (holder: string) => who.admin === true || who.principal === holder;
      if (seg.length === 2 && req.method === 'POST') {
        if (!who.admin) return { status: 403, body: { error: 'forbidden' } };
        const chain = Array.isArray(b.chain) && b.chain.every((x) => typeof x === 'string') ? (b.chain as string[]) : [];
        const r = await reg.accept(b.lease, chain);
        return r.ok ? { status: r.replaced ? 201 : 200, body: r } : { status: STATUS[r.code] ?? 400, body: { error: r.code, ...(r.reason ? { message: r.reason } : {}) } };
      }
      if (seg.length === 3 && seg[2] === 'revoke' && req.method === 'POST') {
        if (!who.admin) return { status: 403, body: { error: 'forbidden' } };
        const r = await reg.revoke(b.revocation);
        return r.ok ? { status: 200, body: r } : { status: r.code === 'store_unreachable' ? 503 : r.code === 'unknown_authority' ? 403 : 400, body: { error: r.code } };
      }
      const id = seg[2];
      if (!id) return { status: 404, body: { error: 'not_found' } };
      if (seg.length === 3 && req.method === 'GET') {
        const cur = await reg.get(id);
        if (cur === undefined || !visible(cur.holder)) return { status: 404, body: { error: 'not_found' } };
        return { status: 200, body: { lease: cur, history: await reg.history(id) } };
      }
      if (seg.length === 4 && seg[3] === 'check' && req.method === 'POST') {
        const cur = await reg.get(id);
        if (cur === undefined || !visible(cur.holder)) return { status: 404, body: { error: 'not_found' } };
        const d = await checkLease(b.lease, reg, clock());
        return { status: d.decision === 'allow' ? 200 : 403, body: d };
      }
      return { status: 404, body: { error: 'not_found' } };
    } catch {
      return { status: 500, body: { error: 'server_error' } };
    }
  };
}
