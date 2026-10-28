import { GrantError, type AmendRequest, type GrantService, type GrantStatus, type Need, type RevokeScope, type GrantErrorCode } from './grant-resource';
import { isObj } from './sig';

/** Framework-neutral HTTP binding of the grant management resource (same shape as the AuthZEN handler). */
export const GRANTS_PATH = '/pca/grants';
export const NEEDS_PATH = '/pca/needs';

export interface GrantHttpRequest {
  method: string;
  /** Path below the mount point, e.g. `/pca/grants/g_1/amend`. */
  path: string;
  query?: Record<string, string | undefined>;
  body?: unknown;
}
export interface GrantHttpResponse {
  status: number;
  body: unknown;
}
/** Who is calling, as the host authenticated them. `principal` limits every read and write to that principal's grants. */
export interface GrantCaller {
  principal?: string;
  admin?: boolean;
}
export interface GrantHttpOptions {
  authenticate: (req: GrantHttpRequest) => GrantCaller | null | Promise<GrantCaller | null>;
}

const STATUS: Record<GrantErrorCode, number> = {
  not_found: 404, conflict: 409, bad_request: 400, not_narrower: 422, signature_required: 401, bad_signature: 401, step_up_required: 403,
  not_active: 409, need_not_lowered_only: 422, need_not_adjustable: 422, forbidden: 403,
};
const err = (e: unknown): GrantHttpResponse =>
  e instanceof GrantError ? { status: STATUS[e.code], body: { error: e.code, message: e.message } } : { status: 500, body: { error: 'server_error' } };

/** Discovery fragment for `/.well-known/pca-configuration`. */
export const grantManagementMetadata = (base: string) => ({
  grant_management: { grants_endpoint: `${base}${GRANTS_PATH}`, needs_endpoint: `${base}${NEEDS_PATH}`, amend_actions: ['narrow', 'merge', 'replace'], revoke_scopes: ['grant', 'agent', 'subtree'], widening: 'new_grant_id_with_supersedes' },
});

export function grantResourceHandler(svc: GrantService, o: GrantHttpOptions): (req: GrantHttpRequest) => Promise<GrantHttpResponse> {
  return async (req) => {
    try {
      const who = await o.authenticate(req);
      if (!who || (!who.admin && !who.principal)) return { status: 401, body: { error: 'unauthenticated' } };
      const seg = req.path.split('/').filter(Boolean); // ['pca','grants',id?,verb?]
      const q = req.query ?? {};
      const b = isObj(req.body) ? req.body : {};
      // A principal-scoped caller may only see and touch its own grants.
      const own = async (id: string): Promise<void> => {
        const g = await svc.inspect(id);
        if (!who.admin && g.principal !== who.principal) throw new GrantError('not_found', 'no such grant');
      };
      if (seg[0] !== 'pca') return { status: 404, body: { error: 'not_found' } };
      if (seg[1] === 'grants') {
        if (seg.length === 2 && req.method === 'GET') {
          const status = q.status as GrantStatus | undefined;
          if (status !== undefined && !['active', 'revoked', 'superseded'].includes(status)) throw new GrantError('bad_request', 'bad status');
          const principal = who.admin ? q.principal : who.principal;
          const limit = q.limit === undefined ? undefined : Number(q.limit);
          return { status: 200, body: await svc.list({ ...(principal ? { principal } : {}), ...(q.agent ? { agent: q.agent } : {}), ...(status ? { status } : {}), ...(limit !== undefined && Number.isFinite(limit) ? { limit } : {}), ...(q.cursor ? { cursor: q.cursor } : {}) }) };
        }
        const id = seg[2];
        if (!id) return { status: 404, body: { error: 'not_found' } };
        await own(id);
        if (seg.length === 3 && req.method === 'GET') return { status: 200, body: await svc.inspect(id) };
        if (seg.length === 3 && req.method === 'DELETE') {
          const scope = (q.scope ?? 'grant') as RevokeScope;
          const sig = typeof b.sig === 'string' ? b.sig : undefined;
          // A principal-scoped caller must still sign; only an admin may revoke without a principal signature.
          const r = await svc.revoke(id, scope, who.admin && !sig ? { admin: true } : { sig: sig ?? '' });
          return { status: 200, body: r };
        }
        if (seg.length === 4 && seg[3] === 'amend' && req.method === 'POST') {
          const r = await svc.amend(id, req.body as AmendRequest);
          return { status: r.created ? 201 : 200, body: r.grant };
        }
        if (seg.length === 4 && seg[3] === 'needs' && req.method === 'POST') {
          return { status: 201, body: await svc.requestNeeds(id, b.needs as Need[]) };
        }
      }
      if (seg[1] === 'needs' && seg[2] && seg[3] === 'approve' && req.method === 'POST') {
        await own(await svc.needGrantId(seg[2]));
        if (typeof b.sig !== 'string' || !Array.isArray(b.approved)) throw new GrantError('bad_request', 'sig and approved are required');
        const r = await svc.approveNeeds(seg[2], b.approved as Need[], b.sig, typeof b.step_up_ref === 'string' ? b.step_up_ref : undefined);
        return { status: 201, body: r.grant };
      }
      if (seg[1] === 'needs' && seg[2] && seg[3] === 'deny' && req.method === 'POST') {
        await own(await svc.needGrantId(seg[2]));
        await svc.denyNeeds(seg[2]);
        return { status: 200, body: { status: 'denied' } };
      }
      return { status: 404, body: { error: 'not_found' } };
    } catch (e) {
      return err(e);
    }
  };
}
