import type { AmendRequest, GrantView, Need, NeedRequest, RevokeScope } from './grant-resource';
import { mergeFreshAt, verifyFreshAt, type FreshAt, type FreshAtState } from './fresh-at';

/** Fetch-based client for the grant management resource. It also carries the newest `fresh_at` token it has seen. */
export interface GrantClientOptions {
  baseUrl: string;
  fetch?: typeof fetch;
  /** The AS's pinned token signer. When set, a `pca-fresh-at` header that does not verify is ignored. */
  freshSigner?: string;
  headers?: () => Record<string, string> | Promise<Record<string, string>>;
}
export class GrantApiError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
    this.name = 'GrantApiError';
  }
}
export function createGrantClient(o: GrantClientOptions) {
  const f = o.fetch ?? fetch;
  let latest: FreshAt | undefined;
  const call = async <T>(method: string, path: string, body?: unknown): Promise<T> => {
    const res = await f(`${o.baseUrl.replace(/\/$/, '')}${path}`, {
      method,
      headers: { 'content-type': 'application/json', ...(latest ? { 'pca-fresh-at': JSON.stringify(latest) } : {}), ...(o.headers ? await o.headers() : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    const tok = res.headers?.get?.('pca-fresh-at');
    if (tok) {
      try {
        const t = JSON.parse(tok) as FreshAt;
        if (o.freshSigner !== undefined && !verifyFreshAt(t, o.freshSigner)) throw new Error('unverified');
        // Monotone fold: never replace a fresher token with an older one.
        if (!latest || (t.revocation_epoch >= latest.revocation_epoch && t.policy_revision >= latest.policy_revision && t.ledger_tree_size >= latest.ledger_tree_size && t.budget_version >= latest.budget_version)) latest = t;
      } catch { /* ignore a malformed header: freshness is only ever tightened by a valid token */ }
    }
    const json = (await res.json().catch(() => ({}))) as { error?: string; message?: string };
    if (!res.ok) throw new GrantApiError(res.status, json.error ?? 'error', json.message ?? res.statusText);
    return json as T;
  };
  return {
    list: (q: { principal?: string; agent?: string; status?: string; limit?: number; cursor?: string } = {}) => {
      const p = new URLSearchParams();
      for (const [k, v] of Object.entries(q)) if (v !== undefined) p.set(k, String(v));
      return call<{ grants: GrantView[]; next_cursor?: string }>('GET', `/pca/grants${p.size ? `?${p}` : ''}`);
    },
    inspect: (id: string) => call<GrantView>('GET', `/pca/grants/${encodeURIComponent(id)}`),
    amend: (id: string, req: AmendRequest) => call<GrantView>('POST', `/pca/grants/${encodeURIComponent(id)}/amend`, req),
    revoke: (id: string, scope: RevokeScope = 'grant', sig?: string) => call<{ revoked: string[] }>('DELETE', `/pca/grants/${encodeURIComponent(id)}?scope=${scope}`, sig ? { sig } : undefined),
    requestNeeds: (id: string, needs: Need[]) => call<NeedRequest>('POST', `/pca/grants/${encodeURIComponent(id)}/needs`, { needs }),
    approveNeeds: (needId: string, approved: Need[], sig: string, stepUpRef?: string) => call<GrantView>('POST', `/pca/needs/${encodeURIComponent(needId)}/approve`, { approved, sig, ...(stepUpRef ? { step_up_ref: stepUpRef } : {}) }),
    denyNeeds: (needId: string) => call<{ status: string }>('POST', `/pca/needs/${encodeURIComponent(needId)}/deny`),
    /** The newest consistency token seen on any response: attach it to later requests to make them read-your-writes. */
    get freshAt(): FreshAt | undefined { return latest; },
    foldFreshAt: (s: FreshAtState): FreshAtState | undefined => (latest ? mergeFreshAt(latest, s) : undefined),
  };
}
