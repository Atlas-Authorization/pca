import { compareUtf8, hashCanonical } from '@atlasauth/pca';
import { isObj, isSafeInt, isStr, signBody, verifyBody } from './sig';

/**
 * GRANT MANAGEMENT RESOURCE: list / inspect / amend / revoke and incremental authorization for principals, as one
 * standard resource every PCA-aware authorization server exposes (advertised in `/.well-known/pca-configuration` under
 * `grant_management`). Modelled on OAuth 2.0 Grant Management (`grant_id`, query, revoke) and the wallet permission
 * calls of ERC-7715, but STRICTER: nothing widens in place.
 *
 *  - `narrow` (or any amendment whose result is not wider) is a signed attenuation by the holder OR the principal; it
 *    revises the grant in place (`rev` + 1, history kept).
 *  - `merge` / `replace` that WIDEN need a fresh principal signature over (grant id, current rev, action, new authority
 *    digest) and a satisfied step-up; they create a NEW grant id with `supersedes`, and the old one becomes `superseded`.
 *  - An incomparable change is treated as wider (fail closed).
 *  - Incremental authorization: the agent files typed `needs`; the principal approves a delta (and, when a need is
 *    `adjustable`, may LOWER its amounts) which becomes a widening merge.
 */
export const GRANT_AMEND_DOMAIN = 'atlas-pca/grant-amend/v1\0';
export const GRANT_REVOKE_DOMAIN = 'atlas-pca/grant-revoke/v1\0';
export const NEED_APPROVE_DOMAIN = 'atlas-pca/need-approve/v1\0';
/** The holder (agent) signs the needs it files, so an authorization server can attribute a request without a shared secret. */
export const NEED_REQUEST_DOMAIN = 'atlas-pca/need-request/v1\0';
/** A server-issued single-use challenge the principal signs on its own device: the step-up that gates a widening. */
export const GRANT_STEPUP_DOMAIN = 'atlas-pca/grant-stepup/v1\0';

/** The comparable shape of a grant's authority. Anything richer lives behind a custom {@link AuthorityCompare}. */
export interface Authority {
  verbs: string[];
  /** Resource patterns: exact ids, or a prefix ending in `*`. */
  resources: string[];
  /** Named numeric ceilings (e.g. `money.usd`); a lower ceiling is narrower. A ceiling absent from the old authority is unbounded there. */
  limits?: Record<string, number>;
  /** Epoch ms; a sooner expiry is narrower. Absent = never expires. */
  expires_at?: number;
}
export type Order = 'narrower' | 'equal' | 'wider' | 'incomparable';
export type AuthorityCompare = (oldA: Authority, newA: Authority) => Order;

const resCovers = (p: string, r: string): boolean => (p.endsWith('*') ? r.startsWith(p.slice(0, -1)) : p === r);
const resSubset = (small: string[], big: string[]): boolean => small.every((s) => big.some((b) => resCovers(b, s) && (s.endsWith('*') ? b.endsWith('*') || b === s : true)));
const verbSubset = (small: string[], big: string[]): boolean => small.every((s) => big.includes(s));

export const compareAuthority: AuthorityCompare = (o, n) => {
  const le = (a: Authority, b: Authority): boolean => {
    // a <= b : everything a allows, b allows
    if (!verbSubset(a.verbs, b.verbs) || !resSubset(a.resources, b.resources)) return false;
    for (const [k, v] of Object.entries(a.limits ?? {})) {
      const bv = b.limits?.[k];
      if (bv !== undefined && !(v <= bv)) return false;
    }
    for (const k of Object.keys(b.limits ?? {})) if (a.limits?.[k] === undefined) return false;
    const ae = a.expires_at ?? Infinity;
    const be = b.expires_at ?? Infinity;
    return ae <= be;
  };
  const nle = le(n, o);
  const ole = le(o, n);
  return nle && ole ? 'equal' : nle ? 'narrower' : ole ? 'wider' : 'incomparable';
};
export const authorityDigest = (a: Authority): string => hashCanonical({ d: 'atlas-pca/authority/v1', a: { ...a, verbs: [...a.verbs].sort(compareUtf8), resources: [...a.resources].sort(compareUtf8) } });

export type GrantStatus = 'active' | 'revoked' | 'superseded';
export interface GrantRecord {
  id: string;
  principal: string;
  agent: string;
  /** Parent grant id for delegated grants (revoke `subtree`). */
  parent?: string;
  status: GrantStatus;
  authority: Authority;
  rev: number;
  /** Digest-addressed chain this grant is backed by. */
  chain_digest: string;
  supersedes?: string;
  superseded_by?: string;
  adjustable?: boolean;
  created_at: number;
  history: Array<{ rev: number; authority_digest: string; at: number; action: string }>;
}
export interface GrantView extends Omit<GrantRecord, 'history'> {
  authority_digest: string;
  /** Filled by the host's {@link GrantProviders}. */
  usage?: unknown;
  remaining_budget?: unknown;
  pending_needs: string[];
  policy_card?: unknown;
  residual?: unknown;
}
export interface GrantProviders {
  usage?: (g: GrantRecord) => unknown | Promise<unknown>;
  remainingBudget?: (g: GrantRecord) => unknown | Promise<unknown>;
  policyCard?: (g: GrantRecord) => unknown | Promise<unknown>;
  residual?: (g: GrantRecord) => unknown | Promise<unknown>;
}
export interface Need {
  verb: string;
  resource: string;
  limits?: Record<string, number>;
  /** The principal may approve a lower amount instead of rejecting. */
  adjustable?: boolean;
}
export interface NeedRequest {
  id: string;
  grant_id: string;
  needs: Need[];
  status: 'pending' | 'approved' | 'denied';
  created_at: number;
  result_grant_id?: string;
}

export interface GrantStore {
  get(id: string): Promise<GrantRecord | undefined>;
  put(g: GrantRecord): Promise<void>;
  list(): Promise<GrantRecord[]>;
  getNeed(id: string): Promise<NeedRequest | undefined>;
  putNeed(n: NeedRequest): Promise<void>;
  listNeeds(grantId: string): Promise<NeedRequest[]>;
}
export class MemoryGrantStore implements GrantStore {
  private readonly g = new Map<string, GrantRecord>();
  private readonly n = new Map<string, NeedRequest>();
  async get(id: string) { const x = this.g.get(id); return x && structuredClone(x); }
  async put(g: GrantRecord) { this.g.set(g.id, structuredClone(g)); }
  async list() { return [...this.g.values()].map((x) => structuredClone(x)); }
  async getNeed(id: string) { const x = this.n.get(id); return x && structuredClone(x); }
  async putNeed(n: NeedRequest) { this.n.set(n.id, structuredClone(n)); }
  async listNeeds(grantId: string) { return [...this.n.values()].filter((x) => x.grant_id === grantId).map((x) => structuredClone(x)); }
}

export type GrantErrorCode =
  | 'not_found' | 'conflict' | 'bad_request' | 'not_narrower' | 'signature_required' | 'bad_signature' | 'step_up_required'
  | 'not_active' | 'need_not_lowered_only' | 'need_not_adjustable' | 'forbidden';
export class GrantError extends Error {
  constructor(readonly code: GrantErrorCode, message: string) {
    super(message);
    this.name = 'GrantError';
  }
}

export type AmendAction = 'narrow' | 'merge' | 'replace';
export interface AmendRequest {
  action: AmendAction;
  /** `narrow`/`replace`: the proposed authority. `merge`: the delta unioned into the current authority. */
  authority: Authority;
  /** Signature by the holder (narrow only) or the principal, over {@link amendMessage}. */
  sig?: string;
  signed_by?: 'holder' | 'principal';
  /** Reference to a satisfied step-up (CIBA / passkey / FROST) when the change widens. */
  step_up_ref?: string;
}
export const amendMessage = (g: Pick<GrantRecord, 'id' | 'rev'>, action: AmendAction, authority: Authority) =>
  ({ grant: g.id, rev: g.rev, action, authority: authorityDigest(authority) });

const union = (a: string[], b: string[]): string[] => [...new Set([...a, ...b])];
/** Union. A ceiling or expiry is only ever RAISED by the delta; one the delta omits is kept (use `replace` to drop it). */
function mergeAuthority(a: Authority, d: Authority): Authority {
  const limits: Record<string, number> = {};
  for (const [k, v] of Object.entries(a.limits ?? {})) limits[k] = Math.max(v, d.limits?.[k] ?? v);
  const exp = a.expires_at === undefined ? undefined : Math.max(a.expires_at, d.expires_at ?? a.expires_at);
  return { verbs: union(a.verbs, d.verbs), resources: union(a.resources, d.resources), ...(Object.keys(limits).length ? { limits } : {}), ...(exp !== undefined ? { expires_at: exp } : {}) };
}

function checkAuthority(a: unknown): asserts a is Authority {
  const ok = isObj(a) && Array.isArray(a.verbs) && a.verbs.length <= 256 && a.verbs.every((v) => isStr(v, 128)) &&
    Array.isArray(a.resources) && a.resources.length <= 1024 && a.resources.every((v) => isStr(v, 512)) &&
    (a.limits === undefined || (isObj(a.limits) && Object.values(a.limits).every((v) => typeof v === 'number' && Number.isFinite(v) && v >= 0))) &&
    (a.expires_at === undefined || isSafeInt(a.expires_at));
  if (!ok) throw new GrantError('bad_request', 'malformed authority');
}


// ---- pure verification (what a verifier or a native SDK replays; no store, no clock) ------------------------------------

export type Verdict<T> = ({ ok: true } & T) | { ok: false; code: GrantErrorCode };
export interface GrantFacts {
  id: string;
  rev: number;
  principal: string;
  agent: string;
  status: GrantStatus;
  authority: Authority;
}
const authorityOk = (a: unknown): a is Authority => {
  try {
    checkAuthority(a);
    return true;
  } catch {
    return false;
  }
};

/**
 * Decide an amendment against the current grant facts. Check order is normative (vectors pin the code):
 * request shape -> authority shape -> grant active -> classification (`narrow` that changes nothing or widens is
 * `not_narrower`) -> signature (`signature_required`, then `bad_signature`; widening needs the PRINCIPAL) -> step-up for a widening.
 * `stepUpOk` is the already-evaluated step-up verdict (false when none was presented).
 */
export function verifyAmendment(cur: GrantFacts, req: unknown, stepUpOk: boolean, cmp: AuthorityCompare = compareAuthority): Verdict<{ widens: boolean; next: Authority }> {
  if (!isObj(req) || !['narrow', 'merge', 'replace'].includes(req.action as string)) return { ok: false, code: 'bad_request' };
  const r = req as unknown as AmendRequest;
  if (!authorityOk(r.authority)) return { ok: false, code: 'bad_request' };
  if (cur.status !== 'active') return { ok: false, code: 'not_active' };
  const next = r.action === 'merge' ? mergeAuthority(cur.authority, r.authority) : r.authority;
  const order = cmp(cur.authority, next);
  const widens = order === 'wider' || order === 'incomparable';
  if (!widens && r.action === 'narrow' && order === 'equal') return { ok: false, code: 'not_narrower' };
  if (widens && r.action === 'narrow') return { ok: false, code: 'not_narrower' };
  if (typeof r.sig !== 'string' || (r.signed_by !== 'holder' && r.signed_by !== 'principal')) return { ok: false, code: 'signature_required' };
  if (widens && r.signed_by !== 'principal') return { ok: false, code: 'signature_required' };
  const signer = r.signed_by === 'principal' ? cur.principal : cur.agent;
  if (!verifyBody(GRANT_AMEND_DOMAIN, amendMessage(cur, r.action, r.authority), signer, r.sig)) return { ok: false, code: 'bad_signature' };
  if (widens && !stepUpOk) return { ok: false, code: 'step_up_required' };
  return { ok: true, widens, next };
}

/** Decide a revocation's authority: the principal's signature over (grant id, scope). Admin authority is the host's, not a wire fact. */
export function verifyRevokeSignature(root: Pick<GrantFacts, 'id' | 'principal'>, scope: unknown, sig: unknown): Verdict<{ scope: RevokeScope }> {
  if (scope !== 'grant' && scope !== 'agent' && scope !== 'subtree') return { ok: false, code: 'bad_request' };
  if (!verifyBody(GRANT_REVOKE_DOMAIN, grantRevokeMessage(root.id, scope), root.principal, sig)) return { ok: false, code: 'bad_signature' };
  return { ok: true, scope };
}

/**
 * Decide a needs approval: principal signature over (need, grant, rev, approved) -> same count -> each approved need names the same
 * verb and resource, amounts only LOWERED and only when `adjustable` -> step-up. Yields the merged authority.
 */
export function verifyNeedApproval(nr: Pick<NeedRequest, 'id' | 'grant_id' | 'needs' | 'status'>, g: GrantFacts, approved: Need[], sig: unknown, stepUpOk: boolean): Verdict<{ authority: Authority }> {
  if (nr.status !== 'pending') return { ok: false, code: 'conflict' };
  if (!verifyBody(NEED_APPROVE_DOMAIN, needApproveMessage(nr, g.rev, approved), g.principal, sig)) return { ok: false, code: 'bad_signature' };
  if (!Array.isArray(approved) || approved.length !== nr.needs.length) return { ok: false, code: 'need_not_lowered_only' };
  const delta: Authority = { verbs: [], resources: [], limits: {} };
  for (let i = 0; i < approved.length; i++) {
    const a = approved[i]!;
    const want = nr.needs[i]!;
    if (a.verb !== want.verb || a.resource !== want.resource) return { ok: false, code: 'need_not_lowered_only' };
    for (const [k, v] of Object.entries(a.limits ?? {})) {
      const w = want.limits?.[k];
      if (w === undefined || v > w) return { ok: false, code: 'need_not_lowered_only' };
      if (v < w && !want.adjustable) return { ok: false, code: 'need_not_adjustable' };
    }
    delta.verbs.push(a.verb);
    delta.resources.push(a.resource);
    // A limit the need names but the principal omitted is not granted at all (omission is the lowest amount).
    for (const [k, v] of Object.entries(a.limits ?? {})) delta.limits![k] = Math.max(delta.limits![k] ?? 0, v);
  }
  if (!Object.keys(delta.limits!).length) delete delta.limits;
  if (!stepUpOk) return { ok: false, code: 'step_up_required' };
  return { ok: true, authority: mergeAuthority(g.authority, delta) };
}

const FAIL_MESSAGE: Record<GrantErrorCode, string> = {
  not_found: 'no such grant', conflict: 'conflict', bad_request: 'malformed request', not_narrower: 'a narrow amendment must be strictly narrower',
  signature_required: 'the amendment is signed (by the principal when it widens)', bad_signature: 'the signature does not verify for this grant revision',
  step_up_required: 'widening needs a satisfied step-up', not_active: 'grant is not active', need_not_lowered_only: 'an approval may only lower amounts of the requested needs',
  need_not_adjustable: 'the need is not adjustable', forbidden: 'not authorised',
};

export interface GrantServiceOptions {
  store: GrantStore;
  now: () => number;
  newId: (kind: 'grant' | 'need') => string;
  compare?: AuthorityCompare;
  providers?: GrantProviders;
  /** Confirms a satisfied step-up for a widening change. Absent: widening is refused (fail closed). */
  verifyStepUp?: (ref: string, grant: GrantRecord) => boolean | Promise<boolean>;
  /** Registry + event hook: revoke the chains and emit the SSF event. Called with every grant id revoked. */
  onRevoke?: (ids: string[], scope: RevokeScope, root: GrantRecord) => void | Promise<void>;
  /** Called on every state change (the host advances its consistency token here). */
  onChange?: (kind: 'amend' | 'revoke' | 'supersede' | 'need', g: GrantRecord) => void | Promise<void>;
  /** Optional typed validation of a need against the action schema. Return an error string to refuse. */
  validateNeed?: (n: Need) => string | null;
}
export type RevokeScope = 'grant' | 'agent' | 'subtree';
export interface ListFilter {
  principal?: string;
  agent?: string;
  status?: GrantStatus;
  limit?: number;
  cursor?: string;
}

export class GrantService {
  private readonly cmp: AuthorityCompare;
  constructor(private readonly o: GrantServiceOptions) {
    this.cmp = o.compare ?? compareAuthority;
  }

  /** Create a grant record (the host calls this when a grant is registered). */
  async register(g: Omit<GrantRecord, 'rev' | 'status' | 'history' | 'created_at'> & { status?: GrantStatus }): Promise<GrantRecord> {
    checkAuthority(g.authority);
    if (await this.o.store.get(g.id)) throw new GrantError('conflict', 'grant id exists');
    const now = this.o.now();
    const rec: GrantRecord = { ...g, status: g.status ?? 'active', rev: 1, created_at: now, history: [{ rev: 1, authority_digest: authorityDigest(g.authority), at: now, action: 'create' }] };
    await this.o.store.put(rec);
    return rec;
  }

  async list(f: ListFilter = {}): Promise<{ grants: GrantView[]; next_cursor?: string }> {
    const limit = Math.min(Math.max(f.limit ?? 50, 1), 200);
    const all = (await this.o.store.list())
      .filter((g) => (f.principal === undefined || g.principal === f.principal) && (f.agent === undefined || g.agent === f.agent) && (f.status === undefined || g.status === f.status))
      .sort((a, b) => (a.id < b.id ? -1 : 1))
      .filter((g) => f.cursor === undefined || g.id > f.cursor);
    const page = all.slice(0, limit);
    const views = await Promise.all(page.map((g) => this.view(g, false)));
    return { grants: views, ...(all.length > limit ? { next_cursor: page[page.length - 1]!.id } : {}) };
  }

  async inspect(id: string): Promise<GrantView> {
    return this.view(await this.must(id), true);
  }

  private async view(g: GrantRecord, rich: boolean): Promise<GrantView> {
    const { history: _h, ...rest } = g;
    const p = this.o.providers;
    const needs = (await this.o.store.listNeeds(g.id)).filter((n) => n.status === 'pending').map((n) => n.id);
    return {
      ...rest, authority_digest: authorityDigest(g.authority), pending_needs: needs,
      ...(rich && p?.usage ? { usage: await p.usage(g) } : {}),
      ...(rich && p?.remainingBudget ? { remaining_budget: await p.remainingBudget(g) } : {}),
      ...(rich && p?.policyCard ? { policy_card: await p.policyCard(g) } : {}),
      ...(rich && p?.residual ? { residual: await p.residual(g) } : {}),
    };
  }

  private async must(id: string): Promise<GrantRecord> {
    const g = await this.o.store.get(id);
    if (!g) throw new GrantError('not_found', 'no such grant');
    return g;
  }

  async amend(id: string, req: AmendRequest): Promise<{ grant: GrantView; created: boolean }> {
    const cur = await this.must(id);
    let v = verifyAmendment(cur, req, false, this.cmp);
    // Evaluate the (possibly consuming) step-up only when everything else already passed.
    if (!v.ok && v.code === 'step_up_required' && req.step_up_ref && this.o.verifyStepUp && (await this.o.verifyStepUp(req.step_up_ref, cur))) v = verifyAmendment(cur, req, true, this.cmp);
    if (!v.ok) throw new GrantError(v.code, FAIL_MESSAGE[v.code]);
    const now = this.o.now();
    if (!v.widens) {
      cur.authority = v.next;
      cur.rev += 1;
      cur.history.push({ rev: cur.rev, authority_digest: authorityDigest(v.next), at: now, action: req.action });
      await this.o.store.put(cur);
      await this.o.onChange?.('amend', cur);
      return { grant: await this.view(cur, true), created: false };
    }
    const nid = this.o.newId('grant');
    const fresh: GrantRecord = {
      ...cur, id: nid, authority: v.next, rev: 1, status: 'active', supersedes: cur.id, created_at: now,
      history: [{ rev: 1, authority_digest: authorityDigest(v.next), at: now, action: `supersedes:${cur.id}` }],
    };
    delete fresh.superseded_by;
    cur.status = 'superseded';
    cur.superseded_by = nid;
    await this.o.store.put(fresh);
    await this.o.store.put(cur);
    await this.o.onChange?.('supersede', fresh);
    return { grant: await this.view(fresh, true), created: true };
  }

  /**
   * Revoke. Authorised by the principal's signature over {grant id, scope} OR by a host-authenticated admin (`admin: true`;
   * the host has already checked its own credential). `agent` revokes every active grant of the grant's agent; `subtree`
   * the grant and every descendant by `parent`.
   */
  async revoke(id: string, scope: RevokeScope, auth: { sig: string } | { admin: true }): Promise<{ revoked: string[] }> {
    if (!['grant', 'agent', 'subtree'].includes(scope)) throw new GrantError('bad_request', 'unknown scope');
    const root = await this.must(id);
    if ('sig' in auth) {
      const rv = verifyRevokeSignature(root, scope, auth.sig);
      if (!rv.ok) throw new GrantError(rv.code, FAIL_MESSAGE[rv.code]);
    } else if (auth.admin !== true) throw new GrantError('forbidden', 'not authorised');
    const all = await this.o.store.list();
    let hit: GrantRecord[];
    if (scope === 'grant') hit = [root];
    else if (scope === 'agent') hit = all.filter((g) => g.agent === root.agent && g.principal === root.principal);
    else {
      const ids = new Set([id]);
      for (let grew = true; grew; ) {
        grew = false;
        for (const g of all) if (g.parent !== undefined && ids.has(g.parent) && !ids.has(g.id)) { ids.add(g.id); grew = true; }
      }
      hit = all.filter((g) => ids.has(g.id));
    }
    const revoked: string[] = [];
    for (const g of hit) {
      if (g.status === 'revoked') continue;
      g.status = 'revoked';
      g.history.push({ rev: g.rev, authority_digest: authorityDigest(g.authority), at: this.o.now(), action: `revoke:${scope}` });
      await this.o.store.put(g);
      revoked.push(g.id);
    }
    await this.o.onRevoke?.(revoked, scope, root);
    await this.o.onChange?.('revoke', root);
    return { revoked };
  }

  /** Agent side: ask for more. Typed needs only (validated); no authority changes until the principal approves. */
  async requestNeeds(grantId: string, needs: Need[]): Promise<NeedRequest> {
    const g = await this.must(grantId);
    if (g.status !== 'active') throw new GrantError('not_active', `grant is ${g.status}`);
    if (!Array.isArray(needs) || needs.length < 1 || needs.length > 32) throw new GrantError('bad_request', '1..32 needs');
    for (const n of needs) {
      if (!isObj(n) || !isStr(n.verb, 128) || !isStr(n.resource, 512) || (n.limits !== undefined && !(isObj(n.limits) && Object.values(n.limits).every((v) => typeof v === 'number' && Number.isFinite(v) && v >= 0)))) throw new GrantError('bad_request', 'malformed need');
      const e = this.o.validateNeed?.(n);
      if (e) throw new GrantError('bad_request', e);
    }
    const nr: NeedRequest = { id: this.o.newId('need'), grant_id: grantId, needs: structuredClone(needs), status: 'pending', created_at: this.o.now() };
    await this.o.store.putNeed(nr);
    await this.o.onChange?.('need', g);
    return nr;
  }

  /**
   * Principal side: approve the delta. `approved` must cover the same needs in order; for each, amounts may only be LOWERED
   * and only when the need is `adjustable`. The principal signs {@link needApproveMessage}; the result is a widening merge.
   */
  async approveNeeds(needId: string, approved: Need[], sig: string, stepUpRef?: string): Promise<{ grant: GrantView; created: boolean }> {
    const nr = await this.o.store.getNeed(needId);
    if (!nr) throw new GrantError('not_found', 'no such need request');
    if (nr.status !== 'pending') throw new GrantError('conflict', `need request is ${nr.status}`);
    const g = await this.must(nr.grant_id);
    let v = verifyNeedApproval(nr, g, approved, sig, false);
    if (!v.ok && v.code === 'step_up_required' && stepUpRef && this.o.verifyStepUp && (await this.o.verifyStepUp(stepUpRef, g))) v = verifyNeedApproval(nr, g, approved, sig, true);
    if (!v.ok) throw new GrantError(v.code, FAIL_MESSAGE[v.code]);
    const authority = v.authority;
    const nid = this.o.newId('grant');
    const now = this.o.now();
    const fresh: GrantRecord = { ...g, id: nid, authority, rev: 1, status: 'active', supersedes: g.id, created_at: now, history: [{ rev: 1, authority_digest: authorityDigest(authority), at: now, action: `needs:${needId}` }] };
    delete fresh.superseded_by;
    g.status = 'superseded';
    g.superseded_by = nid;
    nr.status = 'approved';
    nr.result_grant_id = nid;
    await this.o.store.put(fresh);
    await this.o.store.put(g);
    await this.o.store.putNeed(nr);
    await this.o.onChange?.('supersede', fresh);
    return { grant: await this.view(fresh, true), created: true };
  }

  /** The grant a need request belongs to (the HTTP binding uses it to scope a caller to its own grants). */
  async needGrantId(needId: string): Promise<string> {
    const nr = await this.o.store.getNeed(needId);
    if (!nr) throw new GrantError('not_found', 'no such need request');
    return nr.grant_id;
  }

  async denyNeeds(needId: string): Promise<void> {
    const nr = await this.o.store.getNeed(needId);
    if (!nr) throw new GrantError('not_found', 'no such need request');
    if (nr.status !== 'pending') throw new GrantError('conflict', `need request is ${nr.status}`);
    nr.status = 'denied';
    await this.o.store.putNeed(nr);
  }
}
export const needRequestMessage = (grantId: string, rev: number, needs: Need[]) => ({ grant: grantId, rev, needs });
export const stepUpMessage = (grantId: string, challengeId: string, nonce: string) => ({ grant: grantId, challenge: challengeId, nonce });
export const grantRevokeMessage = (id: string, scope: RevokeScope) => ({ grant: id, scope });
export const needApproveMessage = (nr: Pick<NeedRequest, 'id' | 'grant_id'>, rev: number, approved: Need[]) => ({ need: nr.id, grant: nr.grant_id, rev, approved });
export { signBody as signGrantBody };
