import { isObj, isSafeInt, isStr, signBody, signerOf, verifyBody } from './sig';
import { shardOf, DEFAULT_LEASE_SHARDS, MAX_LEASE_SHARDS, type LeaseKv } from './lease';

/**
 * BREAK-GLASS GRANTS. A pre-authorized, sealed, small-budget, short-lived grant for an emergency, with a mandatory review after
 * the fact. Nothing about it is quiet and nothing about it lasts:
 *  - TIME-BOXED: `expires_at` is at most 24 hours after `issued_at` (checked on signing, verifying and use), and `max_uses` is 1 to 16.
 *  - LOUD: a use is recorded only when the enforcement point reports that it delivered the `notify_to` notification (`notified:
 *    true`); without it the use is refused. Every use is a numbered, timestamped entry bound to the action digest.
 *  - AUTO-REVOKED: past `expires_at`, past `max_uses`, after an `unjustified` review, and for the holder while a review is overdue.
 *  - MANDATORY REVIEW: the first use starts a clock (`review_within`); until a signed review exists, once the clock runs out the
 *    HOLDER IS FROZEN (no use of any of their break-glass grants, no new one). An `unjustified` outcome freezes the holder for good.
 *    The reviewer is a pinned key that is neither the holder nor the issuing authority. The first review of a grant is final.
 *  - REASON: `reason_digest` binds the stated reason into the signed record (the text is display-only).
 * This module gates; it never verifies the grant `grant_ref` names. State is sharded by holder over the same key-value contract as
 * leases, so a holder's grants, uses, reviews and freeze status are one atomic document.
 */
export const BREAK_GLASS_DOMAIN = 'atlas-pca/break-glass/v1\0';
export const BREAK_GLASS_REVIEW_DOMAIN = 'atlas-pca/break-glass-review/v1\0';
export const MAX_BREAK_GLASS_WINDOW_MS = 86_400_000;
export const MAX_BREAK_GLASS_USES = 16;
export const MAX_REVIEW_WITHIN_MS = 30 * 86_400_000;

export interface BreakGlass {
  v: 1;
  id: string;
  holder: string;
  /** The sealed, pre-authorized grant (chain digest) this emergency access exercises. */
  grant_ref: string;
  reason_digest: string;
  max_uses: number;
  issued_at: number;
  expires_at: number;
  /** Milliseconds from the first use within which a signed review must exist. */
  review_within: number;
  /** Who must be told on every use (a channel or principal id). */
  notify_to: string;
  authority: string;
  sig: string;
}
export type NewBreakGlass = Omit<BreakGlass, 'v' | 'sig' | 'authority'>;
const bgBody = (b: Omit<BreakGlass, 'sig'>) => ({
  v: b.v, id: b.id, holder: b.holder, grant_ref: b.grant_ref, reason_digest: b.reason_digest, max_uses: b.max_uses, issued_at: b.issued_at,
  expires_at: b.expires_at, review_within: b.review_within, notify_to: b.notify_to, authority: b.authority,
});
function bgWellFormed(b: unknown): b is Omit<BreakGlass, 'sig'> {
  if (!isObj(b) || b.v !== 1 || !isStr(b.id, 128) || !isStr(b.holder, 128) || !isStr(b.grant_ref, 256) || !isStr(b.reason_digest, 128) || !isStr(b.notify_to, 256) || !isStr(b.authority, 128)) return false;
  if (!isSafeInt(b.max_uses) || b.max_uses < 1 || b.max_uses > MAX_BREAK_GLASS_USES) return false;
  if (!isSafeInt(b.issued_at) || !isSafeInt(b.expires_at) || b.expires_at <= b.issued_at || b.expires_at - b.issued_at > MAX_BREAK_GLASS_WINDOW_MS) return false;
  return isSafeInt(b.review_within) && b.review_within >= 1 && b.review_within <= MAX_REVIEW_WITHIN_MS;
}
export function signBreakGlass(secret: Uint8Array, b: NewBreakGlass): BreakGlass {
  const base = { v: 1 as const, ...b, authority: signerOf(secret) };
  if (!bgWellFormed(base)) throw new RangeError('signBreakGlass: malformed, or the window is longer than 24 hours, or the budget is outside 1..16');
  return { ...base, sig: signBody(BREAK_GLASS_DOMAIN, bgBody(base), secret) };
}
export function verifyBreakGlass(b: unknown): b is BreakGlass {
  if (!bgWellFormed(b)) return false;
  const { sig, ...rest } = b as BreakGlass;
  return verifyBody(BREAK_GLASS_DOMAIN, bgBody(rest), rest.authority, sig);
}

export type ReviewOutcome = 'justified' | 'unjustified';
export interface BreakGlassReview { v: 1; id: string; outcome: ReviewOutcome; notes_digest: string; at: number; reviewer: string; sig: string }
const rvBody = (r: Omit<BreakGlassReview, 'sig'>) => ({ v: r.v, id: r.id, outcome: r.outcome, notes_digest: r.notes_digest, at: r.at, reviewer: r.reviewer });
function rvWellFormed(r: unknown): r is Omit<BreakGlassReview, 'sig'> {
  return isObj(r) && r.v === 1 && isStr(r.id, 128) && (r.outcome === 'justified' || r.outcome === 'unjustified') && isStr(r.notes_digest, 128) && isSafeInt(r.at) && isStr(r.reviewer, 128);
}
export function signBreakGlassReview(secret: Uint8Array, r: Pick<BreakGlassReview, 'id' | 'outcome' | 'notes_digest' | 'at'>): BreakGlassReview {
  const base = { v: 1 as const, ...r, reviewer: signerOf(secret) };
  if (!rvWellFormed(base)) throw new RangeError('signBreakGlassReview: malformed');
  return { ...base, sig: signBody(BREAK_GLASS_REVIEW_DOMAIN, rvBody(base), secret) };
}
export function verifyBreakGlassReview(r: unknown): r is BreakGlassReview {
  if (!rvWellFormed(r)) return false;
  const { sig, ...rest } = r as BreakGlassReview;
  return verifyBody(BREAK_GLASS_REVIEW_DOMAIN, rvBody(rest), rest.reviewer, sig);
}

export interface BreakGlassPolicy {
  /** Keys that may issue break-glass records. */
  authorities: readonly string[];
  /** Keys that may sign reviews. */
  reviewers: readonly string[];
}
export interface BreakGlassUseEntry { n: number; action_digest: string; at: number }
interface BgEntry { rec: BreakGlass; uses: BreakGlassUseEntry[]; review?: BreakGlassReview }
interface BgShard { grants: Record<string, BgEntry> }
const bgKey = (n: number, i: number): string => `breakglass/${n}/${i}`;
const loadShard = (x: unknown): BgShard => (isObj(x) && isObj(x.grants) ? (x as unknown as BgShard) : { grants: {} });
const ownE = (m: Record<string, BgEntry>, id: string): BgEntry | undefined => (Object.prototype.hasOwnProperty.call(m, id) ? m[id] : undefined);

export type BgAcceptCode = 'bad_record' | 'unknown_authority' | 'id_conflict' | 'holder_frozen' | 'store_unreachable';
export type BgReviewCode = 'bad_record' | 'unknown_reviewer' | 'sod' | 'unknown_break_glass' | 'nothing_to_review' | 'already_reviewed' | 'bad_time' | 'store_unreachable';
export type BgUseCode = 'bad_input' | 'unknown_break_glass' | 'wrong_holder' | 'holder_frozen' | 'revoked' | 'not_yet_valid' | 'expired' | 'budget_exhausted' | 'not_notified' | 'store_unreachable';
export type BgUseDecision =
  | { decision: 'allow'; id: string; use: number; remaining: number; review_due: number }
  | { decision: 'deny'; code: BgUseCode; id?: string };

/** Frozen: a grant of this holder was judged unjustified, or has uses, no review and a review clock that has run out. */
function frozenIn(st: BgShard, holder: string, now: number): boolean {
  return Object.values(st.grants).some((e) => e.rec.holder === holder && (e.review?.outcome === 'unjustified' || (e.review === undefined && e.uses.length > 0 && now >= (e.uses[0] as BreakGlassUseEntry).at + e.rec.review_within)));
}

export class BreakGlassRegistry {
  private readonly shards: number;
  private metaOk: Promise<boolean> | undefined;
  constructor(private readonly policy: BreakGlassPolicy, private readonly kv: LeaseKv, o: { shards?: number } = {}) {
    if (typeof kv?.get !== 'function' || typeof kv?.update !== 'function') throw new TypeError('BreakGlassRegistry: a durable key-value store is required (memoryLeaseKv() is for tests and single-process use)');
    const n = o.shards ?? DEFAULT_LEASE_SHARDS;
    if (!Number.isSafeInteger(n) || n < 1 || n > MAX_LEASE_SHARDS) throw new RangeError('BreakGlassRegistry: shards must be an integer from 1 to 4096');
    this.shards = n;
  }
  private ready(): Promise<boolean> {
    this.metaOk ??= this.kv.update('breakglass/meta', (prev) => (prev === undefined ? { v: 1, shards: this.shards } : undefined)).then((m) => isObj(m) && m.shards === this.shards);
    return this.metaOk;
  }
  private key(holder: string): string { return bgKey(this.shards, shardOf(holder, this.shards)); }

  /** Register an issued record. A frozen holder gets no new one. */
  async accept(rec: unknown, now: number): Promise<{ ok: true; replaced: boolean } | { ok: false; code: BgAcceptCode }> {
    if (!verifyBreakGlass(rec) || !isSafeInt(now)) return { ok: false, code: 'bad_record' };
    if (!this.policy.authorities.includes(rec.authority)) return { ok: false, code: 'unknown_authority' };
    let out: { ok: true; replaced: boolean } | { ok: false; code: BgAcceptCode } = { ok: false, code: 'store_unreachable' };
    try {
      if (!(await this.ready())) return out;
      await this.kv.update(this.key(rec.holder), (prev) => {
        const st = loadShard(prev);
        const cur = ownE(st.grants, rec.id);
        if (cur !== undefined) { out = cur.rec.sig === rec.sig ? { ok: true, replaced: false } : { ok: false, code: 'id_conflict' }; return undefined; }
        if (frozenIn(st, rec.holder, now)) { out = { ok: false, code: 'holder_frozen' }; return undefined; }
        st.grants[rec.id] = { rec, uses: [] };
        out = { ok: true, replaced: true };
        return st;
      });
    } catch { return { ok: false, code: 'store_unreachable' }; }
    return out;
  }

  /**
   * Record one use. `notified` must be true: the enforcement point has delivered the notification to `notify_to` before acting.
   * Checks in order: input, existence, holder, freeze, revocation by review, window, budget, notification.
   */
  async use(i: { id: string; holder: string; action_digest: string; now: number; notified: boolean }): Promise<BgUseDecision> {
    if (!isStr(i?.id, 128) || !isStr(i.holder, 128) || !isStr(i.action_digest, 128) || !isSafeInt(i.now) || typeof i.notified !== 'boolean') return { decision: 'deny', code: 'bad_input' };
    let out: BgUseDecision = { decision: 'deny', code: 'store_unreachable', id: i.id };
    const deny = (code: BgUseCode): undefined => { out = { decision: 'deny', code, id: i.id }; return undefined; };
    try {
      if (!(await this.ready())) return out;
      await this.kv.update(this.key(i.holder), (prev) => {
        const st = loadShard(prev);
        const e = ownE(st.grants, i.id);
        if (e === undefined) return deny('unknown_break_glass');
        if (e.rec.holder !== i.holder) return deny('wrong_holder');
        if (frozenIn(st, i.holder, i.now)) return deny('holder_frozen');
        if (e.review?.outcome === 'unjustified') return deny('revoked');
        if (i.now < e.rec.issued_at) return deny('not_yet_valid');
        if (i.now >= e.rec.expires_at) return deny('expired');
        if (e.uses.length >= e.rec.max_uses) return deny('budget_exhausted');
        if (i.notified !== true) return deny('not_notified');
        e.uses.push({ n: e.uses.length + 1, action_digest: i.action_digest, at: i.now });
        out = { decision: 'allow', id: i.id, use: e.uses.length, remaining: e.rec.max_uses - e.uses.length, review_due: (e.uses[0] as BreakGlassUseEntry).at + e.rec.review_within };
        return st;
      });
    } catch { return { decision: 'deny', code: 'store_unreachable', id: i.id }; }
    return out;
  }

  /** Record the signed review. The first review of a grant is final; a review may be late (it then lifts an overdue freeze). */
  async review(rec: unknown, holder: string, now: number): Promise<{ ok: true; replaced: boolean } | { ok: false; code: BgReviewCode }> {
    if (!verifyBreakGlassReview(rec) || !isStr(holder, 128) || !isSafeInt(now)) return { ok: false, code: 'bad_record' };
    if (!this.policy.reviewers.includes(rec.reviewer)) return { ok: false, code: 'unknown_reviewer' };
    let out: { ok: true; replaced: boolean } | { ok: false; code: BgReviewCode } = { ok: false, code: 'store_unreachable' };
    try {
      if (!(await this.ready())) return out;
      await this.kv.update(this.key(holder), (prev) => {
        const st = loadShard(prev);
        const e = ownE(st.grants, rec.id);
        const fail = (code: BgReviewCode): undefined => { out = { ok: false, code }; return undefined; };
        if (e === undefined || e.rec.holder !== holder) return fail('unknown_break_glass');
        if (rec.reviewer === e.rec.holder || rec.reviewer === e.rec.authority) return fail('sod');
        if (e.review !== undefined) { if (e.review.sig === rec.sig) { out = { ok: true, replaced: false }; return undefined; } return fail('already_reviewed'); }
        if (e.uses.length === 0) return fail('nothing_to_review');
        if (rec.at < (e.uses[0] as BreakGlassUseEntry).at || rec.at > now) return fail('bad_time');
        e.review = rec;
        out = { ok: true, replaced: true };
        return st;
      });
    } catch { return { ok: false, code: 'store_unreachable' }; }
    return out;
  }

  async frozen(holder: string, now: number): Promise<boolean> {
    if (!isStr(holder, 128) || !isSafeInt(now)) return true; // fail closed
    try {
      if (!(await this.ready())) return true;
      return frozenIn(loadShard(await this.kv.get(this.key(holder))), holder, now);
    } catch { return true; }
  }
  /** The numbered use log of a grant, oldest first. */
  async uses(holder: string, id: string): Promise<BreakGlassUseEntry[]> {
    if (!(await this.ready())) return [];
    return ownE(loadShard(await this.kv.get(this.key(holder))).grants, id)?.uses.map((u) => ({ ...u })) ?? [];
  }
}
