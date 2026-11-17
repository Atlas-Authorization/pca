import { sha256, utf8 } from '@atlasauth/pca';
import { isObj, isSafeInt, isStr, signBody, signerOf, verifyBody } from './sig';

/**
 * LEASES (the Vault lease model, made verifiable): a time-boxed grant or credential that must be renewed to stay alive, has a
 * hard `max_ttl` it can never outlive, and dies at once when revoked.
 *
 * A lease authority signs a {@link Lease} record. The verifier keeps the newest record per `lease_id` ({@link LeaseRegistry}).
 *  - RENEWAL is a new record with the same identity, `seq + 1`, a strictly later `expires_at`, never past
 *    `issued_at + max_ttl` (the cap runs from first issue and cannot be moved). An expired, revoked or superseded lease cannot be
 *    renewed. With `freshJustification` (default) the renewal's `justification_digest` must differ from the previous one: a
 *    renewal needs a new reason, not a replay of the old one. The reason text is display-only; the digest binds it.
 *  - SEPARATION OF DUTIES: the approvers named on a record must be distinct, must not include the requester or the holder, must
 *    not appear in the holder's delegation chain (`chain` given to `accept`), must be drawn from `eligibleApprovers` when that is
 *    pinned, and must number at least `minApprovals` (k of n). Checked on every issue and every renewal.
 *  - REVOKE by lease id, by path prefix (a segment boundary: `db/prod` covers `db/prod` and `db/prod/ro`, never `db/production`),
 *    or by grant (revoking a grant revokes the leases made from it). A revocation covers leases issued at or before its
 *    `revoked_at`; a lease issued after it is a new lease. Revocation blocks renewal for good.
 *  - Automatic renewal ({@link renewLease}) may be VETOED by a caller-supplied signal check but is never extended by one.
 *
 * `checkLease` only gates; it never verifies the grant or the PCActn the lease was made from.
 */
export const LEASE_DOMAIN = 'atlas-pca/lease/v1\0';
export const LEASE_REVOKE_DOMAIN = 'atlas-pca/lease-revoke/v1\0';
const MAX_APPROVERS = 16;
const PATH_RE = /^[a-z0-9_.-]{1,64}(\/[a-z0-9_.-]{1,64}){0,7}$/;

export interface Lease {
  v: 1;
  lease_id: string;
  /** Slash-separated lease path, the unit of revoke-by-prefix. */
  path: string;
  /** The grant (chain digest) the lease is made from. */
  grant_ref: string;
  holder: string;
  requester: string;
  approvers: string[];
  /** Digest of the reason given for this issue or renewal. */
  justification_digest: string;
  /** 1 on issue, +1 on each renewal. */
  seq: number;
  /** First issue time (fixed for the life of the lease). */
  issued_at: number;
  /** Time of this record (issue time for seq 1). */
  renewed_at: number;
  expires_at: number;
  /** Milliseconds from `issued_at` after which the lease can never be alive, however often it is renewed. */
  max_ttl: number;
  authority: string;
  sig: string;
}
export type NewLease = Omit<Lease, 'v' | 'sig' | 'authority'>;

const bodyOf = (l: Omit<Lease, 'sig'>) => ({
  v: l.v, lease_id: l.lease_id, path: l.path, grant_ref: l.grant_ref, holder: l.holder, requester: l.requester, approvers: l.approvers,
  justification_digest: l.justification_digest, seq: l.seq, issued_at: l.issued_at, renewed_at: l.renewed_at, expires_at: l.expires_at,
  max_ttl: l.max_ttl, authority: l.authority,
});

export const leaseCap = (l: Pick<Lease, 'issued_at' | 'max_ttl'>): number => l.issued_at + l.max_ttl;

function wellFormed(l: unknown): l is Omit<Lease, 'sig'> {
  if (!isObj(l) || l.v !== 1 || !isStr(l.lease_id, 128) || !isStr(l.grant_ref, 256) || !isStr(l.holder, 128) || !isStr(l.requester, 128)) return false;
  if (!isStr(l.authority, 128) || !isStr(l.justification_digest, 128) || typeof l.path !== 'string' || !PATH_RE.test(l.path)) return false;
  if (!isSafeInt(l.seq) || l.seq < 1 || !isSafeInt(l.issued_at) || !isSafeInt(l.renewed_at) || !isSafeInt(l.expires_at) || !isSafeInt(l.max_ttl) || l.max_ttl < 1) return false;
  if (l.renewed_at < l.issued_at || l.expires_at <= l.renewed_at || (l.seq === 1 && l.renewed_at !== l.issued_at)) return false;
  return Array.isArray(l.approvers) && l.approvers.length <= MAX_APPROVERS && l.approvers.every((a) => isStr(a, 128));
}

/** Sign a lease record. Throws on a malformed record or one that outlives its cap. */
export function signLease(secret: Uint8Array, l: NewLease): Lease {
  const base = { v: 1 as const, ...l, authority: signerOf(secret) };
  if (!wellFormed(base) || base.expires_at > leaseCap(base)) throw new RangeError('signLease: a malformed lease, or one past issued_at + max_ttl');
  return { ...base, sig: signBody(LEASE_DOMAIN, bodyOf(base), secret) };
}

/** Conformance-vector builder only: signs a record that outlives its cap, to prove verifiers refuse it. Never use in production. */
export function signLeaseUnsafeOverCap(secret: Uint8Array, l: NewLease): Lease {
  const base = { v: 1 as const, ...l, authority: signerOf(secret) };
  if (!wellFormed(base)) throw new RangeError('signLeaseUnsafeOverCap: malformed');
  return { ...base, sig: signBody(LEASE_DOMAIN, bodyOf(base), secret) };
}

/** Well formed and signed by its `authority` over exactly its content. Does NOT check the cap (the registry reports `over_max_ttl`). */
export function verifyLease(l: unknown): l is Lease {
  if (!wellFormed(l)) return false;
  const { sig, ...rest } = l as Lease;
  return verifyBody(LEASE_DOMAIN, bodyOf(rest), rest.authority, sig);
}

export type RevokeTarget = 'lease' | 'prefix' | 'grant';
export interface LeaseRevocation {
  v: 1;
  target: RevokeTarget;
  /** A lease id, a path prefix or a grant ref, by `target`. */
  value: string;
  revoked_at: number;
  authority: string;
  sig: string;
}
const revBody = (r: Omit<LeaseRevocation, 'sig'>) => ({ v: r.v, target: r.target, value: r.value, revoked_at: r.revoked_at, authority: r.authority });
function revWellFormed(r: unknown): r is Omit<LeaseRevocation, 'sig'> {
  if (!isObj(r) || r.v !== 1 || !isStr(r.value, 256) || !isStr(r.authority, 128) || !isSafeInt(r.revoked_at)) return false;
  if (r.target !== 'lease' && r.target !== 'prefix' && r.target !== 'grant') return false;
  return r.target !== 'prefix' || (typeof r.value === 'string' && PATH_RE.test(r.value));
}
export function signLeaseRevocation(secret: Uint8Array, r: Pick<LeaseRevocation, 'target' | 'value' | 'revoked_at'>): LeaseRevocation {
  const base = { v: 1 as const, ...r, authority: signerOf(secret) };
  if (!revWellFormed(base)) throw new RangeError('signLeaseRevocation: malformed');
  return { ...base, sig: signBody(LEASE_REVOKE_DOMAIN, revBody(base), secret) };
}
export function verifyLeaseRevocation(r: unknown): r is LeaseRevocation {
  if (!revWellFormed(r)) return false;
  const { sig, ...rest } = r as LeaseRevocation;
  return verifyBody(LEASE_REVOKE_DOMAIN, revBody(rest), rest.authority, sig);
}

/** `prefix` covers `path` iff equal or `path` continues it at a segment boundary. */
export const pathUnder = (path: string, prefix: string): boolean => path === prefix || path.startsWith(`${prefix}/`);
const covers = (r: LeaseRevocation, l: Lease): boolean =>
  l.issued_at <= r.revoked_at && (r.target === 'lease' ? l.lease_id === r.value : r.target === 'grant' ? l.grant_ref === r.value : pathUnder(l.path, r.value));

export interface SodPolicy {
  /** Approvals required (k). Default 1. */
  minApprovals?: number;
  /** Who may approve at all (n). Absent: any key that passes the other rules. */
  eligibleApprovers?: readonly string[];
}
/** Separation of duties over one record. `chain` is every key in the holder's delegation chain. Returns a reason or null. */
export function sodError(l: Pick<Lease, 'requester' | 'holder' | 'approvers'>, p: SodPolicy = {}, chain: readonly string[] = []): string | null {
  const k = p.minApprovals ?? 1;
  if (!Number.isSafeInteger(k) || k < 1) return 'minApprovals must be a positive integer';
  const seen = new Set<string>();
  for (const a of l.approvers) {
    if (seen.has(a)) return 'an approver is listed twice';
    seen.add(a);
    if (a === l.requester) return 'the requester may not approve their own request';
    if (a === l.holder) return 'the holder may not approve its own lease';
    if (chain.includes(a)) return 'an approver appears in the holder\'s delegation chain';
    if (p.eligibleApprovers !== undefined && !p.eligibleApprovers.includes(a)) return 'an approver is not eligible';
  }
  return l.approvers.length < k ? `${l.approvers.length} approver(s), need ${k}` : null;
}

export interface LeasePolicy extends SodPolicy {
  /** Keys whose lease records and revocations this verifier accepts. */
  authorities: readonly string[];
  /** A renewal must carry a justification different from the previous record's. Default true. */
  freshJustification?: boolean;
  /**
   * Longest `max_ttl` (ms) this registry accepts (`ttl_ceiling`). When set, a revocation is pruned once `revoked_at + ceiling` is
   * past (every lease it could cover is then beyond its own cap), which keeps the per-shard revocation list bounded.
   * Absent: no ceiling and nothing is ever pruned.
   */
  maxTtlCeiling?: number;
}

export type LeaseAcceptCode =
  | 'bad_record' | 'unknown_authority' | 'sod' | 'revoked' | 'bad_seq' | 'stale_seq' | 'lease_fork' | 'renewal_mismatch' | 'over_max_ttl'
  | 'ttl_ceiling' | 'not_extending' | 'expired_lease' | 'stale_justification' | 'store_unreachable';
export type LeaseAcceptResult = { ok: true; replaced: boolean; seq: number } | { ok: false; code: LeaseAcceptCode; reason?: string };

/** One ledger line per accepted record (the renewal history of a lease). */
export interface LeaseHistoryEntry { seq: number; renewed_at: number; expires_at: number; justification_digest: string }
interface LeaseState { current: Lease; history: LeaseHistoryEntry[] }
/** One shard's document: the leases whose id hashes here, and every prefix / grant revocation (replicated to all shards). */
export interface LeaseShardState { leases: Record<string, LeaseState>; revocations: LeaseRevocation[] }

/** The durable-state shape (structurally the `DurableKv` of `@atlasauth/pca/durable-state`: pass an opened durable state for crash-safe storage). */
export interface LeaseKv {
  get(key: string): Promise<unknown | undefined>;
  update(key: string, fn: (prev: unknown | undefined) => unknown | undefined): Promise<unknown | undefined>;
}
export function memoryLeaseKv(): LeaseKv {
  const m = new Map<string, string>();
  const dec = (k: string) => { const v = m.get(k); return v === undefined ? undefined : JSON.parse(v); };
  return {
    async get(k) { return dec(k); },
    async update(k, fn) { const n = fn(dec(k)); if (n !== undefined) m.set(k, JSON.stringify(n)); return dec(k); },
  };
}

export const DEFAULT_LEASE_SHARDS = 16;
export const MAX_LEASE_SHARDS = 4096;
const META_KEY = 'lease/meta';
const shardKey = (n: number, i: number): string => `lease/${n}/${i}`;
/** The shard a lease id lives in: the first four bytes of SHA-256 of the id, modulo the shard count. Stable across processes. */
export function shardOf(id: string, shards: number): number {
  const h = sha256(utf8(id));
  return (((h[0] as number) << 24 | (h[1] as number) << 16 | (h[2] as number) << 8 | (h[3] as number)) >>> 0) % shards;
}
const emptyShard = (): LeaseShardState => ({ leases: {}, revocations: [] });
const load = (x: unknown): LeaseShardState => (isObj(x) && isObj(x.leases) && Array.isArray(x.revocations) ? (x as unknown as LeaseShardState) : emptyShard());
const own = (m: Record<string, LeaseState>, id: string): LeaseState | undefined => (Object.prototype.hasOwnProperty.call(m, id) ? m[id] : undefined);

export interface LeaseRegistryOptions {
  /** Number of shards (default 16). Fixed for the life of the store: a store opened with another count is refused. */
  shards?: number;
  /** Clock for revocation pruning (default `Date.now`). */
  clock?: () => number;
}

/**
 * The registry keeps each lease in the shard its id hashes to, so an issue, a renewal and a check read and write one small
 * document, and unrelated leases never contend for one lock or one value-size limit. A path-prefix or grant revocation is written
 * to EVERY shard (it can cover leases anywhere); a revocation of one lease id only to that lease's shard. Within a shard each
 * operation is one atomic update. A fan-out revocation is complete when `revoke` returns; a renewal racing it in a shard not yet
 * written succeeds and is then covered by the revocation when it lands (the check applies revocations to the stored lease).
 */
export class LeaseRegistry {
  private readonly shards: number;
  private readonly clock: () => number;
  private metaOk: Promise<boolean> | undefined;
  constructor(private readonly policy: LeasePolicy, private readonly kv: LeaseKv, o: LeaseRegistryOptions = {}) {
    // The registry holds revocations: a process-local default would forget them on restart, so the store is required.
    if (typeof kv?.get !== 'function' || typeof kv?.update !== 'function') throw new TypeError('LeaseRegistry: a durable key-value store is required (memoryLeaseKv() is for tests and single-process use)');
    const n = o.shards ?? DEFAULT_LEASE_SHARDS;
    if (!Number.isSafeInteger(n) || n < 1 || n > MAX_LEASE_SHARDS) throw new RangeError('LeaseRegistry: shards must be an integer from 1 to 4096');
    if (policy.maxTtlCeiling !== undefined && !(Number.isSafeInteger(policy.maxTtlCeiling) && policy.maxTtlCeiling >= 1)) throw new RangeError('LeaseRegistry: maxTtlCeiling must be a positive integer');
    this.shards = n;
    this.clock = o.clock ?? (() => Date.now());
  }
  get shardCount(): number { return this.shards; }

  /** Pin the shard count in the store on first use; a different count would make existing leases invisible, so it is refused. */
  private ready(): Promise<boolean> {
    this.metaOk ??= this.kv.update(META_KEY, (prev) => (prev === undefined ? { v: 1, shards: this.shards } : undefined)).then((m) => isObj(m) && m.shards === this.shards);
    return this.metaOk;
  }
  private prune(st: LeaseShardState): void {
    const c = this.policy.maxTtlCeiling;
    if (c === undefined) return;
    const now = this.clock();
    st.revocations = st.revocations.filter((r) => r.revoked_at + c >= now);
  }

  /** Take an issue (seq 1) or a renewal (seq = current + 1). `chain`: the keys in the holder's delegation chain, for the SoD rule. */
  async accept(rec: unknown, chain: readonly string[] = []): Promise<LeaseAcceptResult> {
    if (!verifyLease(rec)) return { ok: false, code: 'bad_record' };
    const l = rec;
    if (!this.policy.authorities.includes(l.authority)) return { ok: false, code: 'unknown_authority' };
    const sod = sodError(l, this.policy, chain);
    if (sod !== null) return { ok: false, code: 'sod', reason: sod };
    if (l.expires_at > leaseCap(l)) return { ok: false, code: 'over_max_ttl' };
    if (this.policy.maxTtlCeiling !== undefined && l.max_ttl > this.policy.maxTtlCeiling) return { ok: false, code: 'ttl_ceiling' };
    let out: LeaseAcceptResult = { ok: false, code: 'store_unreachable' };
    try {
      if (!(await this.ready())) return out;
      await this.kv.update(shardKey(this.shards, shardOf(l.lease_id, this.shards)), (prev) => {
        const st = load(prev);
        const cur = own(st.leases, l.lease_id)?.current;
        const fail = (code: LeaseAcceptCode, reason?: string) => { out = { ok: false, code, ...(reason ? { reason } : {}) }; return undefined; };
        if (st.revocations.some((r) => covers(r, l))) return fail('revoked');
        if (cur === undefined) {
          if (l.seq !== 1) return fail('bad_seq', 'a new lease starts at seq 1');
        } else {
          if (l.seq < cur.seq) return fail('stale_seq');
          if (l.seq === cur.seq) { if (cur.sig === l.sig) { out = { ok: true, replaced: false, seq: l.seq }; return undefined; } return fail('lease_fork'); }
          if (l.seq !== cur.seq + 1) return fail('bad_seq', 'renewals advance seq by exactly 1');
          if (l.authority !== cur.authority || l.path !== cur.path || l.grant_ref !== cur.grant_ref || l.holder !== cur.holder || l.requester !== cur.requester || l.max_ttl !== cur.max_ttl || l.issued_at !== cur.issued_at) return fail('renewal_mismatch');
          if (l.renewed_at >= cur.expires_at) return fail('expired_lease', 'an expired lease cannot be renewed');
          if (l.renewed_at < cur.renewed_at || l.expires_at <= cur.expires_at) return fail('not_extending');
          if ((this.policy.freshJustification ?? true) && l.justification_digest === cur.justification_digest) return fail('stale_justification');
        }
        const entry: LeaseHistoryEntry = { seq: l.seq, renewed_at: l.renewed_at, expires_at: l.expires_at, justification_digest: l.justification_digest };
        st.leases[l.lease_id] = { current: l, history: [...(own(st.leases, l.lease_id)?.history ?? []), entry] };
        this.prune(st);
        out = { ok: true, replaced: true, seq: l.seq };
        return st;
      });
    } catch {
      return { ok: false, code: 'store_unreachable' };
    }
    return out;
  }

  /** Take a signed revocation. Idempotent. A prefix or grant revocation is written to every shard; the count is leases covered across all of them. */
  async revoke(rec: unknown): Promise<{ ok: true; revoked: number } | { ok: false; code: 'bad_record' | 'unknown_authority' | 'store_unreachable' }> {
    if (!verifyLeaseRevocation(rec)) return { ok: false, code: 'bad_record' };
    if (!this.policy.authorities.includes(rec.authority)) return { ok: false, code: 'unknown_authority' };
    const targets = rec.target === 'lease' ? [shardOf(rec.value, this.shards)] : Array.from({ length: this.shards }, (_, i) => i);
    let n = 0;
    try {
      if (!(await this.ready())) return { ok: false, code: 'store_unreachable' };
      for (const i of targets) {
        await this.kv.update(shardKey(this.shards, i), (prev) => {
          const st = load(prev);
          if (!st.revocations.some((r) => r.sig === rec.sig)) st.revocations.push(rec);
          n += Object.values(st.leases).filter((s) => covers(rec, s.current)).length;
          this.prune(st);
          return st;
        });
      }
    } catch {
      return { ok: false, code: 'store_unreachable' };
    }
    return { ok: true, revoked: n };
  }

  private async shard(id: string): Promise<LeaseShardState> {
    if (!(await this.ready())) throw new Error('shard count mismatch');
    return load(await this.kv.get(shardKey(this.shards, shardOf(id, this.shards))));
  }
  async get(id: string): Promise<Lease | undefined> { return own((await this.shard(id)).leases, id)?.current; }
  /** The renewal ledger of a lease, oldest first. */
  async history(id: string): Promise<LeaseHistoryEntry[]> { return own((await this.shard(id)).leases, id)?.history ?? []; }
  /** The newest record of a lease and whether a stored revocation covers it. */
  async lookup(id: string): Promise<{ current: Lease; revoked: boolean } | undefined> {
    const st = await this.shard(id);
    const cur = own(st.leases, id)?.current;
    return cur === undefined ? undefined : { current: cur, revoked: st.revocations.some((r) => covers(r, cur)) };
  }
  /** Revocations held by one shard (for operators and the conformance kit). */
  async shardRevocations(i: number): Promise<LeaseRevocation[]> {
    if (!Number.isSafeInteger(i) || i < 0 || i >= this.shards) throw new RangeError('no such shard');
    return load(await this.kv.get(shardKey(this.shards, i))).revocations;
  }
}

export type LeaseDenyCode = 'bad_input' | 'unknown_lease' | 'superseded' | 'not_yet_valid' | 'expired' | 'past_max_ttl' | 'revoked' | 'bad_record' | 'store_unreachable';
export type LeaseDecision = { decision: 'allow'; lease_id: string; expires_at: number } | { decision: 'deny'; code: LeaseDenyCode; lease_id?: string };

/**
 * Is `presented` a live lease? It must verify, be the newest record the registry holds (a superseded record is refused even if
 * its window is still open), be inside its window and its cap, and not be covered by a revocation. Fails closed.
 */
export async function checkLease(presented: unknown, registry: LeaseRegistry, now: number): Promise<LeaseDecision> {
  if (!isSafeInt(now)) return { decision: 'deny', code: 'bad_input' };
  if (!verifyLease(presented)) return { decision: 'deny', code: 'bad_record' };
  const id = presented.lease_id;
  try {
    const found = await registry.lookup(id);
    if (found === undefined) return { decision: 'deny', code: 'unknown_lease', lease_id: id };
    const cur = found.current;
    if (cur.sig !== presented.sig) return { decision: 'deny', code: 'superseded', lease_id: id };
    if (found.revoked) return { decision: 'deny', code: 'revoked', lease_id: id };
    if (now < cur.renewed_at) return { decision: 'deny', code: 'not_yet_valid', lease_id: id };
    if (now >= leaseCap(cur)) return { decision: 'deny', code: 'past_max_ttl', lease_id: id };
    if (now >= cur.expires_at) return { decision: 'deny', code: 'expired', lease_id: id };
    return { decision: 'allow', lease_id: id, expires_at: cur.expires_at };
  } catch {
    return { decision: 'deny', code: 'store_unreachable', lease_id: id };
  }
}

export interface RenewOptions {
  now: number;
  /** Advisory increment from now (Vault style); the new expiry is capped at `issued_at + max_ttl`. */
  increment: number;
  justification_digest: string;
  approvers?: string[];
  /** Learned or behavioural signals: return true to REFUSE this renewal. They can only veto, never lengthen the lease. */
  veto?: (current: Lease) => boolean;
  chain?: readonly string[];
}
export type RenewResult = { ok: true; record: Lease } | { ok: false; code: LeaseAcceptCode | 'vetoed' | 'unknown_lease' | 'bad_input' };

/** Authority side: sign and register the next record of a lease. */
export async function renewLease(secret: Uint8Array, registry: LeaseRegistry, id: string, o: RenewOptions): Promise<RenewResult> {
  if (!isSafeInt(o.now) || !isSafeInt(o.increment) || o.increment < 1) return { ok: false, code: 'bad_input' };
  const cur = await registry.get(id);
  if (cur === undefined) return { ok: false, code: 'unknown_lease' };
  if (o.veto?.(cur) === true) return { ok: false, code: 'vetoed' };
  const expires = Math.min(o.now + o.increment, leaseCap(cur));
  const { v: _v, sig: _s, authority: _a, ...rest } = cur;
  let record: Lease;
  try {
    record = signLease(secret, { ...rest, seq: cur.seq + 1, renewed_at: o.now, expires_at: expires, justification_digest: o.justification_digest, approvers: o.approvers ?? cur.approvers });
  } catch {
    return { ok: false, code: expires <= o.now ? 'expired_lease' : 'bad_input' };
  }
  const r = await registry.accept(record, o.chain);
  return r.ok ? { ok: true, record } : { ok: false, code: r.code };
}
