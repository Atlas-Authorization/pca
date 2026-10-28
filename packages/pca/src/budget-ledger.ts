/**
 * Durable aggregate budgets: the `BudgetLedger` contract, a reference store, and scoped admission.
 *
 * WHAT IS CLAIMED. NO OVERSPEND AT PRINCIPAL, ORG AND FLEET SCOPE (spec G-T8), given a ledger that is linearizable per key
 * and durable. An accumulator with `scope: principal | org | fleet` counts the events of EVERY session and delegated agent of
 * that scope in ONE state keyed by the scope id (never by a grant or session), so N sessions share one cap (W9) and a split
 * across sessions or agents buys nothing (W8). A reservation counts as soon as it is made; the ledger refuses a reservation
 * whose post-value would pass the accumulator's `domain_max`, inside the same atomic step that records it, so two concurrent
 * admissions cannot both fit (compare-and-swap on the key's version, plus the cap check under the same lock).
 *
 * TWO PHASES. `reserve` (counted at once) then `commit` (the effect happened) or `release` (it did not). A release is a
 * signed event ({@link signRelease}) that can be anchored in a transparency log ({@link anchorRelease}). A release that never
 * arrives only OVER-restricts: an open reservation keeps counting until it is released, so a crash costs budget, never safety.
 * THREE STEPS FOR AN EFFECT: `reserve`, then `start` (recorded BEFORE the effect runs), then `commit`. `expire` frees only a
 * reservation that was never started; `start` is refused once it is released. The ledger orders start against expire, so an
 * expired reservation's effect can never run and a started one is never freed by a clock: expiry needs no trusted clock (a
 * caller with a skewed `now` can only free budget early for an effect that cannot run). A crash after `start` leaves the
 * reservation counted until a signed release (the effect did not happen) or a commit (it did). A committed event is never
 * released (spent is spent) and a released one is never committed (a late effect without a reservation is refused).
 * TRUSTED: the host releases only when the effect did not happen; the signed event makes a wrong release attributable.
 *
 * WHAT THE STORE MUST GUARANTEE. Each operation is atomic per key; the same reservation again (same id, same content) is a
 * replay that changes nothing (a retry after a lost acknowledgement); acknowledged writes survive a crash; `durable` is true
 * only for a store that does. Run `runBudgetLedgerConformance` (`@atlasauth/pca-store-conformance`) against it.
 *
 * REFUSALS. {@link admitAggregateAction} throws `not_durable` for a ledger whose `durable` is not true, and `scope_unbound`
 * (a deny) when the caller names no id for a scope the root uses. A volatile ledger is for `session` scope only.
 *
 * LIMIT (shortcut: one document per key, rewritten per write, bounded by the kv's `maxValueBytes`; a production ledger is a
 * database row-per-event with a unique index on (key, id) and a version column: reuse {@link reserveInDoc} inside its txn).
 */
import { b64u, canonicalBytesStrict, decodeB64uStrict, hashCanonical, utf8 } from './hash';
import { publicKeyOf, sign, verifyB64u } from './keys';
import { type AccPreState, type AccScope, type AccumulatorDecl, accSelects } from './intent-acc';
import { type IntentEvent, accContextFor, accPost } from './intent-history';
import { type ActionSchema } from './action-schema';
import { isSafeInt } from './intent-strict';
import type { DurableKv } from './durable-state';
import { openDurableState } from './durable-state';
import type { LedgerStore } from './ledger-store';

export type BudgetLedgerErrorCode = 'not_durable' | 'scope_unbound' | 'store_missing' | 'store_corrupt' | 'invalid' | 'conflict_exhausted';
export class BudgetLedgerError extends Error {
  constructor(
    readonly code: BudgetLedgerErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = 'BudgetLedgerError';
  }
}

/** The scope ids the host knows for an admission: who the principal / org / fleet of this action is. */
export interface ScopeIds {
  principal?: string;
  org?: string;
  fleet?: string;
}

const ID_MAX = 256;
const idOk = (s: unknown): s is string => typeof s === 'string' && s.length > 0 && s.length <= ID_MAX && !/[\u0000-\u001f]/.test(s);
/** The ledger key of a scope and its id. Injective: the id is percent-encoded. */
export function scopeKey(scope: Exclude<AccScope, 'session'>, id: string): string {
  if (!idOk(id)) throw new BudgetLedgerError('invalid', 'a scope id is a non-empty string of at most 256 characters without control characters');
  return `${scope}/${encodeURIComponent(id)}`;
}

export interface BudgetEntry extends IntentEvent {
  /** Reservation deadline (epoch ms): `expire` releases an open reservation that was never started at or after it. */
  exp?: number;
  /** The effect is about to run (or ran): the reservation is no longer expirable, only committed or released with evidence. */
  started?: true;
  /** Why and by whom a release happened (see {@link signRelease}); absent for a reserved or committed entry. */
  rel?: ReleaseEvent | { reason: 'expired'; at: number };
}
export interface BudgetDoc {
  v: 1;
  /** Bumped by every write: the compare-and-swap token. */
  ver: number;
  events: BudgetEntry[];
}
export const emptyBudgetDoc = (): BudgetDoc => ({ v: 1, ver: 0, events: [] });
export interface BudgetSnapshot {
  version: number;
  events: readonly BudgetEntry[];
}

export interface ReserveRequest {
  /** `id` is unique per key (the PCActn digest). */
  event: Omit<IntentEvent, 'status'>;
  /** The accumulators of THIS key (each `domain_max` is the cap). */
  accumulators: readonly AccumulatorDecl[];
  schema?: Pick<ActionSchema, 'verbs'>;
  /** Refuse (`conflict`) unless the key is at this version: the compare-and-swap of a read-verify-reserve loop. */
  expectedVersion?: number;
  expiresAt?: number;
}
export type ReserveOutcome =
  | { outcome: 'reserved'; version: number; post: Record<string, number> }
  /** The same reservation was already recorded (a retry): nothing written. `status` is its current state: a `released` replay must NOT run the effect. */
  | { outcome: 'replayed'; version: number; status: IntentEvent['status'] }
  | { outcome: 'over_cap'; version: number; acc: string; post: number; cap: number }
  | { outcome: 'conflict'; version: number }
  | { outcome: 'id_conflict'; version: number };
export type SettleOutcome =
  | { outcome: 'settled'; version: number }
  | { outcome: 'replayed'; version: number }
  /** No such reservation: nothing written (a release without a reserve never credits budget). */
  | { outcome: 'unknown'; version: number }
  /** The opposite settlement already happened (commit of a released entry, release of a committed one): refused. */
  | { outcome: 'refused'; version: number; status: IntentEvent['status'] };

/**
 * The persistence contract of an aggregate budget. Implement it over a database or use {@link KvBudgetLedger}; run
 * `runBudgetLedgerConformance` (`@atlasauth/pca-store-conformance`) against it.
 */
export interface BudgetLedger {
  /** True ONLY when acknowledged writes survive a restart or crash. Non-session scopes refuse a ledger that does not say so. */
  readonly durable: boolean;
  snapshot(key: string): Promise<BudgetSnapshot>;
  reserve(key: string, req: ReserveRequest): Promise<ReserveOutcome>;
  /** The effect is about to run: mark the reservation non-expirable. Refused (`refused`) once released; `replayed` when already started or committed. */
  start(key: string, id: string): Promise<SettleOutcome>;
  commit(key: string, id: string): Promise<SettleOutcome>;
  release(key: string, id: string, evidence?: ReleaseEvent): Promise<SettleOutcome>;
  /** Release every open, never-started reservation whose `exp` is at or before `now`. Returns their ids. */
  expire(key: string, now: number): Promise<{ released: string[]; version: number }>;
}

// ---- the pure transitions (every reference store is these plus a per-key lock) -------------------------------------------

const sameEvent = (a: Omit<IntentEvent, 'status'>, b: Omit<IntentEvent, 'status'>): boolean =>
  hashCanonical({ id: a.id, verb: a.verb, resource: a.resource, params: a.params, t: a.t }) === hashCanonical({ id: b.id, verb: b.verb, resource: b.resource, params: b.params, t: b.t });

export function reserveInDoc(doc: BudgetDoc, req: ReserveRequest): ReserveOutcome {
  const e = req?.event;
  if (!e || !idOk(e.id) || typeof e.verb !== 'string' || typeof e.resource !== 'string' || !isSafeInt(e.t) || e.params === null || typeof e.params !== 'object') throw new RangeError('reserve: a malformed event');
  if (!Array.isArray(req.accumulators)) throw new RangeError('reserve: accumulators must be an array');
  if (req.expectedVersion !== undefined && (!Number.isSafeInteger(req.expectedVersion) || req.expectedVersion < 0)) throw new RangeError('reserve: expectedVersion must be a non-negative safe integer');
  if (req.expiresAt !== undefined && !isSafeInt(req.expiresAt)) throw new RangeError('reserve: expiresAt must be a safe integer');
  const prior = doc.events.find((x) => x.id === e.id);
  if (prior) return sameEvent(prior, e) ? { outcome: 'replayed', version: doc.ver, status: prior.status } : { outcome: 'id_conflict', version: doc.ver };
  if (req.expectedVersion !== undefined && req.expectedVersion !== doc.ver) return { outcome: 'conflict', version: doc.ver };
  const post: Record<string, number> = {};
  for (const a of req.accumulators) {
    if (a.domain_max === undefined) throw new RangeError(`reserve: accumulator ${a.id} has no domain_max (the cap)`);
    if (!accSelects(a, e.verb, req.schema)) continue;
    let p: number;
    try {
      p = accPost(a, doc.events, e, req.schema);
    } catch (err) {
      throw new BudgetLedgerError('store_corrupt', err instanceof Error ? err.message : 'unreadable history');
    }
    if (p > a.domain_max) return { outcome: 'over_cap', version: doc.ver, acc: a.id, post: p, cap: a.domain_max };
    post[a.id] = p;
  }
  const entry: BudgetEntry = { id: e.id, verb: e.verb, resource: e.resource, params: structuredClone(e.params), t: e.t, status: 'reserved' };
  if (req.expiresAt !== undefined) entry.exp = req.expiresAt;
  doc.events.push(entry);
  doc.ver += 1;
  return { outcome: 'reserved', version: doc.ver, post };
}

export function startInDoc(doc: BudgetDoc, id: string): SettleOutcome {
  const e = doc.events.find((x) => x.id === id);
  if (!e) return { outcome: 'unknown', version: doc.ver };
  if (e.status === 'released') return { outcome: 'refused', version: doc.ver, status: e.status };
  if (e.started || e.status === 'committed') return { outcome: 'replayed', version: doc.ver };
  e.started = true;
  doc.ver += 1;
  return { outcome: 'settled', version: doc.ver };
}

export function commitInDoc(doc: BudgetDoc, id: string): SettleOutcome {
  const e = doc.events.find((x) => x.id === id);
  if (!e) return { outcome: 'unknown', version: doc.ver };
  if (e.status === 'committed') return { outcome: 'replayed', version: doc.ver };
  if (e.status !== 'reserved') return { outcome: 'refused', version: doc.ver, status: e.status };
  e.status = 'committed';
  doc.ver += 1;
  return { outcome: 'settled', version: doc.ver };
}

export function releaseInDoc(doc: BudgetDoc, key: string, id: string, evidence?: ReleaseEvent): SettleOutcome {
  const e = doc.events.find((x) => x.id === id);
  if (!e) return { outcome: 'unknown', version: doc.ver };
  if (e.status === 'released') return { outcome: 'replayed', version: doc.ver };
  if (e.status !== 'reserved') return { outcome: 'refused', version: doc.ver, status: e.status };
  if (evidence !== undefined && (evidence.key !== key || evidence.id !== id)) throw new RangeError('release: the evidence is for another reservation');
  e.status = 'released';
  if (evidence) e.rel = structuredClone(evidence);
  doc.ver += 1;
  return { outcome: 'settled', version: doc.ver };
}

export function expireInDoc(doc: BudgetDoc, now: number): { released: string[]; version: number } {
  if (!isSafeInt(now)) throw new RangeError('expire: now must be a safe integer');
  const released: string[] = [];
  for (const e of doc.events) {
    if (e.status === 'reserved' && !e.started && e.exp !== undefined && e.exp <= now) {
      e.status = 'released';
      e.rel = { reason: 'expired', at: now };
      released.push(e.id);
    }
  }
  if (released.length > 0) doc.ver += 1;
  return { released, version: doc.ver };
}

// ---- the reference store -----------------------------------------------------------------------------------------------

const PREFIX = 'pca-budget-ledger/v1/';
const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
function decodeDoc(raw: unknown): BudgetDoc {
  if (raw === undefined) return emptyBudgetDoc();
  if (!isObj(raw) || raw.v !== 1 || !Number.isSafeInteger(raw.ver) || !Array.isArray(raw.events) || !raw.events.every((e) => isObj(e) && typeof e.id === 'string')) throw new BudgetLedgerError('store_corrupt', 'budget document has the wrong shape');
  return raw as unknown as BudgetDoc;
}

/**
 * The reference {@link BudgetLedger}: one document per key in any {@link DurableKv}, so every operation is one atomic
 * read-modify-write. `durable` is declared by the caller because a kv cannot tell: pass true only for a persistent one
 * ({@link openDurableBudgetLedger}); over `createMemoryDurableKv()` it must be false.
 */
export class KvBudgetLedger implements BudgetLedger {
  constructor(
    private readonly kv: DurableKv,
    readonly durable: boolean,
  ) {
    if (!kv || typeof kv.get !== 'function' || typeof kv.update !== 'function') throw new BudgetLedgerError('store_missing', 'KvBudgetLedger needs a DurableKv');
    if (typeof durable !== 'boolean') throw new BudgetLedgerError('invalid', 'say whether the kv is durable (true or false)');
  }
  private k(key: string): string {
    if (!idOk(key)) throw new RangeError('a ledger key is a non-empty string without control characters');
    return PREFIX + key;
  }
  private async txn<T>(key: string, fn: (d: BudgetDoc) => T, writes: (r: T) => boolean): Promise<T> {
    let out!: T;
    await this.kv.update(this.k(key), (prev) => {
      const d = decodeDoc(prev);
      out = fn(d);
      return writes(out) ? d : undefined;
    });
    return out;
  }
  async snapshot(key: string): Promise<BudgetSnapshot> {
    const d = decodeDoc(await this.kv.get(this.k(key)));
    return { version: d.ver, events: structuredClone(d.events) };
  }
  reserve(key: string, req: ReserveRequest): Promise<ReserveOutcome> {
    return this.txn(key, (d) => reserveInDoc(d, req), (r) => r.outcome === 'reserved');
  }
  start(key: string, id: string): Promise<SettleOutcome> {
    return this.txn(key, (d) => startInDoc(d, id), (r) => r.outcome === 'settled');
  }
  commit(key: string, id: string): Promise<SettleOutcome> {
    return this.txn(key, (d) => commitInDoc(d, id), (r) => r.outcome === 'settled');
  }
  release(key: string, id: string, evidence?: ReleaseEvent): Promise<SettleOutcome> {
    return this.txn(key, (d) => releaseInDoc(d, key, id, evidence), (r) => r.outcome === 'settled');
  }
  expire(key: string, now: number): Promise<{ released: string[]; version: number }> {
    return this.txn(key, (d) => expireInDoc(d, now), (r) => r.released.length > 0);
  }
}

/** The reference ledger over durable-state files in `dir`: crash-safe, hash-chained, multi-process safe on one host. */
export async function openDurableBudgetLedger(opts: { dir: string; lockTimeoutMs?: number }): Promise<KvBudgetLedger> {
  return new KvBudgetLedger(await openDurableState({ dir: opts.dir, lockTimeoutMs: opts.lockTimeoutMs }), true);
}

// ---- signed, anchored releases ------------------------------------------------------------------------------------------

export const RELEASE_DOMAIN = 'atlas-pca/budget-release/v1\0';
export type ReleaseReason = 'effect_failed' | 'effect_not_run' | 'denied_downstream' | 'rollback';
/** A signed statement by the releaser (the verifier or sequencer) that a reservation's effect did NOT happen. */
export interface ReleaseEvent {
  v: 1;
  key: string;
  id: string;
  reason: ReleaseReason;
  at: number;
  signer: string;
  sig: string;
}
const RELEASE_REASONS: readonly string[] = ['effect_failed', 'effect_not_run', 'denied_downstream', 'rollback'];
const releaseMessage = (r: Omit<ReleaseEvent, 'sig'>): Uint8Array => {
  const dom = utf8(RELEASE_DOMAIN);
  const b = canonicalBytesStrict({ v: r.v, key: r.key, id: r.id, reason: r.reason, at: r.at, signer: r.signer });
  const out = new Uint8Array(dom.length + b.length);
  out.set(dom);
  out.set(b, dom.length);
  return out;
};
export function signRelease(body: { key: string; id: string; reason: ReleaseReason; at: number }, secret: Uint8Array): ReleaseEvent {
  if (!RELEASE_REASONS.includes(body.reason) || !isSafeInt(body.at) || !idOk(body.key) || !idOk(body.id)) throw new RangeError('signRelease: a malformed release');
  const base = { v: 1 as const, key: body.key, id: body.id, reason: body.reason, at: body.at, signer: b64u(publicKeyOf(secret)) };
  return { ...base, sig: b64u(sign(secret, releaseMessage(base))) };
}
/** True iff `r` is well formed and signed by `expectedSigner` over exactly its content. Never throws. */
export function verifyRelease(r: ReleaseEvent, expectedSigner: string): boolean {
  try {
    if (!isObj(r) || r.v !== 1 || r.signer !== expectedSigner || !RELEASE_REASONS.includes(r.reason) || !isSafeInt(r.at) || !idOk(r.key) || !idOk(r.id) || decodeB64uStrict(r.sig, 64) === null) return false;
    const { sig, ...base } = r;
    return verifyB64u(expectedSigner, releaseMessage(base), sig);
  } catch {
    return false;
  }
}
export const releaseDigest = (r: ReleaseEvent): string => hashCanonical({ d: 'atlas-pca/budget-release-ref/v1', r });
/** The log leaf of a release. */
export const releaseCommit = (r: ReleaseEvent): string => hashCanonical({ d: 'atlas-pca/budget-release-leaf/v1', digest: releaseDigest(r) });
/** Anchor a signed release in a transparency log store (retries on a position conflict). Returns the leaf index. */
export async function anchorRelease(log: LedgerStore, r: ReleaseEvent): Promise<number> {
  const commit = releaseCommit(r);
  for (let i = 0; i < 64; i++) {
    const size = await log.size();
    const o = await log.append(size, [commit]);
    if (o.outcome === 'appended') return size;
    if (o.outcome === 'replayed') return size;
  }
  throw new BudgetLedgerError('conflict_exhausted', 'could not anchor the release: the log kept moving');
}

// ---- scoped admission ---------------------------------------------------------------------------------------------------

export interface AggregateReservation {
  key: string;
  id: string;
}
export type AggregateAdmission<V> =
  | { admitted: true; verdict: V; reservations: AggregateReservation[]; state: Record<string, AccPreState> }
  | { admitted: false; reason: string; verdict?: V };

/** The ledger key of an accumulator for this admission, or null when it is session-scoped. Throws `scope_unbound`. */
export function aggregateKeyOf(a: Pick<AccumulatorDecl, 'id' | 'scope'>, ids: ScopeIds): string | null {
  if (a.scope === undefined || a.scope === 'session') return null;
  const id = ids[a.scope];
  if (id === undefined) throw new BudgetLedgerError('scope_unbound', `accumulator ${a.id} is ${a.scope}-scoped but no ${a.scope} id was given`);
  return scopeKey(a.scope, id);
}

/**
 * Admit one action against every non-session accumulator of the root, atomically per key.
 *
 *   1. read each key's snapshot and compute the pre-states of its accumulators (the cross-session history);
 *   2. `verify(state)` (the host's verifier with those pre-states, merged with the session store's for session scope);
 *   3. on allow, `reserve` in every key with `expectedVersion` = the snapshot's. A moved key repeats from 1 (optimistic
 *      concurrency); a key over its cap denies and releases what the earlier keys reserved (over-restriction only).
 *
 * Refuses (throws `not_durable`) a ledger that is not durable, always: a volatile ledger resets every cap on restart.
 * Settle each reservation with {@link settleAggregate} after the effect.
 */
export async function admitAggregateAction<V extends { allow: boolean }>(
  ledger: BudgetLedger,
  args: {
    ids: ScopeIds;
    accumulators: readonly AccumulatorDecl[];
    schema?: Pick<ActionSchema, 'verbs'>;
    event: Omit<IntentEvent, 'status'>;
    verify: (state: Record<string, AccPreState>) => Promise<V>;
    expiresAt?: number;
    maxAttempts?: number;
  },
): Promise<AggregateAdmission<V>> {
  const scoped = args.accumulators.filter((a) => a.scope !== undefined && a.scope !== 'session');
  if (scoped.length > 0 && ledger?.durable !== true) throw new BudgetLedgerError('not_durable', 'a principal, org or fleet aggregate needs a durable BudgetLedger (a restart would reset every cap)');
  const byKey = new Map<string, AccumulatorDecl[]>();
  try {
    for (const a of scoped) {
      const k = aggregateKeyOf(a, args.ids)!;
      byKey.set(k, [...(byKey.get(k) ?? []), a]);
    }
  } catch (e) {
    if (e instanceof BudgetLedgerError && e.code === 'scope_unbound') return { admitted: false, reason: `scope_unbound: ${e.message}` };
    throw e;
  }
  const keys = [...byKey.keys()].sort();
  for (let attempt = 0; attempt < (args.maxAttempts ?? 256); attempt++) {
    const snaps = new Map<string, BudgetSnapshot>();
    const state: Record<string, AccPreState> = Object.create(null) as Record<string, AccPreState>;
    for (const k of keys) {
      const s = await ledger.snapshot(k);
      snaps.set(k, s);
      Object.assign(state, accContextFor({ accumulators: [...byKey.get(k)!], monitors: [] }, s.events, args.event, args.schema).state);
    }
    const verdict = await args.verify(state);
    if (!verdict.allow) return { admitted: false, reason: 'verifier denied', verdict };
    const done: AggregateReservation[] = [];
    let moved = false;
    for (const k of keys) {
      const r = await ledger.reserve(k, { event: args.event, accumulators: byKey.get(k)!, schema: args.schema, expectedVersion: snaps.get(k)!.version, expiresAt: args.expiresAt });
      if (r.outcome === 'reserved' || (r.outcome === 'replayed' && r.status === 'reserved')) {
        done.push({ key: k, id: args.event.id });
        continue;
      }
      for (const d of done) await ledger.release(d.key, d.id);
      if (r.outcome === 'conflict') {
        moved = true;
        break;
      }
      const why = r.outcome === 'over_cap' ? `over_cap: ${r.acc} would reach ${r.post} (cap ${r.cap})` : r.outcome === 'replayed' ? `already ${r.status}` : r.outcome;
      return { admitted: false, reason: `aggregate: ${why}`, verdict };
    }
    if (!moved) return { admitted: true, verdict, reservations: done, state };
  }
  throw new BudgetLedgerError('conflict_exhausted', 'the aggregate kept moving under this admission');
}

/**
 * BEFORE the effect: mark every reservation started (non-expirable). Returns false when any is refused (it was released or
 * expired in the meantime): the effect must NOT run then. Call it after {@link admitAggregateAction} and before the effect.
 */
export async function startAggregate(ledger: BudgetLedger, reservations: readonly AggregateReservation[]): Promise<boolean> {
  for (const r of reservations) {
    const o = await ledger.start(r.key, r.id);
    if (o.outcome !== 'settled' && o.outcome !== 'replayed') return false;
  }
  return true;
}

/** After the effect: `committed` (it happened) or `released` (it did not; a signed `evidence` is stored and can be anchored). */
export async function settleAggregate(ledger: BudgetLedger, reservations: readonly AggregateReservation[], status: 'committed' | 'released', evidence?: (r: AggregateReservation) => ReleaseEvent | undefined): Promise<SettleOutcome[]> {
  const out: SettleOutcome[] = [];
  for (const r of reservations) out.push(status === 'committed' ? await ledger.commit(r.key, r.id) : await ledger.release(r.key, r.id, evidence?.(r)));
  return out;
}
