/**
 * Guardian high-availability control logic (spec Part 2.6 "resilience/HA is non-negotiable").
 *
 * The guardian / Policy-VM that co-signs tier-2/3 actions is a fast-path SPOF. This is the pure control
 * logic for running it as a quorum: given each guardian's health, decide whether a co-sign quorum is
 * AVAILABLE, which guardians to ask, how to fail over, and — when the quorum is lost — how to DEGRADE
 * GRACEFULLY (fall back to read-only / human-only instead of failing open or hard-halting).
 *
 * Two parts. (1) Pure decision functions over health facts (quorum, degrade, signer selection). (2) A durable,
 * FENCED leader lease (`LeaseStore`, `acquireLease`, `FencedSigner`, `FenceGuard`): at most one holder at a time, a
 * strictly monotone fencing epoch that a stale ex-leader cannot get around, store-side expiry, and "no leader"
 * (halt) whenever the store errs. Process deployment and health probing remain the operator's job.
 *
 * What is guaranteed: lease safety holds IF the store's compare-and-swap is linearizable (run the lease conformance
 * suite against your store) and the holder's clock error stays under `skewMs`. Not guaranteed: availability, and
 * protection of a downstream that never checks the fencing epoch (check it with a `FenceGuard`).
 * It never fails OPEN: losing quorum or the lease restricts authority, never widens it.
 */

import type { DurableKv } from './durable-state';

export interface GuardianHealth {
  id: string;
  healthy: boolean;
  /** Last successful heartbeat (epoch ms). A stale heartbeat counts as unhealthy regardless of `healthy`. */
  lastSeen: number;
  /** Optional preference weight for signer selection (higher = preferred). Default 0. */
  weight?: number;
}

export interface GuardianSet {
  guardians: GuardianHealth[];
  /** Co-sign quorum size (t of n). Must be ≥1 and ≤ guardians.length. */
  quorum: number;
}

export interface QuorumOptions {
  /** A heartbeat older than this (ms) is treated as down. Default 30_000. */
  staleMs?: number;
}

/**
 * Guardians that are both flagged healthy AND have a fresh heartbeat at `now`. Fails closed: a malformed set, a
 * non-finite clock/stale window, a non-finite or FUTURE-dated heartbeat, or a non-boolean `healthy` counts as down.
 */
export function liveGuardians(set: GuardianSet, now: number, opts: QuorumOptions = {}): GuardianHealth[] {
  const staleMs = opts.staleMs ?? 30_000;
  if (!Number.isFinite(now) || !Number.isFinite(staleMs) || staleMs < 0 || !Array.isArray(set?.guardians) || !set.guardians.every((g) => g !== null && typeof g === 'object')) return [];
  return set.guardians.filter((g) => g.healthy === true && Number.isFinite(g.lastSeen) && g.lastSeen <= now && now - g.lastSeen <= staleMs);
}

const weightOf = (g: GuardianHealth): number => (Number.isFinite(g.weight) ? (g.weight as number) : 0);

export interface QuorumStatus {
  total: number;
  live: number;
  quorum: number;
  /** A co-sign quorum is reachable right now. */
  available: boolean;
  /** Some guardians are live but below quorum (degraded, not dead). */
  degraded: boolean;
}

export function quorumStatus(set: GuardianSet, now: number, opts: QuorumOptions = {}): QuorumStatus {
  const live = liveGuardians(set, now, opts).length;
  return {
    total: Array.isArray(set?.guardians) ? set.guardians.length : 0,
    live,
    quorum: set?.quorum,
    available: Number.isInteger(set?.quorum) && set.quorum >= 1 && live >= set.quorum,
    degraded: live > 0 && live < set.quorum,
  };
}

export type DegradeMode =
  /** Quorum available — full operation (tier-2/3 co-signs proceed). */
  | 'normal'
  /** Below quorum but some guardians live — reversible/auto (t=1) only; no new co-signed authority. */
  | 'read-only'
  /** No live guardians — refuse everything that needs a guardian; fail CLOSED. */
  | 'halt';

export interface DegradePolicy {
  /** If false, below-quorum goes straight to `halt` instead of `read-only`. Default true. */
  allowReadOnly?: boolean;
}

/** The degradation mode implied by the current quorum status. Never fails open. */
export function degradeMode(status: QuorumStatus, policy: DegradePolicy = {}): DegradeMode {
  if (status.available) return 'normal';
  if (status.live > 0 && policy.allowReadOnly !== false) return 'read-only';
  return 'halt';
}

/**
 * Select the guardians to ask for a co-sign: the `quorum` freshest+highest-weight live guardians. Empty
 * when quorum is not available (the caller must not attempt a co-sign below quorum).
 */
export function selectSigners(set: GuardianSet, now: number, opts: QuorumOptions = {}): string[] {
  const live = liveGuardians(set, now, opts);
  if (!Number.isInteger(set.quorum) || set.quorum < 1 || live.length < set.quorum) return [];
  return [...live]
    .sort((a, b) => weightOf(b) - weightOf(a) || b.lastSeen - a.lastSeen || a.id.localeCompare(b.id))
    .slice(0, set.quorum)
    .map((g) => g.id);
}

export interface FailoverPlan {
  /** The preferred live guardian (highest weight / freshest), or null if none live. */
  primary: string | null;
  /** The remaining live guardians, in preference order, as standbys. */
  standbys: string[];
}

/** A primary + ordered standbys for the single-signer fast path (with quorum as the backstop). */
export function failoverPlan(set: GuardianSet, now: number, opts: QuorumOptions = {}): FailoverPlan {
  const live = [...liveGuardians(set, now, opts)].sort(
    (a, b) => weightOf(b) - weightOf(a) || b.lastSeen - a.lastSeen || a.id.localeCompare(b.id),
  );
  return { primary: live[0]?.id ?? null, standbys: live.slice(1).map((g) => g.id) };
}

/** Validate a guardian set is well-formed (quorum in range, unique ids). Returns an error string or null. */
export function validateGuardianSet(set: GuardianSet): string | null {
  if (set === null || typeof set !== 'object') return 'guardian set is not an object';
  if (!Array.isArray(set.guardians) || set.guardians.length === 0) return 'guardian set is empty';
  if (!Number.isInteger(set.quorum) || set.quorum < 1) return 'quorum must be an integer ≥ 1';
  if (set.quorum > set.guardians.length) return 'quorum exceeds guardian count';
  if (!set.guardians.every((g) => g !== null && typeof g === 'object' && typeof g.id === 'string' && g.id.length > 0)) return 'guardian id must be a non-empty string';
  const ids = new Set(set.guardians.map((g) => g.id));
  if (ids.size !== set.guardians.length) return 'duplicate guardian ids';
  return null;
}

// ---- durable, fenced leader lease ------------------------------------------------------------

/** One lease record. `epoch` (the fencing token) only ever increases; a released lease keeps its epoch with `expiresAt: 0`. */
export interface LeaseRecord {
  holder: string;
  epoch: number;
  /** Store-clock epoch ms. */
  expiresAt: number;
}

/**
 * The persistence contract. `cas` replaces the record iff the stored one deep-equals `expected` (`undefined` = none), atomically
 * and linearizably, and returns whether it did. `next.epoch` must never be below the stored epoch. `now` is the STORE's clock:
 * every expiry decision uses it, never the caller's.
 */
export interface LeaseStore {
  read(): Promise<LeaseRecord | undefined>;
  cas(expected: LeaseRecord | undefined, next: LeaseRecord): Promise<boolean>;
  now(): Promise<number>;
}

export const MAX_LEASE_TTL_MS = 3_600_000;
export const DEFAULT_LEASE_SKEW_MS = 1_000;
const MAX_HOLDER_LEN = 256;

export interface LeaseOptions {
  /** Lease lifetime from the store clock. Integer in [2, MAX_LEASE_TTL_MS]. */
  ttlMs: number;
  /** Clock-error allowance: a holder stops acting `skewMs` before expiry, a challenger waits `skewMs` after it. Default 1000, must be < ttlMs. */
  skewMs?: number;
}

export type LeaseFailure = 'invalid' | 'held' | 'lost-race' | 'stale' | 'expired' | 'store-error';
export type LeaseResult = { ok: true; lease: LeaseRecord } | { ok: false; reason: LeaseFailure; detail?: string };

const eqLease = (a: LeaseRecord | undefined, b: LeaseRecord | undefined): boolean =>
  a === undefined || b === undefined ? a === b : a.holder === b.holder && a.epoch === b.epoch && a.expiresAt === b.expiresAt;
const validRecord = (r: unknown): r is LeaseRecord =>
  r !== null && typeof r === 'object' && typeof (r as LeaseRecord).holder === 'string' && Number.isSafeInteger((r as LeaseRecord).epoch) && (r as LeaseRecord).epoch >= 1 && Number.isFinite((r as LeaseRecord).expiresAt) && (r as LeaseRecord).expiresAt >= 0;

function leaseOpts(holder: string | null, o: LeaseOptions): { ttl: number; skew: number } | null {
  if (holder !== null && (typeof holder !== 'string' || holder.length === 0 || holder.length > MAX_HOLDER_LEN)) return null;
  const skew = o?.skewMs ?? DEFAULT_LEASE_SKEW_MS;
  if (!Number.isInteger(o?.ttlMs) || o.ttlMs < 2 || o.ttlMs > MAX_LEASE_TTL_MS) return null;
  if (!Number.isFinite(skew) || skew < 0 || skew >= o.ttlMs) return null;
  return { ttl: o.ttlMs, skew };
}

/** Read the record and the store clock; a corrupt record or clock is a store error (never "free"). */
async function snapshot(store: LeaseStore): Promise<{ cur: LeaseRecord | undefined; now: number }> {
  const cur = await store.read();
  const now = await store.now();
  if (!Number.isFinite(now) || (cur !== undefined && !validRecord(cur))) throw new Error('corrupt lease state');
  return { cur, now };
}

/** Take the lease if it is free (never held, released, or expired past the skew). The epoch increments on every takeover. */
export async function acquireLease(store: LeaseStore, holder: string, o: LeaseOptions): Promise<LeaseResult> {
  const p = leaseOpts(holder, o);
  if (!p) return { ok: false, reason: 'invalid' };
  try {
    const { cur, now } = await snapshot(store);
    if (cur !== undefined && cur.expiresAt + p.skew > now && cur.expiresAt !== 0) return { ok: false, reason: 'held' };
    const next: LeaseRecord = { holder, epoch: (cur?.epoch ?? 0) + 1, expiresAt: now + p.ttl };
    return (await store.cas(cur, next)) ? { ok: true, lease: next } : { ok: false, reason: 'lost-race' };
  } catch (e) {
    return { ok: false, reason: 'store-error', detail: e instanceof Error ? e.message : 'unknown' };
  }
}

/** Extend a lease the caller still holds. Refused once the holder's own safe window (expiry minus skew) has passed, or after any takeover. */
export async function renewLease(store: LeaseStore, lease: LeaseRecord, o: LeaseOptions): Promise<LeaseResult> {
  const p = leaseOpts(lease?.holder ?? '', o);
  if (!p || !validRecord(lease)) return { ok: false, reason: 'invalid' };
  try {
    const { cur, now } = await snapshot(store);
    if (!cur || cur.holder !== lease.holder || cur.epoch !== lease.epoch) return { ok: false, reason: 'stale' };
    if (cur.expiresAt - p.skew <= now) return { ok: false, reason: 'expired' };
    const next: LeaseRecord = { holder: cur.holder, epoch: cur.epoch, expiresAt: now + p.ttl };
    return (await store.cas(cur, next)) ? { ok: true, lease: next } : { ok: false, reason: 'lost-race' };
  } catch (e) {
    return { ok: false, reason: 'store-error', detail: e instanceof Error ? e.message : 'unknown' };
  }
}

/** Give the lease up early (expiresAt 0, epoch kept). Only the current holder at the current epoch can. */
export async function releaseLease(store: LeaseStore, lease: LeaseRecord): Promise<LeaseResult> {
  if (!validRecord(lease)) return { ok: false, reason: 'invalid' };
  try {
    const { cur } = await snapshot(store);
    if (!cur || cur.holder !== lease.holder || cur.epoch !== lease.epoch || cur.expiresAt === 0) return { ok: false, reason: 'stale' };
    const next: LeaseRecord = { holder: cur.holder, epoch: cur.epoch, expiresAt: 0 };
    return (await store.cas(cur, next)) ? { ok: true, lease: next } : { ok: false, reason: 'lost-race' };
  } catch (e) {
    return { ok: false, reason: 'store-error', detail: e instanceof Error ? e.message : 'unknown' };
  }
}

/** Is this exact (holder, epoch) still the leader, with its safe window open, per the store? Any error answers no. */
export async function assertFence(store: LeaseStore, token: { holder: string; epoch: number }, skewMs: number = DEFAULT_LEASE_SKEW_MS): Promise<{ ok: true } | { ok: false; reason: 'stale' | 'expired' | 'store-error' }> {
  try {
    if (!token || !Number.isFinite(skewMs) || skewMs < 0) return { ok: false, reason: 'stale' };
    const { cur, now } = await snapshot(store);
    if (!cur || cur.holder !== token.holder || cur.epoch !== token.epoch) return { ok: false, reason: 'stale' };
    return cur.expiresAt - skewMs > now ? { ok: true } : { ok: false, reason: 'expired' };
  } catch {
    return { ok: false, reason: 'store-error' };
  }
}

export class FenceError extends Error {
  constructor(readonly reason: 'stale' | 'expired' | 'store-error' | 'no-lease') {
    super(`fenced: ${reason}`);
    this.name = 'FenceError';
  }
}

/**
 * Wrap a co-sign function so it only runs while the caller is the fenced leader. The fence is checked before AND after the
 * signature: a leader that lost the lease mid-signature gets a FenceError and the signature is discarded.
 * Check-then-sign is inherently racy, so the downstream must also `FenceGuard.admit` the epoch.
 */
export function fencedSigner<A extends unknown[], R>(store: LeaseStore, getLease: () => LeaseRecord | undefined, sign: (...a: A) => Promise<R> | R, skewMs: number = DEFAULT_LEASE_SKEW_MS): (...a: A) => Promise<{ result: R; epoch: number }> {
  return async (...a) => {
    const lease = getLease();
    if (!lease) throw new FenceError('no-lease');
    const pre = await assertFence(store, lease, skewMs);
    if (!pre.ok) throw new FenceError(pre.reason);
    const result = await sign(...a);
    const post = await assertFence(store, lease, skewMs);
    if (!post.ok) throw new FenceError(post.reason);
    return { result, epoch: lease.epoch };
  };
}

/** Resource-side fencing: remembers the highest epoch seen and refuses anything lower (a stale ex-leader's late write). */
export function createFenceGuard(initial = 0): { admit(epoch: number): boolean; highest(): number } {
  let hi = Number.isSafeInteger(initial) && initial >= 0 ? initial : 0;
  return {
    admit(epoch) {
      if (!Number.isSafeInteger(epoch) || epoch < 1 || epoch < hi) return false;
      hi = epoch;
      return true;
    },
    highest: () => hi,
  };
}

/** Reference `LeaseStore` over any `DurableKv` (its `update` is the atomic compare-and-swap). With `openDurableState` it survives restarts. */
export class KvLeaseStore implements LeaseStore {
  constructor(
    private readonly kv: DurableKv,
    private readonly opts: { key?: string; now?: () => number } = {},
  ) {}
  private get key(): string {
    return this.opts.key ?? 'ha/lease';
  }
  async read(): Promise<LeaseRecord | undefined> {
    const v = await this.kv.get(this.key);
    if (v !== undefined && !validRecord(v)) throw new Error('corrupt lease state');
    return v;
  }
  async cas(expected: LeaseRecord | undefined, next: LeaseRecord): Promise<boolean> {
    if (!validRecord(next)) throw new Error('invalid lease record');
    let matched = false;
    await this.kv.update(this.key, (prev) => {
      if (prev !== undefined && !validRecord(prev)) return undefined;
      if (!eqLease(prev as LeaseRecord | undefined, expected) || next.epoch < ((prev as LeaseRecord | undefined)?.epoch ?? 0)) return undefined;
      matched = true;
      return next;
    });
    return matched;
  }
  async now(): Promise<number> {
    return (this.opts.now ?? Date.now)();
  }
}
