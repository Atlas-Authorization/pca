/**
 * Durable approval broker: the production-shaped counterpart of the in-memory `createCibaBroker`.
 * State lives behind an {@link ApprovalStore} (compare-and-set), so a restart or a second process
 * cannot lose, double-apply or replay a human decision.
 */

import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import type { StepUpRequest } from '@atlasauth/pca';
import { toCibaAuthRequest, type CibaAuthRequest, type CibaRequestOptions, type CibaSession, type CibaStatus, type CibaTokenOutcome } from './index';

/** A versioned value. `version` is 0 for "absent"; every successful write bumps it. */
export interface Versioned {
  version: number;
  value: unknown;
}

/**
 * Persistence seam: a JSON key-value store with compare-and-set. `cas` writes `value` only if the stored
 * version equals `expectedVersion` (0 = key must be absent) and returns whether it wrote. Back it with a
 * database row version / `UPDATE ... WHERE version = ?` for multi-process use.
 */
export interface ApprovalStore {
  get(key: string): Versioned | undefined | Promise<Versioned | undefined>;
  cas(key: string, expectedVersion: number, value: unknown): boolean | Promise<boolean>;
}

/**
 * Durable reference store: one JSON file, rewritten atomically (temp file + rename) on each write.
 * Correct for ONE process at a time (read-modify-write is synchronous); use a database store when several
 * processes share the approvals.
 */
export function createFileApprovalStore(path: string): ApprovalStore {
  const load = (): Record<string, Versioned> => {
    if (!existsSync(path)) return {};
    const parsed: unknown = JSON.parse(readFileSync(path, 'utf8')); // corrupt file throws: fail closed
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('ciba: approval store file is corrupt');
    return parsed as Record<string, Versioned>;
  };
  return {
    get: (k) => load()[k],
    cas: (k, exp, value) => {
      const all = load();
      if ((all[k]?.version ?? 0) !== exp) return false;
      all[k] = { version: exp + 1, value };
      const tmp = `${path}.${process.pid}.tmp`;
      writeFileSync(tmp, JSON.stringify(all), { mode: 0o600 });
      renameSync(tmp, path);
      return true;
    },
  };
}

/** Asynchronous broker contract. The in-memory `createCibaBroker` is the sync test double of the same lifecycle. */
export interface ApprovalBroker {
  start(stepUp: StepUpRequest, opts?: CibaRequestOptions): Promise<CibaAuthRequest>;
  poll(auth_req_id: string): Promise<{ status: CibaStatus }>;
  token(auth_req_id: string): Promise<CibaTokenOutcome>;
  resolve(auth_req_id: string, decision: 'approve' | 'deny', by: string): Promise<CibaSession>;
  get(auth_req_id: string): Promise<CibaSession | undefined>;
}

export interface DurableBrokerOptions {
  /** REQUIRED. Where approvals live. */
  store: ApprovalStore;
  /** Clock (ms). Default `Date.now`. */
  now?: () => number;
  /**
   * How long an approval stays redeemable after the human decided, in seconds. Default 300. After that the
   * session reads `expired` and `token` answers `expired_token`: a stale approval can never be replayed later.
   */
  decisionTtlSec?: number;
  /** Called after a decision is durably recorded (PING/PUSH). A throw does not undo the decision. */
  onComplete?: (session: CibaSession) => void | Promise<void>;
}

interface Rec {
  request: CibaAuthRequest;
  createdAt: number;
  expiresAt: number;
  interval: number;
  decision?: 'approve' | 'deny';
  decidedBy?: string;
  decidedAt?: number;
  lastPollAt?: number;
  consumed?: boolean;
}

const MAX_CAS_TRIES = 8;

function asRec(v: unknown): Rec {
  const r = v as Rec | null;
  if (!r || typeof r !== 'object' || typeof r.request?.auth_req_id !== 'string' || !Number.isFinite(r.createdAt) || !Number.isFinite(r.expiresAt) || !Number.isFinite(r.interval)) {
    throw new Error('ciba: stored approval record is malformed');
  }
  return r;
}

export function createDurableCibaBroker(opts: DurableBrokerOptions): ApprovalBroker {
  const store = opts?.store;
  if (!store || typeof store.get !== 'function' || typeof store.cas !== 'function') throw new TypeError('createDurableCibaBroker: `store` is required');
  const clock = opts.now ?? Date.now;
  const ttlMs = (opts.decisionTtlSec ?? 300) * 1000;
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw new TypeError('createDurableCibaBroker: decisionTtlSec must be a positive number');

  const status = (r: Rec, now: number): CibaStatus => {
    if (r.decision === 'deny') return 'denied';
    if (r.decision === 'approve') return now >= (r.decidedAt as number) + ttlMs ? 'expired' : 'approved';
    return now >= r.expiresAt ? 'expired' : 'pending';
  };
  const snap = (r: Rec, now: number): CibaSession => ({
    auth_req_id: r.request.auth_req_id,
    request: r.request,
    status: status(r, now),
    createdAt: r.createdAt,
    expiresAt: r.expiresAt,
    ...(r.decidedBy !== undefined ? { decidedBy: r.decidedBy } : {}),
    ...(r.decidedAt !== undefined ? { decidedAt: r.decidedAt } : {}),
  });
  const load = async (id: string): Promise<{ rec: Rec; version: number } | undefined> => {
    const v = await store.get(`a:${id}`);
    return v === undefined ? undefined : { rec: asRec(v.value), version: v.version };
  };
  /** Read-modify-write with CAS retry; `fn` returns the new record (or undefined for "no write") plus a result. */
  const mutate = async <T>(id: string, fn: (rec: Rec | undefined, now: number) => { next?: Rec; out: T }): Promise<T> => {
    for (let i = 0; i < MAX_CAS_TRIES; i++) {
      const cur = await load(id);
      const { next, out } = fn(cur?.rec ? structuredClone(cur.rec) : undefined, clock());
      if (next === undefined) return out;
      if (await store.cas(`a:${id}`, cur?.version ?? 0, next)) return out;
    }
    throw new Error('ciba: approval store contention, gave up');
  };

  return {
    async start(stepUp, reqOpts) {
      const liveKey = `s:${stepUp.id}`;
      for (let i = 0; i < MAX_CAS_TRIES; i++) {
        const now = clock();
        const idx = await store.get(liveKey);
        if (idx !== undefined) {
          const ex = await load(String(idx.value));
          // Never reset a flow that is still waiting or already approved: that would discard a decision.
          if (ex && ['pending', 'approved'].includes(status(ex.rec, now)) && !ex.rec.consumed) return ex.rec.request;
        }
        const request = toCibaAuthRequest(stepUp, { ...reqOpts, authReqId: randomBytes(20).toString('base64url') });
        const rec: Rec = { request, createdAt: now, expiresAt: now + request.requested_expiry * 1000, interval: request.interval };
        if (!(await store.cas(`a:${request.auth_req_id}`, 0, rec))) continue;
        if (await store.cas(liveKey, idx?.version ?? 0, request.auth_req_id)) return request;
      }
      throw new Error('ciba: approval store contention, gave up');
    },
    async poll(id) {
      const c = await load(id);
      if (!c) throw new Error(`ciba: unknown auth_req_id ${id}`);
      return { status: status(c.rec, clock()) };
    },
    token: (id) =>
      mutate<CibaTokenOutcome>(id, (r, now) => {
        if (!r) return { out: { ok: false, error: 'invalid_grant', interval: 5 } };
        if (r.consumed) return { out: { ok: false, error: 'invalid_grant', interval: r.interval } };
        const tooSoon = r.lastPollAt !== undefined && now - r.lastPollAt < r.interval * 1000;
        r.lastPollAt = now;
        if (tooSoon) {
          r.interval += 5;
          return { next: r, out: { ok: false, error: 'slow_down', interval: r.interval } };
        }
        const st = status(r, now);
        if (st === 'pending') return { next: r, out: { ok: false, error: 'authorization_pending', interval: r.interval } };
        if (st === 'denied') return { next: r, out: { ok: false, error: 'access_denied', interval: r.interval } };
        if (st === 'expired') return { next: r, out: { ok: false, error: 'expired_token', interval: r.interval } };
        r.consumed = true; // single use: a replayed approval gets invalid_grant
        return { next: r, out: { ok: true, session: snap(r, now) } };
      }),
    async resolve(id, decision, by) {
      if (decision !== 'approve' && decision !== 'deny') throw new Error('ciba: decision must be "approve" or "deny"');
      if (typeof by !== 'string' || by === '') throw new Error('ciba: `by` (the authenticated decider) is required');
      const session = await mutate<CibaSession>(id, (r, now) => {
        if (!r) throw new Error(`ciba: unknown auth_req_id ${id}`);
        const cur = status(r, now);
        if (cur !== 'pending') throw new Error(`ciba: cannot resolve ${id} — already ${cur}`);
        r.decision = decision;
        r.decidedBy = by;
        r.decidedAt = now;
        return { next: r, out: snap(r, now) };
      });
      if (opts.onComplete) {
        try {
          await opts.onComplete(session);
        } catch {
          /* the decision is already recorded; a failing notifier must not undo or hide it */
        }
      }
      return session;
    },
    async get(id) {
      const c = await load(id);
      return c ? snap(c.rec, clock()) : undefined;
    },
  };
}
