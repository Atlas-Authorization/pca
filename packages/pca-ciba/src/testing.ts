/**
 * Test doubles. Single-process, in-memory, lose everything on restart: use them in tests of code that takes a broker,
 * a store or a KV, never to guard a real approval. Production code uses `createDurableCibaBroker` over a durable store.
 */
import { randomBytes } from 'node:crypto';
import type { StepUpRequest } from '@atlasauth/pca';
import type { ApprovalStore, Versioned } from './approval';
import type { DurableKv } from './kv-store';
import { toCibaAuthRequest, type CibaAuthRequest, type CibaBroker, type CibaBrokerOptions, type CibaRequestOptions, type CibaSession, type CibaStatus } from './index';

const DEFAULT_INTERVAL_SEC = 5;

interface StoredSession {
  request: CibaAuthRequest;
  createdAt: number;
  expiresAt: number;
  decision?: 'approve' | 'deny';
  decidedBy?: string;
  decidedAt?: number;
  /** Current minimum poll spacing in seconds (grows by 5 on each `slow_down`). */
  interval: number;
  /** ms epoch of the previous token request. */
  lastPollAt?: number;
  /** An approval is redeemable once. */
  consumed?: boolean;
}

/** Status is computed, never stored — a decision wins, else expiry, else pending (read-time truth). */
function effectiveStatus(s: StoredSession, now: number): CibaStatus {
  if (s.decision === 'approve') return 'approved';
  if (s.decision === 'deny') return 'denied';
  if (now >= s.expiresAt) return 'expired';
  return 'pending';
}

function snapshot(s: StoredSession, now: number): CibaSession {
  return {
    auth_req_id: s.request.auth_req_id,
    request: s.request,
    status: effectiveStatus(s, now),
    createdAt: s.createdAt,
    expiresAt: s.expiresAt,
    ...(s.decidedBy !== undefined ? { decidedBy: s.decidedBy } : {}),
    ...(s.decidedAt !== undefined ? { decidedAt: s.decidedAt } : {}),
  };
}

/**
 * An in-memory CIBA broker. Models the backchannel lifecycle without any network: `start` opens a
 * session, `poll` reports `pending`/`approved`/`denied`/`expired`, and `resolve` records the human's
 * decision. Supports both delivery modes — POLL (caller drives `poll`) and PING/PUSH (an `onComplete`
 * callback fires on resolution). A production deployment swaps this for the real OP + FROST cosigners;
 * the shape stays the same.
 */
export function createCibaBroker(opts: CibaBrokerOptions = {}): CibaBroker {
  const clock = opts.now ?? Date.now;
  const sessions = new Map<string, StoredSession>();
  /** step-up id -> the auth_req_id of its live (pending or approved) flow, so a repeated `start` is idempotent. */
  const liveByStepUp = new Map<string, string>();

  return {
    start(stepUp, reqOpts) {
      const now = clock();
      const existingId = liveByStepUp.get(stepUp.id);
      const existing = existingId !== undefined ? sessions.get(existingId) : undefined;
      if (existing !== undefined) {
        const st = effectiveStatus(existing, now);
        // Never reset a flow that is still waiting or already approved: that would silently discard a decision.
        if (st === 'pending' || st === 'approved') return existing.request;
      }
      // CIBA Core 7.3: an unguessable auth_req_id (160 random bits, base64url) per flow.
      const request = toCibaAuthRequest(stepUp, { ...reqOpts, authReqId: randomBytes(20).toString('base64url') });
      const createdAt = now;
      const stored: StoredSession = {
        request,
        createdAt,
        expiresAt: createdAt + request.requested_expiry * 1000,
        interval: request.interval,
      };
      sessions.set(request.auth_req_id, stored);
      liveByStepUp.set(stepUp.id, request.auth_req_id);
      return request;
    },
    poll(auth_req_id) {
      const s = sessions.get(auth_req_id);
      if (!s) throw new Error(`ciba: unknown auth_req_id ${auth_req_id}`);
      return { status: effectiveStatus(s, clock()) };
    },
    token(auth_req_id) {
      const s = sessions.get(auth_req_id);
      if (!s) return { ok: false, error: 'invalid_grant', interval: DEFAULT_INTERVAL_SEC };
      const now = clock();
      if (s.consumed) return { ok: false, error: 'invalid_grant', interval: s.interval };
      const tooSoon = s.lastPollAt !== undefined && now - s.lastPollAt < s.interval * 1000;
      s.lastPollAt = now;
      if (tooSoon) {
        s.interval += 5;
        return { ok: false, error: 'slow_down', interval: s.interval };
      }
      const st = effectiveStatus(s, now);
      if (st === 'pending') return { ok: false, error: 'authorization_pending', interval: s.interval };
      if (st === 'denied') return { ok: false, error: 'access_denied', interval: s.interval };
      if (st === 'expired') return { ok: false, error: 'expired_token', interval: s.interval };
      s.consumed = true;
      return { ok: true, session: snapshot(s, now) };
    },
    resolve(auth_req_id, decision, by) {
      const s = sessions.get(auth_req_id);
      if (!s) throw new Error(`ciba: unknown auth_req_id ${auth_req_id}`);
      const now = clock();
      const current = effectiveStatus(s, now);
      if (current !== 'pending') {
        throw new Error(`ciba: cannot resolve ${auth_req_id} — already ${current}`);
      }
      s.decision = decision;
      s.decidedBy = by;
      s.decidedAt = now;
      const snap = snapshot(s, now);
      if (opts.onComplete) opts.onComplete(snap);
      return snap;
    },
    get(auth_req_id) {
      const s = sessions.get(auth_req_id);
      return s ? snapshot(s, clock()) : undefined;
    },
  };
}

/** Single-process test double. Not durable. */
export function createMemoryApprovalStore(): ApprovalStore {
  const m = new Map<string, Versioned>();
  return {
    get: (k) => {
      const v = m.get(k);
      return v === undefined ? undefined : { version: v.version, value: structuredClone(v.value) };
    },
    cas: (k, exp, value) => {
      if ((m.get(k)?.version ?? 0) !== exp) return false;
      m.set(k, { version: exp + 1, value: structuredClone(value) });
      return true;
    },
  };
}

/** Single-process {@link DurableKv} for tests of code that takes a KV. Not durable. */
export function createMemoryKv(): DurableKv {
  const m = new Map<string, string>();
  return {
    get: (k) => m.get(k),
    putIfEquals: (k, expected, next) => {
      if (m.get(k) !== expected) return false;
      m.set(k, next);
      return true;
    },
  };
}
