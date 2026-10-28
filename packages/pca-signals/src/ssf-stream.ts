/**
 * SSF STREAM HEALTH: configuration, status, verification events and poll/push delivery bookkeeping, plus the CAEP
 * events PCA emits from its decision log.
 *
 * Why it matters for PCA: a pushed revocation is only a guarantee if you know the stream is alive. A receiver that has
 * not seen a verified round trip recently cannot claim "no revocation was missed"; {@link StreamHealth.revocationFreshWithin}
 * turns that into one boolean the verifier combines with the signed revocation epoch (pull bound). Unhealthy = ask the
 * caller to refresh (escalate), never allow.
 *
 * Sources (fetched): OpenID SSF 1.0 sections 6.1, 7.1, 8.1.1, 8.1.2, 8.1.4 (stream configuration, status, verification),
 * RFC 8935 (push delivery, 202 and error codes), RFC 8936 (poll delivery: maxEvents, returnImmediately, ack, setErrs, sets,
 * moreAvailable), OpenID CAEP 1.0 (risk-level-change, assurance-level-change).
 */
import { randomBytes } from 'node:crypto';
import { EVENT_TYPES, buildSET, type CaepAssuranceLevelChangeEvent, type CaepRiskLevelChangeEvent, type SigningKey } from './index';

export const DELIVERY_PUSH = 'urn:ietf:rfc:8935';
export const DELIVERY_POLL = 'urn:ietf:rfc:8936';
export type StreamStatusValue = 'enabled' | 'paused' | 'disabled';
export const STREAM_STATUSES: readonly StreamStatusValue[] = ['enabled', 'paused', 'disabled'];

export interface StreamConfig {
  stream_id: string;
  iss: string;
  aud: string | string[];
  events_supported?: string[];
  events_requested?: string[];
  events_delivered: string[];
  delivery: { method: typeof DELIVERY_PUSH | typeof DELIVERY_POLL; endpoint_url: string };
  min_verification_interval?: number;
  description?: string;
}

/** SSF 8.1.1 shape checks. Returns the problems found (empty = valid). */
export function validateStreamConfig(c: unknown): string[] {
  const e: string[] = [];
  if (typeof c !== 'object' || c === null || Array.isArray(c)) return ['not an object'];
  const o = c as Partial<StreamConfig>;
  const nonEmpty = (x: unknown): x is string => typeof x === 'string' && x.length > 0;
  if (!nonEmpty(o.stream_id)) e.push('stream_id is required');
  if (!nonEmpty(o.iss)) e.push('iss is required');
  if (!(nonEmpty(o.aud) || (Array.isArray(o.aud) && o.aud.length > 0 && o.aud.every(nonEmpty)))) e.push('aud must be a non-empty string or array');
  const strs = (x: unknown): x is string[] => Array.isArray(x) && x.every(nonEmpty);
  if (!strs(o.events_delivered) || o.events_delivered.length === 0) e.push('events_delivered must be a non-empty array of event type URIs');
  if (o.events_supported !== undefined && !strs(o.events_supported)) e.push('events_supported must be an array of URIs');
  if (o.events_requested !== undefined && (!strs(o.events_requested) || o.events_requested.length === 0)) e.push('events_requested must be a non-empty array of URIs');
  if (strs(o.events_delivered) && strs(o.events_supported) && !o.events_delivered.every((x) => (o.events_supported as string[]).includes(x))) e.push('events_delivered must be a subset of events_supported');
  const d = o.delivery;
  if (!d || (d.method !== DELIVERY_PUSH && d.method !== DELIVERY_POLL)) e.push('delivery.method must be the RFC 8935 or RFC 8936 URI');
  else if (typeof d.endpoint_url !== 'string' || !/^https:\/\/[^\s]+$/.test(d.endpoint_url)) e.push('delivery.endpoint_url must be an https URL');
  if (o.min_verification_interval !== undefined && !(Number.isSafeInteger(o.min_verification_interval) && o.min_verification_interval >= 0)) e.push('min_verification_interval must be a non-negative integer (seconds)');
  return e;
}

export type StreamHealthState = 'healthy' | 'degraded' | 'failing' | 'paused' | 'disabled' | 'unverified';
export interface StreamHealthReport {
  state: StreamHealthState;
  status: StreamStatusValue;
  reasons: string[];
  last_event_at?: number;
  last_verified_at?: number;
  pending_verifications: number;
  consecutive_verification_failures: number;
  rejected_verifications: number;
}
export interface StreamHealthOptions {
  /** Verification state values stay valid this long (sec). Default 60. */
  verifyTimeoutSec?: number;
  /** Healthy needs a verified round trip within this many seconds. Default 300. */
  verifiedWithinSec?: number;
  /** After this many consecutive timed-out verifications the stream is `failing`. Default 3. */
  failAfter?: number;
  /** Cap on outstanding verification states (memory bound). Default 16. */
  maxPending?: number;
}

/**
 * Receiver-side health of one stream. All times are epoch SECONDS passed in (no hidden clock).
 * A verification state is single-use, expiring, and only valid if THIS tracker issued it.
 */
export class StreamHealth {
  private statusV: StreamStatusValue = 'enabled';
  private lastEvent: number | undefined;
  private lastVerified: number | undefined;
  private lastRequested: number | undefined;
  private fails = 0;
  private rejected = 0;
  private readonly pending = new Map<string, number>();
  constructor(readonly config: StreamConfig, private readonly o: StreamHealthOptions = {}) {}

  setStatus(s: StreamStatusValue): void {
    if (!STREAM_STATUSES.includes(s)) throw new RangeError('unknown stream status');
    this.statusV = s;
  }
  /** Any valid SET arrived on this stream. */
  recordEvent(nowSec: number): void {
    this.lastEvent = Math.max(this.lastEvent ?? 0, nowSec);
  }
  /**
   * Start a verification: returns the `state` to send to the transmitter's verification endpoint, or `null` when the
   * transmitter's `min_verification_interval` has not elapsed (SSF: it would answer 429) or the stream is not enabled.
   */
  requestVerification(nowSec: number): string | null {
    if (this.statusV !== 'enabled') return null;
    const min = this.config.min_verification_interval ?? 0;
    if (this.lastRequested !== undefined && nowSec - this.lastRequested < min) return null;
    this.expire(nowSec);
    if (this.pending.size >= (this.o.maxPending ?? 16)) return null;
    const state = randomBytes(16).toString('base64url');
    this.pending.set(state, nowSec + (this.o.verifyTimeoutSec ?? 60));
    this.lastRequested = nowSec;
    return state;
  }
  /** A verification SET came back carrying `state`. True iff it matches an outstanding, unexpired request (single use). */
  ackVerification(state: unknown, nowSec: number): boolean {
    this.expire(nowSec);
    const exp = typeof state === 'string' ? this.pending.get(state) : undefined;
    if (exp === undefined) {
      this.rejected++;
      return false;
    }
    this.pending.delete(state as string);
    this.lastVerified = nowSec;
    this.lastEvent = Math.max(this.lastEvent ?? 0, nowSec);
    this.fails = 0;
    return true;
  }
  private expire(nowSec: number): void {
    for (const [k, exp] of this.pending) {
      if (nowSec > exp) {
        this.pending.delete(k);
        this.fails++;
      }
    }
  }
  report(nowSec: number): StreamHealthReport {
    this.expire(nowSec);
    const reasons: string[] = [];
    const within = this.o.verifiedWithinSec ?? 300;
    let state: StreamHealthState;
    if (this.statusV === 'disabled') { state = 'disabled'; reasons.push('stream is disabled: no events are transmitted or held'); }
    else if (this.statusV === 'paused') { state = 'paused'; reasons.push('stream is paused: events may be delayed'); }
    else if (this.fails >= (this.o.failAfter ?? 3)) { state = 'failing'; reasons.push(`${this.fails} consecutive verification requests timed out`); }
    else if (this.lastVerified === undefined) { state = 'unverified'; reasons.push('no verification round trip has completed'); }
    else if (nowSec - this.lastVerified > within) { state = 'degraded'; reasons.push(`last verified ${nowSec - this.lastVerified}s ago, over ${within}s`); }
    else state = 'healthy';
    return {
      state, status: this.statusV, reasons, pending_verifications: this.pending.size, consecutive_verification_failures: this.fails, rejected_verifications: this.rejected,
      ...(this.lastEvent !== undefined ? { last_event_at: this.lastEvent } : {}), ...(this.lastVerified !== undefined ? { last_verified_at: this.lastVerified } : {}),
    };
  }
  /**
   * May the verifier assume no pushed revocation was missed in the last `maxAgeSec`? Only if the stream is enabled and a
   * verified round trip completed inside that window. Otherwise fall back to the signed epoch pull bound.
   */
  revocationFreshWithin(maxAgeSec: number, nowSec: number): boolean {
    return this.statusV === 'enabled' && this.lastVerified !== undefined && nowSec - this.lastVerified <= maxAgeSec;
  }
}

// ---- transmitter side ---------------------------------------------------------------------------------------------------

export type VerificationOutcome =
  | { status: 204; set: string }
  | { status: 400 | 401 | 404 | 429; error: string };
/**
 * SSF 8.1.4.2: handle a verification request for a stream. 404 unknown stream, 400 malformed, 429 inside the stream's
 * `min_verification_interval`; otherwise 204 plus the signed verification SET to deliver on the stream.
 */
export async function handleVerificationRequest(
  streams: Map<string, { config: StreamConfig; lastVerification?: number }>,
  req: unknown,
  nowSec: number,
  key: SigningKey,
): Promise<VerificationOutcome> {
  const r = req as { stream_id?: unknown; state?: unknown } | null;
  if (typeof r !== 'object' || r === null || typeof r.stream_id !== 'string' || (r.state !== undefined && typeof r.state !== 'string')) return { status: 400, error: 'stream_id (string) is required; state must be a string' };
  const s = streams.get(r.stream_id);
  if (!s) return { status: 404, error: 'no such stream' };
  const min = s.config.min_verification_interval ?? 0;
  if (s.lastVerification !== undefined && nowSec - s.lastVerification < min) return { status: 429, error: 'verification requested too soon' };
  s.lastVerification = nowSec;
  const set = await buildSET({ events: { [EVENT_TYPES.verification]: r.state !== undefined ? { state: r.state } : {} }, issuer: s.config.iss, audience: s.config.aud, subject: s.config.stream_id, key });
  return { status: 204, set };
}

export interface PollRequest {
  maxEvents?: number;
  returnImmediately?: boolean;
  ack?: string[];
  setErrs?: Record<string, { err: string; description: string }>;
}
export interface PollResponse {
  sets: Record<string, string>;
  moreAvailable?: boolean;
}
/** RFC 8936 transmitter queue: retains a SET until acknowledged, retransmits unacknowledged ones, records receiver errors. */
export class PollQueue {
  private readonly q = new Map<string, string>();
  readonly errors: Array<{ jti: string; err: string; description: string }> = [];
  enqueue(jti: string, set: string): void {
    this.q.set(jti, set);
  }
  get depth(): number {
    return this.q.size;
  }
  poll(req: PollRequest): PollResponse {
    if (req.maxEvents !== undefined && !(Number.isSafeInteger(req.maxEvents) && req.maxEvents >= 0)) throw new RangeError('maxEvents must be a non-negative integer');
    for (const j of req.ack ?? []) this.q.delete(j);
    // An errored SET is released too: retransmitting a SET the receiver found invalid cannot help.
    for (const [jti, e] of Object.entries(req.setErrs ?? {})) {
      if (this.q.delete(jti)) this.errors.push({ jti, err: e.err, description: e.description });
    }
    const max = req.maxEvents ?? Infinity;
    const sets: Record<string, string> = {};
    let n = 0;
    for (const [jti, set] of this.q) {
      if (n >= max) break;
      sets[jti] = set;
      n++;
    }
    return { sets, ...(this.q.size > n ? { moreAvailable: true } : {}) };
  }
}

/** RFC 8935 receiver status for a `receiveSET` outcome: 202 on success, 400 + {err, description} otherwise. */
export function pushResponse(r: { ok: true } | { ok: false; code: string; reason: string }): { status: 202 } | { status: 400; body: { err: string; description: string } } {
  if (r.ok) return { status: 202 };
  const err = r.code === 'verify_failed' ? 'invalid_key' : r.code === 'malformed' || r.code === 'oversize' ? 'invalid_request' : r.code === 'misconfigured' || r.code === 'replay_store_error' ? 'access_denied' : 'invalid_request';
  return { status: 400, body: { err, description: r.reason } };
}

// ---- CAEP events from the decision log ------------------------------------------------------------------------------------

/** Emit `risk-level-change` (from the behavioural immune system). */
export const riskLevelChangeSET = (a: { issuer: string; audience: string | string[]; key: SigningKey; event: CaepRiskLevelChangeEvent }): Promise<string> =>
  buildSET({ issuer: a.issuer, audience: a.audience, key: a.key, events: { [EVENT_TYPES.riskLevelChange]: a.event } });

/** Emit `assurance-level-change` (from a discharge change). `change_direction` is derived when both levels are comparable. */
export function assuranceLevelChangeSET(a: { issuer: string; audience: string | string[]; key: SigningKey; event: CaepAssuranceLevelChangeEvent; order?: string[] }): Promise<string> {
  const e = { ...a.event };
  if (e.previous_level !== undefined && e.change_direction === undefined && a.order) {
    const i = a.order.indexOf(e.previous_level);
    const j = a.order.indexOf(e.current_level);
    if (i >= 0 && j >= 0 && i !== j) e.change_direction = j > i ? 'increase' : 'decrease';
  }
  return buildSET({ issuer: a.issuer, audience: a.audience, key: a.key, events: { [EVENT_TYPES.assuranceLevelChange]: e } });
}
