/**
 * Typed step-up lifecycle events + signed webhooks for Proof-Carrying Authority.
 *
 * When a PCActn needs a human in the loop, Atlas runs a step-up ceremony: a grant is created, then
 * approved, denied, or left to expire. This package turns those four moments into small, content-addressed
 * events you can serialize, HMAC-sign, and ship to your own inbox, Slack bot, or audit sink — then verify
 * on the way in.
 *
 * HONEST: this does not decide anything. It is a transport contract — a stable event shape plus a
 * Stripe-style webhook signature so the receiver can tell a real delivery from a forged or replayed one.
 * The authority decision still lives in the PCA verifier; these events only report what it already did.
 *
 * Runtime-portable: no `node:crypto`. HMAC-SHA256 comes from `@noble/hashes`, so the same code verifies
 * a delivery in a browser, an edge worker, or Node.
 */

import { type ReplayStore, hashCanonical, replayKey } from '@atlasauth/pca';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// ---- events -----------------------------------------------------------------------------------

export type StepUpEventType = 'step_up.created' | 'step_up.approved' | 'step_up.denied' | 'step_up.expired';

export interface StepUpEvent {
  /** Content-addressed id: a digest of every other field, so the same event always has the same id. */
  id: string;
  type: StepUpEventType;
  /** Unix epoch milliseconds the event happened. */
  at: number;
  /** Reference to the grant this ceremony is about. */
  grant_ref: string;
  action: { verb: string; resource: string };
  /** Step-up assurance tier the ceremony required. */
  tier: 2 | 3;
  /** Who approved or denied — present on `step_up.approved` / `step_up.denied`. */
  actor?: string;
}

const EVENT_TYPES: readonly StepUpEventType[] = [
  'step_up.created',
  'step_up.approved',
  'step_up.denied',
  'step_up.expired',
];

function isStepUpEventType(x: unknown): x is StepUpEventType {
  return typeof x === 'string' && (EVENT_TYPES as readonly string[]).includes(x);
}

/** base64url(sha256(strictCanonical(fields))) — domain-separated so ids never collide across event kinds. */
function eventId(e: Omit<StepUpEvent, 'id'>): string {
  return hashCanonical({
    d: 'atlas-pca/stepup-event/v1',
    type: e.type,
    at: e.at,
    grant_ref: e.grant_ref,
    action: { verb: e.action.verb, resource: e.action.resource },
    tier: e.tier,
    ...(e.actor !== undefined ? { actor: e.actor } : {}),
  });
}

/**
 * Build a step-up event, filling `at` (defaults to `Date.now()`) and deriving a content-addressed `id`
 * from every other field. Two builds with the same inputs produce the same id.
 */
export function buildStepUpEvent(
  type: StepUpEventType,
  data: Omit<StepUpEvent, 'id' | 'at'> & { at?: number },
): StepUpEvent {
  const base: Omit<StepUpEvent, 'id'> = {
    type,
    at: data.at ?? Date.now(),
    grant_ref: data.grant_ref,
    action: { verb: data.action.verb, resource: data.action.resource },
    tier: data.tier,
    ...(data.actor !== undefined ? { actor: data.actor } : {}),
  };
  return { ...base, id: eventId(base) };
}

/** JSON wire form. */
export function serializeEvent(e: StepUpEvent): string {
  return JSON.stringify(e);
}

/** Parse + validate a JSON step-up event. Throws on anything that is not a well-formed event. */
export function parseEvent(s: string): StepUpEvent {
  const raw: unknown = JSON.parse(s);
  if (typeof raw !== 'object' || raw === null) throw new Error('parseEvent: not an object');
  const o = raw as Record<string, unknown>;

  if (typeof o.id !== 'string' || o.id.length === 0) throw new Error('parseEvent: bad id');
  if (!isStepUpEventType(o.type)) throw new Error('parseEvent: bad type');
  if (typeof o.at !== 'number' || !Number.isFinite(o.at)) throw new Error('parseEvent: bad at');
  if (typeof o.grant_ref !== 'string') throw new Error('parseEvent: bad grant_ref');

  const action = o.action;
  if (typeof action !== 'object' || action === null) throw new Error('parseEvent: bad action');
  const a = action as Record<string, unknown>;
  if (typeof a.verb !== 'string' || typeof a.resource !== 'string') {
    throw new Error('parseEvent: bad action fields');
  }

  let tier: 2 | 3;
  if (o.tier === 2) tier = 2;
  else if (o.tier === 3) tier = 3;
  else throw new Error('parseEvent: bad tier');

  const actor = o.actor;
  if (actor !== undefined && typeof actor !== 'string') throw new Error('parseEvent: bad actor');

  const event: StepUpEvent = {
    id: o.id,
    type: o.type,
    at: o.at,
    grant_ref: o.grant_ref,
    action: { verb: a.verb, resource: a.resource },
    tier,
    ...(actor !== undefined ? { actor } : {}),
  };
  // The id is a content address. An event whose id is not the digest of its fields was edited or forged.
  const { id: _id, ...fields } = event;
  if (eventId(fields) !== event.id) throw new Error('parseEvent: id does not match the event content');
  return event;
}

// ---- signed webhooks --------------------------------------------------------------------------

/** Constant-time equality over two byte arrays (length-independent short-circuit only on mismatch). */
function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/** Smallest secret accepted. A short or empty HMAC key makes every signature guessable. */
export const MIN_SECRET_BYTES = 16;
const MAX_HEADER_CHARS = 2048;

function secretBytes(secret: string | Uint8Array): Uint8Array | null {
  const b = typeof secret === 'string' ? new TextEncoder().encode(secret) : secret;
  return b instanceof Uint8Array && b.length >= MIN_SECRET_BYTES ? b : null;
}

/** Parse `t=<digits>,v1=<hex>[,v1=<hex>...]`. Several `v1` are allowed (secret rotation); two different `t` are not. */
function parseSignatureHeader(h: string): { t: number; v1: string[] } | null {
  if (typeof h !== 'string' || h.length > MAX_HEADER_CHARS) return null;
  let t: number | undefined;
  const v1: string[] = [];
  for (const part of h.split(',')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    const val = part.slice(eq + 1).trim();
    if (key === 't') {
      if (!/^\d{1,15}$/.test(val)) return null;
      const n = Number(val);
      if (t !== undefined && t !== n) return null;
      t = n;
    } else if (key === 'v1') {
      v1.push(val);
    }
  }
  if (t === undefined || v1.length === 0) return null;
  return { t, v1 };
}

/**
 * Stripe-style signature for a webhook payload: `t=<unixSeconds>,v1=<hex HMAC-SHA256 of "<t>.<payload>">`.
 * Pass `opts.timestamp` to pin the second count (otherwise `Date.now()` in seconds). Throws on a secret shorter
 * than {@link MIN_SECRET_BYTES} bytes and on a timestamp that is not a non-negative integer; the error never
 * contains the secret.
 */
export function signWebhook(
  secret: string | Uint8Array,
  payload: string,
  opts?: { timestamp?: number },
): string {
  const key = secretBytes(secret);
  if (key === null) throw new RangeError(`signWebhook: the secret must be at least ${MIN_SECRET_BYTES} bytes`);
  const t = opts?.timestamp ?? Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(t) || t < 0) throw new RangeError('signWebhook: timestamp must be a non-negative integer (unix seconds)');
  const mac = hmac(sha256, key, `${t}.${payload}`);
  return `t=${t},v1=${bytesToHex(mac)}`;
}

/**
 * Verify a signature header against the payload. Recomputes the HMAC, compares it constant-time, and
 * enforces the timestamp tolerance (default 300s). Returns false — never throws — on a malformed header,
 * a bad signature, a stale timestamp, a secret that is too short, or a tolerance / clock that is not a finite
 * non-negative number. With several `v1` entries (secret rotation) any one may match. Pass `opts.now` (unix
 * seconds) to pin the clock. A valid signature is not proof of freshness beyond the tolerance window; use
 * {@link verifyDelivery} to also refuse a replay.
 */
export function verifyWebhook(
  secret: string | Uint8Array,
  payload: string,
  signatureHeader: string,
  opts?: { toleranceSec?: number; now?: number },
): boolean {
  try {
    const key = secretBytes(secret);
    if (key === null) return false;
    const parsed = parseSignatureHeader(signatureHeader);
    if (!parsed) return false;

    const toleranceSec = opts?.toleranceSec ?? 300;
    const now = opts?.now ?? Math.floor(Date.now() / 1000);
    if (!Number.isFinite(toleranceSec) || toleranceSec < 0 || !Number.isFinite(now)) return false;
    if (Math.abs(now - parsed.t) > toleranceSec) return false;

    const expected = hmac(sha256, key, `${parsed.t}.${payload}`);
    let match = false;
    for (const v of parsed.v1) {
      let provided: Uint8Array;
      try {
        provided = hexToBytes(v);
      } catch {
        continue;
      }
      if (timingSafeEqualBytes(expected, provided)) match = true; // no early exit: every candidate costs the same
    }
    return match;
  } catch {
    return false;
  }
}

export type DeliveryVerdict = { ok: true; event: StepUpEvent } | { ok: false; reason: string };

/**
 * Accept one webhook delivery: signature and freshness ({@link verifyWebhook}), a well-formed event whose id matches
 * its content ({@link parseEvent}), and a first sight of that event id (`replay.consumeOnce`). A store that throws
 * refuses. Never throws, and no reason contains the secret or the payload.
 */
export async function verifyDelivery(
  secret: string | Uint8Array,
  payload: string,
  signatureHeader: string,
  opts: { replay: ReplayStore; toleranceSec?: number; now?: number },
): Promise<DeliveryVerdict> {
  try {
    if (!opts || typeof opts.replay?.consumeOnce !== 'function') return { ok: false, reason: 'a replay store is required' };
    if (!verifyWebhook(secret, payload, signatureHeader, opts)) return { ok: false, reason: 'bad signature' };
    let event: StepUpEvent;
    try {
      event = parseEvent(payload);
    } catch (e) {
      return { ok: false, reason: (e as Error).message };
    }
    const sig = parseSignatureHeader(signatureHeader)!;
    const nowSec = opts.now ?? Math.floor(Date.now() / 1000);
    const tolerance = opts.toleranceSec ?? 300;
    try {
      const first = await opts.replay.consumeOnce(replayKey('pca-stepup-event/v1', event.id), (sig.t + tolerance) * 1000 + 1, nowSec * 1000);
      if (!first) return { ok: false, reason: 'replayed delivery' };
    } catch {
      return { ok: false, reason: 'replay store unavailable' };
    }
    return { ok: true, event };
  } catch {
    return { ok: false, reason: 'bad signature' };
  }
}

/** Convenience: the headers to attach to an outbound webhook POST. */
export function webhookHeaders(
  secret: string | Uint8Array,
  payload: string,
  opts?: { timestamp?: number },
): Record<string, string> {
  return {
    'PCA-Signature': signWebhook(secret, payload, opts),
    'content-type': 'application/json',
  };
}
