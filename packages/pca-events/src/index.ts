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

import { hashCanonical } from '@atlasauth/pca';
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

  return {
    id: o.id,
    type: o.type,
    at: o.at,
    grant_ref: o.grant_ref,
    action: { verb: a.verb, resource: a.resource },
    tier,
    ...(actor !== undefined ? { actor } : {}),
  };
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

function parseSignatureHeader(h: string): { t: number; v1: string } | null {
  let t: number | undefined;
  let v1: string | undefined;
  for (const part of h.split(',')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    const val = part.slice(eq + 1).trim();
    if (key === 't') {
      const n = Number(val);
      if (val.length > 0 && Number.isFinite(n)) t = n;
    } else if (key === 'v1') {
      v1 = val;
    }
  }
  if (t === undefined || v1 === undefined) return null;
  return { t, v1 };
}

/**
 * Stripe-style signature for a webhook payload: `t=<unixSeconds>,v1=<hex HMAC-SHA256 of "<t>.<payload>">`.
 * Pass `opts.timestamp` to pin the second count (otherwise `Date.now()` in seconds).
 */
export function signWebhook(
  secret: string | Uint8Array,
  payload: string,
  opts?: { timestamp?: number },
): string {
  const t = opts?.timestamp ?? Math.floor(Date.now() / 1000);
  const mac = hmac(sha256, secret, `${t}.${payload}`);
  return `t=${t},v1=${bytesToHex(mac)}`;
}

/**
 * Verify a signature header against the payload. Recomputes the HMAC, compares it constant-time, and
 * enforces the timestamp tolerance (default 300s). Returns false — never throws — on a malformed header,
 * a bad signature, or a stale timestamp. Pass `opts.now` (unix seconds) to pin the clock.
 */
export function verifyWebhook(
  secret: string | Uint8Array,
  payload: string,
  signatureHeader: string,
  opts?: { toleranceSec?: number; now?: number },
): boolean {
  try {
    const parsed = parseSignatureHeader(signatureHeader);
    if (!parsed) return false;

    const toleranceSec = opts?.toleranceSec ?? 300;
    const now = opts?.now ?? Math.floor(Date.now() / 1000);
    if (Math.abs(now - parsed.t) > toleranceSec) return false;

    let provided: Uint8Array;
    try {
      provided = hexToBytes(parsed.v1);
    } catch {
      return false;
    }

    const expected = hmac(sha256, secret, `${parsed.t}.${payload}`);
    return timingSafeEqualBytes(expected, provided);
  } catch {
    return false;
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
