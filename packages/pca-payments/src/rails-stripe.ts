// rails-stripe.ts - the Stripe Issuing adapter for the spend rails (K7).
// Sources (fetched 2026-10): https://docs.stripe.com/issuing/controls/real-time-authorizations (the `issuing_authorization.request`
// webhook; respond 200 with header `Stripe-Version` and JSON {approved, amount?} within 2 seconds, else the Authorization falls to
// your timeout / Autopilot settings), https://docs.stripe.com/issuing/controls/spending-controls (`spending_controls[spending_limits]`
// with interval per_authorization / all_time, `allowed_categories`), https://docs.stripe.com/api/issuing/authorizations/object
// (`merchant_data.category_code`, `merchant_data.network_id`, `pending_request.amount`, `card.id`), https://docs.stripe.com/webhooks
// (`Stripe-Signature: t=<unix>,v1=<hex>`; v1 = HMAC-SHA256 of `<t>.<raw body>` with the endpoint secret; default tolerance 5 minutes).
//
// REQUIRED OPERATOR SETTING: set the Issuing authorization timeout response to DECLINE and turn Autopilot off. If your endpoint is
// slow or down Stripe applies those settings, not this code. The card limits below are a second line, not a substitute.

import { createHmac, timingSafeEqual } from 'node:crypto';
import type { RailAuthorization, RailLimits, RailVerdict } from './rails';

export const STRIPE_WEBHOOK_TOLERANCE_SEC = 300;
export const STRIPE_API_VERSION = '2025-03-31.basil';

/** The form parameters for `POST /v1/issuing/cards` (virtual, active) that carry the rail limits. Throws if an MCC has no Stripe category name. */
export function stripeCardParams(limits: RailLimits, opts: { categoryNames: Readonly<Record<string, string>>; cardholder: string; metadata?: Record<string, string> }): Record<string, string> {
  const p: Record<string, string> = {
    cardholder: opts.cardholder,
    type: 'virtual',
    status: 'active',
    currency: limits.currency.toLowerCase(),
    'spending_controls[spending_limits][0][amount]': String(limits.perAuthorizationMax),
    'spending_controls[spending_limits][0][interval]': 'per_authorization',
    'spending_controls[spending_limits][1][amount]': String(limits.totalMax),
    'spending_controls[spending_limits][1][interval]': 'all_time',
  };
  limits.categories.forEach((mcc, i) => {
    const name = opts.categoryNames[mcc];
    if (name === undefined) throw new RangeError(`stripeCardParams: no Stripe category name for MCC ${mcc}`);
    p[`spending_controls[allowed_categories][${i}]`] = name;
  });
  for (const [k, v] of Object.entries(opts.metadata ?? {})) p[`metadata[${k}]`] = v;
  return p;
}

/** Verify a `Stripe-Signature` header over the RAW body. Total; false on anything malformed, stale (beyond tolerance) or mismatched. */
export function verifyStripeSignature(rawBody: string, header: string | undefined, secret: string, nowSec: number, toleranceSec: number = STRIPE_WEBHOOK_TOLERANCE_SEC): boolean {
  try {
    if (typeof header !== 'string' || typeof secret !== 'string' || secret.length === 0 || !(toleranceSec > 0)) return false;
    let t: string | undefined;
    const v1: string[] = [];
    for (const part of header.split(',')) {
      const i = part.indexOf('=');
      if (i < 0) continue;
      const k = part.slice(0, i).trim();
      const v = part.slice(i + 1).trim();
      if (k === 't') t = v;
      else if (k === 'v1') v1.push(v);
    }
    if (t === undefined || !/^[0-9]{1,12}$/.test(t) || v1.length === 0) return false;
    if (Math.abs(nowSec - Number(t)) > toleranceSec) return false;
    const want = createHmac('sha256', secret).update(`${t}.${rawBody}`, 'utf8').digest();
    return v1.some((sig) => /^[0-9a-f]{64}$/.test(sig) && timingSafeEqual(Buffer.from(sig, 'hex'), want));
  } catch {
    return false;
  }
}

/** Compute the header Stripe would send (tests and local tooling). */
export const signStripePayload = (rawBody: string, secret: string, tSec: number): string => `t=${tSec},v1=${createHmac('sha256', secret).update(`${tSec}.${rawBody}`, 'utf8').digest('hex')}`;

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj | undefined => (v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : undefined);

/** Normalise an `issuing_authorization.request` event. Undefined when it is not a well-formed request with a pending amount. */
export function stripeAuthorizationFromEvent(event: unknown): RailAuthorization | undefined {
  const e = obj(event);
  if (e?.type !== 'issuing_authorization.request') return undefined;
  const a = obj(obj(e.data)?.object);
  const pending = obj(a?.pending_request);
  const card = obj(a?.card);
  const merchant = obj(a?.merchant_data);
  if (a === undefined || pending === undefined || typeof a.id !== 'string' || typeof card?.id !== 'string') return undefined;
  const amount = pending.amount;
  const currency = pending.currency;
  if (typeof amount !== 'number' || typeof currency !== 'string') return undefined;
  return {
    id: a.id,
    instrumentId: card.id,
    amount,
    currency,
    ...(typeof merchant?.network_id === 'string' && merchant.network_id.length > 0 ? { merchantId: merchant.network_id } : {}),
    ...(typeof merchant?.category_code === 'string' ? { mcc: merchant.category_code } : {}),
  };
}

export interface HttpReply {
  status: number;
  headers: Record<string, string>;
  body: string;
}

const reply = (status: number, body: unknown, version: string): HttpReply => ({ status, headers: { 'Stripe-Version': version, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

export interface StripeWebhookOptions {
  /** The endpoint's signing secret (`whsec_...`). */
  secret: string;
  authorize: (a: RailAuthorization) => Promise<RailVerdict>;
  stripeVersion?: string;
  nowSec?: () => number;
  toleranceSec?: number;
}

/**
 * The HTTP handler body for the `issuing_authorization.request` endpoint. Bad signature: 400 (nothing is decided; Stripe applies your
 * timeout setting, which must be decline). A request event gets 200 {approved} from the PCA decision; any other event type gets 200 {}.
 * `amount` is never sent: this adapter never changes the held amount.
 */
export function createStripeIssuingWebhook(opts: StripeWebhookOptions): (req: { rawBody: string; signature: string | undefined }) => Promise<HttpReply> {
  const version = opts.stripeVersion ?? STRIPE_API_VERSION;
  const nowSec = opts.nowSec ?? (() => Math.floor(Date.now() / 1000));
  return async ({ rawBody, signature }) => {
    if (!verifyStripeSignature(rawBody, signature, opts.secret, nowSec(), opts.toleranceSec)) return reply(400, { error: 'bad_signature' }, version);
    let event: unknown;
    try { event = JSON.parse(rawBody); } catch { return reply(400, { error: 'bad_json' }, version); }
    if (obj(event)?.type !== 'issuing_authorization.request') return reply(200, {}, version);
    const auth = stripeAuthorizationFromEvent(event);
    if (auth === undefined) return reply(200, { approved: false }, version);
    const v = await opts.authorize(auth);
    return reply(200, { approved: v.approved === true }, version);
  };
}

/** Normalise an `issuing_transaction.created` capture into a settlement (the amount of a capture is negative in Stripe's ledger). */
export function stripeSettlementFromTransaction(txn: unknown): { authorizationId: string; amount: number; currency: string; merchantId?: string; captures: number } | undefined {
  const t = obj(txn);
  const m = obj(t?.merchant_data);
  if (t === undefined || t.type !== 'capture' || typeof t.authorization !== 'string' || typeof t.amount !== 'number' || typeof t.currency !== 'string') return undefined;
  return { authorizationId: t.authorization, amount: -t.amount, currency: t.currency, ...(typeof m?.network_id === 'string' ? { merchantId: m.network_id } : {}), captures: 1 };
}
