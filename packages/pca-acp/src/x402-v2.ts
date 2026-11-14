/**
 * x402 v2 alongside v1, negotiated. Source: the x402 core specification v2
 * (github.com/coinbase/x402, specs/x402-specification-v2.md): `PaymentRequired` (`x402Version: 2`, optional `error`, required
 * `resource` object and `accepts`, optional `extensions`), `PaymentRequirements` (`scheme`, `network` in CAIP-2 form, `amount`
 * in atomic units as a string, `asset`, `payTo`, `maxTimeoutSeconds`, optional `extra`), `ResourceInfo` (`url` required;
 * `description`, `mimeType`, `serviceName` printable ASCII up to 32, `tags` up to 5 of up to 32, `iconUrl` http/https up to
 * 2048) and `PaymentPayload` (`x402Version`, optional `resource`, `accepted`, scheme-specific `payload`, optional
 * `extensions`). The v2 `PAYMENT-REQUIRED` HTTP header carries the base64 `PaymentRequired` object. v1 stays in `./index`
 * (`x402Challenge`). This module performs no I/O.
 */

export const X402_VERSION_1 = 1 as const;
export const X402_VERSION_2 = 2 as const;
/** Versions this package can speak, newest first. */
export const X402_SUPPORTED_VERSIONS: readonly number[] = [2, 1];
export const X402_V2_PAYMENT_REQUIRED_HEADER = 'PAYMENT-REQUIRED';

export interface X402ResourceInfo {
  url: string;
  description?: string;
  mimeType?: string;
  serviceName?: string;
  tags?: string[];
  iconUrl?: string;
}

export interface X402RequirementV2 {
  scheme: string;
  /** CAIP-2 chain id, e.g. `eip155:84532`. */
  network: string;
  /** Atomic units, decimal string. */
  amount: string;
  /** Token contract address, or an ISO 4217 code for fiat. */
  asset: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra?: Record<string, unknown>;
}

export interface X402PaymentRequiredV2 {
  x402Version: 2;
  error?: string;
  resource: X402ResourceInfo;
  accepts: X402RequirementV2[];
  extensions?: Record<string, { info: Record<string, unknown>; schema: Record<string, unknown> }>;
}

const CAIP2 = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;
const ASCII_PRINTABLE = /^[\x20-\x7e]*$/;
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const nonEmpty = (v: unknown): v is string => typeof v === 'string' && v.length > 0;

function absoluteHttp(u: unknown): u is string {
  if (typeof u !== 'string') return false;
  try {
    const p = new URL(u).protocol;
    return p === 'https:' || p === 'http:';
  } catch {
    return false;
  }
}

/** Problems with a `ResourceInfo` (empty = valid). */
export function resourceInfoProblems(r: unknown): string[] {
  if (!isObj(r)) return ['resource must be an object'];
  const p: string[] = [];
  if (!absoluteHttp(r.url)) p.push('resource.url must be an absolute http(s) URL');
  for (const k of ['description', 'mimeType'] as const) if (r[k] !== undefined && typeof r[k] !== 'string') p.push(`resource.${k} must be a string`);
  if (r.serviceName !== undefined && !(typeof r.serviceName === 'string' && r.serviceName.length <= 32 && ASCII_PRINTABLE.test(r.serviceName))) p.push('resource.serviceName must be printable ASCII up to 32 characters');
  if (r.tags !== undefined && !(Array.isArray(r.tags) && r.tags.length <= 5 && r.tags.every((t) => typeof t === 'string' && t.length <= 32 && ASCII_PRINTABLE.test(t)))) p.push('resource.tags must be up to 5 printable ASCII strings of up to 32 characters');
  if (r.iconUrl !== undefined && !(absoluteHttp(r.iconUrl) && (r.iconUrl as string).length <= 2048)) p.push('resource.iconUrl must be an absolute http(s) URL up to 2048 characters');
  return p;
}

/** Problems with one v2 `PaymentRequirements` (empty = valid). */
export function requirementV2Problems(q: unknown): string[] {
  if (!isObj(q)) return ['requirements must be an object'];
  const p: string[] = [];
  if (!nonEmpty(q.scheme)) p.push('scheme is required');
  if (typeof q.network !== 'string' || !CAIP2.test(q.network)) p.push('network must be a CAIP-2 identifier');
  if (typeof q.amount !== 'string' || !/^(0|[1-9][0-9]*)$/.test(q.amount) || q.amount === '0') p.push('amount must be a positive decimal string of atomic units');
  if (!nonEmpty(q.asset)) p.push('asset is required');
  if (!nonEmpty(q.payTo)) p.push('payTo is required');
  if (typeof q.maxTimeoutSeconds !== 'number' || !Number.isSafeInteger(q.maxTimeoutSeconds) || q.maxTimeoutSeconds <= 0) p.push('maxTimeoutSeconds must be a positive integer');
  if (q.extra !== undefined && !isObj(q.extra)) p.push('extra must be an object');
  return p;
}

/** Problems with a v2 `PaymentRequired` (empty = valid). */
export function paymentRequiredV2Problems(pr: unknown): string[] {
  if (!isObj(pr)) return ['PaymentRequired must be an object'];
  const p: string[] = [];
  if (pr.x402Version !== 2) p.push('x402Version must be 2');
  if (pr.error !== undefined && typeof pr.error !== 'string') p.push('error must be a string');
  p.push(...resourceInfoProblems(pr.resource));
  if (!Array.isArray(pr.accepts) || pr.accepts.length === 0) p.push('accepts must be a non-empty array');
  else pr.accepts.forEach((q, i) => p.push(...requirementV2Problems(q).map((m) => `accepts[${i}].${m}`)));
  if (pr.extensions !== undefined) {
    if (!isObj(pr.extensions)) p.push('extensions must be an object');
    else for (const [k, v] of Object.entries(pr.extensions)) if (!isObj(v) || !isObj(v.info) || !isObj(v.schema)) p.push(`extensions.${k} needs info and schema objects`);
  }
  return p;
}

export interface X402ChallengeV2Options {
  amount: number;
  /** ISO 4217 code or token address. */
  asset: string;
  payTo: string;
  /** CAIP-2 chain id (required in v2; there is no default network). */
  network: string;
  scheme?: string;
  maxTimeoutSeconds?: number;
  extra?: Record<string, unknown>;
  error?: string;
  extensions?: X402PaymentRequiredV2['extensions'];
}

export interface X402ChallengeV2 {
  status: 402;
  headers: Record<string, string>;
  body: X402PaymentRequiredV2;
}

const b64 = (s: string): string => Buffer.from(s, 'utf8').toString('base64');

/** Encode a `PaymentRequired` for the `PAYMENT-REQUIRED` header (validates first; throws on a problem). */
export function encodePaymentRequiredHeader(pr: X402PaymentRequiredV2): string {
  const problems = paymentRequiredV2Problems(pr);
  if (problems.length > 0) throw new TypeError(`x402: ${problems.join('; ')}`);
  return b64(JSON.stringify(pr));
}

/** Decode and validate a `PAYMENT-REQUIRED` header value. Throws `TypeError` on bad base64, bad JSON or an invalid object. */
export function decodePaymentRequiredHeader(value: string): X402PaymentRequiredV2 {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new TypeError('x402: PAYMENT-REQUIRED is not base64');
  let doc: unknown;
  try {
    doc = JSON.parse(Buffer.from(value, 'base64').toString('utf8'));
  } catch {
    throw new TypeError('x402: PAYMENT-REQUIRED is not JSON');
  }
  const problems = paymentRequiredV2Problems(doc);
  if (problems.length > 0) throw new TypeError(`x402: ${problems.join('; ')}`);
  return doc as X402PaymentRequiredV2;
}

/** Build the v2 402 challenge: JSON body plus the base64 `PAYMENT-REQUIRED` header. Refuses anything the v2 spec makes invalid. */
export function x402ChallengeV2(resource: string | X402ResourceInfo, opts: X402ChallengeV2Options): X402ChallengeV2 {
  if (!Number.isSafeInteger(opts.amount) || opts.amount <= 0) throw new TypeError('x402Challenge: amount must be a positive integer in atomic units');
  const info: X402ResourceInfo = typeof resource === 'string' ? { url: resource } : { ...resource };
  const body: X402PaymentRequiredV2 = {
    x402Version: 2,
    error: opts.error ?? 'PAYMENT-SIGNATURE header is required',
    resource: info,
    accepts: [{
      scheme: opts.scheme ?? 'exact',
      network: opts.network,
      amount: String(opts.amount),
      asset: opts.asset,
      payTo: opts.payTo,
      maxTimeoutSeconds: opts.maxTimeoutSeconds ?? 60,
      ...(opts.extra !== undefined ? { extra: opts.extra } : {}),
    }],
    ...(opts.extensions !== undefined ? { extensions: opts.extensions } : {}),
  };
  const header = encodePaymentRequiredHeader(body); // validates
  return { status: 402, headers: { 'Content-Type': 'application/json', [X402_V2_PAYMENT_REQUIRED_HEADER]: header }, body };
}

/**
 * Version negotiation. `offered` is what the client says it speaks (for example the versions it lists, or `[1]` for a client
 * that sends nothing). Returns the highest version both sides support, or `undefined` when there is none (answer 402 v1 with
 * an error, never guess).
 */
export function x402Negotiate(offered: readonly number[] | undefined, supported: readonly number[] = X402_SUPPORTED_VERSIONS): 1 | 2 | undefined {
  const mine = supported.filter((v): v is 1 | 2 => v === 1 || v === 2);
  const theirs = offered === undefined || offered.length === 0 ? [1] : offered;
  return [...mine].sort((a, b) => b - a).find((v) => theirs.includes(v));
}

const stable = (v: unknown): string => {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(stable).join(',')}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${stable(o[k])}`).join(',')}}`;
};

/** True when `accepted` (echoed by the client in its v2 payload) is exactly one of the requirements the server offered. */
export function x402AcceptedMatches(offered: readonly X402RequirementV2[], accepted: unknown): boolean {
  if (requirementV2Problems(accepted).length > 0) return false;
  const a = stable(accepted);
  return offered.some((o) => stable(o) === a);
}

/** What the settlement code needs from a payload of either version. */
export type NormalizedX402Payload =
  | { ok: true; version: 1 | 2; token: string; merchant?: string; amount?: number; accepted?: X402RequirementV2 }
  | { ok: false; reason: string };

/**
 * Read a client payload of either version. v1: the token, merchant and amount are top-level members. v2: the delegated
 * token is `payload.token` (scheme-specific payload), and the echoed `accepted` must be a valid v2 requirement; the merchant
 * is never read from a v2 payload and the amount only from `accepted.amount`. Anything else is `{ ok: false }`.
 */
export function normalizeX402Payload(raw: unknown): NormalizedX402Payload {
  if (!isObj(raw)) return { ok: false, reason: 'x402 payment payload is not an object' };
  if (raw.x402Version === 2) {
    const inner = raw.payload;
    if (!isObj(inner) || typeof inner.token !== 'string' || inner.token.length === 0) return { ok: false, reason: 'x402 v2 payload is missing payload.token' };
    const problems = requirementV2Problems(raw.accepted);
    if (problems.length > 0) return { ok: false, reason: `x402 v2 payload.accepted is invalid: ${problems.join('; ')}` };
    const accepted = raw.accepted as X402RequirementV2;
    const amount = Number(accepted.amount);
    return { ok: true, version: 2, token: inner.token, accepted, ...(Number.isSafeInteger(amount) ? { amount } : {}) };
  }
  if (raw.x402Version !== undefined && raw.x402Version !== 1) return { ok: false, reason: `unsupported x402Version ${String(raw.x402Version)}` };
  if (typeof raw.token !== 'string') return { ok: false, reason: 'x402 payment payload is missing a token' };
  return {
    ok: true,
    version: 1,
    token: raw.token,
    ...(typeof raw.merchant === 'string' ? { merchant: raw.merchant } : {}),
    ...(typeof raw.amount === 'number' ? { amount: raw.amount } : {}),
  };
}
