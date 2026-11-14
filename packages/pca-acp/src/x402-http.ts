/**
 * x402 v2 HTTP transport. Source: the x402 HTTP transport specification v2 (github.com/coinbase/x402,
 * `specs/transports-v2/http.md`): three headers, each the base64 of a JSON object. `PAYMENT-REQUIRED` (server to client,
 * with status 402, see `./x402-v2`), `PAYMENT-SIGNATURE` (client to server, the `PaymentPayload`) and `PAYMENT-RESPONSE`
 * (server to client, the `SettlementResponse`). Status codes: 402 payment required, 400 malformed payload or requirements,
 * 402 verification or settlement failed, 500 internal error, 200 verified and settled. The body is the server's. The object
 * shapes are those of the x402 core specification v2 (`specs/x402-specification-v2.md`). No I/O.
 */
import { type X402RequirementV2, type X402ResourceInfo, requirementV2Problems, resourceInfoProblems } from './x402-v2';

export const X402_PAYMENT_SIGNATURE_HEADER = 'PAYMENT-SIGNATURE';
export const X402_PAYMENT_RESPONSE_HEADER = 'PAYMENT-RESPONSE';

export interface X402PaymentPayloadV2 {
  x402Version: 2;
  resource?: X402ResourceInfo;
  accepted: X402RequirementV2;
  /** Scheme-specific; for the delegated token scheme this is `{ token }`. */
  payload: Record<string, unknown>;
  extensions?: Record<string, unknown>;
}

export interface X402SettlementResponse {
  success: boolean;
  errorReason?: string;
  payer?: string;
  /** Empty string when nothing was broadcast. */
  transaction: string;
  /** CAIP-2. */
  network: string;
  /** Actual settled amount in atomic units. */
  amount?: string;
  extensions?: Record<string, unknown>;
}

const CAIP2 = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/** Problems with a v2 `PaymentPayload` (empty = valid). */
export function paymentPayloadV2Problems(p: unknown): string[] {
  if (!isObj(p)) return ['PaymentPayload must be an object'];
  const out: string[] = [];
  if (p.x402Version !== 2) out.push('x402Version must be 2');
  if (p.resource !== undefined) out.push(...resourceInfoProblems(p.resource));
  out.push(...requirementV2Problems(p.accepted).map((m) => `accepted.${m}`));
  if (!isObj(p.payload)) out.push('payload must be an object');
  if (p.extensions !== undefined && !isObj(p.extensions)) out.push('extensions must be an object');
  return out;
}

/** Problems with a `SettlementResponse` (empty = valid). A success must not carry an `errorReason`; a failure must. */
export function settlementResponseProblems(r: unknown): string[] {
  if (!isObj(r)) return ['SettlementResponse must be an object'];
  const out: string[] = [];
  if (typeof r.success !== 'boolean') out.push('success must be a boolean');
  if (typeof r.transaction !== 'string') out.push('transaction must be a string');
  else if (r.success === true && r.transaction === '') out.push('a successful settlement needs a transaction');
  if (typeof r.network !== 'string' || !CAIP2.test(r.network)) out.push('network must be a CAIP-2 identifier');
  if (r.errorReason !== undefined && typeof r.errorReason !== 'string') out.push('errorReason must be a string');
  if (r.success === true && r.errorReason !== undefined) out.push('errorReason must be omitted on success');
  if (r.success === false && (typeof r.errorReason !== 'string' || r.errorReason === '')) out.push('errorReason is required on failure');
  if (r.payer !== undefined && typeof r.payer !== 'string') out.push('payer must be a string');
  if (r.amount !== undefined && !(typeof r.amount === 'string' && /^(0|[1-9][0-9]*)$/.test(r.amount))) out.push('amount must be a decimal string of atomic units');
  if (r.extensions !== undefined && !isObj(r.extensions)) out.push('extensions must be an object');
  return out;
}

const encodeHeader = (obj: unknown, problems: string[]): string => {
  if (problems.length > 0) throw new TypeError(`x402: ${problems.join('; ')}`);
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64');
};

const decodeHeader = (value: unknown, name: string): unknown => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new TypeError(`x402: ${name} is not base64`);
  try {
    return JSON.parse(Buffer.from(value, 'base64').toString('utf8'));
  } catch {
    throw new TypeError(`x402: ${name} is not JSON`);
  }
};

/** Encode a `PaymentPayload` for the `PAYMENT-SIGNATURE` request header (validates first; throws `TypeError`). */
export function encodePaymentSignatureHeader(p: X402PaymentPayloadV2): string {
  return encodeHeader(p, paymentPayloadV2Problems(p));
}

/** Decode and validate a `PAYMENT-SIGNATURE` header value. Throws `TypeError` on bad base64, bad JSON or an invalid object. */
export function decodePaymentSignatureHeader(value: string): X402PaymentPayloadV2 {
  const doc = decodeHeader(value, 'PAYMENT-SIGNATURE');
  const problems = paymentPayloadV2Problems(doc);
  if (problems.length > 0) throw new TypeError(`x402: ${problems.join('; ')}`);
  return doc as X402PaymentPayloadV2;
}

/** Encode a `SettlementResponse` for the `PAYMENT-RESPONSE` response header. */
export function encodePaymentResponseHeader(r: X402SettlementResponse): string {
  return encodeHeader(r, settlementResponseProblems(r));
}

/** Decode and validate a `PAYMENT-RESPONSE` header value. */
export function decodePaymentResponseHeader(value: string): X402SettlementResponse {
  const doc = decodeHeader(value, 'PAYMENT-RESPONSE');
  const problems = settlementResponseProblems(doc);
  if (problems.length > 0) throw new TypeError(`x402: ${problems.join('; ')}`);
  return doc as X402SettlementResponse;
}

/** The HTTP status for each x402 outcome (transport specification, "Status codes"). */
export const X402_HTTP_STATUS = {
  payment_required: 402,
  malformed: 400,
  failed: 402,
  internal_error: 500,
  settled: 200,
} as const;

/** Case-insensitive header lookup over a plain header record (first value of an array). */
function header(headers: Record<string, string | string[] | undefined>, name: string): string | undefined {
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === name.toLowerCase()) return Array.isArray(v) ? v[0] : v;
  }
  return undefined;
}

export type PaymentSignatureRead =
  | { ok: true; payload: X402PaymentPayloadV2 }
  | { ok: false; status: 400 | 402; reason: string };

/**
 * Server side: read the client's `PAYMENT-SIGNATURE` header from a request. A missing header is 402 (payment required, answer
 * with a `PAYMENT-REQUIRED` challenge); a present but undecodable or invalid one is 400 (malformed). Never throws.
 */
export function readPaymentSignature(headers: Record<string, string | string[] | undefined>): PaymentSignatureRead {
  const v = header(headers, X402_PAYMENT_SIGNATURE_HEADER);
  if (v === undefined || v === '') return { ok: false, status: X402_HTTP_STATUS.payment_required, reason: 'PAYMENT-SIGNATURE header is required' };
  try {
    return { ok: true, payload: decodePaymentSignatureHeader(v) };
  } catch (e) {
    return { ok: false, status: X402_HTTP_STATUS.malformed, reason: (e as Error).message };
  }
}

export interface X402HttpResponse {
  status: 200 | 402 | 500;
  headers: Record<string, string>;
}

/**
 * Server side: the status and `PAYMENT-RESPONSE` header for a settlement outcome. A success is 200 and needs the transaction;
 * a failure is 402 with `success: false`, the reason and an empty transaction unless one was broadcast. `network` is the CAIP-2
 * id the payment was made on. Throws `TypeError` if the response would be invalid.
 */
export function x402SettlementResponse(
  outcome: { settled: true; transaction: string; payer?: string; amount?: string } | { settled: false; reason: string; transaction?: string; payer?: string },
  network: string,
): X402HttpResponse {
  const body: X402SettlementResponse = outcome.settled
    ? { success: true, transaction: outcome.transaction, network, ...(outcome.payer !== undefined ? { payer: outcome.payer } : {}), ...(outcome.amount !== undefined ? { amount: outcome.amount } : {}) }
    : { success: false, errorReason: outcome.reason, transaction: outcome.transaction ?? '', network, ...(outcome.payer !== undefined ? { payer: outcome.payer } : {}) };
  return {
    status: outcome.settled ? X402_HTTP_STATUS.settled : X402_HTTP_STATUS.failed,
    headers: { [X402_PAYMENT_RESPONSE_HEADER]: encodePaymentResponseHeader(body) },
  };
}

/** Client side: the request header to attach on the retry, from a payload built for an offered requirement. */
export function x402PaymentSignatureHeaders(p: X402PaymentPayloadV2): Record<string, string> {
  return { [X402_PAYMENT_SIGNATURE_HEADER]: encodePaymentSignatureHeader(p) };
}
