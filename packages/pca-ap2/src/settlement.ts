/**
 * Settlement backends: the rails PCA's governance feeds. STRUCTURAL ONLY, no network.
 *
 * A backend turns a payment mandate that has ALREADY been verified (`verifyPaymentChain` /
 * `verifyPurchase`, plus `verifyPcaBinding` for the PCA side) into the rail's wire shape. Amounts are
 * the mandate's integer minor units; nothing here accepts a decimal.
 */
import { Ap2Error } from './sdjwt';
import { currencyExponent, type Amount, type PaymentMandateClaims } from './mandates';

/** Context the caller supplies for building a rail-specific settlement payload. */
export interface SettlementContext {
  /** Protected resource URL (x402). */
  resourceUrl?: string;
  /** Payee address / account (x402 `payTo`, Stripe `on_behalf_of`). */
  payTo?: string;
  /** Rail network, e.g. an x402 chain id like `base-sepolia`. */
  network?: string;
  /** x402 `asset`: the token contract address. Defaults to the mandate's currency code (a placeholder; supply the address). */
  asset?: string;
  /** x402: decimals of the asset, used to convert the mandate amount to atomic units. Default 6 (USDC). */
  decimals?: number;
  /** x402 `maxTimeoutSeconds`: how long the payer has to complete payment. Default 60. */
  maxTimeoutSeconds?: number;
}

/**
 * Convert integer minor units to an integer string of atomic units. Scales by `10 ** (decimals - exponent)`
 * with BigInt, so no float is involved; when the asset has fewer decimals than the currency the
 * division must be exact. Throws otherwise (fail closed).
 */
export function toAtomicUnits(amount: Amount, decimals: number): string {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) throw new RangeError(`x402: decimals must be an integer in 0..18, got ${String(decimals)}`);
  if (!Number.isSafeInteger(amount.amount) || amount.amount < 0) throw new RangeError(`x402: amount ${String(amount.amount)} cannot be expressed in atomic units with ${decimals} decimals`);
  const exp = currencyExponent(amount.currency);
  const minor = BigInt(amount.amount);
  if (decimals >= exp) return String(minor * 10n ** BigInt(decimals - exp));
  const div = 10n ** BigInt(exp - decimals);
  if (minor % div !== 0n) throw new RangeError(`x402: amount ${String(amount.amount)} cannot be expressed in atomic units with ${decimals} decimals`);
  return String(minor / div);
}

/** A rail-specific settlement payload shape. No network is performed; this is the wire shape only. */
export interface SettlementInstruction {
  rail: string;
  amount: Amount;
  merchant?: string;
  /** The rail-specific payload (structural). */
  payload: Readonly<Record<string, unknown>>;
}

export interface SettlementBackend {
  readonly rail: string;
  /** Build the rail payload for a (presumed-verified) closed Payment Mandate. Pure; no network. */
  settle(payment: PaymentMandateClaims, ctx?: SettlementContext): SettlementInstruction;
}

/**
 * Coinbase x402 adapter: the HTTP 402 `Payment Required` challenge (`accepts`) plus the `X-PAYMENT`
 * request header (standard base64 of the JSON payment payload). The payload is a placeholder envelope,
 * not a signed authorization: the real rail settles on-chain.
 */
export const x402Settlement: SettlementBackend = {
  rail: 'x402',
  settle(payment, ctx) {
    const network = ctx?.network ?? 'base-sepolia';
    const requirement = {
      scheme: 'exact',
      network,
      // x402 v1: `maxAmountRequired` is a string in ATOMIC token units, not a decimal amount.
      maxAmountRequired: toAtomicUnits(payment.payment_amount, ctx?.decimals ?? 6),
      resource: ctx?.resourceUrl ?? '',
      description: `AP2 payment mandate ${payment.transaction_id}`,
      payTo: ctx?.payTo ?? payment.payee.id,
      asset: ctx?.asset ?? payment.payment_amount.currency,
      mimeType: 'application/json',
      maxTimeoutSeconds: ctx?.maxTimeoutSeconds ?? 60,
    };
    const xPayment = Buffer.from(
      JSON.stringify({
        x402Version: 1,
        scheme: 'exact',
        network,
        payload: { transactionId: payment.transaction_id, amount: payment.payment_amount.amount, currency: payment.payment_amount.currency },
      }),
      'utf8',
    ).toString('base64');
    return {
      rail: 'x402',
      amount: payment.payment_amount,
      merchant: payment.payee.id,
      payload: { httpStatus: 402, x402Version: 1, error: 'X-PAYMENT header is required', accepts: [requirement], header: { 'X-PAYMENT': xPayment } },
    };
  },
};

/**
 * Stripe Shared Payment Token adapter: a shared token the buyer's agent grants the merchant to pull a
 * bounded amount. The mandate amount is already in minor units, which is what Stripe takes. The token
 * is the mandate's payment instrument id, never a raw PAN.
 */
export const stripeSptSettlement: SettlementBackend = {
  rail: 'stripe-spt',
  settle(payment, ctx) {
    if (payment.payment_instrument.type !== 'shared_payment_token') throw new Ap2Error(`stripe-spt: the payment instrument must be of type shared_payment_token, got ${payment.payment_instrument.type}`);
    return {
      rail: 'stripe-spt',
      amount: payment.payment_amount,
      merchant: payment.payee.id,
      payload: {
        shared_payment_token: payment.payment_instrument.id,
        amount: payment.payment_amount.amount,
        currency: payment.payment_amount.currency.toLowerCase(),
        ...(ctx?.payTo ? { on_behalf_of: ctx.payTo } : {}),
      },
    };
  },
};
