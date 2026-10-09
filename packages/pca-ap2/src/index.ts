/**
 * @atlasauth/pca-ap2 — an AP2-modelled (Agent Payments Protocol) mandate chain for PCA.
 *
 * ┌──────────────────────────────────────────────────────────────────────────────────────────────┐
 * │  PCA GOVERNS. AP2 is the payment-MANDATE wire. x402 / Stripe Shared-Payment-Tokens SETTLE.      │
 * └──────────────────────────────────────────────────────────────────────────────────────────────┘
 *
 * AP2 (donated to the FIDO Alliance, v0.2 shape, 2026-04-28) standardizes agentic payments as a chain
 * of signed Verifiable Digital Credentials (VDCs):
 *
 *     IntentMandate  →  CartMandate  →  PaymentMandate
 *     (the user's      (the merchant's  (the payment authorization +
 *      goal + caps)     concrete cart)   human-present / not-present signal)
 *
 * This is a near-isomorphism of PCA's attenuating capability chain: the Root Intent Grant bounds the
 * authority; each narrowing step may only RESTRICT it, never amplify it. PCA's trust-budget + risk
 * policy (`@atlasauth/pca-payments`) decide WHETHER a charge is autonomous (tier 1) or needs a human
 * co-sign (tier 3); AP2 carries that decision on the wire; the settlement rail moves the money.
 *
 * This is a BRIDGE, not a replacement:
 *   - PCA  = the authority / budget layer (who may spend, how much, until when, before a human co-sign).
 *   - AP2  = the payment-mandate wire (the Intent→Cart→Payment VDC chain other parties verify).
 *   - x402 / Stripe SPT = the settlement rails that actually move value, fed by PCA's governance.
 * Compose them; do not fold one into another.
 *
 * ────────────────────────────────────────────────────────────────────────────────────────────────
 * HONEST CAVEAT — VERIFY BEFORE PRODUCTION WIRE USE
 * ────────────────────────────────────────────────────────────────────────────────────────────────
 * AP2 is a moving target and its mandate field-level signing roles differ between secondary sources
 * (e.g. whether a cart is co-signed by both merchant and user, and whether the step is called "Cart"
 * or "Checkout"). The spec also layers over UCP (ucp.dev) whose dated releases move the payment token
 * between `payment_data.token` and `payment.instruments[*].credential.token`. This module models the
 * v0.2 Intent/Cart/Payment chain to the best public understanding; it MUST be validated against the
 * AP2 repository `schemas/` (and the official spec at ap2-protocol.org) before any production wire use.
 * That validation has now been run (see conformance.test.ts): the output does NOT conform to the current
 * official SD-JWT mandate schemas, so treat this as a PCA rendition of the concepts, not the AP2 wire format.
 * PCA-native terms that AP2 has no field for are carried in a namespaced `x_pca` extension so the chain
 * can round-trip back to PCA terms; those fields are non-standard by construction.
 */

import {
  canonicalBytes,
  encodeSig,
  hashCanonical,
  sign,
  verifyB64u,
} from '@atlasauth/pca';
import type { MandateTerms, PaymentMandate as PcaPaymentMandate } from '@atlasauth/pca-payments';

// ===================================================================================================
// AP2 version pin
// ===================================================================================================

/** The AP2 shape this module models. See the HONEST CAVEAT above. */
export const AP2_VERSION = '0.2' as const;

/**
 * Illustrative JSON-LD contexts for the VDC envelope. The second entry is a placeholder for the AP2
 * context URL — replace with the canonical context from the AP2 repo before production.
 */
export const AP2_CONTEXT: readonly string[] = [
  'https://www.w3.org/2018/credentials/v1',
  'https://ap2-protocol.org/context/v0.2',
];

// ===================================================================================================
// Verifiable Digital Credential envelope
// ===================================================================================================

/** ISO-4217 currency + decimal value (use minor units in production to avoid float drift). */
export interface MonetaryAmount {
  currency: string;
  value: number;
}

export type AP2MandateType = 'IntentMandate' | 'CartMandate' | 'PaymentMandate';

/**
 * A detached signature over the canonicalized credential body (everything except `proof`). Structural
 * analogue of a JWS / Data-Integrity proof; signed with the issuer's Ed25519 key (PCA's own `sign`).
 */
export interface AP2Proof {
  type: 'Ed25519Signature2020';
  /** ISO timestamp the proof was created. */
  created: string;
  /** The issuer public key (b64u) the signature verifies under; equals the VDC `issuer`. */
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  /** b64u Ed25519 signature over `canonicalBytes(<credential without proof>)`. */
  signatureValue: string;
}

/** A signed (or signable) Verifiable Digital Credential carrying one AP2 mandate. */
export interface VerifiableDigitalCredential<T extends AP2MandateType, S> {
  '@context': readonly string[];
  type: readonly ['VerifiableCredential', T];
  /** Issuer public key (b64u). Intent: the user/principal. Cart: the merchant. Payment: the payer. */
  issuer: string;
  /** ISO issuance time. */
  issuanceDate: string;
  /** ISO expiry, when the mandate names one. */
  expirationDate?: string;
  credentialSubject: S;
  /** Present once signed (see {@link signMandate}). */
  proof?: AP2Proof;
}

// ===================================================================================================
// The three mandate payloads (credentialSubject shapes)
// ===================================================================================================

/**
 * PCA-native extension carried inside an Intent Mandate so the VDC chain can round-trip back to the
 * attenuating PCA terms AP2 has no standard field for. NON-STANDARD by construction (namespaced).
 */
export interface PcaIntentExtension {
  /** Y — at/under ⇒ autonomous (human_present can be false); over ⇒ human co-sign (tier 3). */
  auto_approve_threshold: number;
  /** bMax — total autonomous spend between human co-signs. */
  cumulative_cap: number;
  /** X — hard per-transaction ceiling (mirrors `max_amount.value`). */
  per_transaction_cap: number;
  period_start?: number;
  period_end?: number;
  max_transactions_per_period?: number;
  /** The PCA grant's salted goal commitment, if the source was a full PaymentMandate. */
  goal_commit?: string;
}

/** IntentMandate: the user's natural-language/structured intent + the constraints the agent must obey. */
export interface IntentMandateContents {
  natural_language_description: string;
  /** Allowlisted merchant ids; `null` = any merchant (AP2 uses null for "unconstrained"). */
  merchants: string[] | null;
  /** Allowlisted SKUs; `null` = any. */
  skus: string[] | null;
  /** Allowlisted MCC categories; omitted = any. */
  categories?: string[];
  /** The ceiling a single purchase under this intent may reach (PCA's hard per-transaction cap X). */
  max_amount: MonetaryAmount;
  /** Whether purchases must be refundable/bonded (PCA mints charges in the `reversible` class ⇒ true). */
  required_refundability: boolean;
  /** Whether the user must confirm the concrete cart before payment (maps from PCA Y < X). */
  user_cart_confirmation_required: boolean;
  /** ISO expiry of the intent, if any. */
  intent_expiry?: string;
  /** PCA-native round-trip extension (non-standard). */
  x_pca?: PcaIntentExtension;
}

/** A concrete line item the merchant commits to in a cart. */
export interface CartItem {
  sku?: string;
  name: string;
  quantity: number;
  unit_price: MonetaryAmount;
}

/** CartMandate: the concrete items/amounts the merchant commits, bound to the intent it fulfils. */
export interface CartMandateContents {
  /** Stable cart id. */
  id: string;
  /** The merchant this cart is with (matched against the intent allowlist). */
  merchant: string;
  items: CartItem[];
  /** The committed total (Σ quantity · unit_price). */
  total: MonetaryAmount;
  /** Hash of the IntentMandate VDC this cart fulfils — binds cart → intent. */
  intent_reference?: string;
  /** ISO expiry of the cart quote, if any. */
  cart_expiry?: string;
}

/** The payment instrument a payment mandate authorizes. */
export interface PaymentMethod {
  /** e.g. `card`, `crypto`, `shared_payment_token`, `x402`. */
  type: string;
  display?: string;
  /** Opaque token (e.g. a Stripe Shared Payment Token id); never a raw PAN. */
  token?: string;
}

/**
 * PaymentMandate: the minimal payment authorization derived from the cart. Carries the human-present /
 * human-not-present modality signal and binds to the cart (and intent) by hash — WITHOUT re-exposing
 * the full cart contents.
 */
export interface PaymentMandateContents {
  /** Hash of the CartMandate VDC — binds payment → cart. */
  cart_hash: string;
  /** Hash of the IntentMandate VDC — binds payment → intent (optional but recommended). */
  intent_hash?: string;
  amount: MonetaryAmount;
  payment_method: PaymentMethod;
  /**
   * The AP2 modality signal. MAPPING: PCA tier-3 human step-up ⇒ `human_present = true`; a tier-1
   * autonomous charge (amount ≤ Y, budget available) ⇒ `human_present = false` (human-not-present).
   */
  human_present: boolean;
  merchant?: string;
}

export type IntentMandate = VerifiableDigitalCredential<'IntentMandate', IntentMandateContents>;
export type CartMandate = VerifiableDigitalCredential<'CartMandate', CartMandateContents>;
/** AP2's Payment Mandate VDC (NOT the PCA `PaymentMandate` grant from `@atlasauth/pca-payments`). */
export type PaymentMandate = VerifiableDigitalCredential<'PaymentMandate', PaymentMandateContents>;

export type AnyAP2Mandate = IntentMandate | CartMandate | PaymentMandate;

// ===================================================================================================
// Signing / verification / hashing
// ===================================================================================================

/** Strip `proof` for canonical signing/verification (the signature covers everything else). */
function proofless<V extends { proof?: AP2Proof }>(vdc: V): Omit<V, 'proof'> {
  const { proof: _proof, ...rest } = vdc;
  void _proof;
  return rest;
}

/** Sign a VDC with the issuer's Ed25519 secret key, returning a copy carrying the `proof`. */
export function signMandate<T extends AP2MandateType, S>(
  vdc: VerifiableDigitalCredential<T, S>,
  secretKey: Uint8Array,
): VerifiableDigitalCredential<T, S> {
  const sig = sign(secretKey, canonicalBytes(proofless(vdc)));
  const proof: AP2Proof = {
    type: 'Ed25519Signature2020',
    created: vdc.issuanceDate,
    verificationMethod: vdc.issuer,
    proofPurpose: 'assertionMethod',
    signatureValue: encodeSig(sig),
  };
  return { ...vdc, proof };
}

/** Verify a VDC's detached signature. Returns false when unsigned or the signature does not verify. */
export function verifyMandate(vdc: AnyAP2Mandate): boolean {
  if (!vdc.proof) return false;
  // The proof must verify under the credential's own declared issuer (no key substitution).
  if (vdc.proof.verificationMethod !== vdc.issuer) return false;
  return verifyB64u(vdc.issuer, canonicalBytes(proofless(vdc)), vdc.proof.signatureValue);
}

/** Stable content hash of a VDC (used to bind one mandate to the next). */
export function mandateHash(vdc: AnyAP2Mandate): string {
  return hashCanonical(vdc);
}

// ===================================================================================================
// PCA → AP2 mapping (the narrowing chain)
// ===================================================================================================

const round2 = (n: number): number => Math.round((n + Number.EPSILON) * 100) / 100;

/** Normalize the two accepted inputs to `MandateTerms` (+ the goal commitment when a full mandate). */
function termsOf(mandate: PcaPaymentMandate | MandateTerms): { terms: MandateTerms; goalCommit?: string } {
  if ('terms' in mandate) return { terms: mandate.terms, goalCommit: mandate.goalCommit };
  return { terms: mandate };
}

function describeTerms(terms: MandateTerms): string {
  const where = terms.merchants.length ? ` at [${terms.merchants.join(', ')}]` : '';
  return (
    `Purchase up to ${terms.perTransactionCap} ${terms.currency} per transaction` +
    ` (autonomous up to ${terms.autoApproveThreshold}, cumulative ${terms.cumulativeCap})${where}`
  );
}

export interface IntentMapOptions {
  /** Issuer (user/principal) public key, b64u. */
  issuerPublic: string;
  /** If present, the Intent VDC is signed with this Ed25519 secret key. */
  issuerSecret?: Uint8Array;
  /** Override the natural-language description (else derived from the terms). */
  naturalLanguageDescription?: string;
  /** Allowlisted SKUs, or null for any (default null). */
  skus?: string[] | null;
  /** Override `user_cart_confirmation_required` (default: Y < X ⇒ true). */
  userCartConfirmationRequired?: boolean;
  /** Issuance clock (ms). Default `Date.now()`. */
  now?: number;
}

/** Map a PCA payment mandate (or raw terms) to an AP2 Intent Mandate VDC. */
export function toAP2IntentMandate(
  mandate: PcaPaymentMandate | MandateTerms,
  opts: IntentMapOptions,
): IntentMandate {
  const { terms, goalCommit } = termsOf(mandate);
  const now = Number.isFinite(opts.now) ? (opts.now as number) : Date.now();

  const x_pca: PcaIntentExtension = {
    auto_approve_threshold: terms.autoApproveThreshold,
    cumulative_cap: terms.cumulativeCap,
    per_transaction_cap: terms.perTransactionCap,
    period_start: terms.periodStart,
    ...(terms.periodEnd !== undefined ? { period_end: terms.periodEnd } : {}),
    ...(terms.maxTransactionsPerPeriod !== undefined
      ? { max_transactions_per_period: terms.maxTransactionsPerPeriod }
      : {}),
    ...(goalCommit !== undefined ? { goal_commit: goalCommit } : {}),
  };

  const contents: IntentMandateContents = {
    natural_language_description: opts.naturalLanguageDescription ?? describeTerms(terms),
    merchants: terms.merchants.length ? [...terms.merchants] : null,
    skus: opts.skus ?? null,
    ...(terms.categories.length ? { categories: [...terms.categories] } : {}),
    max_amount: { currency: terms.currency, value: terms.perTransactionCap },
    required_refundability: true,
    user_cart_confirmation_required:
      opts.userCartConfirmationRequired ?? terms.autoApproveThreshold < terms.perTransactionCap,
    ...(terms.periodEnd !== undefined ? { intent_expiry: new Date(terms.periodEnd).toISOString() } : {}),
    x_pca,
  };

  const vdc: IntentMandate = {
    '@context': AP2_CONTEXT,
    type: ['VerifiableCredential', 'IntentMandate'],
    issuer: opts.issuerPublic,
    issuanceDate: new Date(now).toISOString(),
    ...(terms.periodEnd !== undefined ? { expirationDate: new Date(terms.periodEnd).toISOString() } : {}),
    credentialSubject: contents,
  };
  return opts.issuerSecret ? signMandate(vdc, opts.issuerSecret) : vdc;
}

export interface CartInput {
  merchant: string;
  items: CartItem[];
  /** Currency; defaults to the intent's `max_amount.currency`. */
  currency?: string;
  /** Stable cart id; derived from the item digest when omitted. */
  id?: string;
  /** Cart-quote expiry (ms). */
  expiry?: number;
  now?: number;
}

export interface CartMapOptions {
  /** Issuer (merchant) public key, b64u. */
  issuerPublic: string;
  /** If present, the Cart VDC is signed with this Ed25519 secret key. */
  issuerSecret?: Uint8Array;
}

/** Narrow an Intent Mandate into a concrete AP2 Cart Mandate VDC (items + committed total). */
export function toAP2CartMandate(intent: IntentMandate, cart: CartInput, opts: CartMapOptions): CartMandate {
  const currency = cart.currency ?? intent.credentialSubject.max_amount.currency;
  const total = round2(
    cart.items.reduce((sum, it) => sum + it.quantity * it.unit_price.value, 0),
  );
  const id = cart.id ?? `cart_${hashCanonical({ merchant: cart.merchant, items: cart.items }).slice(0, 16)}`;

  const contents: CartMandateContents = {
    id,
    merchant: cart.merchant,
    items: cart.items.map((it) => ({ ...it, unit_price: { ...it.unit_price } })),
    total: { currency, value: total },
    intent_reference: mandateHash(intent),
    ...(cart.expiry !== undefined ? { cart_expiry: new Date(cart.expiry).toISOString() } : {}),
  };

  const vdc: CartMandate = {
    '@context': AP2_CONTEXT,
    type: ['VerifiableCredential', 'CartMandate'],
    issuer: opts.issuerPublic,
    issuanceDate: new Date(Number.isFinite(cart.now) ? (cart.now as number) : Date.now()).toISOString(),
    ...(cart.expiry !== undefined ? { expirationDate: new Date(cart.expiry).toISOString() } : {}),
    credentialSubject: contents,
  };
  return opts.issuerSecret ? signMandate(vdc, opts.issuerSecret) : vdc;
}

export interface PaymentMapOptions {
  /** Issuer (payer/user agent) public key, b64u. */
  issuerPublic: string;
  /** If present, the Payment VDC is signed with this Ed25519 secret key. */
  issuerSecret?: Uint8Array;
  paymentMethod: PaymentMethod;
  /** Amount to authorize; defaults to the cart total (and must not exceed it to stay a narrowing). */
  amount?: MonetaryAmount;
  /**
   * The human-present modality. If omitted, derived from `pcaTier` (tier 3 ⇒ true); if that is also
   * omitted, defaults to `false` (human-not-present).
   */
  humanPresent?: boolean;
  /** PCA required-threshold tier for this charge (1 autonomous … 3 human co-sign). */
  pcaTier?: number;
  /** The Intent Mandate, if available — lets the payment also bind to the intent by hash. */
  intent?: IntentMandate;
  now?: number;
}

/** Narrow a Cart Mandate into an AP2 Payment Mandate VDC (the payment authorization + modality). */
export function toAP2PaymentMandate(cart: CartMandate, opts: PaymentMapOptions): PaymentMandate {
  const amount = opts.amount ?? { ...cart.credentialSubject.total };
  const humanPresent =
    opts.humanPresent ?? (opts.pcaTier !== undefined ? opts.pcaTier >= 3 : false);

  const contents: PaymentMandateContents = {
    cart_hash: mandateHash(cart),
    ...(opts.intent ? { intent_hash: mandateHash(opts.intent) } : {}),
    amount,
    payment_method: { ...opts.paymentMethod },
    human_present: humanPresent,
    ...(cart.credentialSubject.merchant ? { merchant: cart.credentialSubject.merchant } : {}),
  };

  const vdc: PaymentMandate = {
    '@context': AP2_CONTEXT,
    type: ['VerifiableCredential', 'PaymentMandate'],
    issuer: opts.issuerPublic,
    issuanceDate: new Date(Number.isFinite(opts.now) ? (opts.now as number) : Date.now()).toISOString(),
    credentialSubject: contents,
  };
  return opts.issuerSecret ? signMandate(vdc, opts.issuerSecret) : vdc;
}

// ===================================================================================================
// AP2 → PCA parsing (round-trip back toward PCA terms)
// ===================================================================================================

/** The PCA-facing view recovered from an AP2 mandate (fields depend on the mandate type). */
export interface ParsedAP2Mandate {
  type: AP2MandateType;
  /** Intent: the allowlist (absent/null ⇒ any). */
  merchants?: string[];
  categories?: string[];
  currency?: string;
  /** Intent: X (from `max_amount`); also recovered from `x_pca`. */
  perTransactionCap?: number;
  /** Intent: Y (from `x_pca`). */
  autoApproveThreshold?: number;
  /** Intent: bMax (from `x_pca`). */
  cumulativeCap?: number;
  periodStart?: number;
  periodEnd?: number;
  maxTransactionsPerPeriod?: number;
  goalCommit?: string;
  /** Cart/Payment: the concrete amount. */
  amount?: number;
  /** Cart/Payment: the concrete merchant. */
  merchant?: string;
  /** Payment: the modality signal. */
  humanPresent?: boolean;
}

/** Parse an AP2 mandate VDC back toward PCA terms (lossless for an Intent minted with `x_pca`). */
export function fromAP2Mandate(vdc: AnyAP2Mandate): ParsedAP2Mandate {
  const kind = vdc.type[1];
  if (kind === 'IntentMandate') {
    const cs = (vdc as IntentMandate).credentialSubject;
    const x = cs.x_pca;
    return {
      type: 'IntentMandate',
      ...(cs.merchants ? { merchants: [...cs.merchants] } : {}),
      ...(cs.categories ? { categories: [...cs.categories] } : {}),
      currency: cs.max_amount.currency,
      perTransactionCap: x?.per_transaction_cap ?? cs.max_amount.value,
      ...(x ? { autoApproveThreshold: x.auto_approve_threshold, cumulativeCap: x.cumulative_cap } : {}),
      ...(x?.period_start !== undefined ? { periodStart: x.period_start } : {}),
      ...(x?.period_end !== undefined ? { periodEnd: x.period_end } : {}),
      ...(x?.max_transactions_per_period !== undefined
        ? { maxTransactionsPerPeriod: x.max_transactions_per_period }
        : {}),
      ...(x?.goal_commit !== undefined ? { goalCommit: x.goal_commit } : {}),
    };
  }
  if (kind === 'CartMandate') {
    const cs = (vdc as CartMandate).credentialSubject;
    return { type: 'CartMandate', merchant: cs.merchant, amount: cs.total.value, currency: cs.total.currency };
  }
  const cs = (vdc as PaymentMandate).credentialSubject;
  return {
    type: 'PaymentMandate',
    amount: cs.amount.value,
    currency: cs.amount.currency,
    humanPresent: cs.human_present,
    ...(cs.merchant ? { merchant: cs.merchant } : {}),
  };
}

// ===================================================================================================
// The signed chain + its non-amplifying-narrowing verifier (mirrors PCA attenuation)
// ===================================================================================================

export interface ChainVerification {
  ok: boolean;
  reasons: string[];
}

export interface AP2MandateChain {
  intent: IntentMandate;
  cart: CartMandate;
  payment: PaymentMandate;
  /** Verify the signatures, the hash bindings, and that each step is a non-amplifying narrowing. */
  verify(): ChainVerification;
}

/**
 * Verify an AP2 Intent→Cart→Payment chain: each VDC's signature, the hash bindings (cart→intent,
 * payment→cart), and that every step only RESTRICTS the one above (never amplifies). This mirrors
 * PCA's attenuation check: a child capability may narrow authority but never widen it.
 */
export function verifyAP2Chain(
  intent: IntentMandate,
  cart: CartMandate,
  payment: PaymentMandate,
): ChainVerification {
  const reasons: string[] = [];

  // 1. Signatures (each mandate must be signed and verify under its own issuer).
  if (!verifyMandate(intent)) reasons.push('intent signature invalid or missing');
  if (!verifyMandate(cart)) reasons.push('cart signature invalid or missing');
  if (!verifyMandate(payment)) reasons.push('payment signature invalid or missing');

  const i = intent.credentialSubject;
  const c = cart.credentialSubject;
  const p = payment.credentialSubject;

  // 2. Hash bindings (cart → intent, payment → cart).
  if (c.intent_reference !== mandateHash(intent)) reasons.push('cart does not reference this intent');
  if (p.cart_hash !== mandateHash(cart)) reasons.push('payment does not reference this cart');
  if (p.intent_hash !== undefined && p.intent_hash !== mandateHash(intent)) {
    reasons.push('payment intent_hash does not match this intent');
  }

  // 3. Currency consistency (no implicit FX across the chain).
  if (c.total.currency !== i.max_amount.currency) reasons.push('cart currency differs from intent');
  if (p.amount.currency !== c.total.currency) reasons.push('payment currency differs from cart');

  // 4. Non-amplifying narrowing of AMOUNT (the core attenuation check).
  if (c.total.value > i.max_amount.value) {
    reasons.push(`cart total ${c.total.value} exceeds intent cap ${i.max_amount.value} (amplifying)`);
  }
  if (p.amount.value > c.total.value) {
    reasons.push(`payment amount ${p.amount.value} exceeds cart total ${c.total.value} (amplifying)`);
  }

  // 5. Merchant allowlist narrowing (null intent.merchants ⇒ any merchant permitted).
  if (i.merchants !== null && !i.merchants.includes(c.merchant)) {
    reasons.push(`cart merchant '${c.merchant}' not in intent allowlist`);
  }

  return { ok: reasons.length === 0, reasons };
}

/** Assemble the signed Intent→Cart→Payment chain and attach its non-amplifying-narrowing verifier. */
export function chainMandates(
  intent: IntentMandate,
  cart: CartMandate,
  payment: PaymentMandate,
): AP2MandateChain {
  return { intent, cart, payment, verify: () => verifyAP2Chain(intent, cart, payment) };
}

// ===================================================================================================
// Settlement backends (the rails PCA's governance feeds — STRUCTURAL ONLY, no network)
// ===================================================================================================

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
 * Convert a decimal amount to an integer string of atomic units (`10 ** decimals` per unit). Throws on
 * anything that is not a finite, non-negative amount that fits exactly in a safe integer.
 */
function toAtomicUnits(value: number, decimals: number): string {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) {
    throw new RangeError(`x402: decimals must be an integer in 0..18, got ${String(decimals)}`);
  }
  const atomic = Math.round(value * 10 ** decimals);
  if (!Number.isFinite(value) || value < 0 || !Number.isSafeInteger(atomic)) {
    throw new RangeError(`x402: amount ${String(value)} cannot be expressed in atomic units with ${decimals} decimals`);
  }
  return String(atomic);
}

/** A rail-specific settlement payload shape. No network is performed; this is the wire shape only. */
export interface SettlementInstruction {
  rail: string;
  amount: MonetaryAmount;
  merchant?: string;
  /** The rail-specific payload (structural). */
  payload: Readonly<Record<string, unknown>>;
}

/**
 * A settlement rail PCA's governance feeds. PCA + AP2 decide WHETHER a charge is authorized and carry
 * the signed mandate; a `SettlementBackend` turns a verified Payment Mandate into the rail's wire shape.
 * It never moves money here — it is the hook a real integration fills in.
 */
export interface SettlementBackend {
  readonly rail: string;
  /** Build the rail payload for a (presumed-verified) Payment Mandate. Pure; no network. */
  settle(payment: PaymentMandate, ctx?: SettlementContext): SettlementInstruction;
}

/**
 * Coinbase x402 adapter: models the HTTP 402 `Payment Required` challenge (the server's `accepts`
 * payment requirements) plus the `X-PAYMENT` request header carrying the base64 payment payload the
 * client re-sends. Structural only — the real rail settles on-chain. (Field names follow the public
 * x402 shape and should be checked against the x402 spec before production.)
 */
export const x402Settlement: SettlementBackend = {
  rail: 'x402',
  settle(payment, ctx) {
    const cs = payment.credentialSubject;
    const network = ctx?.network ?? 'base-sepolia';
    const requirement = {
      scheme: 'exact',
      network,
      // x402 v1: `maxAmountRequired` is a string in ATOMIC token units, not a decimal amount.
      maxAmountRequired: toAtomicUnits(cs.amount.value, ctx?.decimals ?? 6),
      resource: ctx?.resourceUrl ?? '',
      description: `AP2 payment mandate ${cs.cart_hash}`,
      payTo: ctx?.payTo ?? cs.merchant ?? '',
      asset: ctx?.asset ?? cs.amount.currency,
      mimeType: 'application/json',
      maxTimeoutSeconds: ctx?.maxTimeoutSeconds ?? 60,
    };
    // x402 carries `X-PAYMENT` as STANDARD base64 (with padding) of the JSON PaymentPayload. This
    // envelope is a placeholder: a real client replaces `payload` with its signed authorization.
    const xPayment = Buffer.from(
      JSON.stringify({
        x402Version: 1,
        scheme: 'exact',
        network,
        payload: { cartHash: cs.cart_hash, humanPresent: cs.human_present, amount: cs.amount.value },
      }),
      'utf8',
    ).toString('base64');
    return {
      rail: 'x402',
      amount: cs.amount,
      ...(cs.merchant ? { merchant: cs.merchant } : {}),
      payload: {
        httpStatus: 402,
        x402Version: 1,
        error: 'X-PAYMENT header is required',
        accepts: [requirement],
        header: { 'X-PAYMENT': xPayment },
      },
    };
  },
};

/**
 * Stripe Shared Payment Token adapter: models the SPT charge shape — a shared token the buyer's agent
 * grants the merchant to pull a bounded amount. Structural only — a real integration calls Stripe with
 * the token. Amount is converted to minor units (cents). (Check field names against Stripe's SPT docs
 * before production.)
 */
export const stripeSptSettlement: SettlementBackend = {
  rail: 'stripe-spt',
  settle(payment, ctx) {
    const cs = payment.credentialSubject;
    return {
      rail: 'stripe-spt',
      amount: cs.amount,
      ...(cs.merchant ? { merchant: cs.merchant } : {}),
      payload: {
        shared_payment_token: cs.payment_method.token ?? '',
        amount: Math.round(cs.amount.value * 100),
        currency: cs.amount.currency.toLowerCase(),
        human_present: cs.human_present,
        ...(ctx?.payTo ? { on_behalf_of: ctx.payTo } : {}),
      },
    };
  },
};
