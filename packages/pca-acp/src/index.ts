/**
 * @atlasauth/pca-acp — Agentic Commerce Protocol (ACP) + x402 for PCA.
 *
 * ┌──────────────────────────────────────────────────────────────────────────────────────────────┐
 * │  PCA GOVERNS. ACP mints the delegated one-time payment token. x402 (HTTP 402) is the pay rail.  │
 * │  "Every payment mandate is a verifiable proof-carrying action."                                 │
 * └──────────────────────────────────────────────────────────────────────────────────────────────┘
 *
 * ACP (the Agentic Commerce Protocol, OpenAI + Stripe, 2025) lets an agent complete a purchase inside a
 * chat/agent surface. Its payment leg is the Delegated / Shared Payment Token: a one-time, scope-bound
 * token the buyer's agent hands the merchant to pull a bounded amount for ONE checkout
 * (session + merchant + amount + expiry). x402 (Coinbase's HTTP 402 "Payment Required" flow) is the
 * other net-new rail: a resource server answers `402` with a payment challenge, the client pays, and
 * the server settles.
 *
 * This module makes BOTH of those proof-carrying. A delegated payment token is minted FROM a PCActn and
 * carries that proof's authority by reference (its digest); the PCA proof's capability caveats — the
 * spend cap, the merchant/category allowlist, the human-present requirement — GATE issuance: a token is
 * refused at mint when the requested amount / currency / merchant / category / modality exceeds what the
 * proof authorizes. At settlement the token's session/merchant/amount/expiry binding is re-checked and
 * the bound PCActn can be re-verified, failing closed on over-amount, wrong-merchant, expiry, or a proof
 * that no longer matches.
 *
 * This is ACP + x402, NOT AP2. The AP2 Intent→Cart→Payment VDC chain is `@atlasauth/pca-ap2`; this
 * package reuses that mandate vocabulary (MonetaryAmount / merchants / categories / human_present /
 * PaymentMethod) for consistency but is a distinct, wire-compatible adapter, not a re-implementation.
 *
 * ────────────────────────────────────────────────────────────────────────────────────────────────
 * HONEST CAVEAT — VERIFY BEFORE PRODUCTION WIRE USE
 * ────────────────────────────────────────────────────────────────────────────────────────────────
 * ACP and x402 are young and moving. The exact JSON field names of the Stripe Shared Payment Token and
 * the Coinbase x402 `accepts` requirement object should be validated against their current specs before
 * production. The AUTHORITY model here (mint-time caveat gating + settlement-time PCActn binding) is the
 * stable, load-bearing contribution; the wire envelopes are structural and injectable.
 */

import {
  type Capability,
  type CapabilityChain,
  type Caveat,
  type PCActn,
  type VerifyResult,
  pcactnDigest,
  utf8,
  verifyPCActnCore,
} from '@atlasauth/pca';
import {
  CompactSign,
  type CompactJWSHeaderParameters,
  compactVerify,
  importJWK,
  type JWK,
  type KeyLike,
} from 'jose';

// ===================================================================================================
// Version + token type
// ===================================================================================================

/** The ACP delegated-payment-token shape this module emits (version pinned into the claims). */
export const ACP_DELEGATED_TOKEN_VERSION = 1 as const;
/** The `typ` claim carried in a delegated payment token (identifies the envelope to a verifier). */
export const ACP_DELEGATED_TOKEN_TYPE = 'acp-delegated-payment' as const;

// ===================================================================================================
// Mandate vocabulary (mirrors @atlasauth/pca-ap2 — same field names, NOT imported)
// ===================================================================================================

/** ISO-4217 currency + decimal value (use minor units in production to avoid float drift). */
export interface MonetaryAmount {
  currency: string;
  value: number;
}

/** The payment instrument a delegated token authorizes. Mirrors the AP2 `PaymentMethod` shape. */
export interface PaymentMethod {
  /** e.g. `card`, `shared_payment_token`, `x402`, `crypto`. */
  type: string;
  display?: string;
  /** Opaque token (e.g. a Stripe Shared Payment Token id); never a raw PAN. */
  token?: string;
}

// ===================================================================================================
// Payment caveat vocabulary (what the PCA proof's capability chain carries to bound a purchase)
// ===================================================================================================
//
// The PCA capability chain is attenuating and append-only (see @atlasauth/pca `capability.ts`): a child
// hop can only ADD caveats, never drop or widen one. The leaf hop therefore carries the full cumulative
// caveat list, and these payment caveats COMBINE CONJUNCTIVELY (the tightest spend cap wins; merchant /
// category allowlists INTERSECT; any `human_present` requirement sticks). A malformed PAYMENT caveat
// fails closed; caveats of any other type (ttl, scope, …) are ignored here.

/** `{ type: 'max_amount', max, currency? }` — per-transaction spend ceiling (optionally currency-bound). */
export const SPEND_CAP_CAVEAT = 'max_amount' as const;
/** `{ type: 'merchant_allow', merchants: [...] }` — allowlisted merchant ids (absent ⇒ any merchant). */
export const MERCHANT_ALLOW_CAVEAT = 'merchant_allow' as const;
/** `{ type: 'merchant_category', categories: [...] }` — allowlisted MCC categories (absent ⇒ any). */
export const MERCHANT_CATEGORY_CAVEAT = 'merchant_category' as const;
/** `{ type: 'human_present', required: boolean }` — require a human-present modality for the charge. */
export const HUMAN_PRESENT_CAVEAT = 'human_present' as const;

export interface SpendCapCaveat extends Caveat {
  type: typeof SPEND_CAP_CAVEAT;
  max: number;
  currency?: string;
}
export interface MerchantAllowCaveat extends Caveat {
  type: typeof MERCHANT_ALLOW_CAVEAT;
  merchants: string[];
}
export interface MerchantCategoryCaveat extends Caveat {
  type: typeof MERCHANT_CATEGORY_CAVEAT;
  categories: string[];
}
export interface HumanPresentCaveat extends Caveat {
  type: typeof HUMAN_PRESENT_CAVEAT;
  required: boolean;
}

/** Build a per-transaction spend-cap caveat `{ type: 'max_amount', max, currency? }`. */
export function spendCapCaveat(max: number, currency?: string): SpendCapCaveat {
  return currency !== undefined ? { type: SPEND_CAP_CAVEAT, max, currency } : { type: SPEND_CAP_CAVEAT, max };
}
/** Build a merchant-allowlist caveat `{ type: 'merchant_allow', merchants }`. */
export function merchantAllowCaveat(merchants: string[]): MerchantAllowCaveat {
  return { type: MERCHANT_ALLOW_CAVEAT, merchants: [...merchants] };
}
/** Build a merchant-category (MCC) allowlist caveat `{ type: 'merchant_category', categories }`. */
export function merchantCategoryCaveat(categories: string[]): MerchantCategoryCaveat {
  return { type: MERCHANT_CATEGORY_CAVEAT, categories: [...categories] };
}
/** Build a human-present requirement caveat `{ type: 'human_present', required }`. */
export function humanPresentCaveat(required = true): HumanPresentCaveat {
  return { type: HUMAN_PRESENT_CAVEAT, required };
}

// ===================================================================================================
// Errors
// ===================================================================================================

/** Thrown when a delegated payment token cannot be minted because the request exceeds the proof's authority. */
export class AcpAuthorityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AcpAuthorityError';
  }
}

// ===================================================================================================
// The effective payment authority carried by a PCActn's capability chain
// ===================================================================================================

/** The conjunction of all payment caveats on a proof's leaf capability. */
export interface PaymentAuthority {
  /** Tightest per-transaction spend cap, or undefined when unconstrained. */
  maxAmount?: number;
  /** Currency the spend cap is denominated in, or undefined when the cap is currency-agnostic. */
  currency?: string;
  /** Allowlisted merchant ids (intersection of every allowlist caveat), or `null` for "any merchant". */
  merchants: string[] | null;
  /** Allowlisted MCC categories (intersection), or `null` for "any category". */
  categories: string[] | null;
  /** True when any caveat requires the charge to be human-present. */
  humanPresentRequired: boolean;
}

function asStringArray(v: unknown, label: string): string[] {
  if (!Array.isArray(v) || !v.every((x) => typeof x === 'string')) {
    throw new AcpAuthorityError(`malformed ${label} caveat: expected a string[] (fail closed)`);
  }
  return v as string[];
}

/**
 * Collapse a leaf capability's cumulative caveat list into its effective payment authority. Payment
 * caveats combine conjunctively (tightest cap, intersected allowlists, sticky human-present); a malformed
 * PAYMENT caveat throws (fail closed); any non-payment caveat type is ignored. The order of caveats does
 * not matter — the result is the same conjunction either way.
 */
export function extractPaymentAuthority(caveats: readonly Caveat[]): PaymentAuthority {
  let maxAmount: number | undefined;
  let currency: string | undefined;
  let merchants: string[] | null = null;
  let categories: string[] | null = null;
  let humanPresentRequired = false;

  for (const c of caveats) {
    switch (c.type) {
      case SPEND_CAP_CAVEAT: {
        const max = (c as { max?: unknown }).max;
        if (typeof max !== 'number' || !Number.isFinite(max) || max < 0) {
          throw new AcpAuthorityError('malformed max_amount caveat: max must be a finite number >= 0 (fail closed)');
        }
        maxAmount = maxAmount === undefined ? max : Math.min(maxAmount, max);
        const cur = (c as { currency?: unknown }).currency;
        if (cur !== undefined) {
          if (typeof cur !== 'string' || cur.length === 0) {
            throw new AcpAuthorityError('malformed max_amount caveat: currency must be a non-empty string (fail closed)');
          }
          if (currency !== undefined && currency !== cur) {
            throw new AcpAuthorityError(`conflicting spend-cap currencies "${currency}" vs "${cur}" (fail closed)`);
          }
          currency = cur;
        }
        break;
      }
      case MERCHANT_ALLOW_CAVEAT: {
        const list = asStringArray((c as { merchants?: unknown }).merchants, 'merchant_allow');
        merchants = merchants === null ? [...new Set(list)] : merchants.filter((m) => list.includes(m));
        break;
      }
      case MERCHANT_CATEGORY_CAVEAT: {
        const list = asStringArray((c as { categories?: unknown }).categories, 'merchant_category');
        categories = categories === null ? [...new Set(list)] : categories.filter((m) => list.includes(m));
        break;
      }
      case HUMAN_PRESENT_CAVEAT: {
        const req = (c as { required?: unknown }).required;
        if (typeof req !== 'boolean') {
          throw new AcpAuthorityError('malformed human_present caveat: required must be a boolean (fail closed)');
        }
        humanPresentRequired = humanPresentRequired || req;
        break;
      }
      default:
        break; // non-payment caveat (ttl, scope, resource, …) — not this adapter's concern
    }
  }

  return {
    ...(maxAmount !== undefined ? { maxAmount } : {}),
    ...(currency !== undefined ? { currency } : {}),
    merchants,
    categories,
    humanPresentRequired,
  };
}

/** The leaf (acting) capability of a proof's chain. */
function leafCapability(pcActn: PCActn): Capability {
  const chain: CapabilityChain = pcActn.cap_chain;
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new AcpAuthorityError('PCActn carries no capability chain (fail closed)');
  }
  const leaf = chain[chain.length - 1];
  if (leaf === undefined) throw new AcpAuthorityError('PCActn capability chain has no leaf (fail closed)');
  return leaf;
}

/** A concrete purchase request, checked against a {@link PaymentAuthority}. */
export interface PaymentRequest {
  amount: number;
  currency: string;
  merchant: string;
  /** The merchant's MCC category, when known (required only if the proof constrains categories). */
  category?: string;
  /** Whether a human is present/attesting for this charge (the ACP modality signal). */
  humanPresent?: boolean;
}

/** The outcome of checking a purchase request against a proof's payment authority. */
export interface AuthorityCheck {
  ok: boolean;
  reason?: string;
}

/**
 * Check a concrete purchase request against the payment authority a PCActn carries. Pure and fail-closed:
 * an over-cap amount, a currency the cap forbids, a merchant / category outside the allowlist, or a
 * missing human-present signal the proof demands all return `{ ok: false }`.
 */
export function checkPaymentAuthority(authority: PaymentAuthority, request: PaymentRequest): AuthorityCheck {
  if (typeof request.amount !== 'number' || !Number.isFinite(request.amount) || request.amount <= 0) {
    return { ok: false, reason: 'amount must be a finite number > 0' };
  }
  if (typeof request.currency !== 'string' || request.currency.length === 0) {
    return { ok: false, reason: 'currency must be a non-empty string' };
  }
  if (typeof request.merchant !== 'string' || request.merchant.length === 0) {
    return { ok: false, reason: 'merchant must be a non-empty string' };
  }
  if (authority.currency !== undefined && authority.currency !== request.currency) {
    return { ok: false, reason: `currency "${request.currency}" is not the authorized currency "${authority.currency}"` };
  }
  if (authority.maxAmount !== undefined && request.amount > authority.maxAmount) {
    return { ok: false, reason: `amount ${request.amount} exceeds the authorized spend cap ${authority.maxAmount}` };
  }
  if (authority.merchants !== null && !authority.merchants.includes(request.merchant)) {
    return { ok: false, reason: `merchant "${request.merchant}" is not in the authorized allowlist` };
  }
  if (authority.categories !== null) {
    if (request.category === undefined) {
      return { ok: false, reason: 'the proof constrains merchant categories but no category was supplied' };
    }
    if (!authority.categories.includes(request.category)) {
      return { ok: false, reason: `category "${request.category}" is not in the authorized allowlist` };
    }
  }
  if (authority.humanPresentRequired && request.humanPresent !== true) {
    return { ok: false, reason: 'the proof requires a human-present charge but humanPresent was not asserted' };
  }
  return { ok: true };
}

// ===================================================================================================
// The PCA authority reference carried inside a delegated payment token
// ===================================================================================================

/** How a delegated payment token points back at the PCActn that authorized it (authority by reference). */
export interface PcaAuthorityRef {
  /** `pcactnDigest()` of the authorizing proof — the binding a verifier re-checks against the proof. */
  digest: string;
  /** The proof's audience (resource server / Atlas instance id). */
  aud: string;
  /** The proof's grant id. */
  grant_ref: string;
  /** The acting leaf capability holder (b64u public key). */
  leaf_holder: string;
  verb: string;
  resource: string;
  params_digest: string;
}

function authorityRef(pcActn: PCActn): PcaAuthorityRef {
  const leaf = leafCapability(pcActn);
  return {
    digest: pcactnDigest(pcActn),
    aud: pcActn.aud,
    grant_ref: pcActn.grant_ref,
    leaf_holder: leaf.holder,
    verb: pcActn.action.verb,
    resource: pcActn.action.resource,
    params_digest: pcActn.action.params_digest,
  };
}

// ===================================================================================================
// Delegated payment token (the ACP Shared-Payment-Token shape, as a JWS)
// ===================================================================================================

/** A key usable to sign/verify a delegated payment token. A plain JWK is imported; other forms pass through. */
export type TokenKey = KeyLike | Uint8Array | JWK;

function isJwk(k: TokenKey): k is JWK {
  return typeof k === 'object' && k !== null && !(k instanceof Uint8Array) && 'kty' in k;
}

/** The claims a delegated payment token carries (the JWS payload). One-time, scope-bound, proof-referenced. */
export interface DelegatedPaymentClaims {
  typ: typeof ACP_DELEGATED_TOKEN_TYPE;
  ver: typeof ACP_DELEGATED_TOKEN_VERSION;
  /** One-time id (a resource server tracks it to enforce single-use). */
  jti: string;
  /** The ACP checkout session this token is bound to. */
  session: string;
  /** The merchant this token may pay. */
  merchant: string;
  /** The maximum amount this token authorizes (minor-unit-safe decimal). */
  amount: number;
  currency: string;
  /** Issued-at (epoch ms). */
  iat: number;
  /** Expiry (epoch ms). */
  exp: number;
  paymentMethod: PaymentMethod;
  /** The ACP human-present modality signal for this charge. */
  humanPresent: boolean;
  /** The merchant category, when supplied at mint. */
  category?: string;
  /** Optional issuer id of the minting party (agent platform / facilitator). */
  iss?: string;
  /** The PCA authority this token carries by reference. */
  pca: PcaAuthorityRef;
}

/** Options for {@link mintDelegatedPaymentToken}. */
export interface MintOptions {
  /** The amount to authorize (the token's ceiling for this one checkout). */
  amount: number;
  currency: string;
  /** The merchant the token may pay. */
  merchant: string;
  /** The ACP checkout session id the token is bound to. */
  session: string;
  /** Token expiry (epoch ms). Must be in the future and not outlive the authorizing proof's `exp`. */
  expiresAt: number;
  paymentMethod: PaymentMethod;
  /** The JWS signing key (the minting party's key). Required to produce the token. */
  signingKey: TokenKey;
  /** JWS algorithm (default `'EdDSA'`). */
  alg?: string;
  /** Merchant category (MCC), required only when the proof constrains categories. */
  category?: string;
  /** The human-present modality to stamp; also satisfies a `human_present` caveat when `true`. */
  humanPresent?: boolean;
  /** Issuer id to stamp into the claims. */
  issuer?: string;
  /** JWS `kid` header (set it when verifiers resolve the key from a JWKS). */
  kid?: string;
  /** Explicit one-time id. Default: a deterministic digest of the binding + proof digest. */
  jti?: string;
  /** Issued-at clock (epoch ms). Default `Date.now()`. */
  now?: number;
}

/**
 * Mint a one-time ACP delegated payment token (a JWS) FROM a PCActn. The token is bound to
 * session + merchant + amount + currency + expiry and carries the proof's authority BY REFERENCE
 * (`pca.digest`). The PCActn's capability caveats gate issuance: the request is checked against the
 * proof's {@link PaymentAuthority} and the mint is REFUSED (throws {@link AcpAuthorityError}) when the
 * amount / currency / merchant / category / modality exceeds it, or when the requested expiry is in the
 * past or would outlive the proof. The token never re-exposes the proof's contents — only the digest.
 */
export async function mintDelegatedPaymentToken(pcActn: PCActn, opts: MintOptions): Promise<string> {
  const now = Number.isFinite(opts.now) ? (opts.now as number) : Date.now();

  // 1. Gate issuance on the proof's authority (fail closed on an over-authority request).
  const authority = extractPaymentAuthority(leafCapability(pcActn).caveats);
  const check = checkPaymentAuthority(authority, {
    amount: opts.amount,
    currency: opts.currency,
    merchant: opts.merchant,
    ...(opts.category !== undefined ? { category: opts.category } : {}),
    ...(opts.humanPresent !== undefined ? { humanPresent: opts.humanPresent } : {}),
  });
  if (!check.ok) throw new AcpAuthorityError(`refused: ${check.reason ?? 'request exceeds the proof authority'}`);

  // 2. Expiry binding: the token must expire in the future and never outlive the proof that authorized it.
  if (!Number.isFinite(opts.expiresAt)) throw new AcpAuthorityError('refused: expiresAt must be a finite epoch-ms timestamp');
  if (opts.expiresAt <= now) throw new AcpAuthorityError('refused: expiresAt is not in the future');
  if (opts.expiresAt > pcActn.exp) {
    throw new AcpAuthorityError(`refused: token expiry ${opts.expiresAt} would outlive the proof's exp ${pcActn.exp}`);
  }
  if (!opts.session) throw new AcpAuthorityError('refused: a session id is required');

  const pca = authorityRef(pcActn);
  const jti =
    opts.jti ??
    pcactnDigest({
      ...pcActn,
      // Derive a stable one-time id from the proof digest + the token binding (not a real PCActn; just a hash seed).
      nonce: `acp:${opts.session}:${opts.merchant}:${opts.amount}:${opts.currency}:${opts.expiresAt}:${pca.digest}`,
    });

  const claims: DelegatedPaymentClaims = {
    typ: ACP_DELEGATED_TOKEN_TYPE,
    ver: ACP_DELEGATED_TOKEN_VERSION,
    jti,
    session: opts.session,
    merchant: opts.merchant,
    amount: opts.amount,
    currency: opts.currency,
    iat: now,
    exp: opts.expiresAt,
    paymentMethod: { ...opts.paymentMethod },
    humanPresent: opts.humanPresent === true,
    ...(opts.category !== undefined ? { category: opts.category } : {}),
    ...(opts.issuer !== undefined ? { iss: opts.issuer } : {}),
    pca,
  };

  const alg = opts.alg ?? 'EdDSA';
  const key: KeyLike | Uint8Array = isJwk(opts.signingKey) ? await importJWK(opts.signingKey, alg) : opts.signingKey;
  const protectedHeader: CompactJWSHeaderParameters = {
    alg,
    typ: ACP_DELEGATED_TOKEN_TYPE,
    ...(opts.kid !== undefined ? { kid: opts.kid } : {}),
  };
  return new CompactSign(utf8(JSON.stringify(claims))).setProtectedHeader(protectedHeader).sign(key);
}

// ===================================================================================================
// Delegated payment token verification
// ===================================================================================================

/** Options for {@link verifyDelegatedPaymentToken}. */
export interface VerifyTokenOptions {
  /** The expected merchant the token must authorize. */
  expectedMerchant: string;
  /** The amount the caller intends to settle. Fails closed when it exceeds the token's authorized amount. */
  amount: number;
  /** The JWS verification key. */
  verifyKey: TokenKey;
  /** JWS algorithm (default `'EdDSA'`). */
  alg?: string;
  /** Verification clock (epoch ms). Default `Date.now()`. */
  now?: number;
  /** The session the token must be bound to, when the caller wants it checked. */
  expectedSession?: string;
  /** Expected settlement currency, when the caller wants it checked. */
  expectedCurrency?: string;
  /**
   * The authorizing PCActn. When supplied, its `pcactnDigest()` must equal the token's `pca.digest`
   * (proof-binding). When `grant` is ALSO supplied, the proof is additionally re-verified end-to-end.
   */
  pcActn?: PCActn;
  /** The grant to re-verify `pcActn` against (enables a full `verifyPCActnCore` pass). */
  grant?: Capability;
  /** This verifier's audience for the full `verifyPCActnCore` pass (see the core's fail-closed rule). */
  audience?: string | null;
}

/** The outcome of verifying a delegated payment token. */
export interface TokenVerification {
  ok: boolean;
  reason?: string;
  /** The verified claims (present only on success, or when the JWS verified but a binding check failed). */
  claims?: DelegatedPaymentClaims;
  /** The full PCActn verify result, when a re-verify was requested. */
  pcaResult?: VerifyResult;
}

function isPaymentMethod(v: unknown): v is PaymentMethod {
  return v !== null && typeof v === 'object' && typeof (v as { type?: unknown }).type === 'string';
}

function parseClaims(bytes: Uint8Array): DelegatedPaymentClaims | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const c = parsed as Record<string, unknown>;
  if (c.typ !== ACP_DELEGATED_TOKEN_TYPE || c.ver !== ACP_DELEGATED_TOKEN_VERSION) return null;
  if (
    typeof c.jti !== 'string' ||
    typeof c.session !== 'string' ||
    typeof c.merchant !== 'string' ||
    typeof c.amount !== 'number' ||
    typeof c.currency !== 'string' ||
    typeof c.iat !== 'number' ||
    typeof c.exp !== 'number' ||
    typeof c.humanPresent !== 'boolean' ||
    !isPaymentMethod(c.paymentMethod)
  ) {
    return null;
  }
  const pcaRaw = c.pca;
  if (pcaRaw === null || typeof pcaRaw !== 'object' || Array.isArray(pcaRaw)) return null;
  const p = pcaRaw as Record<string, unknown>;
  if (
    typeof p.digest !== 'string' ||
    typeof p.aud !== 'string' ||
    typeof p.grant_ref !== 'string' ||
    typeof p.leaf_holder !== 'string' ||
    typeof p.verb !== 'string' ||
    typeof p.resource !== 'string' ||
    typeof p.params_digest !== 'string'
  ) {
    return null;
  }
  // Shape validated field-by-field above; assemble the typed view.
  return parsed as DelegatedPaymentClaims;
}

/**
 * Verify a delegated payment token at settlement. Checks the JWS signature, then the token binding:
 * merchant must equal `expectedMerchant`, the amount being settled must not exceed the token's authorized
 * amount, the token must not be expired, and (when asked) the session / currency must match. When a
 * `pcActn` is supplied its digest must equal the token's `pca.digest`; with a `grant` it is re-verified
 * end-to-end. Fails CLOSED on every mismatch.
 */
export async function verifyDelegatedPaymentToken(
  token: string,
  opts: VerifyTokenOptions,
): Promise<TokenVerification> {
  const alg = opts.alg ?? 'EdDSA';
  const now = Number.isFinite(opts.now) ? (opts.now as number) : Date.now();

  // 1. JWS signature.
  let claims: DelegatedPaymentClaims | null;
  try {
    const key: KeyLike | Uint8Array = isJwk(opts.verifyKey) ? await importJWK(opts.verifyKey, alg) : opts.verifyKey;
    const { payload } = await compactVerify(token, key, { algorithms: [alg] });
    claims = parseClaims(payload);
  } catch (e) {
    return { ok: false, reason: `token signature did not verify: ${(e as Error).message}` };
  }
  if (claims === null) return { ok: false, reason: 'token payload is not a well-formed delegated payment token' };

  // 2. Binding checks (fail closed).
  if (claims.merchant !== opts.expectedMerchant) {
    return { ok: false, reason: `token merchant "${claims.merchant}" does not match expected "${opts.expectedMerchant}"`, claims };
  }
  if (typeof opts.amount !== 'number' || !Number.isFinite(opts.amount) || opts.amount <= 0) {
    return { ok: false, reason: 'settlement amount must be a finite number > 0', claims };
  }
  if (opts.amount > claims.amount) {
    return { ok: false, reason: `settlement amount ${opts.amount} exceeds the token's authorized amount ${claims.amount}`, claims };
  }
  if (now > claims.exp) {
    return { ok: false, reason: 'the delegated payment token has expired', claims };
  }
  if (opts.expectedSession !== undefined && claims.session !== opts.expectedSession) {
    return { ok: false, reason: `token session "${claims.session}" does not match expected "${opts.expectedSession}"`, claims };
  }
  if (opts.expectedCurrency !== undefined && claims.currency !== opts.expectedCurrency) {
    return { ok: false, reason: `token currency "${claims.currency}" does not match expected "${opts.expectedCurrency}"`, claims };
  }

  // 3. Proof binding (optional): the token's digest must match the supplied PCActn.
  if (opts.pcActn !== undefined) {
    if (pcactnDigest(opts.pcActn) !== claims.pca.digest) {
      return { ok: false, reason: 'pcactn_digest mismatch: the supplied proof is not the one that minted this token', claims };
    }
    if (opts.grant !== undefined) {
      const pcaResult = await verifyPCActnCore(opts.pcActn, {
        grant: opts.grant,
        nowEpoch: now,
        audience: opts.audience,
      });
      if (!pcaResult.allow) {
        return { ok: false, reason: `bound proof failed to verify: ${pcaResult.reason ?? 'denied'}`, claims, pcaResult };
      }
      return { ok: true, claims, pcaResult };
    }
  }

  return { ok: true, claims };
}

// ===================================================================================================
// x402 (HTTP 402 "Payment Required") facilitator hook
// ===================================================================================================

/** A single x402 payment requirement (the server's `accepts` entry). Structural; check against the x402 spec. */
export interface X402Requirement {
  scheme: string;
  network: string;
  maxAmountRequired: string;
  resource: string;
  description: string;
  payTo: string;
  asset: string;
  mimeType: string;
}

/** The HTTP 402 challenge a resource server returns to demand payment. */
export interface X402Challenge {
  status: 402;
  headers: Record<string, string>;
  body: {
    x402Version: 1;
    accepts: X402Requirement[];
    error?: string;
  };
}

/** Options for {@link x402Challenge}. */
export interface X402ChallengeOptions {
  amount: number;
  currency?: string;
  /** The settlement network (e.g. an x402 chain id). Default `base-sepolia`. */
  network?: string;
  /** Payee address / account. */
  payTo?: string;
  description?: string;
  /** Payment scheme. Default `exact`. */
  scheme?: string;
  mimeType?: string;
  /** An error reason to surface alongside the challenge (e.g. on a rejected prior attempt). */
  error?: string;
}

/**
 * Build the HTTP 402 `Payment Required` challenge for a protected resource — the server's `accepts`
 * payment requirement plus the `402` status. Structural only; no network. (Field names follow the
 * public x402 shape and should be validated against the x402 spec before production.)
 */
export function x402Challenge(resource: string, opts: X402ChallengeOptions): X402Challenge {
  const requirement: X402Requirement = {
    scheme: opts.scheme ?? 'exact',
    network: opts.network ?? 'base-sepolia',
    maxAmountRequired: String(opts.amount),
    resource,
    description: opts.description ?? `Payment required for ${resource}`,
    payTo: opts.payTo ?? '',
    asset: opts.currency ?? '',
    mimeType: opts.mimeType ?? 'application/json',
  };
  return {
    status: 402,
    headers: { 'Content-Type': 'application/json' },
    body: {
      x402Version: 1,
      accepts: [requirement],
      ...(opts.error !== undefined ? { error: opts.error } : {}),
    },
  };
}

/** The client's x402 payment payload (the decoded `X-PAYMENT`). Carries the delegated payment token. */
export interface X402PaymentPayload {
  x402Version?: number;
  scheme?: string;
  network?: string;
  /** The ACP delegated payment token (a JWS) proving proof-carrying authority for this charge. */
  token: string;
  /** The merchant the client is paying (checked against the token). */
  merchant?: string;
  /** The amount the client intends to settle (checked against the token). */
  amount?: number;
  resource?: string;
  [k: string]: unknown;
}

/** The outcome an injected x402 verifier returns. */
export interface X402VerifyResult {
  ok: boolean;
  reason?: string;
  /** The verified token claims, when the payment verified. */
  claims?: DelegatedPaymentClaims;
}

/** An injectable function that verifies an x402 payment payload (fed a verified PCActn-bound token). */
export type X402Verify = (payload: X402PaymentPayload) => X402VerifyResult | Promise<X402VerifyResult>;

/** An injectable settlement step run once payment is verified (e.g. a facilitator call). No network here. */
export type X402Settler = (
  payload: X402PaymentPayload,
  claims: DelegatedPaymentClaims,
) => unknown | Promise<unknown>;

/** Options for {@link x402Settle} — the injected verify (required) and optional settlement step. */
export interface X402SettleOptions {
  verify: X402Verify;
  /** Optional settlement step run only after `verify` passes; its return value becomes the `receipt`. */
  settle?: X402Settler;
}

/** The outcome of an x402 settlement attempt. */
export interface X402SettleResult {
  settled: boolean;
  status: number;
  reason?: string;
  claims?: DelegatedPaymentClaims;
  receipt?: unknown;
}

/**
 * Gate an x402 settlement on a verified, PCActn-bound payment. Runs the injected `verify` over the
 * client's payment payload; on failure it REFUSES with a fresh `402` (fail closed), on success it
 * optionally runs the injected `settle` step and returns the receipt. The verify/settle steps are
 * injectable so this composes with {@link verifyDelegatedPaymentToken} (see {@link acpX402Verifier})
 * without this module performing any network itself.
 */
export async function x402Settle(payload: X402PaymentPayload, opts: X402SettleOptions): Promise<X402SettleResult> {
  if (payload === null || typeof payload !== 'object' || typeof payload.token !== 'string') {
    return { settled: false, status: 402, reason: 'x402 payment payload is missing a token' };
  }
  const v = await opts.verify(payload);
  if (!v.ok) {
    return { settled: false, status: 402, reason: v.reason ?? 'payment verification failed', ...(v.claims ? { claims: v.claims } : {}) };
  }
  if (v.claims === undefined) {
    return { settled: false, status: 402, reason: 'verifier admitted the payment but returned no claims (fail closed)' };
  }
  const receipt = opts.settle ? await opts.settle(payload, v.claims) : undefined;
  return { settled: true, status: 200, claims: v.claims, ...(receipt !== undefined ? { receipt } : {}) };
}

/** Options for {@link acpX402Verifier}. */
export interface AcpX402VerifierOptions {
  /** The JWS verification key for the delegated payment token. */
  verifyKey: TokenKey;
  alg?: string;
  now?: number;
  /** Override the expected merchant (default: the payload's `merchant`). */
  expectedMerchant?: string;
  /** Override the settlement amount (default: the payload's `amount`). */
  amount?: number;
  expectedSession?: string;
  expectedCurrency?: string;
  /** The authorizing proof to re-check the token against (digest, and end-to-end with `grant`). */
  pcActn?: PCActn;
  grant?: Capability;
  audience?: string | null;
}

/**
 * Adapt {@link verifyDelegatedPaymentToken} into an {@link X402Verify} for {@link x402Settle}: it reads
 * the delegated payment token (and, by default, the merchant + amount the client claims) from the x402
 * payload and verifies the token's binding + bound proof. This is the glue that makes the
 * 402 → pay-with-proof → settle flow proof-carrying end to end.
 */
export function acpX402Verifier(opts: AcpX402VerifierOptions): X402Verify {
  return async (payload: X402PaymentPayload): Promise<X402VerifyResult> => {
    const merchant = opts.expectedMerchant ?? payload.merchant;
    if (typeof merchant !== 'string' || merchant.length === 0) {
      return { ok: false, reason: 'x402 payload has no merchant to check the token against' };
    }
    const amount = opts.amount ?? payload.amount;
    if (typeof amount !== 'number') {
      return { ok: false, reason: 'x402 payload has no amount to check the token against' };
    }
    const res = await verifyDelegatedPaymentToken(payload.token, {
      expectedMerchant: merchant,
      amount,
      verifyKey: opts.verifyKey,
      ...(opts.alg !== undefined ? { alg: opts.alg } : {}),
      ...(opts.now !== undefined ? { now: opts.now } : {}),
      ...(opts.expectedSession !== undefined ? { expectedSession: opts.expectedSession } : {}),
      ...(opts.expectedCurrency !== undefined ? { expectedCurrency: opts.expectedCurrency } : {}),
      ...(opts.pcActn !== undefined ? { pcActn: opts.pcActn } : {}),
      ...(opts.grant !== undefined ? { grant: opts.grant } : {}),
      ...(opts.audience !== undefined ? { audience: opts.audience } : {}),
    });
    return { ok: res.ok, ...(res.reason !== undefined ? { reason: res.reason } : {}), ...(res.claims ? { claims: res.claims } : {}) };
  };
}
