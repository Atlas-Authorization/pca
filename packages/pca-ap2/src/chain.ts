/**
 * AP2 mandate issuance, presentation and verification.
 *
 * Wire format (AP2 `docs/ap2`, `ap2.sdk.sdjwt`): a mandate is the single object in an SD-JWT's
 * `delegate_payload` array, itself an array-element disclosure. An *open* mandate is signed by the
 * issuer (the user's trusted surface / agent provider) and names the agent's key in `cnf.jwk`. A
 * *closed* mandate is a KB-SD-JWT hop (`typ: kb+sd-jwt`) signed by that agent key, carrying `iat`,
 * `aud`, `nonce` and an `sd_hash` over the preceding hop. Hops are joined by `~~`. That hop is AP2's
 * key-binding mechanism; no trailing RFC 9901 KB-JWT is used or accepted.
 */
import type { KeyObject } from 'node:crypto';
import {
  Ap2Error,
  assertP256Jwk,
  disclosureBuilder,
  isObject,
  issuerJwtHashOf,
  parseJwt,
  parseSdJwtHop,
  processDisclosures,
  sdDigest,
  sdHashOf,
  signSdJwt,
  verifyHopSignature,
  verifyJwtEs256,
  type DisclosureBuilder,
  type Json,
  type JsonObject,
  type JwtHeader,
  type P256Jwk,
  type SdAlg,
  type SdJwtHop,
} from './sdjwt';
import {
  PCA_CLAIM,
  VCT_CHECKOUT,
  VCT_CHECKOUT_OPEN,
  VCT_PAYMENT,
  VCT_PAYMENT_OPEN,
  checkoutMandateProblems,
  openCheckoutMandateProblems,
  openPaymentMandateProblems,
  paymentMandateProblems,
  type CheckoutConstraint,
  type CheckoutMandateClaims,
  type Merchant,
  type OpenCheckoutMandateClaims,
  type OpenPaymentMandateClaims,
  type PaymentConstraint,
  type PaymentInstrument,
  type PaymentMandateClaims,
  type Pisp,
} from './mandates';
import {
  checkCheckoutConstraints,
  checkPaymentConstraints,
  checkoutTotal,
  projectCheckout,
  type MandateContext,
  type UcpCheckout,
} from './constraints';

// ---------------------------------------------------------------------------------------------
// issuing open mandates
// ---------------------------------------------------------------------------------------------

/** The signer of an open mandate: the user's trusted surface or agent provider (an ES256 key). */
export interface MandateIssuer {
  privateKey: KeyObject;
  /** `kid` header; a verifier's key resolver maps it to the public key. */
  kid?: string;
  /** Optional `x5c` header (base64 DER certificates); chain validation is the resolver's job. */
  x5c?: string[];
}

export interface OpenMandateCommon {
  issuer: MandateIssuer;
  /** The agent's public key; becomes `cnf.jwk` and is the only key that can sign the closed mandate. */
  agentJwk: P256Jwk;
  /** Issued-at, epoch seconds. */
  iat: number;
  /** Expiry, epoch seconds (required: an open mandate must be bounded in time). */
  exp: number;
  /** `x_pca` claim (PCA's proof of the grant); see `pca.ts`. */
  pca?: JsonObject;
  sdAlg?: SdAlg;
  /** Salt source (tests inject a deterministic one). */
  salt?: () => string;
  /** Root `typ` header; the reference SDK imposes none. */
  typ?: string;
}

const ROOT_TYP = 'dc+sd-jwt';

function signRoot(c: OpenMandateCommon, mandate: JsonObject, b: DisclosureBuilder): string {
  const element = b.element(mandate);
  return signSdJwt({
    header: { typ: c.typ ?? ROOT_TYP, ...(c.issuer.kid !== undefined ? { kid: c.issuer.kid } : {}), ...(c.issuer.x5c ? { x5c: c.issuer.x5c } : {}) },
    payload: { delegate_payload: [element], _sd_alg: c.sdAlg ?? 'sha-256' },
    disclosures: b.disclosures,
    privateKey: c.issuer.privateKey,
  });
}

function commonClaims(c: OpenMandateCommon): JsonObject {
  const jwk = assertP256Jwk(c.agentJwk, 'agentJwk');
  if (!Number.isSafeInteger(c.iat) || !Number.isSafeInteger(c.exp) || c.exp <= c.iat) throw new Ap2Error('open mandate: need integer iat < exp (epoch seconds)');
  return {
    cnf: { jwk: { crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y } },
    iat: c.iat,
    exp: c.exp,
    ...(c.pca ? { [PCA_CLAIM]: c.pca } : {}),
  };
}

/** Wrap the selectively-disclosable arrays of a payment constraint (`allowed` payees / instruments). */
function sdPaymentConstraint(c: PaymentConstraint, b: DisclosureBuilder): Json {
  if (c.type === 'payment.allowed_payees' || c.type === 'payment.allowed_payment_instruments') {
    return { type: c.type, allowed: (c.allowed as unknown as Json[]).map((x) => b.element(x)) };
  }
  return c as unknown as Json;
}

function sdCheckoutConstraint(c: CheckoutConstraint, b: DisclosureBuilder): Json {
  if (c.type === 'checkout.allowed_merchants') return { type: c.type, allowed: (c.allowed as unknown as Json[]).map((x) => b.element(x)) };
  return {
    type: c.type,
    items: c.items.map((it) => ({ id: it.id, acceptable_items: (it.acceptable_items as unknown as Json[]).map((x) => b.element(x)), quantity: it.quantity })),
  };
}

export interface OpenPaymentMandateInput extends OpenMandateCommon {
  constraints: PaymentConstraint[];
  payee?: Merchant;
  paymentAmount?: { amount: number; currency: string };
  paymentInstrument?: PaymentInstrument;
  pisp?: Pisp;
  executionDate?: string;
}

/** Issue an open Payment Mandate (`mandate.payment.open.1`) as a signed SD-JWT. */
export function issueOpenPaymentMandate(input: OpenPaymentMandateInput): string {
  const b = disclosureBuilder(input.sdAlg ?? 'sha-256', input.salt);
  const mandate: JsonObject = {
    vct: VCT_PAYMENT_OPEN,
    constraints: input.constraints.map((c) => sdPaymentConstraint(c, b)),
    ...(input.payee ? { payee: input.payee as unknown as Json } : {}),
    ...(input.paymentAmount ? { payment_amount: input.paymentAmount } : {}),
    ...(input.paymentInstrument ? { payment_instrument: input.paymentInstrument as unknown as Json } : {}),
    ...(input.pisp ? { pisp: input.pisp as unknown as Json } : {}),
    ...(input.executionDate !== undefined ? { execution_date: input.executionDate } : {}),
    ...commonClaims(input),
  };
  assertWellFormed(mandate, openPaymentMandateProblems, 'open payment mandate', input.constraints);
  return signRoot(input, mandate, b);
}

export interface OpenCheckoutMandateInput extends OpenMandateCommon {
  constraints: CheckoutConstraint[];
}

/** Issue an open Checkout Mandate (`mandate.checkout.open.1`) as a signed SD-JWT. */
export function issueOpenCheckoutMandate(input: OpenCheckoutMandateInput): string {
  const b = disclosureBuilder(input.sdAlg ?? 'sha-256', input.salt);
  const mandate: JsonObject = { vct: VCT_CHECKOUT_OPEN, constraints: input.constraints.map((c) => sdCheckoutConstraint(c, b)), ...commonClaims(input) };
  assertWellFormed(mandate, openCheckoutMandateProblems, 'open checkout mandate', input.constraints);
  return signRoot(input, mandate, b);
}

/** Validate the *plain* claims (before selective-disclosure wrapping) so a bad input fails at issuance. */
function assertWellFormed(wrapped: JsonObject, problems: (v: unknown) => string[], what: string, plainConstraints: unknown[]): void {
  const plain = { ...wrapped, constraints: plainConstraints };
  const p = problems(plain);
  if (p.length > 0) throw new Ap2Error(`${what}: ${p.join('; ')}`);
}

// ---------------------------------------------------------------------------------------------
// presenting closed mandates (KB-SD-JWT hops)
// ---------------------------------------------------------------------------------------------

export interface ClosedHopCommon {
  /** The preceding token (an open mandate, or a chain ending in an intermediate hop). */
  open: string;
  /** The agent's key pair: its public key must be the open mandate's `cnf.jwk`. */
  agentKey: { privateKey: KeyObject; publicJwk: P256Jwk };
  /** Audience of this hop (the merchant for a checkout, the credential provider for a payment). */
  aud: string;
  /** Verifier-supplied nonce; the verifier checks it on receipt. */
  nonce: string;
  /** Issued-at, epoch seconds. */
  iat: number;
  /** Optional mandate-level expiry, epoch seconds. */
  exp?: number;
  pca?: JsonObject;
  /** Binding claim: `sd_hash` (default; pins the preceding hop's disclosures) or `issuer_jwt_hash`. */
  hashMode?: 'sd_hash' | 'issuer_jwt_hash';
  salt?: () => string;
}

function presentHop(c: ClosedHopCommon, build: (b: DisclosureBuilder) => JsonObject): string {
  if (!c.aud || !c.nonce) throw new Ap2Error('closed mandate: aud and nonce are required');
  if (!Number.isSafeInteger(c.iat)) throw new Ap2Error('closed mandate: iat must be an integer');
  const prev = parseSdJwtHop(c.open);
  const b = disclosureBuilder(prev.sdAlg, c.salt);
  const mandate = build(b);
  const element = b.element(mandate);
  const mode = c.hashMode ?? 'sd_hash';
  const hop = signSdJwt({
    header: { typ: 'kb+sd-jwt' },
    payload: {
      delegate_payload: [element],
      iat: c.iat,
      aud: c.aud,
      nonce: c.nonce,
      [mode]: mode === 'sd_hash' ? sdHashOf(prev) : issuerJwtHashOf(prev),
      _sd_alg: prev.sdAlg,
    },
    disclosures: b.disclosures,
    privateKey: c.agentKey.privateKey,
  });
  // Hops are joined by "~~": the preceding token's own trailing "~" plus one separator "~".
  return `${c.open}~${hop}`;
}

export interface ClosedPaymentInput extends ClosedHopCommon {
  /** Hash of the closed checkout's `checkout_jwt` (= the closed checkout mandate's `checkout_hash`). */
  transactionId: string;
  payee: Merchant;
  paymentAmount: { amount: number; currency: string };
  paymentInstrument: PaymentInstrument;
  pisp?: Pisp;
  executionDate?: string;
  riskData?: JsonObject;
}

/** Present a closed Payment Mandate (`mandate.payment.1`) on top of an open payment mandate. */
export function presentClosedPayment(input: ClosedPaymentInput): string {
  return presentHop(input, () => {
    const mandate: JsonObject = {
      vct: VCT_PAYMENT,
      transaction_id: input.transactionId,
      payee: input.payee as unknown as Json,
      payment_amount: input.paymentAmount,
      payment_instrument: input.paymentInstrument as unknown as Json,
      ...(input.pisp ? { pisp: input.pisp as unknown as Json } : {}),
      ...(input.executionDate !== undefined ? { execution_date: input.executionDate } : {}),
      ...(input.riskData ? { risk_data: input.riskData } : {}),
      ...(input.exp !== undefined ? { exp: input.exp } : {}),
      ...(input.pca ? { [PCA_CLAIM]: input.pca } : {}),
    };
    const p = paymentMandateProblems(mandate);
    if (p.length > 0) throw new Ap2Error(`closed payment mandate: ${p.join('; ')}`);
    return mandate;
  });
}

export interface ClosedCheckoutInput extends ClosedHopCommon {
  /** The merchant-signed checkout JWT (compact). */
  checkoutJwt: string;
}

/** Present a closed Checkout Mandate (`mandate.checkout.1`) on top of an open checkout mandate. */
export function presentClosedCheckout(input: ClosedCheckoutInput): string {
  return presentHop(input, (b) => {
    const prevAlg = parseSdJwtHop(input.open).sdAlg;
    const mandate: JsonObject = {
      _sd: [b.property('checkout_jwt', input.checkoutJwt)],
      vct: VCT_CHECKOUT,
      checkout_hash: sdDigest(input.checkoutJwt, prevAlg),
      ...(input.exp !== undefined ? { exp: input.exp } : {}),
      ...(input.pca ? { [PCA_CLAIM]: input.pca } : {}),
    };
    const p = checkoutMandateProblems({ ...mandate, checkout_jwt: input.checkoutJwt });
    if (p.length > 0) throw new Ap2Error(`closed checkout mandate: ${p.join('; ')}`);
    return mandate;
  });
}

// ---------------------------------------------------------------------------------------------
// verifying a delegation chain
// ---------------------------------------------------------------------------------------------

export const TYP_TERMINAL: readonly string[] = ['kb+sd-jwt', 'kb-sd-jwt'];
export const TYP_INTERMEDIATE: readonly string[] = ['kb+sd-jwt+kb', 'kb-sd-jwt+kb'];
const MAX_HOPS = 8;

export interface VerifiedHop {
  index: number;
  kind: 'root' | 'intermediate' | 'terminal';
  hop: SdJwtHop;
  /** Hop-level claims after disclosure processing. */
  claims: JsonObject;
  /** The single mandate object disclosed in `delegate_payload`. */
  mandate: JsonObject;
}

export interface VerifyChainOptions {
  /** Resolve the root hop's public key from its header (`kid` / `x5c`); return undefined to refuse. */
  resolveIssuerKey: (header: JwtHeader) => P256Jwk | undefined;
  /** The terminal hop's `aud` must equal this. Required: a verifier that does not name itself cannot detect redirection. */
  expectedAudience: string;
  /** The terminal hop's `nonce` must equal this. Required: it is the replay defence. */
  expectedNonce: string;
  /** Verification time, epoch seconds (default: now). */
  now?: number;
  /** Tolerated clock skew in seconds (default 60). */
  clockSkewSeconds?: number;
}

export type ChainResult = { ok: true; hops: VerifiedHop[] } | { ok: false; reason: string };

/** Split a `~~`-joined chain into hops, each restored to `<jwt>~<d>...~`. */
export function splitChain(token: string): string[] {
  if (typeof token !== 'string' || token.length === 0) throw new Ap2Error('chain: empty');
  const parts = token.split('~~');
  if (parts.length > MAX_HOPS) throw new Ap2Error(`chain: more than ${MAX_HOPS} hops`);
  return parts.map((p, i) => (i === parts.length - 1 ? p : `${p}~`));
}

function checkTimes(label: string, o: JsonObject, now: number, skew: number): void {
  const { exp, iat } = o;
  if (exp !== undefined) {
    if (!Number.isSafeInteger(exp)) throw new Ap2Error(`${label}: exp must be an integer`);
    if (now > (exp as number) + skew) throw new Ap2Error(`${label}: expired at ${String(exp)}`);
  }
  if (iat !== undefined) {
    if (!Number.isSafeInteger(iat)) throw new Ap2Error(`${label}: iat must be an integer`);
    if ((iat as number) > now + skew) throw new Ap2Error(`${label}: iat is in the future`);
  }
}

function delegateMandate(claims: JsonObject, label: string): JsonObject {
  const dp = claims.delegate_payload;
  if (!Array.isArray(dp)) throw new Ap2Error(`${label}: delegate_payload missing`);
  if (dp.length !== 1 || !isObject(dp[0])) throw new Ap2Error(`${label}: delegate_payload must disclose exactly one mandate (got ${dp.length})`);
  return dp[0];
}

function cnfJwk(mandate: JsonObject, label: string): P256Jwk {
  const cnf = mandate.cnf;
  if (!isObject(cnf) || !isObject(cnf.jwk)) throw new Ap2Error(`${label}: no cnf.jwk to delegate to`);
  return assertP256Jwk(cnf.jwk, `${label} cnf.jwk`);
}

/** Verify one key-binding hop against its predecessor (signature, typ, binding hash, times, aud/nonce). */
export function verifyKbHop(
  hop: SdJwtHop,
  prev: { hop: SdJwtHop; mandate: JsonObject },
  o: { terminal: boolean; expectedAudience?: string; expectedNonce?: string; now: number; skew: number },
  label: string,
): VerifiedHop {
  const typ = hop.header.typ;
  const allowed = o.terminal ? TYP_TERMINAL : TYP_INTERMEDIATE;
  if (typeof typ !== 'string' || !allowed.includes(typ)) throw new Ap2Error(`${label}: typ must be one of ${allowed.join(', ')}`);
  if (hop.header.crit !== undefined) throw new Ap2Error(`${label}: crit headers are not supported`);
  const key = cnfJwk(prev.mandate, 'preceding mandate');
  if (!verifyHopSignature(hop, key)) throw new Ap2Error(`${label}: signature does not verify under the preceding mandate's cnf.jwk`);
  const claims = processDisclosures(hop.payload, hop.disclosures, hop.sdAlg);
  const hasSd = 'sd_hash' in claims;
  const hasIss = 'issuer_jwt_hash' in claims;
  if (hasSd === hasIss) throw new Ap2Error(`${label}: exactly one of sd_hash / issuer_jwt_hash is required`);
  const expected = hasSd ? sdHashOf(prev.hop) : issuerJwtHashOf(prev.hop);
  const actual = hasSd ? claims.sd_hash : claims.issuer_jwt_hash;
  if (actual !== expected) throw new Ap2Error(`${label}: ${hasSd ? 'sd_hash' : 'issuer_jwt_hash'} does not match the preceding hop`);
  if (claims.iat === undefined) throw new Ap2Error(`${label}: iat is required`);
  checkTimes(label, claims, o.now, o.skew);
  const mandate = delegateMandate(claims, label);
  checkTimes(`${label} mandate`, mandate, o.now, o.skew);
  const hasCnf = isObject(mandate.cnf);
  if (o.terminal && hasCnf) throw new Ap2Error(`${label}: a terminal hop must not carry cnf`);
  if (!o.terminal && !hasCnf) throw new Ap2Error(`${label}: an intermediate hop requires cnf`);
  if (o.terminal) {
    if (o.expectedAudience === undefined || claims.aud !== o.expectedAudience) throw new Ap2Error(`${label}: aud mismatch`);
    if (o.expectedNonce === undefined || claims.nonce !== o.expectedNonce) throw new Ap2Error(`${label}: nonce mismatch`);
  }
  return { index: -1, kind: o.terminal ? 'terminal' : 'intermediate', hop, claims, mandate };
}

/** Verify a whole chain: root signature, then every hop in order. Never throws; reports the reason. */
export function verifyDelegationChain(token: string, o: VerifyChainOptions): ChainResult {
  try {
    if (!o.expectedAudience || !o.expectedNonce) throw new Ap2Error('verify: expectedAudience and expectedNonce are required');
    const now = o.now ?? Math.floor(Date.now() / 1000);
    const skew = o.clockSkewSeconds ?? 60;
    const segments = splitChain(token).map(parseSdJwtHop);
    const root = segments[0] as SdJwtHop;
    if (root.header.crit !== undefined) throw new Ap2Error('root: crit headers are not supported');
    const issuerKey = o.resolveIssuerKey(root.header);
    if (!issuerKey) throw new Ap2Error('root: no issuer key for this header');
    if (!verifyHopSignature(root, issuerKey)) throw new Ap2Error('root: signature does not verify under the issuer key');
    const rootClaims = processDisclosures(root.payload, root.disclosures, root.sdAlg);
    checkTimes('root', rootClaims, now, skew);
    const rootMandate = delegateMandate(rootClaims, 'root');
    checkTimes('root mandate', rootMandate, now, skew);
    const hops: VerifiedHop[] = [{ index: 0, kind: 'root', hop: root, claims: rootClaims, mandate: rootMandate }];
    for (let i = 1; i < segments.length; i++) {
      const prev = hops[i - 1] as VerifiedHop;
      const v = verifyKbHop(segments[i] as SdJwtHop, prev, { terminal: i === segments.length - 1, expectedAudience: o.expectedAudience, expectedNonce: o.expectedNonce, now, skew }, `hop ${i}`);
      hops.push({ ...v, index: i });
    }
    return { ok: true, hops };
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
}

// ---------------------------------------------------------------------------------------------
// typed chains
// ---------------------------------------------------------------------------------------------

const pair = (r: Extract<ChainResult, { ok: true }>): [VerifiedHop, VerifiedHop] => {
  if (r.hops.length !== 2) throw new Ap2Error(`expected an open mandate followed by one closed mandate, got ${r.hops.length} hop(s)`);
  return [r.hops[0] as VerifiedHop, r.hops[1] as VerifiedHop];
};

function requireOpenExpiry(m: JsonObject, label: string): void {
  if (!Number.isSafeInteger(m.exp)) throw new Ap2Error(`${label}: an open mandate must carry exp`);
}

export type CheckoutChainResult =
  | {
      ok: true;
      open: OpenCheckoutMandateClaims;
      closed: CheckoutMandateClaims;
      checkoutJwt: string;
      checkout: UcpCheckout;
      /** `sd_hash` of the open checkout mandate token: the value an open payment mandate's `payment.reference` must hold. */
      openHash: string;
      hops: VerifiedHop[];
    }
  | { ok: false; reason: string; violations?: string[] };

export interface VerifyCheckoutOptions extends VerifyChainOptions {
  /** Resolve the merchant's key for the `checkout_jwt` signature; return undefined to refuse. */
  resolveMerchantKey: (header: JwtHeader) => P256Jwk | undefined;
}

/** Verify an open+closed checkout chain, the merchant-signed checkout, its hash, and the open constraints. */
export function verifyCheckoutChain(token: string, o: VerifyCheckoutOptions): CheckoutChainResult {
  const r = verifyDelegationChain(token, o);
  if (!r.ok) return r;
  try {
    const [openHop, closedHop] = pair(r);
    const open = openHop.mandate as unknown as OpenCheckoutMandateClaims;
    const closed = closedHop.mandate as unknown as CheckoutMandateClaims;
    const op = openCheckoutMandateProblems(open);
    if (op.length) throw new Ap2Error(`open checkout mandate: ${op.join('; ')}`);
    requireOpenExpiry(open as unknown as JsonObject, 'open checkout mandate');
    const cp = checkoutMandateProblems(closed);
    if (cp.length) throw new Ap2Error(`closed checkout mandate: ${cp.join('; ')}`);
    const alg = closedHop.hop.sdAlg;
    if (sdDigest(closed.checkout_jwt, alg) !== closed.checkout_hash) throw new Ap2Error('checkout_hash does not match checkout_jwt');
    const jwt = parseJwt(closed.checkout_jwt, 'checkout_jwt');
    const key = o.resolveMerchantKey(jwt.header);
    if (!key) throw new Ap2Error('checkout_jwt: no merchant key for this header');
    if (!verifyJwtEs256(jwt, key)) throw new Ap2Error('checkout_jwt: merchant signature does not verify');
    const checkout = projectCheckout(jwt.payload);
    const violations = checkCheckoutConstraints(open, checkout);
    if (violations.length) return { ok: false, reason: `open checkout constraints violated: ${violations.join('; ')}`, violations };
    return { ok: true, open, closed, checkoutJwt: closed.checkout_jwt, checkout, openHash: sdHashOf(openHop.hop), hops: r.hops };
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
}

export type PaymentChainResult =
  | { ok: true; open: OpenPaymentMandateClaims; closed: PaymentMandateClaims; openHash: string; hops: VerifiedHop[] }
  | { ok: false; reason: string; violations?: string[] };

export interface VerifyPaymentOptions extends VerifyChainOptions {
  /** `sd_hash` of the open checkout mandate (from `verifyCheckoutChain().openHash`); checked against `payment.reference`. */
  openCheckoutHash: string;
  /** Usage state under this open mandate (needed for `payment.budget` and recurrence). */
  context?: MandateContext;
  /** The `checkout_hash` this payment must settle (from the closed checkout mandate). */
  expectedTransactionId?: string;
}

/** Verify an open+closed payment chain and every open payment constraint. */
export function verifyPaymentChain(token: string, o: VerifyPaymentOptions): PaymentChainResult {
  const r = verifyDelegationChain(token, o);
  if (!r.ok) return r;
  try {
    const [openHop, closedHop] = pair(r);
    const open = openHop.mandate as unknown as OpenPaymentMandateClaims;
    const closed = closedHop.mandate as unknown as PaymentMandateClaims;
    const op = openPaymentMandateProblems(open);
    if (op.length) throw new Ap2Error(`open payment mandate: ${op.join('; ')}`);
    requireOpenExpiry(open as unknown as JsonObject, 'open payment mandate');
    const cp = paymentMandateProblems(closed);
    if (cp.length) throw new Ap2Error(`closed payment mandate: ${cp.join('; ')}`);
    if (o.expectedTransactionId !== undefined && closed.transaction_id !== o.expectedTransactionId) throw new Ap2Error('transaction_id does not match the checkout being settled');
    const violations = checkPaymentConstraints(open, closed, { openCheckoutHash: o.openCheckoutHash, ...(o.context ? { context: o.context } : {}), now: o.now ?? Math.floor(Date.now() / 1000) });
    if (violations.length) return { ok: false, reason: `open payment constraints violated: ${violations.join('; ')}`, violations };
    return { ok: true, open, closed, openHash: sdHashOf(openHop.hop), hops: r.hops };
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
}

export interface VerifyPurchaseOptions {
  resolveIssuerKey: VerifyChainOptions['resolveIssuerKey'];
  resolveMerchantKey: VerifyCheckoutOptions['resolveMerchantKey'];
  checkout: { expectedAudience: string; expectedNonce: string };
  payment: { expectedAudience: string; expectedNonce: string };
  context?: MandateContext;
  now?: number;
  clockSkewSeconds?: number;
}

export type PurchaseResult =
  | { ok: true; checkout: Extract<CheckoutChainResult, { ok: true }>; payment: Extract<PaymentChainResult, { ok: true }> }
  | { ok: false; reason: string };

/**
 * Verify a complete purchase: the checkout chain, then the payment chain bound to it (the payment's
 * `payment.reference` is the open checkout hash; its `transaction_id` is the closed checkout's
 * `checkout_hash`), and that the payment settles what the merchant quoted (payee, currency, total).
 */
export function verifyPurchase(checkoutToken: string, paymentToken: string, o: VerifyPurchaseOptions): PurchaseResult {
  const base = {
    resolveIssuerKey: o.resolveIssuerKey,
    ...(o.now !== undefined ? { now: o.now } : {}),
    ...(o.clockSkewSeconds !== undefined ? { clockSkewSeconds: o.clockSkewSeconds } : {}),
  };
  const co = verifyCheckoutChain(checkoutToken, { ...base, ...o.checkout, resolveMerchantKey: o.resolveMerchantKey });
  if (!co.ok) return { ok: false, reason: `checkout: ${co.reason}` };
  const pay = verifyPaymentChain(paymentToken, { ...base, ...o.payment, openCheckoutHash: co.openHash, expectedTransactionId: co.closed.checkout_hash, ...(o.context ? { context: o.context } : {}) });
  if (!pay.ok) return { ok: false, reason: `payment: ${pay.reason}` };
  const total = checkoutTotal(co.checkout);
  if (total === undefined) return { ok: false, reason: 'checkout: needs exactly one total entry' };
  const amt = pay.closed.payment_amount;
  if (amt.currency !== co.checkout.currency) return { ok: false, reason: 'payment currency differs from the checkout currency' };
  if (amt.amount !== total) return { ok: false, reason: `payment amount ${amt.amount} differs from the checkout total ${total}` };
  if (!co.checkout.merchant) return { ok: false, reason: 'checkout: no merchant to compare the payee with' };
  if (co.checkout.merchant.id !== pay.closed.payee.id) return { ok: false, reason: 'payee differs from the checkout merchant' };
  return { ok: true, checkout: co, payment: pay };
}
