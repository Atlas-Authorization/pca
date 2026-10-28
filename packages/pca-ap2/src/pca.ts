/**
 * Binding AP2 mandates to a PCA grant and to the PCA proof of each action.
 *
 * AP2 decides what a mandate may say; PCA decides whether the agent may act. The two are tied
 * together by a namespaced `x_pca` claim that lives INSIDE the mandate object (so it is covered by
 * the issuer's / agent's signature and by the next hop's `sd_hash`). The official schemas do not set
 * `additionalProperties: false` and the reference SDK ignores unknown mandate claims, so the claim
 * does not affect schema validity or reference verification (both are tested).
 *
 *   open mandate   `x_pca = { v, grant, terms }`          the PCA grant (principal-signed, Ed25519)
 *                                                          and the terms it was minted from
 *   closed payment `x_pca = { v, charge, pcactn }`        the PCActn (agent-signed, Ed25519) that
 *                                                          authorises exactly this charge
 *
 * The PCActn's signed `nonce` commits to the AP2 side: the transaction id, payee, amount, instrument,
 * the open mandate's `sd_hash` and the thumbprint of the agent's AP2 key. Swapping any of those, or
 * replaying the PCActn under another mandate or another AP2 agent key, breaks the binding.
 */
import {
  buildPCActn,
  hashCanonical,
  paramsDigest,
  readEnvelope,
  requiredThreshold,
  verifyChain,
  verifyPCActnCore,
  type Capability,
  type PCActn,
  type ThresholdSignature,
} from '@atlasauth/pca';
import {
  authorizeCharge,
  chargeParams,
  chargePlanNode,
  mandateCaveats,
  mandatePredicates,
  type MandateTerms,
  type PaymentMandate as PcaPaymentMandate,
} from '@atlasauth/pca-payments';
import {
  Ap2Error,
  jwkThumbprint,
  parseSdJwtHop,
  sdHashOf,
  type JsonObject,
  type P256Jwk,
} from './sdjwt';
import {
  currencyExponent,
  type Merchant,
  type OpenCheckoutMandateClaims,
  type OpenPaymentMandateClaims,
  type PaymentConstraint,
  type PaymentMandateClaims,
} from './mandates';
import { issueOpenCheckoutMandate, issueOpenPaymentMandate, type MandateIssuer } from './chain';
import type { CheckoutConstraint } from './mandates';

export const PCA_BINDING_VERSION = 1;

/** A PCA term as integer minor units; anything else (a major-unit float from an older mandate) is refused. */
function minorTerm(v: unknown, name: string): number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) throw new Ap2Error(`PCA term ${name} must be a non-negative integer in minor units, got ${String(v)}`);
  return v;
}

const toJson = <T>(v: T): JsonObject => JSON.parse(JSON.stringify(v)) as JsonObject;

// ---------------------------------------------------------------------------------------------
// PCA terms -> AP2 open mandates
// ---------------------------------------------------------------------------------------------

/** The `x_pca` claim of an open mandate: the principal-signed grant and the terms it was minted from. */
export function pcaOpenClaim(mandate: PcaPaymentMandate): JsonObject {
  return { v: PCA_BINDING_VERSION, grant: toJson(mandate.grant), terms: toJson(mandate.terms) };
}

export interface FromTermsOptions {
  issuer: MandateIssuer;
  agentJwk: P256Jwk;
  /** Descriptors for every merchant id in the PCA terms (AP2 needs a name; PCA only holds the id). */
  merchants: Merchant[];
  /** Issued-at, epoch seconds. */
  iat: number;
  /** Expiry, epoch seconds; must not exceed the PCA period end. Required when the terms have no period end. */
  exp?: number;
  salt?: () => string;
}

function openExpiry(terms: MandateTerms, o: FromTermsOptions): number {
  const periodEnd = terms.periodEnd !== undefined ? Math.floor(terms.periodEnd / 1000) : undefined;
  const exp = o.exp ?? periodEnd;
  if (exp === undefined) throw new Ap2Error('exp is required when the PCA terms have no period end');
  if (periodEnd !== undefined && exp > periodEnd) throw new Ap2Error('exp must not exceed the PCA period end');
  return exp;
}

function merchantsFor(terms: MandateTerms, merchants: Merchant[]): Merchant[] {
  return terms.merchants.map((id) => {
    const m = merchants.find((x) => x.id === id);
    if (!m) throw new Ap2Error(`no merchant descriptor supplied for PCA merchant ${id}`);
    return m;
  });
}

/** Next representable double above a positive finite `x`. */
function nextUp(x: number): number {
  const f = new Float64Array([x]);
  const u = new BigUint64Array(f.buffer);
  u[0] = u[0]! + 1n;
  return f[0]!;
}

/**
 * The value of AP2 `payment.budget.max` for a PCA cap in integer minor units. The official AP2 SDK reads it as
 * `int(max * 100)` whatever the currency, while the schema calls it an amount, so two readers exist: the SDK
 * (hundredths) and a major-unit reader (`max * 10^exponent`). The value emitted never lets EITHER read more than the cap:
 *   exponent 0 or 1 (JPY): `cap / 100`, so the SDK reads exactly the cap and a major-unit reader reads less;
 *   exponent 2 (USD): `cap / 100`, exact for both;
 *   exponent 3 or more (KWD): `cap / 10^exponent`, exact for a major-unit reader; the SDK reads `floor(cap / 10^(exponent-2))`.
 * The double is nudged up by at most a few ulps when `cap / divisor` falls just under the exact decimal, so that
 * the SDK's `int(max * 100)` is exact (0.29 * 100 is 28.999999999999996 in floating point).
 */
export function ap2BudgetMax(capMinor: number, currency: string): number {
  const cap = minorTerm(capMinor, 'cumulativeCap');
  const e = currencyExponent(currency);
  const sdkTarget = e <= 2 ? cap : Math.floor(cap / 10 ** (e - 2));
  let d = cap / 10 ** Math.max(e, 2);
  for (let i = 0; i < 8 && d > 0 && Math.trunc(d * 100) < sdkTarget; i++) d = nextUp(d);
  if (Math.trunc(d * 100) !== sdkTarget || Math.round(d * 10 ** e) > cap) throw new Ap2Error(`cumulativeCap ${cap} ${currency} has no exact AP2 budget.max representation`);
  return d;
}

/** What the two readers of an AP2 `budget.max` read, in minor units of `currency`: the SDK (`int(max * 100)`) and a major-unit reader. */
export function ap2BudgetReads(max: number, currency: string): { sdk: number; major: number } {
  const e = currencyExponent(currency);
  if (typeof max !== 'number' || !Number.isFinite(max) || max < 0) throw new Ap2Error(`budget.max must be a finite non-negative number, got ${String(max)}`);
  return { sdk: Math.trunc(max * 100), major: Math.round(max * 10 ** e) };
}

/**
 * The AP2 open payment constraints a set of PCA terms denotes. PCA terms are INTEGER MINOR UNITS of the mandate currency
 * (ISO 4217 exponent per currency: USD 2, JPY 0, KWD 3); `amount_range` is in the same minor units. `budget.max` is
 * derived exactly by {@link ap2BudgetMax}; no currency is refused for its exponent.
 */
export function paymentConstraintsFromTerms(terms: MandateTerms, merchants: Merchant[], checkoutReference: string): PaymentConstraint[] {
  const cur = terms.currency;
  const perTx = minorTerm(terms.perTransactionCap, 'perTransactionCap');
  const budgetMax = ap2BudgetMax(terms.cumulativeCap, cur);
  return [
    { type: 'payment.amount_range', currency: cur, min: 0, max: perTx },
    { type: 'payment.allowed_payees', allowed: merchantsFor(terms, merchants) },
    { type: 'payment.reference', conditional_transaction_id: checkoutReference },
    { type: 'payment.budget', currency: cur, max: budgetMax },
    { type: 'payment.agent_recurrence', frequency: 'ON_DEMAND', ...(terms.maxTransactionsPerPeriod !== undefined ? { max_occurrences: terms.maxTransactionsPerPeriod } : {}) },
  ];
}

/** Issue the open payment mandate for a PCA mandate (grant + terms), chained to `checkoutReference`. */
export function openPaymentMandateFromPca(mandate: PcaPaymentMandate, o: FromTermsOptions & { checkoutReference: string }): string {
  return issueOpenPaymentMandate({
    issuer: o.issuer,
    agentJwk: o.agentJwk,
    iat: o.iat,
    exp: openExpiry(mandate.terms, o),
    pca: pcaOpenClaim(mandate),
    constraints: paymentConstraintsFromTerms(mandate.terms, o.merchants, o.checkoutReference),
    ...(o.salt ? { salt: o.salt } : {}),
  });
}

/** Issue the open checkout mandate for a PCA mandate: the merchant allowlist and the acceptable line items. */
export function openCheckoutMandateFromPca(
  mandate: PcaPaymentMandate,
  o: FromTermsOptions & { lineItems: Extract<CheckoutConstraint, { type: 'checkout.line_items' }>['items'] },
): string {
  return issueOpenCheckoutMandate({
    issuer: o.issuer,
    agentJwk: o.agentJwk,
    iat: o.iat,
    exp: openExpiry(mandate.terms, o),
    pca: pcaOpenClaim(mandate),
    constraints: [
      { type: 'checkout.line_items', items: o.lineItems },
      { type: 'checkout.allowed_merchants', allowed: merchantsFor(mandate.terms, o.merchants) },
    ],
    ...(o.salt ? { salt: o.salt } : {}),
  });
}

// ---------------------------------------------------------------------------------------------
// the closed payment: PCActn bound to the AP2 mandate
// ---------------------------------------------------------------------------------------------

export interface BindingFacts {
  transactionId: string;
  payeeId: string;
  amount: number;
  currency: string;
  instrumentId: string;
  /** `sd_hash` of the open payment mandate token the closed mandate is chained to. */
  openHash: string;
  /** RFC 7638 thumbprint of the agent's AP2 (P-256) key. */
  agentJkt: string;
}

/** The value the PCActn's signed `nonce` must equal for these AP2 facts. */
export function pcaBindingNonce(f: BindingFacts): string {
  return `ap2:${hashCanonical({ v: PCA_BINDING_VERSION, ...f })}`;
}

export interface PcaPaymentBindingInput {
  /** The PCA mandate (grant + terms + budget) the agent holds. */
  mandate: PcaPaymentMandate;
  /** The open payment mandate token the closed mandate will be chained to. */
  open: string;
  agentJwk: P256Jwk;
  /** The agent's Ed25519 secret (the PCA grant's holder); signs the PCActn. */
  agentSecret: Uint8Array;
  /** PCA audience (the resource server / Atlas instance id this action is for). */
  audience: string;
  counter: number;
  transactionId: string;
  payee: Merchant;
  amount: { amount: number; currency: string };
  instrumentId: string;
  category?: string;
  /** PCActn `iat`, epoch ms. */
  now?: number;
  /** For a charge that needs a human co-sign (PCA step-up): returns the threshold shares over the built PCActn. */
  cosign?: (pcactn: PCActn) => ThresholdSignature;
}

/**
 * amount / cap, clamped to [0, 1] and rounded UP to 12 decimals. PCA's canonical encoding refuses
 * numbers with more than 15 significant digits (so 100/300 cannot be signed as-is); rounding up can
 * only raise the risk the threshold policy sees, never lower it.
 */
export function riskRatio(amount: number, cap: number): number {
  const r = cap > 0 ? amount / cap : 1;
  return Math.min(1, Math.max(0, Math.ceil(r * 1e12 - 1e-6) / 1e12));
}

/** Build the `x_pca` claim of a closed payment mandate: a PCActn authorising exactly this charge. */
export function buildPcaPaymentBinding(i: PcaPaymentBindingInput): JsonObject {
  const major = minorTerm(i.amount.amount, 'amount'); // the charge amount is integer minor units, as in the mandate
  const charge = { merchant: i.payee.id, amount: major, currency: i.amount.currency, ...(i.category !== undefined ? { category: i.category } : {}) };
  const facts: BindingFacts = {
    transactionId: i.transactionId,
    payeeId: i.payee.id,
    amount: i.amount.amount,
    currency: i.amount.currency,
    instrumentId: i.instrumentId,
    openHash: sdHashOf(parseSdJwtHop(i.open)),
    agentJkt: jwkThumbprint(i.agentJwk),
  };
  const risk = riskRatio(major, i.mandate.terms.perTransactionCap);
  const nodeId = `ap2:${i.transactionId}`;
  const node = chargePlanNode(i.mandate, charge, nodeId);
  const built = buildPCActn({
    grant: i.mandate.grant,
    chain: [i.mandate.grant],
    plan: [node],
    nodeId,
    params: chargeParams(i.mandate, charge),
    counter: i.counter,
    signerSecret: i.agentSecret,
    aud: i.audience,
    nonce: pcaBindingNonce(facts),
    riskClaim: { r: risk, inputs: { ...chargeParams(i.mandate, charge), blastRadius: risk } },
    ...(i.now !== undefined ? { now: i.now } : {}),
  });
  const pcactn: PCActn = i.cosign ? { ...built, threshold: i.cosign(built) } : built;
  return {
    v: PCA_BINDING_VERSION,
    charge: { amount: major, currency: i.amount.currency, ...(i.category !== undefined ? { category: i.category } : {}) },
    pcactn: toJson(pcactn),
  };
}

// ---------------------------------------------------------------------------------------------
// verification
// ---------------------------------------------------------------------------------------------

type PcaVerifyExtras = Pick<NonNullable<Parameters<typeof verifyPCActnCore>[1]>, 'hooks' | 'enforce'>;

export interface VerifyPcaBindingInput extends PcaVerifyExtras {
  open: OpenPaymentMandateClaims;
  closed: PaymentMandateClaims;
  /** `sd_hash` of the open payment mandate hop (from `verifyPaymentChain().openHash`). */
  openHash: string;
  /** The Ed25519 key (b64u) of the principal who must have signed the grant. Required. */
  expectedPrincipal: string;
  /** verifier-side PQ pins by Ed25519 identity (R3-01). A pure-PQ / hybrid ROOT is accepted only if the root issuer has a pin equal to its `pq_pk` (a signed binding from `pqPinFor`, or your own registry); without one it is refused. */
  pqPins?: Readonly<Record<string, string>>;
  /** This verifier's PCA audience; the PCActn's signed `aud` must equal it. */
  audience: string;
  /** Verification time, epoch ms. */
  now?: number;
  /**
   * REQUIRED: the PCA mandate state THIS verifier holds (its live budget). The policy decision always runs on it, so the
   * cumulative budget is enforced; without it the binding is refused ({@link PcaBindingError} `mandate_required`).
   */
  mandate: PcaPaymentMandate;
  /**
   * Epoch-ms times of this holder's earlier admitted charges, from the verifier's own records (the velocity `rate`
   * caveat reads them). REQUIRED when the mandate limits the charge count (`maxTransactionsPerPeriod`); otherwise empty.
   */
  recentChargeTimes?: number[];
}

/** Thrown when `verifyPcaBinding` lacks the server-held state the policy decision needs. */
export class PcaBindingError extends Error {
  constructor(
    readonly code: 'mandate_required' | 'charge_history_required',
    message: string,
  ) {
    super(message);
    this.name = 'PcaBindingError';
  }
}

export type PcaBindingResult = { ok: true; pcactn: PCActn; grant: Capability; terms: MandateTerms } | { ok: false; reason: string };

const isRec = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Check the open mandate's constraints never exceed the PCA terms (the AP2 side only narrows the grant). */
function constraintsWithinTerms(open: OpenPaymentMandateClaims, terms: MandateTerms): string | undefined {
  const cur = terms.currency;
  const perTx = minorTerm(terms.perTransactionCap, 'perTransactionCap');
  const range = open.constraints.find((c) => c.type === 'payment.amount_range');
  if (!range || range.type !== 'payment.amount_range') return 'open mandate has no amount_range to compare with the PCA per-transaction cap';
  if (range.currency !== cur) return 'amount_range currency differs from the PCA terms';
  if (range.max > perTx) return `amount_range.max ${range.max} exceeds the PCA per-transaction cap ${perTx}`;
  const payees = open.constraints.find((c) => c.type === 'payment.allowed_payees');
  if (payees && payees.type === 'payment.allowed_payees' && payees.allowed.some((m) => !terms.merchants.includes(m.id))) return 'allowed_payees names a merchant outside the PCA allowlist';
  if (!payees) return 'open mandate has no allowed_payees; the PCA allowlist would not be enforced on the AP2 side';
  const budget = open.constraints.find((c) => c.type === 'payment.budget');
  if (!budget || budget.type !== 'payment.budget') return 'open mandate has no budget to compare with the PCA cumulative cap';
  if (budget.currency !== cur) return 'budget exceeds the PCA cumulative cap';
  const reads = ap2BudgetReads(budget.max, cur);
  const capMinor = minorTerm(terms.cumulativeCap, 'cumulativeCap');
  if (reads.sdk > capMinor || reads.major > capMinor) return 'budget exceeds the PCA cumulative cap';
  const rec = open.constraints.find((c) => c.type === 'payment.agent_recurrence');
  if (terms.maxTransactionsPerPeriod !== undefined && (!rec || rec.type !== 'payment.agent_recurrence' || rec.max_occurrences === undefined || rec.max_occurrences > terms.maxTransactionsPerPeriod)) {
    return 'max_occurrences is missing or exceeds the PCA transaction limit';
  }
  if (terms.periodEnd !== undefined && (open.exp === undefined || open.exp > Math.floor(terms.periodEnd / 1000))) return 'open mandate outlives the PCA period';
  return undefined;
}

/**
 * Verify the PCA side of a verified AP2 payment chain: the grant in the open mandate (signed by the
 * expected principal, consistent with the terms it claims and with the open constraints), and the
 * closed mandate's PCActn (valid under that grant, for this audience, committing to exactly this
 * AP2 charge). Run it after `verifyPaymentChain`, which establishes the AP2 signatures.
 */
export async function verifyPcaBinding(i: VerifyPcaBindingInput): Promise<PcaBindingResult> {
  // The decision (cumulative budget, charge-count rate limit, caveats) needs the verifier's OWN mandate state and history.
  if (!i || !isRec(i.mandate)) throw new PcaBindingError('mandate_required', 'verifyPcaBinding needs the server-held PCA mandate (its live budget); the policy decision is never skipped');
  const maxTx = (i.mandate as { terms?: { maxTransactionsPerPeriod?: unknown } }).terms?.maxTransactionsPerPeriod;
  if (maxTx !== undefined && !(Array.isArray(i.recentChargeTimes) && i.recentChargeTimes.every((t) => typeof t === 'number' && Number.isFinite(t)))) {
    throw new PcaBindingError('charge_history_required', 'the mandate limits the charge count: pass recentChargeTimes from your own records');
  }
  const fail = (reason: string): PcaBindingResult => ({ ok: false, reason });
  try {
    const oc = i.open.x_pca;
    if (!isRec(oc) || oc.v !== PCA_BINDING_VERSION || !isRec(oc.grant) || !isRec(oc.terms)) return fail('open mandate carries no x_pca grant');
    const grant = oc.grant as unknown as Capability;
    const terms = oc.terms as unknown as MandateTerms;
    const chain = verifyChain([grant], i.expectedPrincipal, { pqPins: i.pqPins });
    if (!chain.ok) return fail(`PCA grant: ${chain.reason ?? 'invalid'}`);
    const env = readEnvelope(grant);
    if (!env) return fail('PCA grant has no envelope');
    if (hashCanonical(env.predicates) !== hashCanonical(mandatePredicates(terms)) || hashCanonical(env.caveats) !== hashCanonical(mandateCaveats(terms))) return fail('x_pca terms do not match the grant envelope');
    if (env.risk_policy.kappa !== terms.perTransactionCap || env.risk_policy.bMax !== terms.cumulativeCap) return fail('x_pca terms do not match the grant risk policy');
    const within = constraintsWithinTerms(i.open, terms);
    if (within) return fail(within);

    const cc = i.closed.x_pca;
    if (!isRec(cc) || cc.v !== PCA_BINDING_VERSION || !isRec(cc.pcactn) || !isRec(cc.charge)) return fail('closed mandate carries no x_pca PCActn');
    const pcactn = cc.pcactn as unknown as PCActn;
    const charge = cc.charge as { amount?: unknown; currency?: unknown; category?: unknown };
    const { payment_amount: amt, payee } = i.closed;
    if (charge.currency !== amt.currency || charge.amount !== amt.amount) return fail('x_pca charge differs from the mandate payment_amount');
    if (terms.categories.length > 0 && (typeof charge.category !== 'string' || !terms.categories.includes(charge.category))) return fail('x_pca charge lacks an allowed category');

    // R2-09: remember the `t` the threshold hook REPORTS it enforced (as the core verifier does), so a hook built for a smaller t cannot satisfy a charge that needs more.
    let enforcedT: number | undefined;
    const thresholdHook = i.hooks?.threshold;
    const hooks = i.hooks
      ? {
          ...i.hooks,
          ...(thresholdHook
            ? {
                threshold: async (ctx: Parameters<typeof thresholdHook>[0]) => {
                  const r = await thresholdHook(ctx);
                  if (r.enforced && r.ok && typeof r.t === 'number') enforcedT = r.t;
                  return r;
                },
              }
            : {}),
        }
      : undefined;
    const core = await verifyPCActnCore(pcactn, { insecureSkipPlanRootCheck: true, grant, audience: i.audience, ...(i.now !== undefined ? { nowEpoch: i.now } : {}), ...(hooks ? { hooks } : {}), ...(i.enforce ? { enforce: i.enforce } : {}) });
    if (!core.allow) return fail(`PCActn: ${core.reason ?? 'rejected'}`);
    if (pcactn.action.verb !== 'charge' || pcactn.action.resource !== `merchant:${payee.id}`) return fail('PCActn action is not a charge at this payee');
    const params = { amount: charge.amount, currency: charge.currency, ...(typeof charge.category === 'string' ? { category: charge.category } : {}) };
    if (pcactn.action.params_digest !== paramsDigest(params)) return fail('PCActn params do not commit to the x_pca charge');
    const agentJwk = i.open.cnf.jwk;
    const expectedNonce = pcaBindingNonce({
      transactionId: i.closed.transaction_id,
      payeeId: payee.id,
      amount: amt.amount,
      currency: amt.currency,
      instrumentId: i.closed.payment_instrument.id,
      openHash: i.openHash,
      agentJkt: jwkThumbprint(agentJwk),
    });
    if (pcactn.nonce !== expectedNonce) return fail('PCActn nonce does not bind this AP2 transaction, open mandate and agent key');
    if (amt.amount > minorTerm(terms.perTransactionCap, 'perTransactionCap')) return fail('payment exceeds the PCA per-transaction cap');
    // The agent may not understate the risk of its own charge, and a charge whose risk needs a human
    // co-sign (t > 1) is only accepted when the verifier supplies a threshold verifier to check it.
    const recomputed = riskRatio(amt.amount, terms.perTransactionCap);
    const claimed = pcactn.risk_claim.r;
    if (!(typeof claimed === 'number' && claimed >= recomputed - 1e-9)) return fail('PCActn understates the risk of this charge');
    const need = requiredThreshold(claimed, env.risk_policy);
    if (need.t > 1 && !i.hooks?.threshold) return fail(`this charge needs a threshold of ${need.t} (human co-sign); supply hooks.threshold to verify it`);
    if (need.t > 1 && !(typeof enforcedT === 'number' && enforcedT >= need.t)) {
      return fail(`this charge needs a threshold of ${need.t} but the threshold hook enforced t=${enforcedT === undefined ? 'unreported' : String(enforcedT)}; build it with createThresholdVerifier({ t: ${need.t} })`);
    }
    if (amt.currency !== terms.currency || !terms.merchants.includes(payee.id)) return fail('payment currency or payee is outside the PCA terms');

    {
      if (hashCanonical(i.mandate.grant) !== hashCanonical(grant)) return fail('the supplied PCA mandate is not the one in the open mandate');
      // `grant` was verified above under the caller-pinned principal (verifyChain + pqPins); the decision is bound to it
      const decision = authorizeCharge(i.mandate, { merchant: payee.id, amount: amt.amount, currency: amt.currency, ...(typeof charge.category === 'string' ? { category: charge.category } : {}), recentChargeTimes: i.recentChargeTimes ?? [], ...(i.now !== undefined ? { now: i.now } : {}) }, grant);
      if (decision.outcome === 'deny') return fail(`PCA denies this charge: ${decision.reasons.join('; ')}`);
      if (decision.outcome === 'step_up' && !(typeof enforcedT === 'number' && enforcedT >= 2)) return fail('PCA requires a human co-sign for this charge and no verified threshold (t >= 2) was enforced');
    }
    return { ok: true, pcactn, grant, terms };
  } catch (e) {
    return fail(e instanceof Error ? e.message : String(e));
  }
}

export type { OpenCheckoutMandateClaims };
