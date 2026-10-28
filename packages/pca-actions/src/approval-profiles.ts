// approval-profiles.ts - the regulatory and platform views of the canonical approval render (K7).
//
// PSD2 RTS Art. 5 "dynamic linking" (Commission Delegated Regulation (EU) 2018/389). Text verified 2026-10 against the UK-retained
// copy https://www.legislation.gov.uk/eur/2018/389/article/5 ; the EUR-Lex original (CELEX 32018R0389) could not be fetched (the
// server answered HTTP 202 without a body) and is UNVERIFIED here.
//   5(1)(a) the payer is made aware of the amount and of the payee;
//   5(1)(b) the authentication code is specific to the amount and the payee agreed to;
//   5(1)(c) the accepted code corresponds to the original amount and the identity of the payee;
//   5(1)(d) any change to the amount or the payee invalidates the code;
//   5(3)(b) for a batch of remote electronic payments to one or several payees, the code is specific to the TOTAL amount of the
//           batch and to the specified payees.
// Secure Payment Confirmation: https://www.w3.org/TR/secure-payment-confirmation/ (fetched 2026-10): clientData.type "payment.get";
// clientData.payment {rpId, topOrigin, payeeName?, payeeOrigin?, total: PaymentCurrencyAmount, instrument, ...}; the challenge is
// verified as for WebAuthn (here: the approval challenge, which commits to the render).

import { approvalRenderDigest, bindingWords, hashCanonical, merkleRoot, approvalChallenge, type ApprovalRender, type RenderField } from '@atlasauth/pca';
import { ActionKitError } from './def';

const payeeField = (r: ApprovalRender): RenderField & { value: string } => {
  const hits = r.fields.filter((f) => f.class === 'party.payee');
  if (hits.length !== 1 || typeof hits[0]!.value !== 'string' || (hits[0]!.value as string).length === 0) throw new ActionKitError('psd2_unlinkable', 'a payment approval needs exactly one non-empty party.payee parameter');
  return hits[0] as RenderField & { value: string };
};

export interface Psd2Linking {
  /** Integer minor units. */
  amount_minor: number;
  currency: string;
  exp: number;
  payee: string;
}

/**
 * The amount and the payee of a payment render, as Art. 5(1) needs them. Fail strict: an unreviewed definition, a render without
 * exactly one money.amount (with a money unit) and exactly one party.payee, or a negative / non-integer amount is not linkable.
 */
export function psd2Linking(r: ApprovalRender): Psd2Linking {
  if (r.unreviewed) throw new ActionKitError('psd2_unlinkable', 'an unreviewed definition cannot be a payment approval');
  const amts = r.fields.filter((f) => f.class === 'money.amount');
  if (amts.length !== 1) throw new ActionKitError('psd2_unlinkable', 'a payment approval needs exactly one money.amount parameter');
  const a = amts[0]!;
  if (a.unit?.kind !== 'money') throw new ActionKitError('psd2_unlinkable', 'the money.amount parameter has no money unit');
  if (typeof a.value !== 'number' || !Number.isSafeInteger(a.value) || a.value < 0) throw new ActionKitError('psd2_unlinkable', 'the amount must be a non-negative integer in minor units');
  return { amount_minor: a.value, currency: a.unit.ccy, exp: a.unit.exp, payee: payeeField(r).value };
}

/** Minor units to the decimal string of the major unit ("1250", exp 2 -> "12.50"). */
export function minorToDecimal(minor: number, exp: number): string {
  if (!Number.isSafeInteger(minor) || minor < 0 || !Number.isSafeInteger(exp) || exp < 0 || exp > 18) throw new ActionKitError('psd2_unlinkable', 'minor units must be a non-negative safe integer');
  if (exp === 0) return String(minor);
  const s = String(minor).padStart(exp + 1, '0');
  return `${s.slice(0, s.length - exp)}.${s.slice(s.length - exp)}`;
}

/** What `verifyAssertion` (pca-webauthn) must find in the signed `clientData.payment`. Structural twin of its SpcPaymentExpectation. */
export interface SpcExpectation {
  topOrigin: string;
  total: { currency: string; value: string };
  payeeName?: string;
  payeeOrigin?: string;
}

/** The SPC expectation for a payment render. The payee parameter's value must be the payee name or the payee origin the browser shows. */
export function spcExpectation(r: ApprovalRender, topOrigin: string, payeeAs: 'name' | 'origin' = 'name'): SpcExpectation {
  const l = psd2Linking(r);
  return {
    topOrigin,
    total: { currency: l.currency, value: minorToDecimal(l.amount_minor, l.exp) },
    ...(payeeAs === 'name' ? { payeeName: l.payee } : { payeeOrigin: l.payee }),
  };
}

// ---- batches (Art. 5(3)(b)) -----------------------------------------------------------------------------------------------

export const APPROVAL_BATCH_DOMAIN = 'atlas-pca/approval-batch/v1';
const ITEM_DOMAIN = 'atlas-pca/approval-batch-item/v1';
const PAYEE_DOMAIN = 'atlas-pca/approval-payee/v1';

export interface ApprovalBatch {
  v: 1;
  kind: 'pca-approval-batch';
  n: number;
  /** Per-currency totals in minor units, sorted by currency. */
  totals: { ccy: string; exp: number; minor: number }[];
  /** Merkle root over the sorted distinct payees. */
  payees_root: string;
  /** Merkle root over the ordered (action digest, render digest) pairs: a per-item proof is an inclusion proof. */
  items_root: string;
}

export interface BatchItem {
  action_digest: string;
  render: ApprovalRender;
}

/**
 * One approval over N payments: the batch commits to the per-currency totals, the payee set and every item. The batch "action
 * digest" is the items root and the batch "render digest" is the digest of the batch summary, so the same
 * `approvalChallenge(action_digest, render_digest)` applies. Refuses an empty batch, mixed exponents for one currency, and a total
 * beyond 2^53-1.
 */
export function approvalBatch(items: readonly BatchItem[]): { batch: ApprovalBatch; action_digest: string; render_digest: string; challenge: Uint8Array; words: string } {
  if (items.length === 0) throw new ActionKitError('psd2_unlinkable', 'a batch needs at least one payment');
  const totals = new Map<string, { exp: number; minor: number }>();
  const payees = new Set<string>();
  for (const it of items) {
    const l = psd2Linking(it.render);
    const t = totals.get(l.currency);
    if (t !== undefined && t.exp !== l.exp) throw new ActionKitError('psd2_unlinkable', `currency ${l.currency} appears with two exponents`);
    const minor = (t?.minor ?? 0) + l.amount_minor;
    if (!Number.isSafeInteger(minor)) throw new ActionKitError('psd2_unlinkable', 'the batch total exceeds the safe integer range');
    totals.set(l.currency, { exp: l.exp, minor });
    payees.add(l.payee);
  }
  const batch: ApprovalBatch = {
    v: 1,
    kind: 'pca-approval-batch',
    n: items.length,
    totals: [...totals.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([ccy, t]) => ({ ccy, exp: t.exp, minor: t.minor })),
    payees_root: merkleRoot([...payees].sort().map((payee) => ({ d: PAYEE_DOMAIN, payee }))),
    items_root: merkleRoot(items.map((it) => ({ d: ITEM_DOMAIN, a: it.action_digest, r: approvalRenderDigest(it.render) }))),
  };
  const render_digest = hashCanonical({ d: APPROVAL_BATCH_DOMAIN, batch });
  return { batch, action_digest: batch.items_root, render_digest, challenge: approvalChallenge(batch.items_root, render_digest), words: bindingWords(render_digest) };
}

// ---- CIBA / RAR ----------------------------------------------------------------------------------------------------------

/** RFC 9396 authorization_details entry carrying the canonical render, plus the speakable match code. */
export function cibaApprovalDetails(r: ApprovalRender): { authorization_details: { type: 'pca_approval'; render: ApprovalRender; render_digest: string }[]; match_code: string } {
  const render_digest = approvalRenderDigest(r);
  return { authorization_details: [{ type: 'pca_approval', render: r, render_digest }], match_code: bindingWords(render_digest) };
}
