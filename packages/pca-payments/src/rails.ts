// rails.ts - spend rails (K7): a virtual card (or any instrument) whose limits mirror the grant, and a real-time authorization
// callback that answers from authorizeCharge() inside a latency budget. The rail is a SECOND enforcement point: its limits are an
// upper-bounded copy of the PCA limits, PCA never relaxes because the rail would have blocked, and a rail answer is only ever
// "approve" when PCA's own decision is `auto`. A step-up, a deny, an unknown card, a timeout, an exception: all decline.
// Heuristic-free: no merchant-name matching, no classifier. The merchant id and the category come from the rail's structured fields.

import type { Capability } from '@atlasauth/pca';
import { authorizeChargeAtomic, type ChargeBudgetStore, type ChargeDecision } from './authorize';
import type { PaymentMandate } from './mandate';
import { sharedPaymentTokenLimits } from './spt-limits';

export interface RailLimits {
  /** Upper-case ISO 4217. */
  currency: string;
  /** Per-authorization ceiling, integer minor units: min(auto-approve threshold, remaining autonomous budget). */
  perAuthorizationMax: number;
  /** Cumulative ceiling over the instrument's life, integer minor units: the remaining autonomous budget. */
  totalMax: number;
  /** MCC codes the instrument may spend in. Empty only when the caller passed `allowAnyCategory`. */
  categories: string[];
  /** Merchant ids the mandate allows (informational for rails that cannot express them; the callback enforces them). */
  merchants: string[];
  /** Epoch ms; the mandate period end, when it has one. */
  expiresAt?: number;
}

/** Action-kit convention: a custom trait `mcc.c5734` on the verb says the verb may spend in MCC 5734. Traits only narrow. */
export const MCC_TRAIT_RE = /^mcc\.c(\d{4})$/;

export function categoriesFromTraits(traits: readonly string[]): string[] {
  const out = new Set<string>();
  for (const t of traits) {
    const m = MCC_TRAIT_RE.exec(t);
    if (m) out.add(m[1]!);
  }
  return [...out].sort();
}

export interface RailLimitOptions {
  /** The effective trait set of the action being funded (`traitsOf(def, registry, ...)`). Unconfirmed defs have the top set: pass only confirmed traits. */
  actionTraits?: readonly string[];
  /** Mint an instrument that may spend in every category. Off by default: a card without a category control is refused. */
  allowAnyCategory?: boolean;
}

/**
 * The limits an instrument for this mandate may carry. Amounts come from `sharedPaymentTokenLimits` (no autonomous capacity left
 * throws: a card for more would need a co-sign). Categories are the mandate's allowlist narrowed by the action's `mcc.*` traits
 * (an empty intersection throws); with neither, the call is refused unless `allowAnyCategory`.
 */
export function railLimits(mandate: PaymentMandate, now: number, opts: RailLimitOptions = {}): RailLimits {
  const spt = sharedPaymentTokenLimits(mandate, now);
  const total = Math.floor(mandate.budget.B);
  const fromMandate = [...mandate.terms.categories];
  const fromTraits = categoriesFromTraits(opts.actionTraits ?? []);
  let categories: string[];
  if (fromMandate.length > 0 && fromTraits.length > 0) {
    categories = fromMandate.filter((c) => fromTraits.includes(c)).sort();
    if (categories.length === 0) throw new RangeError('railLimits: the action traits and the mandate categories do not intersect; nothing may be spent');
  } else categories = (fromMandate.length > 0 ? fromMandate : fromTraits).sort();
  if (categories.length === 0 && opts.allowAnyCategory !== true) throw new RangeError('railLimits: no category control (mandate categories or mcc.* traits); pass allowAnyCategory to accept any merchant category');
  return {
    currency: mandate.terms.currency.toUpperCase(),
    perAuthorizationMax: spt.max_amount,
    totalMax: total,
    categories,
    merchants: [...mandate.terms.merchants],
    ...(spt.expires_at !== undefined ? { expiresAt: spt.expires_at * 1000 } : {}),
  };
}

// ---- the real-time authorization callback ------------------------------------------------------------------------------

/** A live authorization request from a rail, normalised. Amounts are integer minor units in `currency`. */
export interface RailAuthorization {
  /** The rail's id for this authorization (idempotency / audit). */
  id: string;
  /** The instrument (card) that is being used. */
  instrumentId: string;
  amount: number;
  currency: string;
  /** The merchant id the mandate allowlist is written in (from the rail's structured data, never from a display name). */
  merchantId?: string;
  /** Merchant category code, when the rail provides one. */
  mcc?: string;
}

export interface InstrumentBinding {
  mandate: PaymentMandate;
  /** The grant the caller verified or loaded from its own store. */
  grant: Capability;
  /** Budget store key; default the grant hash. */
  budgetKey?: string;
}

export interface RailVerdict {
  approved: boolean;
  reasons: string[];
  decision?: ChargeDecision;
}

export interface RailAuthorizerOptions {
  instruments: (instrumentId: string) => InstrumentBinding | undefined | Promise<InstrumentBinding | undefined>;
  store: ChargeBudgetStore;
  /** Answer by this many ms or decline. Stripe waits 2000 ms; the default 1500 leaves room for the network. */
  latencyBudgetMs?: number;
  now?: () => number;
  /** A step-up cannot wait at a card terminal: it is declined here, and this hook may notify the principal. */
  onStepUp?: (a: RailAuthorization, d: ChargeDecision) => void | Promise<void>;
}

const decline = (...reasons: string[]): RailVerdict => ({ approved: false, reasons });

/** The single code path from a rail request to a PCA decision. Total: every failure is a decline. */
export function createRailAuthorizer(opts: RailAuthorizerOptions): (a: RailAuthorization) => Promise<RailVerdict> {
  const budgetMs = opts.latencyBudgetMs ?? 1500;
  if (!Number.isFinite(budgetMs) || budgetMs <= 0) throw new RangeError('createRailAuthorizer: latencyBudgetMs must be positive');
  const now = opts.now ?? (() => Date.now());
  const decide = async (a: RailAuthorization): Promise<RailVerdict> => {
    if (a === null || typeof a !== 'object' || typeof a.id !== 'string' || typeof a.instrumentId !== 'string' || a.id.length === 0) return decline('malformed_authorization');
    if (!Number.isSafeInteger(a.amount) || a.amount <= 0) return decline('amount_not_positive_minor_units');
    if (typeof a.currency !== 'string' || a.currency.length === 0) return decline('currency_missing');
    if (typeof a.merchantId !== 'string' || a.merchantId.length === 0) return decline('merchant_unknown');
    const inst = await opts.instruments(a.instrumentId);
    if (inst === undefined) return decline('instrument_unknown');
    const category = a.mcc;
    const d = await authorizeChargeAtomic(
      inst.mandate,
      { merchant: a.merchantId, amount: a.amount, currency: a.currency.toUpperCase(), ...(category !== undefined ? { category } : {}), now: now() },
      inst.grant,
      opts.store,
      inst.budgetKey,
    );
    if (d.outcome === 'auto') return { approved: true, reasons: [], decision: d };
    if (d.outcome === 'step_up') {
      try { await opts.onStepUp?.(a, d); } catch { /* a failing notifier must not change the answer */ }
      return { approved: false, reasons: ['step_up_required', ...d.reasons], decision: d };
    }
    return { approved: false, reasons: d.reasons.length > 0 ? d.reasons : ['denied'], decision: d };
  };
  return async (a) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const late = new Promise<RailVerdict>((resolve) => { timer = setTimeout(() => resolve(decline('latency_budget_exceeded')), budgetMs); });
    try {
      // shortcut: a decision that finishes after the timeout may still have debited the budget with no approval sent (budget under-spend, the safe direction); an operator reconciles by cosign/refill
      return await Promise.race([decide(a).catch((): RailVerdict => decline('authorizer_error')), late]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  };
}

// ---- settlement --------------------------------------------------------------------------------------------------------

export interface RailSettlement {
  authorizationId: string;
  amount: number;
  currency: string;
  merchantId?: string;
  /** How many captures the rail reports against this authorization. */
  captures: number;
}

export type Reconciliation = { ok: true } | { ok: false; reasons: string[]; action: 'freeze_grant' };

/**
 * Compare what settled with what PCA approved. Commit only on an exact fit; any excess, a different merchant or currency, or a second
 * capture is a tighten-only event: freeze the grant, escalate every further action in the same bond scope, tell the principal.
 * No classifier; the caller applies the action.
 */
export function reconcileSettlement(approved: { id: string; amount: number; currency: string; merchantId: string }, s: RailSettlement): Reconciliation {
  const reasons: string[] = [];
  if (s.authorizationId !== approved.id) reasons.push('authorization_id_mismatch');
  if (s.amount > approved.amount) reasons.push('settled_more_than_approved');
  if (s.currency.toUpperCase() !== approved.currency.toUpperCase()) reasons.push('currency_mismatch');
  if (s.merchantId !== approved.merchantId) reasons.push('merchant_mismatch');
  if (s.captures > 1) reasons.push('second_capture');
  return reasons.length === 0 ? { ok: true } : { ok: false, reasons, action: 'freeze_grant' };
}
