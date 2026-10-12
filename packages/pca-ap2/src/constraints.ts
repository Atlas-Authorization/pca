/**
 * Evaluation of AP2 open-mandate constraints against a closed mandate / checkout.
 *
 * This follows the AP2 documentation's evaluation rules and cross-checks against the official Python
 * SDK (`ap2.sdk.constraints`). It is deliberately *stricter* than that SDK in four places, each a
 * fail-closed choice (and each covered by a test):
 *   - a line-item requirement whose `acceptable_items` is empty (for instance because the holder
 *     withheld every disclosure) matches nothing, where the SDK treats it as a wildcard;
 *   - the documentation requires the maximal flow to equal both the required and the carted
 *     quantity; the SDK only rejects surplus items, never a cart with too few;
 *   - a closed payment without `execution_date` is "immediate", i.e. evaluated at the verification
 *     time, so a not-yet-open execution window refuses it (the SDK returns no violation);
 *   - `execution_date` bounds are compared as instants, not as strings.
 */
import type {
  CheckoutConstraint,
  Frequency,
  LineItemRequirement,
  Merchant,
  OpenCheckoutMandateClaims,
  OpenPaymentMandateClaims,
  PaymentConstraint,
  PaymentMandateClaims,
} from './mandates';
import { currencyExponent } from './mandates';
import { isObject, type JsonObject } from './sdjwt';

/** Usage state a verifier tracks for an open mandate (budget and recurrence need it). */
export interface MandateContext {
  /** Sum of the minor-unit amounts of previously closed payments under this open mandate. */
  totalAmount: number;
  /** Number of previous closed payments under this open mandate. */
  totalUses: number;
  /** Epoch seconds of the most recent previous use, if any. */
  lastUsedDate?: number;
}

export function merchantMatches(candidate: Merchant, target: Merchant): boolean {
  if (candidate.id && target.id) return candidate.id === target.id;
  return !!candidate.name && !!candidate.website && candidate.name === target.name && candidate.website === target.website;
}

const sameJson = (a: unknown, b: unknown): boolean => JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b));
function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (isObject(v)) return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]));
  return v;
}

function parseInstant(s: string): number | undefined {
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : undefined;
}

/** Start (epoch ms, UTC) of the calendar period of `frequency` that contains `ms`. */
function periodStart(ms: number, frequency: Frequency): number {
  const d = new Date(ms);
  const day = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  const DAY = 86_400_000;
  switch (frequency) {
    case 'ON_DEMAND':
      return 0;
    case 'DAILY':
      return day;
    case 'WEEKLY':
      return day - ((d.getUTCDay() + 6) % 7) * DAY; // Monday
    case 'BIWEEKLY': {
      const weekStart = day - ((d.getUTCDay() + 6) % 7) * DAY;
      const WEEK = 7 * DAY;
      const epochMonday = -3 * DAY; // 1970-01-01 was a Thursday; the Monday before is -3 days
      return epochMonday + Math.floor((weekStart - epochMonday) / (2 * WEEK)) * 2 * WEEK;
    }
    case 'MONTHLY':
      return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
    case 'QUARTERLY':
      return Date.UTC(d.getUTCFullYear(), Math.floor(d.getUTCMonth() / 3) * 3, 1);
    case 'ANNUALLY':
      return Date.UTC(d.getUTCFullYear(), 0, 1);
  }
}

export interface PaymentCheckOptions {
  /** `sd_hash` of the open checkout mandate this payment is chained to (for `payment.reference`). */
  openCheckoutHash?: string;
  /** Usage state; required to evaluate `payment.budget` and recurrence limits / frequency. */
  context?: MandateContext;
  /** Verification time, epoch seconds. */
  now: number;
}

function evaluatePayment(c: PaymentConstraint, closed: PaymentMandateClaims, o: PaymentCheckOptions): string[] {
  const amt = closed.payment_amount;
  switch (c.type) {
    case 'payment.amount_range': {
      const v: string[] = [];
      if (amt.currency !== c.currency) v.push(`currency mismatch: expected ${c.currency}, got ${amt.currency}`);
      if (c.min !== undefined && amt.amount < c.min) v.push(`amount ${amt.amount} below minimum ${c.min}`);
      if (amt.amount > c.max) v.push(`amount ${amt.amount} exceeds maximum ${c.max}`);
      return v;
    }
    case 'payment.allowed_payees':
      return c.allowed.some((m) => merchantMatches(m, closed.payee)) ? [] : [`payee ${closed.payee.name} is not in the allowed list`];
    case 'payment.allowed_payment_instruments':
      return c.allowed.some((i) => i.id === closed.payment_instrument.id) ? [] : [`payment instrument ${closed.payment_instrument.id} is not in the allowed list`];
    case 'payment.allowed_pisps': {
      const p = closed.pisp;
      if (!p) return ['missing PISP in the closed mandate'];
      return c.allowed.some((a) => a.legal_name === p.legal_name && a.brand_name === p.brand_name && a.domain_name === p.domain_name) ? [] : ['PISP is not in the allowed list'];
    }
    case 'payment.reference': {
      if (!o.openCheckoutHash) return ['openCheckoutHash is required to evaluate a payment.reference constraint'];
      return o.openCheckoutHash === c.conditional_transaction_id ? [] : ['payment.reference does not match the open checkout mandate hash'];
    }
    case 'payment.budget': {
      if (amt.currency !== c.currency) return [`budget currency mismatch: expected ${c.currency}, got ${amt.currency}`];
      // The official SDK converts the budget with `int(max * 100)`; any other exponent would be read differently by it.
      if (currencyExponent(c.currency) !== 2) return [`budget in ${c.currency} is unsupported: budget.max is converted with a fixed x100 factor`];
      if (!o.context) return ['mandate context is required to evaluate a budget'];
      const scaled = c.max * 100;
      const maxMinor = Math.round(scaled);
      if (Math.abs(scaled - maxMinor) > 1e-6) return ['budget.max is not a whole number of minor units'];
      const spend = o.context.totalAmount + amt.amount;
      return spend > maxMinor ? [`cumulative spend ${spend} exceeds budget ${maxMinor} (past spend ${o.context.totalAmount})`] : [];
    }
    case 'payment.agent_recurrence': {
      const v: string[] = [];
      if (c.max_occurrences !== undefined) {
        if (!o.context) return ['mandate context is required to evaluate recurrence limits'];
        if (o.context.totalUses >= c.max_occurrences) v.push(`maximum occurrences exceeded: ${o.context.totalUses} >= ${c.max_occurrences}`);
      }
      if (c.frequency !== 'ON_DEMAND') {
        if (!o.context) return ['mandate context is required to evaluate recurrence frequency'];
        const last = o.context.lastUsedDate;
        if (last !== undefined && last * 1000 >= periodStart(o.now * 1000, c.frequency)) v.push(`already used in the current ${c.frequency} period`);
      }
      return v;
    }
    case 'payment.execution_date': {
      const at = closed.execution_date !== undefined ? parseInstant(closed.execution_date) : o.now * 1000;
      if (at === undefined) return [`execution_date ${String(closed.execution_date)} is not a valid instant`];
      const v: string[] = [];
      for (const [key, bound, before] of [['not_before', c.not_before, true], ['not_after', c.not_after, false]] as const) {
        if (bound === undefined) continue;
        const b = parseInstant(bound);
        if (b === undefined) v.push(`${key} ${bound} is not a valid instant`);
        else if (before ? at < b : at > b) v.push(`execution date is ${before ? 'before' : 'after'} the allowed window (${key} ${bound})`);
      }
      return v;
    }
    default:
      return [`unknown constraint type ${String((c as { type?: unknown }).type)}`];
  }
}

/** Violations of the open payment mandate's constraints and pre-set claims by `closed` (empty = satisfied). */
export function checkPaymentConstraints(open: OpenPaymentMandateClaims, closed: PaymentMandateClaims, o: PaymentCheckOptions): string[] {
  const v: string[] = [];
  if (open.payee !== undefined && !merchantMatches(open.payee, closed.payee)) v.push(`pre-set payee mismatch: expected ${open.payee.name}, got ${closed.payee.name}`);
  if (open.payment_amount !== undefined && !sameJson(open.payment_amount, closed.payment_amount)) v.push('pre-set payment_amount mismatch');
  if (open.payment_instrument !== undefined && !sameJson(open.payment_instrument, closed.payment_instrument)) v.push('pre-set payment_instrument mismatch');
  if (open.pisp !== undefined && !sameJson(open.pisp, closed.pisp)) v.push('pre-set pisp mismatch');
  if (open.execution_date !== undefined && open.execution_date !== closed.execution_date) v.push('pre-set execution_date mismatch');

  const types = new Set(open.constraints.map((c) => c.type));
  if (types.has('payment.agent_recurrence')) {
    if (!types.has('payment.amount_range')) v.push('payment.agent_recurrence requires a payment.amount_range constraint');
    if (!types.has('payment.budget')) v.push('payment.agent_recurrence requires a payment.budget constraint');
  }
  for (const c of open.constraints) v.push(...evaluatePayment(c, closed, o));
  return v;
}

// ---------------------------------------------------------------------------------------------
// checkout side
// ---------------------------------------------------------------------------------------------

/** The slice of the UCP Checkout object (`checkout_jwt` payload) the constraints read. */
export interface UcpCheckout {
  id: string;
  merchant?: Merchant;
  currency: string;
  line_items: { id: string; item: { id: string; title: string; price: number }; quantity: number }[];
  totals: { type: string; amount: number }[];
}

/** Validate and project the checkout payload; throws a descriptive message when malformed. */
export function projectCheckout(payload: JsonObject): UcpCheckout {
  const bad = (m: string): never => {
    throw new Error(`checkout_jwt payload: ${m}`);
  };
  if (typeof payload.id !== 'string' || !payload.id) bad('id is required');
  if (typeof payload.currency !== 'string' || !/^[A-Z]{3}$/.test(payload.currency)) bad('currency must be ISO 4217');
  if (!Array.isArray(payload.line_items) || payload.line_items.length === 0) bad('line_items must be a non-empty array');
  if (!Array.isArray(payload.totals)) bad('totals must be an array');
  const line_items = (payload.line_items as unknown[]).map((li, i) => {
    if (!isObject(li) || typeof li.id !== 'string' || !isObject(li.item)) return bad(`line_items[${i}] is malformed`);
    const item = li.item as JsonObject;
    if (typeof item.id !== 'string' || typeof item.title !== 'string' || !Number.isSafeInteger(item.price) || (item.price as number) < 0) bad(`line_items[${i}].item needs id, title and integer minor-unit price`);
    if (!Number.isSafeInteger(li.quantity) || (li.quantity as number) < 1) bad(`line_items[${i}].quantity must be a positive integer`);
    return { id: li.id, item: { id: item.id as string, title: item.title as string, price: item.price as number }, quantity: li.quantity as number };
  });
  const totals = (payload.totals as unknown[]).map((t, i) => {
    if (!isObject(t) || typeof t.type !== 'string' || !Number.isSafeInteger(t.amount)) return bad(`totals[${i}] is malformed`);
    return { type: t.type as string, amount: t.amount as number };
  });
  let merchant: Merchant | undefined;
  if (payload.merchant !== undefined) {
    const m = payload.merchant;
    if (!isObject(m) || typeof m.id !== 'string' || typeof m.name !== 'string') bad('merchant needs id and name');
    const mm = m as JsonObject;
    merchant = { id: mm.id as string, name: mm.name as string, ...(typeof mm.website === 'string' ? { website: mm.website } : {}) };
  }
  return { id: payload.id as string, currency: payload.currency as string, line_items, totals, ...(merchant ? { merchant } : {}) };
}

/** The checkout's single `total` entry in minor units, or undefined if absent / ambiguous. */
export function checkoutTotal(c: UcpCheckout): number | undefined {
  const t = c.totals.filter((x) => x.type === 'total');
  return t.length === 1 ? t[0]?.amount : undefined;
}

/**
 * Maximal-flow assignment of cart quantities to requirement slots (Edmonds-Karp on the bipartite
 * graph of the documentation): satisfied iff the flow equals both the required and the carted total.
 */
function lineItemViolations(cart: UcpCheckout['line_items'], reqs: LineItemRequirement[]): string[] {
  const qty = new Map<string, number>();
  for (const li of cart) qty.set(li.item.id, (qty.get(li.item.id) ?? 0) + li.quantity);
  const skus = [...qty.keys()];
  const S = 0;
  const T = 1 + skus.length + reqs.length;
  const cap: Map<number, number>[] = Array.from({ length: T + 1 }, () => new Map());
  const add = (u: number, v: number, c: number): void => {
    cap[u]?.set(v, (cap[u]?.get(v) ?? 0) + c);
    cap[v]?.set(u, cap[v]?.get(u) ?? 0);
  };
  const INF = Number.MAX_SAFE_INTEGER;
  skus.forEach((s, i) => add(S, 1 + i, qty.get(s) as number));
  reqs.forEach((r, j) => {
    add(1 + skus.length + j, T, r.quantity);
    const ok = new Set(r.acceptable_items.map((a) => a.id));
    skus.forEach((s, i) => {
      if (ok.has(s)) add(1 + i, 1 + skus.length + j, INF);
    });
  });
  let flow = 0;
  for (;;) {
    const parent = new Map<number, number>([[S, S]]);
    const queue = [S];
    for (let h = 0; h < queue.length && !parent.has(T); h++) {
      const u = queue[h] as number;
      for (const [v, c] of cap[u] ?? []) if (c > 0 && !parent.has(v)) {
        parent.set(v, u);
        queue.push(v);
      }
    }
    if (!parent.has(T)) break;
    let push = INF;
    for (let v = T; v !== S; v = parent.get(v) as number) push = Math.min(push, cap[parent.get(v) as number]?.get(v) as number);
    for (let v = T; v !== S; v = parent.get(v) as number) {
      const u = parent.get(v) as number;
      cap[u]?.set(v, (cap[u]?.get(v) as number) - push);
      cap[v]?.set(u, (cap[v]?.get(u) as number) + push);
    }
    flow += push;
  }
  const required = reqs.reduce((a, r) => a + r.quantity, 0);
  const carted = [...qty.values()].reduce((a, b) => a + b, 0);
  if (flow === required && flow === carted) return [];
  return [`line items do not satisfy the constraint: assigned ${flow} of ${required} required and ${carted} carted units`];
}

function evaluateCheckout(c: CheckoutConstraint, checkout: UcpCheckout): string[] {
  if (c.type === 'checkout.allowed_merchants') {
    if (!checkout.merchant) return ['missing merchant in the checkout'];
    const m = checkout.merchant;
    return c.allowed.some((a) => merchantMatches(a, m)) ? [] : [`merchant ${m.name} is not in the allowed list`];
  }
  if (c.type !== 'checkout.line_items') return [`unknown constraint type ${String((c as { type?: unknown }).type)}`];
  return checkout.line_items.length === 0 ? ['empty cart does not satisfy a line_items constraint'] : lineItemViolations(checkout.line_items, c.items);
}

/** Violations of the open checkout mandate's constraints by `checkout` (empty = satisfied). */
export function checkCheckoutConstraints(open: OpenCheckoutMandateClaims, checkout: UcpCheckout): string[] {
  return open.constraints.flatMap((c) => evaluateCheckout(c, checkout));
}
