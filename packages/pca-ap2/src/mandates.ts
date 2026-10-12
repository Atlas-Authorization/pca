/**
 * AP2 mandate claim shapes (Intent/Cart/Payment, closed and open) and their validators.
 *
 * The shapes follow the official AP2 JSON Schemas (`checkout_mandate`, `open_checkout_mandate`,
 * `payment_mandate`, `open_payment_mandate` and `types/*`). The validators are hand-written, check at
 * least what those schemas check (the test-suite runs both against the same documents) and are
 * stricter in places where a lax reading would be unsafe (non-negative safe-integer amounts,
 * well-formed JWKs).
 */
import { Ap2Error, assertP256Jwk, isObject, type Json, type JsonObject, type P256Jwk } from './sdjwt';

// ---------------------------------------------------------------------------------------------
// vct values
// ---------------------------------------------------------------------------------------------

export const VCT_CHECKOUT = 'mandate.checkout.1';
export const VCT_CHECKOUT_OPEN = 'mandate.checkout.open.1';
export const VCT_PAYMENT = 'mandate.payment.1';
export const VCT_PAYMENT_OPEN = 'mandate.payment.open.1';

/** Namespaced claim carrying PCA's own proof inside a mandate object (see `pca.ts`). */
export const PCA_CLAIM = 'x_pca';

// ---------------------------------------------------------------------------------------------
// currencies and minor units
// ---------------------------------------------------------------------------------------------

const ZERO_DECIMAL = new Set(['BIF', 'CLP', 'DJF', 'GNF', 'ISK', 'JPY', 'KMF', 'KRW', 'PYG', 'RWF', 'UGX', 'UYI', 'VND', 'VUV', 'XAF', 'XOF', 'XPF']);
const THREE_DECIMAL = new Set(['BHD', 'IQD', 'JOD', 'KWD', 'LYD', 'OMR', 'TND']);
const FOUR_DECIMAL = new Set(['CLF', 'UYW']);

/** ISO 4217 minor-unit exponent for `currency` (2 for any code not in the 0/3/4-digit tables). */
export function currencyExponent(currency: string): number {
  if (!/^[A-Z]{3}$/.test(currency)) throw new Ap2Error(`currency must be an ISO 4217 alpha-3 code, got ${JSON.stringify(currency)}`);
  if (ZERO_DECIMAL.has(currency)) return 0;
  if (THREE_DECIMAL.has(currency)) return 3;
  if (FOUR_DECIMAL.has(currency)) return 4;
  return 2;
}

/**
 * Convert a major-unit amount (e.g. `120.5` USD) to integer minor units (`12050`). Throws unless the
 * amount is exactly representable with the currency's exponent: float drift (`0.1 + 0.2`) is refused
 * rather than rounded away.
 */
export function toMinorUnits(major: number, currency: string): number {
  const e = currencyExponent(currency);
  if (typeof major !== 'number' || !Number.isFinite(major) || major < 0) throw new Ap2Error(`amount must be a finite non-negative number, got ${String(major)}`);
  const fixed = major.toFixed(e);
  if (Number(fixed) !== major) throw new Ap2Error(`amount ${String(major)} is not exactly representable in ${currency} minor units`);
  const minor = Number(fixed.replace('.', ''));
  if (!Number.isSafeInteger(minor)) throw new Ap2Error(`amount ${String(major)} is outside the safe integer range in minor units`);
  return minor;
}

/** Integer minor units to the major-unit number PCA budgets use (exact for any safe integer). */
export function fromMinorUnits(minor: number, currency: string): number {
  const e = currencyExponent(currency);
  if (!Number.isSafeInteger(minor) || minor < 0) throw new Ap2Error(`minor-unit amount must be a non-negative safe integer, got ${String(minor)}`);
  return minor / 10 ** e;
}

// ---------------------------------------------------------------------------------------------
// types (mirrors types/*.json)
// ---------------------------------------------------------------------------------------------

export interface Merchant {
  id: string;
  name: string;
  website?: string;
}
export interface Amount {
  /** Integer minor units per ISO 4217 (27999 = USD 279.99). */
  amount: number;
  currency: string;
}
export interface PaymentInstrument {
  id: string;
  type: string;
  description?: string;
}
export interface Pisp {
  legal_name: string;
  brand_name: string;
  domain_name: string;
}
export interface CheckoutItem {
  id: string;
  title: string;
}

export type Frequency = 'ON_DEMAND' | 'DAILY' | 'WEEKLY' | 'BIWEEKLY' | 'MONTHLY' | 'QUARTERLY' | 'ANNUALLY';
export const FREQUENCIES: readonly Frequency[] = ['ON_DEMAND', 'DAILY', 'WEEKLY', 'BIWEEKLY', 'MONTHLY', 'QUARTERLY', 'ANNUALLY'];

export type PaymentConstraint =
  | { type: 'payment.agent_recurrence'; frequency: Frequency; max_occurrences?: number }
  | { type: 'payment.allowed_payees'; allowed: Merchant[] }
  | { type: 'payment.allowed_payment_instruments'; allowed: PaymentInstrument[] }
  | { type: 'payment.allowed_pisps'; allowed: Pisp[] }
  | { type: 'payment.amount_range'; currency: string; max: number; min?: number }
  | { type: 'payment.budget'; currency: string; max: number }
  | { type: 'payment.execution_date'; not_before?: string; not_after?: string }
  | { type: 'payment.reference'; conditional_transaction_id: string };

export interface LineItemRequirement {
  id: string;
  acceptable_items: CheckoutItem[];
  quantity: number;
}
export type CheckoutConstraint =
  | { type: 'checkout.allowed_merchants'; allowed: Merchant[] }
  | { type: 'checkout.line_items'; items: LineItemRequirement[] };

interface Common {
  iat?: number;
  exp?: number;
  [PCA_CLAIM]?: JsonObject;
}
export interface OpenPaymentMandateClaims extends Common {
  vct: typeof VCT_PAYMENT_OPEN;
  constraints: PaymentConstraint[];
  cnf: { jwk: P256Jwk };
  payee?: Merchant;
  payment_amount?: Amount;
  payment_instrument?: PaymentInstrument;
  pisp?: Pisp;
  execution_date?: string;
  risk_data?: JsonObject;
}
export interface PaymentMandateClaims extends Common {
  vct: typeof VCT_PAYMENT;
  transaction_id: string;
  payee: Merchant;
  payment_amount: Amount;
  payment_instrument: PaymentInstrument;
  pisp?: Pisp;
  execution_date?: string;
  risk_data?: JsonObject;
}
export interface OpenCheckoutMandateClaims extends Common {
  vct: typeof VCT_CHECKOUT_OPEN;
  constraints: CheckoutConstraint[];
  cnf: { jwk: P256Jwk };
}
export interface CheckoutMandateClaims extends Common {
  vct: typeof VCT_CHECKOUT;
  checkout_jwt: string;
  checkout_hash: string;
}

// ---------------------------------------------------------------------------------------------
// validators: each returns the list of problems (empty = valid)
// ---------------------------------------------------------------------------------------------

const isStr = (v: unknown): v is string => typeof v === 'string';
const isNonEmptyStr = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v);
const isNonNegInt = (v: unknown): v is number => isInt(v) && v >= 0;

function merchantProblems(v: unknown, at: string): string[] {
  if (!isObject(v)) return [`${at}: not an object`];
  const p: string[] = [];
  if (!isNonEmptyStr(v.id)) p.push(`${at}.id: required string`);
  if (!isNonEmptyStr(v.name)) p.push(`${at}.name: required string`);
  if (v.website !== undefined && !isStr(v.website)) p.push(`${at}.website: must be a string`);
  return p;
}
function amountProblems(v: unknown, at: string): string[] {
  if (!isObject(v)) return [`${at}: not an object`];
  const p: string[] = [];
  if (!isNonNegInt(v.amount)) p.push(`${at}.amount: must be a non-negative integer (minor units)`);
  if (!isStr(v.currency) || !/^[A-Z]{3}$/.test(v.currency)) p.push(`${at}.currency: must be an ISO 4217 alpha-3 code`);
  return p;
}
function instrumentProblems(v: unknown, at: string): string[] {
  if (!isObject(v)) return [`${at}: not an object`];
  const p: string[] = [];
  if (!isNonEmptyStr(v.id)) p.push(`${at}.id: required string`);
  if (!isNonEmptyStr(v.type)) p.push(`${at}.type: required string`);
  if (v.description !== undefined && !isStr(v.description)) p.push(`${at}.description: must be a string`);
  return p;
}
function pispProblems(v: unknown, at: string): string[] {
  if (!isObject(v)) return [`${at}: not an object`];
  return ['legal_name', 'brand_name', 'domain_name'].filter((k) => !isNonEmptyStr(v[k])).map((k) => `${at}.${k}: required string`);
}
function timeProblems(v: JsonObject): string[] {
  const p: string[] = [];
  for (const k of ['iat', 'exp']) if (v[k] !== undefined && !isNonNegInt(v[k])) p.push(`${k}: must be an integer epoch-seconds`);
  return p;
}
function cnfProblems(v: unknown): string[] {
  if (!isObject(v) || !isObject(v.jwk)) return ['cnf: must be { jwk }'];
  try {
    assertP256Jwk(v.jwk, 'cnf.jwk');
    return [];
  } catch (e) {
    return [(e as Error).message];
  }
}
function pcaClaimProblems(v: JsonObject): string[] {
  return v[PCA_CLAIM] !== undefined && !isObject(v[PCA_CLAIM]) ? [`${PCA_CLAIM}: must be an object`] : [];
}
function listProblems(v: unknown, at: string, each: (x: unknown, at: string) => string[]): string[] {
  if (!Array.isArray(v)) return [`${at}: must be an array`];
  return v.flatMap((x, i) => each(x, `${at}[${i}]`));
}

function paymentConstraintProblems(c: unknown, at: string): string[] {
  if (!isObject(c) || !isStr(c.type)) return [`${at}: constraint must be an object with a string type`];
  switch (c.type) {
    case 'payment.agent_recurrence': {
      const p: string[] = [];
      if (!isStr(c.frequency) || !(FREQUENCIES as readonly string[]).includes(c.frequency)) p.push(`${at}.frequency: not a known frequency`);
      if (c.max_occurrences !== undefined && !(isInt(c.max_occurrences) && c.max_occurrences > 0)) p.push(`${at}.max_occurrences: must be a positive integer`);
      return p;
    }
    case 'payment.allowed_payees':
      return listProblems(c.allowed, `${at}.allowed`, merchantProblems);
    case 'payment.allowed_payment_instruments':
      return listProblems(c.allowed, `${at}.allowed`, instrumentProblems);
    case 'payment.allowed_pisps':
      return listProblems(c.allowed, `${at}.allowed`, pispProblems);
    case 'payment.amount_range': {
      const p: string[] = [];
      if (!isStr(c.currency) || !/^[A-Z]{3}$/.test(c.currency)) p.push(`${at}.currency: must be an ISO 4217 alpha-3 code`);
      if (!isNonNegInt(c.max)) p.push(`${at}.max: must be a non-negative integer (minor units)`);
      if (c.min !== undefined && !isNonNegInt(c.min)) p.push(`${at}.min: must be a non-negative integer (minor units)`);
      if (isInt(c.max) && isInt(c.min) && c.min > c.max) p.push(`${at}: min exceeds max`);
      return p;
    }
    case 'payment.budget': {
      const p: string[] = [];
      if (!isStr(c.currency) || !/^[A-Z]{3}$/.test(c.currency)) p.push(`${at}.currency: must be an ISO 4217 alpha-3 code`);
      if (typeof c.max !== 'number' || !Number.isFinite(c.max) || c.max < 0) p.push(`${at}.max: must be a non-negative number (major units)`);
      return p;
    }
    case 'payment.execution_date':
      return ['not_before', 'not_after'].filter((k) => c[k] !== undefined && !isStr(c[k])).map((k) => `${at}.${k}: must be a string`);
    case 'payment.reference':
      return isNonEmptyStr(c.conditional_transaction_id) ? [] : [`${at}.conditional_transaction_id: required string`];
    default:
      return [`${at}: unknown constraint type ${c.type}`];
  }
}

function checkoutConstraintProblems(c: unknown, at: string): string[] {
  if (!isObject(c) || !isStr(c.type)) return [`${at}: constraint must be an object with a string type`];
  if (c.type === 'checkout.allowed_merchants') return listProblems(c.allowed, `${at}.allowed`, merchantProblems);
  if (c.type === 'checkout.line_items') {
    if (!Array.isArray(c.items) || c.items.length === 0) return [`${at}.items: must be a non-empty array`];
    return c.items.flatMap((it, i) => {
      const a = `${at}.items[${i}]`;
      if (!isObject(it)) return [`${a}: not an object`];
      const p: string[] = [];
      if (!isNonEmptyStr(it.id)) p.push(`${a}.id: required string`);
      if (!isInt(it.quantity) || it.quantity <= 0) p.push(`${a}.quantity: must be a positive integer`);
      p.push(
        ...listProblems(it.acceptable_items, `${a}.acceptable_items`, (x, ax) =>
          !isObject(x) ? [`${ax}: not an object`] : ['id', 'title'].filter((k) => !isNonEmptyStr(x[k])).map((k) => `${ax}.${k}: required string`),
        ),
      );
      return p;
    });
  }
  return [`${at}: unknown constraint type ${c.type}`];
}

function vctProblem(v: JsonObject, want: string): string[] {
  return v.vct === want ? [] : [`vct: must be ${want}`];
}

export function openPaymentMandateProblems(v: unknown): string[] {
  if (!isObject(v)) return ['mandate: not an object'];
  const p = [...vctProblem(v, VCT_PAYMENT_OPEN), ...timeProblems(v), ...cnfProblems(v.cnf), ...pcaClaimProblems(v)];
  p.push(...listProblems(v.constraints, 'constraints', paymentConstraintProblems));
  if (Array.isArray(v.constraints) && !v.constraints.some((c) => isObject(c) && c.type === 'payment.reference')) p.push('constraints: must contain a payment.reference constraint');
  if (v.payee !== undefined) p.push(...merchantProblems(v.payee, 'payee'));
  if (v.payment_amount !== undefined) p.push(...amountProblems(v.payment_amount, 'payment_amount'));
  if (v.payment_instrument !== undefined) p.push(...instrumentProblems(v.payment_instrument, 'payment_instrument'));
  if (v.pisp !== undefined) p.push(...pispProblems(v.pisp, 'pisp'));
  if (v.execution_date !== undefined && !isStr(v.execution_date)) p.push('execution_date: must be a string');
  if (v.risk_data !== undefined && !isObject(v.risk_data)) p.push('risk_data: must be an object');
  return p;
}

export function paymentMandateProblems(v: unknown): string[] {
  if (!isObject(v)) return ['mandate: not an object'];
  const p = [...vctProblem(v, VCT_PAYMENT), ...timeProblems(v), ...pcaClaimProblems(v)];
  if (!isNonEmptyStr(v.transaction_id)) p.push('transaction_id: required string');
  p.push(...merchantProblems(v.payee, 'payee'), ...amountProblems(v.payment_amount, 'payment_amount'), ...instrumentProblems(v.payment_instrument, 'payment_instrument'));
  if (v.pisp !== undefined) p.push(...pispProblems(v.pisp, 'pisp'));
  if (v.execution_date !== undefined && !isStr(v.execution_date)) p.push('execution_date: must be a string');
  if (v.risk_data !== undefined && !isObject(v.risk_data)) p.push('risk_data: must be an object');
  return p;
}

export function openCheckoutMandateProblems(v: unknown): string[] {
  if (!isObject(v)) return ['mandate: not an object'];
  const p = [...vctProblem(v, VCT_CHECKOUT_OPEN), ...timeProblems(v), ...cnfProblems(v.cnf), ...pcaClaimProblems(v)];
  p.push(...listProblems(v.constraints, 'constraints', checkoutConstraintProblems));
  if (Array.isArray(v.constraints) && !v.constraints.some((c) => isObject(c) && c.type === 'checkout.line_items')) p.push('constraints: must contain a checkout.line_items constraint');
  return p;
}

export function checkoutMandateProblems(v: unknown): string[] {
  if (!isObject(v)) return ['mandate: not an object'];
  const p = [...vctProblem(v, VCT_CHECKOUT), ...timeProblems(v), ...pcaClaimProblems(v)];
  if (!isNonEmptyStr(v.checkout_jwt)) p.push('checkout_jwt: required string');
  if (!isNonEmptyStr(v.checkout_hash)) p.push('checkout_hash: required string');
  return p;
}

export function assertValid<T>(v: unknown, problems: (v: unknown) => string[], what: string): T {
  const p = problems(v);
  if (p.length > 0) throw new Ap2Error(`${what}: ${p.join('; ')}`);
  return v as T;
}

export type { Json };
