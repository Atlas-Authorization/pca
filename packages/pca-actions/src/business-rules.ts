// business-rules.ts - a platform's own business rules for one action, written in plain terms (amount ceilings per currency,
// approval thresholds, "only the caller's own records", rate limits, business hours, allowed recipients, required fields) and
// COMPILED into the policy machinery PCA already has:
//   tighten rules (rule 21's `{id, when, signal}`: when the condition holds OR CANNOT BE DECIDED, the decision is capped at the
//   signal), over the predicate language (`action.params.*`, `subject.*`, `env.*`), and
//   count accumulators (`AccumulatorDecl`, agg count, sliding window, principal/org scope, `domain_max` = the cap a durable
//   BudgetLedger enforces atomically) whose pre-state the evaluator exposes as `env.acc.<id>`.
// Every compiled rule carries the signal `escalate` or `deny`, never `allow`: a rule can only lower a decision, so the final
// decision is meet(base, trait floors, rules) and adding, or tightening, a rule never raises it (tested adversarially).
// Anything the evaluator cannot decide (an absent caller attribute, an unknown currency, an unreadable clock, an unset count)
// fires the rule: fail closed.

import { b64u, canonicalBytesStrict, evaluateConditionTri, hashCanonical, sign, utf8, verifyB64u, type ActionContext, type Condition, type TightenRule } from '@atlasauth/pca';
import type { AccumulatorDecl } from '@atlasauth/pca/ext/intent';
import { reviewerPinsError, type ReviewerPins } from './confirmation';
import { ActionKitError, type ActionDef, type ParamDef } from './def';
import { defDigest } from './digest';
import type { Finding } from './lint';
import { meetDecision, type Decision } from './traits';

// ---- the authoring form ----------------------------------------------------------------------------------------------------

export const RULE_DAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'] as const;
export type RuleDay = (typeof RULE_DAYS)[number];
export const RATE_PERIODS = { hour: 3_600_000, day: 86_400_000 } as const;
export type RatePeriod = keyof typeof RATE_PERIODS;

/** A parameter, by name or by role (the unique parameter of the action with that role). */
export type ParamRef = { param: string } | { role: string };
/** A money amount: integer minor units, or a decimal string in major units ("250", "250.00"). */
export type MoneyValue = number | string;

export interface BusinessRules {
  /** Ceilings per currency on the action's `money.amount` parameter. A currency not listed is refused. */
  amount?: { max: Record<string, MoneyValue> };
  /** When a human must approve first: above an amount per currency, or always; by how many approvers, of which group. */
  approval?: { above?: Record<string, MoneyValue>; always?: boolean; approvers?: number; group?: string };
  /** "Only the caller's own records": the parameter must equal an attribute of the caller (`subject.<caller>`). */
  scope?: Array<ParamRef & { caller: string }>;
  /** At most `max` per hour or day, per principal (default) or per organisation. */
  rate?: Array<{ max: number; per: RatePeriod; by?: 'principal' | 'org' }>;
  /** Business hours in a time zone; outside them the action escalates (default) or is refused. */
  hours?: { days: RuleDay[]; from: string; to: string; tz: string; outside?: 'escalate' | 'deny' };
  /** Allowed recipients of an email parameter: whole domains and/or exact addresses (lowercase). */
  recipients?: ParamRef & { domains?: string[]; addresses?: string[] };
  /** Parameters that must be present (and, for strings, non-empty) even where the definition makes them optional. */
  required?: string[];
  /** Executable examples of the rules (run by `pca actions test`). */
  examples?: RuleExample[];
}

export interface RuleExample {
  params: Record<string, unknown>;
  /** Attributes of the caller (`subject.*`). */
  caller?: Record<string, unknown>;
  /** The time of the call (RFC 3339 UTC, `Z`). Default 2026-01-07T15:00:00Z (a Wednesday, mid-day UTC). */
  at?: string;
  /** Actions already counted in each rate window, by rate index ("0", "1", ...). Default 0. */
  recent?: Record<string, number>;
  expect: Decision;
}

export const MAX_RULE_CURRENCIES = 32;
export const MAX_RULE_LIST = 64;
export const MAX_RULE_APPROVERS = 16;
export const MAX_RULE_EXAMPLES = 32;
const CCY_RE = /^[A-Z]{3}$/;
const NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;
const HHMM_RE = /^([01]\d|2[0-3]):([0-5]\d)$/;
const DOMAIN_RE = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const ADDRESS_RE = /^[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}$/;
const DEC_RE = /^(0|[1-9]\d{0,14})(?:\.(\d{1,6}))?$/;
const RULE_KEYS = ['amount', 'approval', 'scope', 'rate', 'hours', 'recipients', 'required', 'examples'];

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const own = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);
function closed(o: Record<string, unknown>, allowed: readonly string[], at: string): void {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) throw new ActionKitError('bad_rules', `${at}: unknown member '${k}'`);
}
function bad(msg: string): never {
  throw new ActionKitError('bad_rules', msg);
}

/** The parameter a reference names, with its definition. Throws `bad_rules` when it resolves to none or to several. */
export function resolveParamRef(d: Pick<ActionDef, 'verb' | 'params'>, r: unknown, at: string): { name: string; p: ParamDef } {
  if (!isObj(r)) return bad(`${at}: name a parameter ({param} or {role})`);
  const hasP = typeof r.param === 'string';
  const hasR = typeof r.role === 'string';
  if (hasP === hasR) return bad(`${at}: give exactly one of param or role`);
  if (hasP) {
    const p = d.params[r.param as string];
    if (!p || !own(d.params, r.param as string)) return bad(`${at}: '${d.verb}' has no parameter '${String(r.param)}'`);
    return { name: r.param as string, p };
  }
  const hits = Object.keys(d.params).filter((n) => d.params[n]!.role === r.role).sort();
  if (hits.length !== 1) return bad(`${at}: '${d.verb}' has ${hits.length === 0 ? 'no' : 'several'} parameter${hits.length === 0 ? '' : 's'} with role ${String(r.role)}`);
  return { name: hits[0]!, p: d.params[hits[0]!]! };
}

/** The money parameters of an action: the amount, its exponent, and its currency (a literal or another parameter). */
export function moneyOf(d: Pick<ActionDef, 'verb' | 'params'>): { amount: string; exp: number; ccy: { literal: string } | { param: string } } {
  const hits = Object.keys(d.params).filter((n) => d.params[n]!.role === 'money.amount').sort();
  if (hits.length !== 1) bad(`'${d.verb}' needs exactly one parameter with role money.amount for an amount or approval-above rule (has ${hits.length})`);
  const name = hits[0]!;
  const p = d.params[name]!;
  if (p.type !== 'integer') bad(`'${d.verb}': the money.amount parameter '${name}' must be an integer`);
  const u = p.unit;
  if (u === undefined || u.kind !== 'money') return bad(`'${d.verb}': the amount parameter '${name}' declares no money unit (its currency)`);
  if (typeof u.ccy === 'string') return { amount: name, exp: u.exp, ccy: { literal: u.ccy } };
  const from = u.ccy.from;
  if (!own(d.params, from)) bad(`'${d.verb}': the currency parameter '${from}' does not exist`);
  return { amount: name, exp: u.exp, ccy: { param: from } };
}

/** Integer minor units of a money value under exponent `exp`. Throws `bad_rules` for a non-integer or over-precise value. */
export function minorUnits(v: unknown, exp: number, at: string): number {
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v) || v < 0) bad(`${at}: an amount is a non-negative integer of minor units, or a decimal string`);
    return v;
  }
  if (typeof v !== 'string') return bad(`${at}: an amount is a number of minor units or a decimal string`);
  const m = DEC_RE.exec(v);
  if (!m) return bad(`${at}: '${v}' is not a decimal amount`);
  const frac = m[2] ?? '';
  if (frac.length > exp) bad(`${at}: '${v}' has more decimals than the currency's ${exp}`);
  const n = Number(m[1]) * 10 ** exp + Number(frac.padEnd(exp, '0') || '0');
  if (!Number.isSafeInteger(n)) bad(`${at}: '${v}' is too large`);
  return n;
}

const mins = (hhmm: string): number => Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3, 5));

/** Is this a time zone the runtime knows (IANA name)? */
export function knownTimeZone(tz: string): boolean {
  if (typeof tz !== 'string' || tz.length === 0 || tz.length > 64 || !/^[A-Za-z0-9_+\-/]+$/.test(tz)) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

/**
 * Null iff `rules` is a well-formed rules block for `d`: closed members, every parameter reference resolves to a parameter of
 * the right kind, every amount is integral in the currency's exponent, every list is bounded. The reason otherwise.
 */
export function businessRulesError(d: ActionDef, rules: unknown): string | null {
  try {
    validateRules(d, rules);
    return null;
  } catch (e) {
    return (e as Error).message;
  }
}

function validateRules(d: ActionDef, rules: unknown): asserts rules is BusinessRules {
  if (!isObj(rules)) bad('rules must be an object');
  const r = rules as Record<string, unknown>;
  closed(r, RULE_KEYS, 'rules');
  if (Object.keys(r).filter((k) => k !== 'examples').length === 0) bad('rules: name at least one rule');
  const ccyMap = (m: unknown, at: string): void => {
    if (!isObj(m) || Object.keys(m).length === 0 || Object.keys(m).length > MAX_RULE_CURRENCIES) bad(`${at}: a map of 1..${MAX_RULE_CURRENCIES} currencies to amounts`);
    const money = moneyOf(d);
    for (const [c, v] of Object.entries(m as Record<string, unknown>)) {
      if (!CCY_RE.test(c)) bad(`${at}: '${c}' is not an ISO 4217 currency code`);
      minorUnits(v, money.exp, `${at}.${c}`);
    }
  };
  if (r.amount !== undefined) {
    if (!isObj(r.amount)) bad('rules.amount must be {max: {CCY: amount}}');
    closed(r.amount as Record<string, unknown>, ['max'], 'rules.amount');
    ccyMap((r.amount as Record<string, unknown>).max, 'rules.amount.max');
  }
  if (r.approval !== undefined) {
    const a = r.approval;
    if (!isObj(a)) bad('rules.approval must be an object');
    closed(a as Record<string, unknown>, ['above', 'always', 'approvers', 'group'], 'rules.approval');
    const ap = a as BusinessRules['approval'] & object;
    if (ap.always !== undefined && ap.always !== true) bad('rules.approval.always is true or absent');
    if ((ap.above === undefined) === (ap.always === undefined)) bad('rules.approval: give exactly one of above or always');
    if (ap.above !== undefined) ccyMap(ap.above, 'rules.approval.above');
    if (ap.approvers !== undefined && (!Number.isSafeInteger(ap.approvers) || ap.approvers < 1 || ap.approvers > MAX_RULE_APPROVERS)) bad(`rules.approval.approvers is 1..${MAX_RULE_APPROVERS}`);
    if (ap.group !== undefined && (typeof ap.group !== 'string' || !NAME_RE.test(ap.group))) bad('rules.approval.group is a lowercase name');
  }
  if (r.scope !== undefined) {
    if (!Array.isArray(r.scope) || r.scope.length === 0 || r.scope.length > MAX_RULE_LIST) bad(`rules.scope is a list of 1..${MAX_RULE_LIST} bindings`);
    (r.scope as unknown[]).forEach((s0, i) => {
      if (!isObj(s0)) bad(`rules.scope[${i}] must be an object`);
      const s = s0 as Record<string, unknown>;
      closed(s, ['param', 'role', 'caller'], `rules.scope[${i}]`);
      const { p } = resolveParamRef(d, { ...(s.param !== undefined ? { param: s.param } : {}), ...(s.role !== undefined ? { role: s.role } : {}) }, `rules.scope[${i}]`);
      if (p.type !== 'string' && p.type !== 'integer') bad(`rules.scope[${i}]: the bound parameter must be a string or integer id`);
      if (typeof s.caller !== 'string' || !NAME_RE.test(s.caller)) bad(`rules.scope[${i}].caller is a lowercase attribute name of the caller`);
    });
  }
  if (r.rate !== undefined) {
    if (!Array.isArray(r.rate) || r.rate.length === 0 || r.rate.length > 4) bad('rules.rate is a list of 1..4 limits');
    (r.rate as unknown[]).forEach((x0, i) => {
      if (!isObj(x0)) bad(`rules.rate[${i}] must be an object`);
      const x = x0 as Record<string, unknown>;
      closed(x, ['max', 'per', 'by'], `rules.rate[${i}]`);
      if (!Number.isSafeInteger(x.max) || (x.max as number) < 1 || (x.max as number) > 1_000_000) bad(`rules.rate[${i}].max is 1..1000000`);
      if (!own(RATE_PERIODS, x.per as string)) bad(`rules.rate[${i}].per is hour or day`);
      if (x.by !== undefined && x.by !== 'principal' && x.by !== 'org') bad(`rules.rate[${i}].by is principal or org`);
    });
  }
  if (r.hours !== undefined) {
    if (!isObj(r.hours)) bad('rules.hours must be an object');
    const h = r.hours as Record<string, unknown>;
    closed(h, ['days', 'from', 'to', 'tz', 'outside'], 'rules.hours');
    if (!Array.isArray(h.days) || h.days.length === 0 || new Set(h.days).size !== h.days.length || !h.days.every((x) => (RULE_DAYS as readonly unknown[]).includes(x))) bad(`rules.hours.days is a list of distinct days (${RULE_DAYS.join(', ')})`);
    if (typeof h.from !== 'string' || !HHMM_RE.test(h.from) || typeof h.to !== 'string' || !HHMM_RE.test(h.to)) bad('rules.hours.from and .to are HH:MM (24 h)');
    if (typeof h.tz !== 'string' || !knownTimeZone(h.tz)) bad(`rules.hours.tz '${String(h.tz)}' is not a known IANA time zone`);
    if (h.outside !== undefined && h.outside !== 'escalate' && h.outside !== 'deny') bad('rules.hours.outside is escalate or deny');
  }
  if (r.recipients !== undefined) {
    if (!isObj(r.recipients)) bad('rules.recipients must be an object');
    const x = r.recipients as Record<string, unknown>;
    closed(x, ['param', 'role', 'domains', 'addresses'], 'rules.recipients');
    const { name, p } = resolveParamRef(d, { ...(x.param !== undefined ? { param: x.param } : {}), ...(x.role !== undefined ? { role: x.role } : {}) }, 'rules.recipients');
    if (p.type === 'array' || p.type === 'set') {
      if (p.items !== undefined && p.items !== 'string') bad(`rules.recipients: '${name}' must hold strings`);
      if (!Number.isSafeInteger(p.max_items) || (p.max_items as number) > MAX_RULE_LIST) bad(`rules.recipients: the list parameter '${name}' needs max_items <= ${MAX_RULE_LIST} so every entry can be checked`);
    } else if (p.type !== 'string') bad(`rules.recipients: '${name}' must be a string or a bounded list of strings`);
    const doms = x.domains, adds = x.addresses;
    if (doms === undefined && adds === undefined) bad('rules.recipients: give domains and/or addresses');
    if (doms !== undefined && (!Array.isArray(doms) || doms.length === 0 || doms.length > MAX_RULE_LIST || !doms.every((v) => typeof v === 'string' && DOMAIN_RE.test(v)))) bad('rules.recipients.domains is a list of lowercase domain names');
    if (adds !== undefined && (!Array.isArray(adds) || adds.length === 0 || adds.length > MAX_RULE_LIST || !adds.every((v) => typeof v === 'string' && ADDRESS_RE.test(v)))) bad('rules.recipients.addresses is a list of lowercase email addresses');
  }
  if (r.required !== undefined) {
    if (!Array.isArray(r.required) || r.required.length === 0 || r.required.length > MAX_RULE_LIST || new Set(r.required).size !== r.required.length) bad('rules.required is a list of distinct parameter names');
    for (const n of r.required as unknown[]) if (typeof n !== 'string' || !own(d.params, n)) bad(`rules.required: '${d.verb}' has no parameter '${String(n)}'`);
  }
  if (r.examples !== undefined) {
    if (!Array.isArray(r.examples) || r.examples.length > MAX_RULE_EXAMPLES) bad(`rules.examples is a list of at most ${MAX_RULE_EXAMPLES}`);
    (r.examples as unknown[]).forEach((e0, i) => {
      if (!isObj(e0)) bad(`rules.examples[${i}] must be an object`);
      const e = e0 as Record<string, unknown>;
      closed(e, ['params', 'caller', 'at', 'recent', 'expect'], `rules.examples[${i}]`);
      if (!isObj(e.params)) bad(`rules.examples[${i}].params must be an object`);
      if (e.caller !== undefined && !isObj(e.caller)) bad(`rules.examples[${i}].caller must be an object`);
      if (e.at !== undefined && (typeof e.at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(e.at) || Number.isNaN(Date.parse(e.at)))) bad(`rules.examples[${i}].at is an RFC 3339 UTC time (…Z)`);
      if (e.recent !== undefined && (!isObj(e.recent) || !Object.values(e.recent).every((n) => Number.isSafeInteger(n) && (n as number) >= 0))) bad(`rules.examples[${i}].recent maps rate indexes to counts`);
      if (!['allow', 'escalate', 'deny'].includes(e.expect as string)) bad(`rules.examples[${i}].expect is allow, escalate or deny`);
    });
  }
}

// ---- compiled form ---------------------------------------------------------------------------------------------------------

export const BUSINESS_RULES_DOMAIN = 'atlas-pca/action-business-rules/v1';

/** What `compileBusinessRules` emits: only existing wire forms (tighten rules, accumulators) plus what an escalation requires. */
export interface CompiledRules {
  v: 1;
  verb: string;
  /** Digest of the rules (examples excluded) and the def digest they were compiled against. */
  rules_digest: string;
  def_digest: string;
  /** Rule 21 tighten rules. Ids: `amount_*`, `approval_*`, `scope_<i>`, `rate_<i>`, `hours`, `recipients`, `required_<i>`. */
  tighten: TightenRule[];
  /** One count accumulator per rate limit; its pre-state is `env.acc.<id>`. */
  accumulators: AccumulatorDecl[];
  /** The time zone whose clock (`env.clock.dow`, `env.clock.min`) the hours rule reads. */
  clock_tz?: string;
  /** What an escalation raised by an `approval_*` rule needs. */
  approval?: { approvers: number; group?: string };
}

/** Digest of a rules block (examples are tests, not rules). */
export function businessRulesDigest(verb: string, rules: BusinessRules): string {
  const { examples: _e, ...body } = rules;
  void _e;
  return hashCanonical({ d: BUSINESS_RULES_DOMAIN, verb, rules: body });
}

const P = (n: string) => `action.params.${n}`;
const ccyCond = (m: ReturnType<typeof moneyOf>, c: string): Condition | null =>
  'param' in m.ccy ? { field: P(m.ccy.param), op: 'eq', value: c } : m.ccy.literal === c ? null : { field: 'action.verb', op: 'eq', value: '\u0000never' };
const and = (cs: (Condition | null)[]): Condition => {
  const xs = cs.filter((c): c is Condition => c !== null);
  return xs.length === 1 ? xs[0]! : { all_of: xs };
};
const always = (verb: string): Condition => ({ field: 'action.verb', op: 'eq', value: verb });
const ruleId = (s: string) => s.toLowerCase().replace(/[^a-z0-9_]/g, '_').slice(0, 64);

/**
 * Compile a rules block for `d` into tighten rules and accumulators. Throws ActionKitError `bad_rules` for a malformed block.
 * Deterministic: the same def and rules give the same output, in the same order.
 */
export function compileBusinessRules(d: ActionDef, rules: BusinessRules): CompiledRules {
  validateRules(d, rules);
  const t: TightenRule[] = [];
  const acc: AccumulatorDecl[] = [];
  const out: CompiledRules = { v: 1, verb: d.verb, rules_digest: businessRulesDigest(d.verb, rules), def_digest: defDigest(d), tighten: t, accumulators: acc };
  const money = rules.amount !== undefined || rules.approval?.above !== undefined ? moneyOf(d) : undefined;
  const unlisted = (listed: string[]): Condition | null =>
    money === undefined ? null : 'param' in money.ccy ? { not: { field: P(money.ccy.param), op: 'in', value: listed } } : listed.includes(money.ccy.literal) ? null : always(d.verb);
  if (rules.amount) {
    const m = money!;
    const listed = Object.keys(rules.amount.max).sort();
    for (const c of listed) {
      const max = minorUnits(rules.amount.max[c], m.exp, `rules.amount.max.${c}`);
      t.push({ id: ruleId(`amount_max_${c}`), when: and([ccyCond(m, c), { field: P(m.amount), op: 'gt', value: max }]), signal: 'deny', reason: `the amount is above the ${formatMoney(max, c, m.exp)} ceiling` });
    }
    const u = unlisted(listed);
    if (u) t.push({ id: 'amount_currency', when: u, signal: 'deny', reason: `only ${listed.join(', ')} amounts are allowed` });
  }
  if (rules.approval) {
    const ap = rules.approval;
    out.approval = { approvers: ap.approvers ?? 1, ...(ap.group !== undefined ? { group: ap.group } : {}) };
    if (ap.always) t.push({ id: 'approval_always', when: always(d.verb), signal: 'escalate', reason: 'this action always needs approval' });
    else {
      const m = money!;
      const listed = Object.keys(ap.above!).sort();
      for (const c of listed) {
        const x = minorUnits(ap.above![c], m.exp, `rules.approval.above.${c}`);
        t.push({ id: ruleId(`approval_above_${c}`), when: and([ccyCond(m, c), { field: P(m.amount), op: 'gt', value: x }]), signal: 'escalate', reason: `amounts above ${formatMoney(x, c, m.exp)} need approval` });
      }
      const u = unlisted(listed);
      if (u) t.push({ id: 'approval_currency', when: u, signal: 'escalate', reason: `amounts in a currency other than ${listed.join(', ')} need approval` });
    }
  }
  (rules.scope ?? []).forEach((s, i) => {
    const { name } = resolveParamRef(d, 'param' in s ? { param: s.param } : { role: s.role }, `rules.scope[${i}]`);
    // `not eq`: an absent caller attribute or parameter is undecided, so the rule fires
    t.push({ id: `scope_${i}`, when: { not: { field: P(name), op: 'eq', ref: `subject.${s.caller}` } }, signal: 'deny', reason: `${name} must be the caller's own ${s.caller}` });
  });
  (rules.rate ?? []).forEach((r, i) => {
    const id = `rate_${i}`;
    const by = r.by ?? 'principal';
    acc.push({ id, agg: 'count', sel: { verbs: [d.verb] }, win: { kind: 'sliding', ms: RATE_PERIODS[r.per] }, key: null, domain_max: r.max, cap: r.max, holder: { kind: 'site_local' }, scope: by });
    t.push({ id, when: { field: `env.acc.${id}`, op: 'gte', value: r.max }, signal: 'deny', reason: `at most ${r.max} per ${r.per} per ${by}` });
  });
  if (rules.hours) {
    const h = rules.hours;
    const from = mins(h.from), to = mins(h.to);
    const dows = h.days.map((x) => RULE_DAYS.indexOf(x)).sort((a, b) => a - b);
    const inTime: Condition = from < to
      ? { all_of: [{ field: 'env.clock.min', op: 'gte', value: from }, { field: 'env.clock.min', op: 'lt', value: to }] }
      // an overnight window (22:00-06:00): the day named is the day the window starts
      : { any_of: [{ field: 'env.clock.min', op: 'gte', value: from }, { field: 'env.clock.min', op: 'lt', value: to }] };
    const day: Condition = from < to
      ? { field: 'env.clock.dow', op: 'in', value: dows }
      : { any_of: [{ all_of: [{ field: 'env.clock.dow', op: 'in', value: dows }, { field: 'env.clock.min', op: 'gte', value: from }] }, { all_of: [{ field: 'env.clock.dow', op: 'in', value: dows.map((x) => (x + 1) % 7) }, { field: 'env.clock.min', op: 'lt', value: to }] }] };
    out.clock_tz = h.tz;
    t.push({ id: 'hours', when: { not: { all_of: [day, inTime] } }, signal: h.outside ?? 'escalate', reason: `outside ${hoursText(h)}` });
  }
  if (rules.recipients) {
    const x = rules.recipients;
    const { name, p } = resolveParamRef(d, 'param' in x ? { param: x.param } : { role: x.role }, 'rules.recipients');
    const okAt = (path: string): Condition => ({ any_of: [...(x.domains ?? []).map((dm): Condition => ({ field: path, op: 'like', value: `*@${dm.replace(/[\\*?]/g, '\\$&')}` })), ...(x.addresses ? [{ field: path, op: 'in', value: [...x.addresses].sort() } as Condition] : [])] });
    let ok: Condition;
    if (p.type === 'string') ok = okAt(P(name));
    else {
      const n = p.max_items!;
      // every present entry is allowed, and the list is no longer than max_items (index n absent)
      ok = { all_of: [...Array.from({ length: n }, (_, i): Condition => ({ any_of: [{ field: P(`${name}.${i}`), op: 'exists', value: false }, okAt(P(`${name}.${i}`))] })), { field: P(`${name}.${n}`), op: 'exists', value: false }] };
    }
    t.push({ id: 'recipients', when: { not: ok }, signal: 'deny', reason: `${name} may only name ${recipientsText(x)}` });
  }
  (rules.required ?? []).forEach((n, i) => {
    const pr = d.params[n]!;
    const missing: Condition = pr.type === 'string' ? { any_of: [{ field: P(n), op: 'exists', value: false }, { field: P(n), op: 'eq', value: '' }] } : { field: P(n), op: 'exists', value: false };
    t.push({ id: `required_${i}`, when: missing, signal: 'deny', reason: `${n} is required` });
  });
  for (const r of t) if (r.reason !== undefined && r.reason.length > 256) r.reason = `${r.reason.slice(0, 253)}...`;
  return out;
}

// ---- evaluation --------------------------------------------------------------------------------------------------------------

export interface RulesInput {
  params: Record<string, unknown>;
  /** Trusted caller attributes (never agent claims). */
  subject?: Record<string, unknown>;
  /** Milliseconds since the epoch. */
  now: number;
  /** Actions already counted in each accumulator window (by accumulator id). An absent count fires the rule (fail closed). */
  counts?: Record<string, number>;
  resource?: string;
}
export interface RulesVerdict {
  decision: Decision;
  /** One reason per rule that fired (`<id>: <reason>`), in rule order. */
  reasons: string[];
  fired: string[];
  /** Set when an `approval_*` rule escalated: what the escalation needs. */
  approval?: { approvers: number; group?: string };
}

/** Day of week (0 = Sunday) and minute of day at `now` in `tz`, or null when it cannot be computed. */
export function clockAt(now: number, tz: string): { dow: number; min: number } | null {
  try {
    if (!Number.isFinite(now)) return null;
    const parts = new Intl.DateTimeFormat('en-US', { timeZone: tz, weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(new Date(now));
    const get = (t: string) => parts.find((p) => p.type === t)?.value;
    const dow = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(get('weekday') ?? '');
    const h = Number(get('hour')), m = Number(get('minute'));
    if (dow < 0 || !Number.isInteger(h) || !Number.isInteger(m)) return null;
    return { dow, min: (h % 24) * 60 + m };
  } catch {
    return null;
  }
}

/** The predicate context the compiled rules are evaluated in. Verifier-computed `env` members only. */
export function rulesContext(c: CompiledRules, i: RulesInput): ActionContext {
  const env: Record<string, unknown> = {};
  if (c.clock_tz !== undefined) {
    const k = clockAt(i.now, c.clock_tz);
    if (k) env.clock = k;
  }
  const acc: Record<string, number> = {};
  for (const a of c.accumulators) {
    const n = i.counts?.[a.id];
    if (typeof n === 'number' && Number.isSafeInteger(n) && n >= 0) acc[a.id] = n;
  }
  env.acc = acc;
  return { action: { verb: c.verb, resource: i.resource ?? '', params: i.params }, subject: i.subject ?? {}, env };
}

/** Evaluate compiled rules: `allow` unless a rule fires; a fired rule caps the decision at its signal. Never throws. */
export function evaluateBusinessRules(c: CompiledRules, i: RulesInput): RulesVerdict {
  try {
    const ctx = rulesContext(c, i);
    let decision: Decision = 'allow';
    const reasons: string[] = [];
    const fired: string[] = [];
    let approval = false;
    for (const r of c.tighten) {
      if (evaluateConditionTri(r.when, ctx) === 'false') continue;
      decision = meetDecision(decision, r.signal);
      fired.push(r.id);
      reasons.push(`${r.id}: ${r.reason ?? r.signal}`);
      if (r.signal === 'escalate' && r.id.startsWith('approval_')) approval = true;
    }
    return { decision, reasons, fired, ...(approval && c.approval ? { approval: c.approval } : {}) };
  } catch (e) {
    return { decision: 'deny', reasons: [`rules: evaluation error (fail closed): ${(e as Error).message}`], fired: [] };
  }
}

/** The decision with rules applied to a base decision: the meet, so rules never raise it. */
export const withBusinessRules = (base: Decision, v: RulesVerdict): Decision => meetDecision(base, v.decision);

/** Run a rules block's examples. */
export function runRuleExamples(d: ActionDef, rules: BusinessRules): Array<{ index: number; expect: Decision; got: Decision; ok: boolean; why: string }> {
  const c = compileBusinessRules(d, rules);
  return (rules.examples ?? []).map((e, index) => {
    const counts: Record<string, number> = {};
    c.accumulators.forEach((a, k) => (counts[a.id] = e.recent?.[String(k)] ?? 0));
    const v = evaluateBusinessRules(c, { params: e.params, ...(e.caller ? { subject: e.caller } : {}), now: Date.parse(e.at ?? '2026-01-07T15:00:00Z'), counts });
    return { index, expect: e.expect, got: v.decision, ok: v.decision === e.expect, why: v.reasons.join('; ') || 'no rule fired' };
  });
}

// ---- plain language -----------------------------------------------------------------------------------------------------------

/** `12345` minor units of USD (exp 2) -> "123.45 USD". Deterministic (no locale). */
export function formatMoney(minor: number, ccy: string, exp: number): string {
  const s = String(minor).padStart(exp + 1, '0');
  return `${exp > 0 ? `${s.slice(0, -exp)}.${s.slice(-exp)}` : s} ${ccy}`;
}
const DAY_NAMES: Record<RuleDay, string> = { sun: 'Sun', mon: 'Mon', tue: 'Tue', wed: 'Wed', thu: 'Thu', fri: 'Fri', sat: 'Sat' };
function hoursText(h: NonNullable<BusinessRules['hours']>): string {
  const ds = [...h.days].sort((a, b) => RULE_DAYS.indexOf(a) - RULE_DAYS.indexOf(b));
  const idx = ds.map((x) => RULE_DAYS.indexOf(x));
  const run = idx.length > 2 && idx.every((x, k) => k === 0 || x === idx[k - 1]! + 1);
  return `${run ? `${DAY_NAMES[ds[0]!]}-${DAY_NAMES[ds[ds.length - 1]!]}` : ds.map((x) => DAY_NAMES[x]).join(', ')} ${h.from}-${h.to} (${h.tz})`;
}
function recipientsText(x: NonNullable<BusinessRules['recipients']>): string {
  return [...(x.domains ?? []).map((dm) => `addresses at ${dm}`), ...(x.addresses ?? [])].join(' or ');
}

/** One plain sentence per rule, for the policy card and the dashboard. Throws `bad_rules` for a malformed block. */
export function explainBusinessRules(d: ActionDef, rules: BusinessRules): string[] {
  validateRules(d, rules);
  const out: string[] = [];
  const m = rules.amount !== undefined || rules.approval?.above !== undefined ? moneyOf(d) : undefined;
  const list = (mp: Record<string, MoneyValue>) => Object.keys(mp).sort().map((c) => formatMoney(minorUnits(mp[c], m!.exp, c), c, m!.exp)).join(', ');
  if (rules.amount) out.push(`Refuses amounts above ${list(rules.amount.max)}; any other currency is refused.`);
  if (rules.approval) {
    const who = `${rules.approval.approvers ?? 1} approver${(rules.approval.approvers ?? 1) === 1 ? '' : 's'}${rules.approval.group ? ` from the ${rules.approval.group} group` : ''}`;
    out.push(rules.approval.always ? `Always needs approval by ${who}.` : `Needs approval by ${who} when the amount is above ${list(rules.approval.above!)} (or in another currency).`);
  }
  for (const s of rules.scope ?? []) {
    const { name } = resolveParamRef(d, 'param' in s ? { param: s.param } : { role: s.role }, 'rules.scope');
    out.push(`Only the caller's own records: ${name} must be the caller's ${s.caller}.`);
  }
  for (const r of rules.rate ?? []) out.push(`At most ${r.max} per ${r.per} per ${r.by === 'org' ? 'organisation' : 'principal'}.`);
  if (rules.hours) out.push(`Only ${hoursText(rules.hours)}; outside those hours it ${rules.hours.outside === 'deny' ? 'is refused' : 'needs approval'}.`);
  if (rules.recipients) {
    const { name } = resolveParamRef(d, 'param' in rules.recipients ? { param: rules.recipients.param } : { role: rules.recipients.role }, 'rules.recipients');
    out.push(`${name} may only name ${recipientsText(rules.recipients)}.`);
  }
  if (rules.required) out.push(`Requires ${rules.required.join(', ')}.`);
  return out;
}

// ---- lint (contradictions and dead rules) ------------------------------------------------------------------------------------

/** Rules findings live outside LINT_RULES (whose digest is pinned); ids LR-*. */
export const BUSINESS_RULE_LINTS = [
  { id: 'LR-001', severity: 'error', title: 'a rules block is malformed or names a parameter the action does not have' },
  { id: 'LR-002', severity: 'error', title: 'a contradiction: under the rules the action can never be allowed' },
  { id: 'LR-003', severity: 'warning', title: 'a rule that can never fire or that another rule already covers' },
  { id: 'LR-004', severity: 'error', title: 'a rules example does not decide as it expects' },
] as const;

/** Lint one action's rules. */
export function lintBusinessRules(d: ActionDef, rules: unknown): Finding[] {
  const f = (rule: string, severity: 'error' | 'warning', message: string): Finding => ({ rule, severity, verb: d.verb, message });
  const e = businessRulesError(d, rules);
  if (e) return [f('LR-001', 'error', e)];
  const r = rules as BusinessRules;
  const out: Finding[] = [];
  const m = r.amount !== undefined || r.approval?.above !== undefined ? moneyOf(d) : undefined;
  const amt = m ? d.params[m.amount]! : undefined;
  const ccyValues = !m ? undefined : 'param' in m.ccy ? d.params[m.ccy.param]!.values : [m.ccy.literal];
  if (r.amount && m) {
    const listed = Object.keys(r.amount.max);
    if (ccyValues && !ccyValues.some((c) => listed.includes(c))) out.push(f('LR-002', 'error', `rules.amount: none of the action's currencies (${ccyValues.join(', ')}) has a ceiling, so every call is refused`));
    for (const c of listed) {
      const max = minorUnits(r.amount.max[c], m.exp, c);
      if (ccyValues && !ccyValues.includes(c)) out.push(f('LR-003', 'warning', `rules.amount.max.${c}: the action never uses ${c}`));
      if (amt?.min !== undefined && max < amt.min) out.push(f('LR-002', 'error', `rules.amount.max.${c}: the ceiling ${formatMoney(max, c, m.exp)} is below the parameter's minimum, so every ${c} call is refused`));
      if (amt?.max !== undefined && max >= amt.max) out.push(f('LR-003', 'warning', `rules.amount.max.${c}: the parameter's own maximum already bounds the amount below this ceiling`));
    }
  }
  if (r.approval?.above && m) {
    for (const c of Object.keys(r.approval.above)) {
      const x = minorUnits(r.approval.above[c], m.exp, c);
      const ceil = r.amount?.max[c];
      if (ceil !== undefined && x >= minorUnits(ceil, m.exp, c)) out.push(f('LR-003', 'warning', `rules.approval.above.${c}: above the amount ceiling, so the approval can never be asked for`));
      if (r.amount && ceil === undefined) out.push(f('LR-003', 'warning', `rules.approval.above.${c}: ${c} has no ceiling, so it is always refused before an approval`));
    }
  }
  if (r.hours) {
    if (r.hours.from === r.hours.to) out.push(f('LR-002', 'error', `rules.hours: the window ${r.hours.from}-${r.hours.to} is empty, so the action is ${r.hours.outside === 'deny' ? 'always refused' : 'always escalated'}`));
  }
  if (r.required) for (const n of r.required) if (d.params[n]!.required !== false && d.params[n]!.type !== 'string') out.push(f('LR-003', 'warning', `rules.required: '${n}' is already required by the definition`));
  if (r.rate) {
    const seen = new Map<string, number>();
    for (const x of r.rate) {
      const k = `${x.per}|${x.by ?? 'principal'}`;
      if (seen.has(k)) out.push(f('LR-003', 'warning', `rules.rate: two limits per ${x.per} per ${x.by ?? 'principal'}; only the lower (${Math.min(seen.get(k)!, x.max)}) matters`));
      seen.set(k, Math.min(seen.get(k) ?? Infinity, x.max));
    }
    const h = seen.get('hour|principal'), dd = seen.get('day|principal');
    if (h !== undefined && dd !== undefined && dd <= h) out.push(f('LR-003', 'warning', 'rules.rate: the daily limit is not above the hourly one, so the hourly limit never fires'));
  }
  try {
    for (const x of runRuleExamples(d, r)) if (!x.ok) out.push(f('LR-004', 'error', `rules.examples[${x.index}]: expected ${x.expect}, got ${x.got} (${x.why})`));
  } catch (err) {
    out.push(f('LR-001', 'error', (err as Error).message));
  }
  return out;
}

// ---- semantic diff of rules (widening needs a reviewer) ---------------------------------------------------------------------

export type RulesDiffClass = 'equal' | 'narrow' | 'widen' | 'incomparable';
type Rel = 'eq' | 'narrow' | 'widen' | 'inc';

const setRel = (a: readonly string[], b: readonly string[]): Rel => {
  const A = new Set(a), B = new Set(b);
  const aInB = [...A].every((x) => B.has(x)), bInA = [...B].every((x) => A.has(x));
  return aInB && bInA ? 'eq' : bInA ? 'narrow' : aInB ? 'widen' : 'inc';
};
/** A numeric limit where lower is stricter. */
const numRel = (a: number, b: number): Rel => (a === b ? 'eq' : b < a ? 'narrow' : 'widen');
/** Absent rule vs present rule: adding a rule narrows, dropping one widens. */
const presence = (a: unknown, b: unknown): Rel | null => (a === undefined && b === undefined ? 'eq' : a === undefined ? 'narrow' : b === undefined ? 'widen' : null);

/**
 * The semantic diff of two rules blocks of one action (either may be absent). `narrow`/`equal` can be published without a
 * reviewer; `widen` and `incomparable` need a reviewer's signed rules review. Conservative: anything not ordered is incomparable.
 */
export function diffBusinessRules(d: ActionDef, prev: BusinessRules | undefined, next: BusinessRules | undefined): { class: RulesDiffClass; reasons: string[] } {
  const rels: Array<[string, Rel]> = [];
  const o = prev ?? {}, n = next ?? {};
  const m = (o.amount || n.amount || o.approval?.above || n.approval?.above) ? moneyOf(d) : undefined;
  const ccyMapRel = (a: Record<string, MoneyValue>, b: Record<string, MoneyValue>): Rel => {
    // a currency only in the new map widens (it was refused); only in the old map narrows (now refused); shared: compare
    const rs: Rel[] = [setRel(Object.keys(a), Object.keys(b))];
    for (const c of Object.keys(a)) if (own(b, c)) rs.push(numRel(minorUnits(a[c], m!.exp, c), minorUnits(b[c], m!.exp, c)));
    return combine(rs);
  };
  rels.push(['amount', presence(o.amount, n.amount) ?? ccyMapRel(o.amount!.max, n.amount!.max)]);
  rels.push(['approval', presence(o.approval, n.approval) ?? (() => {
    const a = o.approval!, b = n.approval!;
    const rs: Rel[] = [];
    if (a.always && b.always) rs.push('eq');
    else if (a.always) rs.push('widen');
    else if (b.always) rs.push('narrow');
    else rs.push(ccyMapRel(a.above!, b.above!));
    rs.push(numRel(-(a.approvers ?? 1), -(b.approvers ?? 1)));
    rs.push(a.group === b.group ? 'eq' : 'inc');
    return combine(rs);
  })()]);
  const key = (s: { param?: string; role?: string; caller: string }) => `${s.param ?? ''}|${s.role ?? ''}|${s.caller}`;
  rels.push(['scope', flip(setRel((o.scope ?? []).map((s) => key(s as never)), (n.scope ?? []).map((s) => key(s as never))))]);
  rels.push(['rate', (() => {
    const best = (rs: BusinessRules['rate']) => {
      const mp = new Map<string, number>();
      for (const x of rs ?? []) { const k = `${x.per}|${x.by ?? 'principal'}`; mp.set(k, Math.min(mp.get(k) ?? Infinity, x.max)); }
      return mp;
    };
    const A = best(o.rate), B = best(n.rate);
    const rs: Rel[] = [];
    for (const k of new Set([...A.keys(), ...B.keys()])) rs.push(!A.has(k) ? 'narrow' : !B.has(k) ? 'widen' : numRel(A.get(k)!, B.get(k)!));
    return combine(rs);
  })()]);
  rels.push(['hours', presence(o.hours, n.hours) ?? (() => {
    const a = o.hours!, b = n.hours!;
    if (a.tz !== b.tz) return 'inc';
    const sa = minutesOfWeek(a), sb = minutesOfWeek(b);
    const inner = sa.size === sb.size && [...sa].every((x) => sb.has(x)) ? 'eq' : [...sb].every((x) => sa.has(x)) ? 'narrow' : [...sa].every((x) => sb.has(x)) ? 'widen' : 'inc';
    const out: Rel = numRel(a.outside === 'deny' ? 0 : 1, b.outside === 'deny' ? 0 : 1);
    return combine([inner as Rel, out]);
  })()]);
  rels.push(['recipients', presence(o.recipients, n.recipients) ?? (() => {
    const a = o.recipients!, b = n.recipients!;
    if ((a as { param?: string }).param !== (b as { param?: string }).param || (a as { role?: string }).role !== (b as { role?: string }).role) return 'inc';
    // fewer allowed recipients is narrower: the allow sets are compared, an address now covered by a domain counts as allowed
    const allowedA = [...(a.domains ?? []).map((x) => `@${x}`), ...(a.addresses ?? [])];
    const allowedB = [...(b.domains ?? []).map((x) => `@${x}`), ...(b.addresses ?? [])];
    const covered = (x: string, set: string[]) => set.includes(x) || (!x.startsWith('@') && set.includes(`@${x.split('@')[1]}`));
    const bInA = allowedB.every((x) => covered(x, allowedA)), aInB = allowedA.every((x) => covered(x, allowedB));
    return bInA && aInB ? 'eq' : bInA ? 'narrow' : aInB ? 'widen' : 'inc';
  })()]);
  rels.push(['required', flip(setRel(o.required ?? [], n.required ?? []))]);
  const diffs = rels.filter(([, r]) => r !== 'eq');
  const reasons = diffs.map(([k, r]) => `rules.${k}: ${r === 'inc' ? 'incomparable' : r}`).sort();
  const cls = combine(diffs.map(([, r]) => r));
  return { class: cls === 'eq' ? 'equal' : cls === 'inc' ? 'incomparable' : cls, reasons };
}
function combine(rs: readonly Rel[]): Rel {
  const has = (r: Rel) => rs.includes(r);
  return has('inc') || (has('narrow') && has('widen')) ? 'inc' : has('widen') ? 'widen' : has('narrow') ? 'narrow' : 'eq';
}
/** For sets of restrictions (scope bindings, required fields) more is narrower: invert a set relation. */
const flip = (r: Rel): Rel => (r === 'narrow' ? 'widen' : r === 'widen' ? 'narrow' : r);
function minutesOfWeek(h: NonNullable<BusinessRules['hours']>): Set<number> {
  const s = new Set<number>();
  const from = mins(h.from), to = mins(h.to);
  for (const day of h.days) {
    const base = RULE_DAYS.indexOf(day) * 1440;
    if (from < to) for (let x = from; x < to; x++) s.add(base + x);
    else if (from > to) {
      for (let x = from; x < 1440; x++) s.add(base + x);
      for (let x = 0; x < to; x++) s.add(((base + 1440) % 10080) + x);
    }
  }
  return s;
}

// ---- the reviewer's signature over a widened rules block ------------------------------------------------------------------------

export const RULES_REVIEW_DOMAIN = 'atlas-pca/action-rules-review/v1';
export interface RulesReview {
  verb: string;
  def_digest: string;
  rules_digest: string;
  reviewer_kid: string;
  /** Seconds since the epoch. */
  ts: number;
  sig?: string;
}

export function rulesReviewMessage(b: Omit<RulesReview, 'sig'>): Uint8Array {
  const body = canonicalBytesStrict({ verb: b.verb, def_digest: b.def_digest, rules_digest: b.rules_digest, reviewer_kid: b.reviewer_kid, ts: b.ts });
  const dom = utf8(RULES_REVIEW_DOMAIN + '\0');
  const out = new Uint8Array(dom.length + body.length);
  out.set(dom);
  out.set(body, dom.length);
  return out;
}

export function signRulesReview(b: Omit<RulesReview, 'sig'>, secret: Uint8Array): RulesReview {
  return { ...b, sig: b64u(sign(secret, rulesReviewMessage(b))) };
}

/**
 * Null iff `r` is a valid review of exactly these rules on exactly this def: digests match, the signer is pinned with the
 * `reviewer` role, the time is inside the key validity, the signature verifies. A reason otherwise. Never throws.
 */
export function rulesReviewError(r: unknown, d: ActionDef, rules: BusinessRules, pins: ReviewerPins | undefined): string | null {
  try {
    if (pins === undefined) return 'no reviewer keys are pinned';
    const pe = reviewerPinsError(pins);
    if (pe) return `bad pins: ${pe}`;
    if (!isObj(r)) return 'no rules review';
    const x = r as unknown as RulesReview;
    if (x.verb !== d.verb) return 'the rules review names another action';
    if (x.def_digest !== defDigest(d)) return 'the rules review covers another version of the action';
    if (x.rules_digest !== businessRulesDigest(d.verb, rules)) return 'the rules review covers other rules';
    if (typeof x.sig !== 'string' || typeof x.reviewer_kid !== 'string' || !Number.isSafeInteger(x.ts)) return 'malformed rules review';
    const key = pins.keys.find((k) => k.kid === x.reviewer_kid);
    if (!key) return `no pinned key '${x.reviewer_kid}'`;
    if (!key.roles.includes('reviewer')) return `key '${key.kid}' does not hold the reviewer role`;
    if ((key.not_before !== undefined && x.ts < key.not_before) || (key.not_after !== undefined && x.ts > key.not_after)) return 'the review time is outside the key validity';
    const { sig, ...body } = x;
    return verifyB64u(key.pk, rulesReviewMessage(body), sig) ? null : 'the rules review signature is invalid';
  } catch (e) {
    return `malformed rules review: ${(e as Error).message}`;
  }
}
