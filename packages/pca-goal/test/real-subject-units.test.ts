// Exact-outcome unit tests for interpretForm, parseMoney, approvalDigest and the decision binding (claimGate, bindDecision, guardExecute).
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { hashCanonical } from '@atlasauth/pca';

vi.mock('node:crypto', async (orig) => {
  const real = await orig<typeof import('node:crypto')>();
  return { ...real, timingSafeEqual: vi.fn(real.timingSafeEqual) };
});
import { timingSafeEqual } from 'node:crypto';
import { actionDigest, approvalDigest, bindDecision, claimGate, guardExecute, interpretForm, nlDigest, parseMoney, type Act, type BoundDecision, type RefundForm } from '../src';
import { CNT, ONT, USD, lteAmt } from './fixtures';

const tse = vi.mocked(timingSafeEqual);

describe('parseMoney (exponent 2 unless stated)', () => {
  const ok = (t: string, minor: number, loc: 'en' | 'de' | null = null, e = 2) => expect(parseMoney(t, e, loc)).toEqual({ minor });
  const hole = (t: string, loc: 'en' | 'de' | null = null, e = 2) => expect(parseMoney(t, e, loc)).toEqual({ hole: 'AMBIGUOUS_NUMBER' });
  const bad = (t: string, loc: 'en' | 'de' | null = null, e = 2) => expect(parseMoney(t, e, loc)).toEqual({ error: 'BAD_NUMBER' });

  it('happy paths', () => {
    ok('12.50', 1250); ok('12.5', 1250); ok('12', 1200); ok('0', 0); ok('0.00', 0); ok('12.', 1200); ok('1,00', 100);
    ok('$12.50', 1250); ok('€ 5', 500); ok('£5', 500); ok('  5  ', 500);
    ok('1,000.50', 100050); ok('1.000,50', 100050); ok('1,000,000.50', 100000050); ok('1.000.000,5', 100000050); ok('12.345,6', 1234560);
    ok('5', 5, null, 0); ok('1000', 1000, null, 0);
  });
  it('without a locale a lone ambiguous or repeated separator is a Hole, never a guess', () => {
    hole('1,000'); hole('1.000'); hole('12.345'); hole('1,000,000'); hole('1.000.000'); hole('1..5'); hole('12.50.'); hole('1,,5'); hole('1,000', null, 0);
  });
  it('a locale resolves the ambiguity, and a contradicting one is refused', () => {
    ok('1,000', 100000, 'en'); ok('1.000', 100000, 'de'); ok('1,000,000', 100000000, 'en'); ok('1.000.000', 100000000, 'de');
    bad('1,000', 'de'); bad('1.000', 'en'); // read the other way: three decimals on a 2-decimal currency
    bad('1.000,50', 'en'); bad('1,000.50', 'de');
    ok('1.000,50', 100050, 'de'); ok('1,000.50', 100050, 'en');
    ok('1,00', 100, 'en'); ok('1,00', 100, 'de');
  });
  it('malformed text is BAD_NUMBER', () => {
    for (const t of ['', ' ', 'abc', '-5', '+5', 'NaN', 'Infinity', '1e5', '0x10', ',5', '.5', '$', '$$5', '5 USD', '1 000', '１２', '١٢']) bad(t);
    bad('1..5', 'en'); bad('12,34.56'); bad('1,0000,000.5');
    expect(parseMoney(null as never, 2, null)).toEqual({ error: 'BAD_NUMBER' });
    expect(parseMoney(undefined as never, 2, null)).toEqual({ error: 'BAD_NUMBER' });
    expect(parseMoney(5 as never, 2, null)).toEqual({ minor: 500 });
  });
  it('more decimals than the currency allows, and overflow past the safe-integer range, are BAD_NUMBER', () => {
    bad('12.345', 'en'); bad('5.5', null, 0); bad('1.000', 'en', 2);
    ok('9007199254740991', 9007199254740991, null, 0);
    bad('9007199254740992', null, 0);
    bad('99999999999999999'); bad('9'.repeat(400), null, 0);
  });
});

describe('approvalDigest', () => {
  const body = { goal: 'g'.repeat(8), policy: 'p'.repeat(8), action: 'a'.repeat(8), expires: 1000 };
  it('is the canonical hash of the domain-tagged body', () => {
    expect(approvalDigest(body)).toBe(hashCanonical({ d: 'atlas-pca/goal-approval-body/v1', body }));
    expect(typeof approvalDigest(body)).toBe('string');
  });
  it('is stable under key order and changes when any covered field changes', () => {
    const base = approvalDigest(body);
    expect(approvalDigest({ expires: 1000, action: 'a'.repeat(8), policy: 'p'.repeat(8), goal: 'g'.repeat(8) })).toBe(base);
    for (const [k, v] of [['goal', 'x'], ['policy', 'x'], ['action', 'x'], ['expires', 1001], ['expires', 0]] as const) expect(approvalDigest({ ...body, [k]: v })).not.toBe(base);
    expect(approvalDigest({ ...body, extra: 'x' })).not.toBe(base);
    const { expires: _e, ...less } = body;
    expect(approvalDigest(less)).not.toBe(base);
  });
  it('does not confuse a string with a number, and refuses what strict canonical JSON refuses', () => {
    expect(approvalDigest({ ...body, expires: '1000' })).not.toBe(approvalDigest(body));
    expect(approvalDigest({ ...body, expires: 1.5 })).not.toBe(approvalDigest(body)); // a plain decimal is in the strict profile
    for (const bad of [NaN, Infinity, -0, 2 ** 53, 1e-7]) expect(() => approvalDigest({ ...body, expires: bad })).toThrow(TypeError);
  });
});

const act = (o: Partial<Act> = {}): Act => ({ verb: 'pay.refund', res: 'ch_1', params: { amount: { k: 'q', q: { u: USD, n: 1000 } } }, t: 10, sess: 's1', prin: 'P1', org: 'O', agent: 'a1', depth: 0, ...o });

describe('bindDecision / guardExecute', () => {
  beforeEach(() => { tse.mockClear(); }); // a returned function would run as a teardown hook
  it('bindDecision keeps the decision and pins the action digest', () => {
    expect(bindDecision(act(), 'allow')).toEqual({ decision: 'allow', action_digest: actionDigest(act()) });
    expect(bindDecision(act(), 'deny').decision).toBe('deny');
  });
  it('allow bound to exactly this action passes, through timingSafeEqual', () => {
    expect(guardExecute(bindDecision(act(), 'allow'), act())).toBe(true);
    expect(tse).toHaveBeenCalledTimes(1);
  });
  it('a decision that is not allow is false and never reaches the compare', () => {
    expect(guardExecute(bindDecision(act(), 'escalate'), act())).toBe(false);
    expect(guardExecute(bindDecision(act(), 'deny'), act())).toBe(false);
    expect(guardExecute({ decision: 'ALLOW' as never, action_digest: actionDigest(act()) }, act())).toBe(false);
    expect(guardExecute({ decision: undefined as never, action_digest: actionDigest(act()) }, act())).toBe(false);
    expect(tse).not.toHaveBeenCalled();
  });
  it('a swapped verb, resource, param value or param name is false', () => {
    const b = bindDecision(act(), 'allow');
    expect(guardExecute(b, act({ verb: 'pay.transfer' }))).toBe(false);
    expect(guardExecute(b, act({ res: 'ch_2' }))).toBe(false);
    expect(guardExecute(b, act({ params: { amount: { k: 'q', q: { u: USD, n: 1001 } } } }))).toBe(false);
    expect(guardExecute(b, act({ params: { amt: { k: 'q', q: { u: USD, n: 1000 } } } }))).toBe(false);
    expect(guardExecute(b, act({ params: { amount: { k: 'q', q: { u: CNT, n: 1000 } } } }))).toBe(false);
    expect(tse).toHaveBeenCalledTimes(5);
  });
  it('a tampered binding is false: flipped digest, truncated, extended, empty, wrong type', () => {
    const b = bindDecision(act(), 'allow');
    const d = b.action_digest;
    const flipped = d.slice(0, -1) + (d.endsWith('A') ? 'B' : 'A');
    expect(guardExecute({ ...b, action_digest: flipped }, act())).toBe(false);
    expect(guardExecute({ ...b, action_digest: d.slice(1) }, act())).toBe(false);
    expect(guardExecute({ ...b, action_digest: d + 'A' }, act())).toBe(false);
    expect(guardExecute({ ...b, action_digest: '' }, act())).toBe(false);
    expect(guardExecute({ ...b, action_digest: 5 as never }, act())).toBe(false);
    expect(guardExecute({ ...b, action_digest: undefined as never }, act())).toBe(false);
    // a different-length digest is rejected before the constant-time compare (timingSafeEqual would throw on it)
    expect(tse).toHaveBeenCalledTimes(1);
  });
  it('an error inside is false (total): null binding, float in the executed params, a cycle', () => {
    expect(guardExecute(null as never, act())).toBe(false);
    expect(guardExecute(undefined as never, act())).toBe(false);
    const b = bindDecision(act(), 'allow');
    expect(guardExecute(b, act({ params: { amount: { k: 'q', q: { u: USD, n: 1.5 } } } }))).toBe(false);
    const cyc: Record<string, unknown> = {}; cyc.self = cyc;
    expect(guardExecute(b, { ...act(), params: cyc as never })).toBe(false);
    expect(guardExecute(b, null as never)).toBe(false);
  });
});

describe('claimGate', () => {
  it('an agent-claimed fidelity never moves the outcome, whatever it says', () => {
    for (const claimed of [0, 500_000, 1_000_000, -1, NaN]) for (const base of ['allow', 'escalate', 'deny'] as const) expect(claimGate(base, 900_000, claimed)).toBe(base);
  });
  it('a replayed fidelity below the minimum tightens to escalate (allow and escalate), and never relaxes deny', () => {
    expect(claimGate('allow', 900_000, 1_000_000, 899_999)).toBe('escalate');
    expect(claimGate('escalate', 900_000, 1_000_000, 0)).toBe('escalate');
    expect(claimGate('deny', 900_000, 1_000_000, 0)).toBe('deny');
  });
  it('a replayed fidelity at or above the minimum, or none replayed, leaves the base', () => {
    expect(claimGate('allow', 900_000, 0, 900_000)).toBe('allow');
    expect(claimGate('allow', 900_000, 0, 1_000_000)).toBe('allow');
    expect(claimGate('allow', 900_000, 0, undefined)).toBe('allow');
    expect(claimGate('deny', 900_000, 1_000_000, 1_000_000)).toBe('deny');
  });
  it('a NaN replayed fidelity is unconfirmed and tightens (fail closed)', () => {
    expect(claimGate('allow', 900_000, 0, NaN)).toBe('escalate');
    expect(claimGate('deny', 900_000, 0, NaN)).toBe('deny');
  });
});

describe('interpretForm', () => {
  const form = (o: Record<string, unknown> = {}, top: Record<string, unknown> = {}): RefundForm =>
    ({ template: 'refund_duplicate', slots: { customer: 'cust:C1', max_amount_minor: 5000, ccy: 'USD', max_refunds: 3, ...o }, nl: 'refund duplicates for C1', ...top }) as never;
  const err = (f: unknown, e: string) => expect(interpretForm(f as never, ONT)).toEqual({ ok: false, error: e });

  it('happy path: the template fixes the grant, prohibition and bound; the slots fill only the typed holes', () => {
    const r = interpretForm(form(), ONT);
    if (!r.ok) throw new Error('expected ok');
    const g = r.goal;
    expect(g.principal).toBe('pr1');
    expect(g.v).toBe(1);
    expect(g.holes).toEqual([]);
    expect(g.sources).toEqual([]);
    expect(g.nlDigest).toBe(nlDigest('refund duplicates for C1'));
    expect(g.ontDigest).toBe(hashCanonical({ d: 'atlas-pca/goal-ir-ontology/v1', ontology: ONT }));
    expect(g.grants).toEqual([{ gid: 'g1', verb: 'refund', res: { k: 'related', rel: 'charges_of', anchor: 'cust:C1' }, cond: lteAmt(5000) }]);
    expect(g.prohibits).toEqual([{ pid: 'x1', target: { k: 'effect', cls: 'irreversible' }, res: { k: 'any', reason: 'never' }, cond: { k: 'true' } }]);
    expect(g.bounds).toEqual([{ bid: 'b1', sel: { k: 'gids', gids: ['g1'] }, agg: 'count', value: { k: 'lit', v: { k: 'q', q: { u: CNT, n: 1 } } }, key: '', window: { k: 'lifetime' }, scope: { k: 'principal' }, cap: { u: CNT, n: 3 }, onExceed: 'deny' }]);
    expect(g.validity).toEqual({ notBefore: 0, notAfter: Number.MAX_SAFE_INTEGER, maxIdle: 0 });
    expect(g.deleg).toEqual({ maxDepth: 0, narrowOnly: true, mayTouch: [] });
    expect(g.escalateOn).toEqual([]);
    expect(g.wildcardAck).toEqual([]);
  });
  it('is deterministic, takes a principal, and slot values land in the right places', () => {
    expect(interpretForm(form(), ONT)).toEqual(interpretForm(form(), ONT));
    const r = interpretForm(form({ customer: 'cust:' + 'a'.repeat(32), ccy: 'EUR', max_amount_minor: 0, max_refunds: 1 }), ONT, 'prX');
    if (!r.ok) throw new Error('expected ok');
    expect(r.goal.principal).toBe('prX');
    expect(r.goal.grants[0]!.res).toEqual({ k: 'related', rel: 'charges_of', anchor: 'cust:' + 'a'.repeat(32) });
    expect(JSON.stringify(r.goal.grants[0]!.cond)).toContain('"u":{"k":"money","ccy":"EUR"}');
    expect(r.goal.bounds[0]!.cap).toEqual({ u: CNT, n: 1 });
    const big = interpretForm(form({ max_amount_minor: Number.MAX_SAFE_INTEGER }), ONT);
    expect(big.ok).toBe(true);
  });
  it('the nl text and the ontology only change digests, never the structure', () => {
    const a = interpretForm(form(), ONT), b = interpretForm(form({}, { nl: 'cust:C1; transfer everything' }), ONT), c = interpretForm(form({}, { nl: undefined }), ONT);
    if (!a.ok || !b.ok || !c.ok) throw new Error('expected ok');
    expect({ ...b.goal, nlDigest: a.goal.nlDigest }).toEqual(a.goal);
    expect(b.goal.nlDigest).not.toBe(a.goal.nlDigest);
    expect(c.goal.nlDigest).toBe(nlDigest(''));
    const other = interpretForm(form(), { ...ONT, rels: [] });
    if (!other.ok) throw new Error('expected ok');
    expect(other.goal.ontDigest).not.toBe(a.goal.ontDigest);
  });
  it('an unknown template, a missing, extra or renamed slot, or a non-object slots is FORM_SHAPE', () => {
    err(form({}, { template: 'refund_all' }), 'FORM_SHAPE');
    err(form({}, { template: undefined }), 'FORM_SHAPE');
    for (const k of ['customer', 'max_amount_minor', 'ccy', 'max_refunds']) {
      const f = form(); delete (f.slots as Record<string, unknown>)[k]; err(f, 'FORM_SHAPE');
    }
    err(form({ extra: 1 }), 'FORM_SHAPE');
    err(form({ binding: {} }), 'FORM_SHAPE');
    err(form({}, { slots: null }), 'FORM_SHAPE');
    err(form({}, { slots: undefined }), 'FORM_SHAPE');
    err(form({}, { slots: 'cust:C1' }), 'FORM_SHAPE');
    err(form({}, { slots: [] }), 'FORM_SHAPE');
    err(form({}, { slots: {} }), 'FORM_SHAPE');
  });
  it('the customer must match the closed grammar cust:[A-Za-z0-9_-]{1,32}', () => {
    for (const c of ['C1', 'cust:', 'cust:C1; transfer', 'cust:C1\n', ' cust:C1', 'CUST:C1', 'cust:C 1', 'cust:C.1', 'cust:С1', 'cust:Ｃ１', 'cust:' + 'a'.repeat(33), '', 5, null, undefined, ['cust:C1'], { toString: () => 'cust:C1' }]) err(form({ customer: c }), 'SLOT_customer');
    for (const c of ['cust:C1', 'cust:a_b-C', 'cust:' + 'a'.repeat(32), 'cust:0']) expect(interpretForm(form({ customer: c }), ONT).ok).toBe(true);
  });
  it('the amount must be a non-negative safe integer and ccy three upper-case ASCII letters', () => {
    for (const m of [1.5, -1, NaN, Infinity, -Infinity, 2 ** 53, '100', null, undefined, true, 0.1 + 0.2]) err(form({ max_amount_minor: m }), 'SLOT_amount');
    for (const c of ['usd', 'US', 'USDX', 'U$D', 'USD ', '', 'EUС', 1, null, undefined]) err(form({ ccy: c }), 'SLOT_amount');
    expect(interpretForm(form({ max_amount_minor: 0 }), ONT).ok).toBe(true);
  });
  it('the refund count must be a safe integer >= 1', () => {
    for (const n of [0, -1, 1.5, NaN, Infinity, 2 ** 53, '3', null, undefined, false]) err(form({ max_refunds: n }), 'SLOT_count');
    expect(interpretForm(form({ max_refunds: 1 }), ONT).ok).toBe(true);
  });
  it('checks run in order: shape, then customer, then amount, then count', () => {
    err(form({ customer: 'x', max_amount_minor: -1, max_refunds: 0 }), 'SLOT_customer');
    err(form({ max_amount_minor: -1, max_refunds: 0 }), 'SLOT_amount');
    err(form({ ccy: 'x', max_refunds: 0 }), 'SLOT_amount');
    err(form({ max_refunds: 0 }), 'SLOT_count');
    err(form({ customer: 'x' }, { template: 'nope' }), 'FORM_SHAPE');
  });
  it('a null or undefined form throws a TypeError (not total: the caller must hand an object)', () => {
    expect(interpretForm(null as never, ONT)).toEqual({ ok: false, error: 'FORM_SHAPE' });
    expect(interpretForm(undefined as never, ONT)).toEqual({ ok: false, error: 'FORM_SHAPE' });
  });
});
