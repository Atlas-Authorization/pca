import { describe, expect, it } from 'vitest';
import { collectObligations, mergeObligations, obligationError, obligationOutcome, pepObligationGate, type Obligation } from './obligations';

const hostile = () => new Proxy([], { get() { throw new Error('boom'); } });
const wm = (i: number): Obligation => ({ kind: 'watermark', params: { id: `w${i}` } });
const FAIL_CLOSED = 'evaluation error (fail closed)';
const sentinel = ['Stry', 'ker was here'].join('');

describe('obligation validation edges', () => {
  it('refuses a non-object obligation, including undefined', () => {
    expect(obligationError(undefined)).toBe('an obligation must be an object');
    expect(obligationError(null)).toBe('an obligation must be an object');
    expect(obligationError('log')).toBe('an obligation must be an object');
    expect(obligationError(() => 1)).toBe('an obligation must be an object');
  });
  it('require_receipt takes no parameters at all', () => {
    expect(obligationError({ kind: 'require_receipt', params: { [sentinel]: 1 } })).toBe(`unknown parameter '${sentinel}' for 'require_receipt'`);
    expect(obligationError({ kind: 'require_receipt', params: {} })).toBeNull();
  });
  it('redact.fields: every entry must be a dotted path string', () => {
    const msg = 'redact.fields must be 1..32 dotted field paths';
    expect(obligationError({ kind: 'redact', params: { fields: ['a', '1bad'] } })).toBe(msg);
    expect(obligationError({ kind: 'redact', params: { fields: ['1bad', 'a'] } })).toBe(msg);
    expect(obligationError({ kind: 'redact', params: { fields: [['a']] } })).toBe(msg);
    expect(obligationError({ kind: 'redact', params: { fields: ['a', 'b.c'] } })).toBeNull();
  });
  it('log.sink is checked only when present; other kinds cannot carry one', () => {
    expect(obligationError({ kind: 'log', params: { sink: '' } })).toBe('log.sink must be a non-empty string of at most 128 characters');
    expect(obligationError({ kind: 'log', params: {} })).toBeNull();
    expect(obligationError({ kind: 'notify', params: { to: 'x', sink: 's' } })).toBe("unknown parameter 'sink' for 'notify'");
  });
  it('rejects an unknown or non-string kind with the printed value', () => {
    expect(obligationError({ kind: 5 })).toBe("unknown obligation kind '5'");
    expect(obligationError({ kind: 'nope' })).toBe("unknown obligation kind 'nope'");
  });
});

describe('merge and collect', () => {
  it('allows exactly the maximum number of merged obligations and refuses one more', () => {
    const sixteen = Array.from({ length: 16 }, (_, i) => wm(i));
    const r = mergeObligations(sixteen);
    expect(r.ok).toBe(true);
    expect(r.ok && r.obligations).toHaveLength(16);
    expect(mergeObligations(sixteen, [wm(99)])).toEqual({ ok: false, reason: 'more than 16 obligations after merging' });
  });
  it('fails closed with the exact refusal when a list cannot be read', () => {
    expect(mergeObligations(hostile())).toEqual({ ok: false, reason: FAIL_CLOSED });
    expect(collectObligations(hostile(), {})).toEqual({ ok: false, reason: FAIL_CLOSED });
  });
  it('refuses non-array rules with a typed reason, not by throwing', () => {
    expect(collectObligations({}, {})).toEqual({ ok: false, reason: 'obligation rules must be an array' });
    expect(collectObligations('x', {})).toEqual({ ok: false, reason: 'obligation rules must be an array' });
  });
  it('names the duplicated rule id', () => {
    const rule = { id: 'r1', when: { field: 'env.x', op: 'eq' as const, value: 1 }, obligations: [wm(1)] };
    expect(collectObligations([rule, rule], {})).toEqual({ ok: false, reason: "obligation rule id 'r1' is a duplicate" });
  });
});

describe('PEP gate and outcome edges', () => {
  it('fails closed with the exact record when the obligation list cannot be read', () => {
    expect(pepObligationGate('allow', false, hostile(), ['log'])).toEqual({ decision: 'deny', perform: [], unsupported: [], reason: FAIL_CLOSED });
  });
  it('names the validation error of a malformed obligation list', () => {
    expect(pepObligationGate('allow', false, 'x', ['log'])).toEqual({ decision: 'deny', perform: [], unsupported: [], reason: 'malformed obligations: obligations must be an array' });
  });
  it('lists every unsupported kind, comma separated and sorted', () => {
    const r = pepObligationGate('allow', false, [{ kind: 'notify', params: { to: 'x' } }, { kind: 'log' }], []);
    expect(r).toEqual({ decision: 'deny', perform: [], unsupported: ['log', 'notify'], reason: 'the enforcement point does not support obligation(s) log, notify' });
  });
  it('treats an unreadable list as escalate with nothing overdue listed', () => {
    expect(obligationOutcome(hostile(), [], 0)).toEqual({ outcome: 'escalate', overdue: [], status: 'obligation_unmet' });
  });
  it('treats malformed fulfilled indexes as overdue-everything', () => {
    const list: Obligation[] = [{ kind: 'log', due: 100 }];
    const all = { outcome: 'escalate', overdue: [0], status: 'obligation_unmet' };
    expect(obligationOutcome(list, [-1], 0)).toEqual(all);
    expect(obligationOutcome(list, [1.5], 0)).toEqual(all);
    expect(obligationOutcome(list, ['0'], 0)).toEqual(all);
    expect(obligationOutcome(list, [0], 0)).toEqual({ outcome: 'ok', overdue: [] });
    expect(obligationOutcome(list, [], 0)).toEqual({ outcome: 'ok', overdue: [] });
  });
  it('accepts now = 0 as a valid time and reports only the overdue obligations', () => {
    const list: Obligation[] = [{ kind: 'log', due: 0 }, { kind: 'notify', params: { to: 'x' }, due: 100 }, { kind: 'require_receipt' }];
    expect(obligationOutcome(list, [], 0)).toEqual({ outcome: 'escalate', overdue: [0], status: 'obligation_unmet' });
    expect(obligationOutcome(list, [0], 0)).toEqual({ outcome: 'ok', overdue: [] });
    expect(obligationOutcome(list, [], -1)).toEqual({ outcome: 'escalate', overdue: [0, 1, 2], status: 'obligation_unmet' });
  });
});
