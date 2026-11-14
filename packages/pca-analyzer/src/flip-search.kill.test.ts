import { describe, expect, it } from 'vitest';
import type { Condition, Predicate } from '@atlasauth/pca';
import { minimalFlip, type FlipResult } from './flip';
import { refund, refundShape } from './k2-fixtures';
import type { AnalyzerAction, PolicyInput, VerbShape } from './types';

const c = (field: string, op: string, value?: unknown) => ({ field, op, ...(value !== undefined ? { value } : {}) }) as unknown as Condition;
const P = (verb: string, where?: Condition[], resource?: string): Predicate => ({ verb, ...(resource !== undefined ? { resource } : {}), ...(where ? { where } : {}) }) as Predicate;
const who = { holderAuthenticated: true };
const act = (resource: string, params?: Record<string, unknown>): AnalyzerAction => ({ verb: 'v', resource, ...(params ? { params } : {}) });
const kinds = (r: FlipResult): string[] => r.repairs.map((x) => x.repair.kind);
const ctx = (now: number, recentActionTimes: number[] = []) => ({ now, blastRadius: 0, reversibilityClass: 'reversible', recentActionTimes }) as never;
const waits = (caveats: unknown[], now: number, recent: number[] = []): FlipResult => minimalFlip({ predicates: [P('v')], caveats: caveats as never }, act('/r'), { ...who, caveatContext: ctx(now, recent) });
const WAIT = (at: number) => ({ repair: { kind: 'wait_until', at, reason: 'a time or rate caveat opens then' }, cost: 1, decision: 'allow', action: act('/r') });

describe('minimalFlip splitting: when a split is offered', () => {
  it('a current value that is not a number is never split', () => {
    const r = minimalFlip({ predicates: [P('v', [c('action.params.p', 'gte', 3)])] }, act('/r', { p: 'abc' }), { ...who, allowSplit: true });
    expect(kinds(r)).toEqual(['set_param']);
  });

  it('with no single repair there is nothing to split', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.amount', 'lte', 500), c('action.params.flag', 'eq', 'y')])] };
    const r = minimalFlip(p, act('/r', { amount: 900, flag: 'n' }), { ...who, allowSplit: true, changeable: ['amount'] });
    expect(r.repairs).toEqual([]);
    expect(r.repairExists).toBe(false);
  });

  it('a repair that is not a number is not a split part', () => {
    const r = minimalFlip({ predicates: [P('v', [c('action.params.amount', 'in', ['a'])])] }, act('/r', { amount: 900 }), { ...who, allowSplit: true });
    expect(kinds(r)).toEqual(['set_param']);
  });

  it('a repair to a negative value is not a split part', () => {
    const r = minimalFlip({ predicates: [P('v', [c('action.params.amount', 'lte', -3)])] }, act('/r', { amount: 900 }), { ...who, allowSplit: true });
    expect(kinds(r)).toEqual(['set_param']);
  });

  it('each parameter is split using its own repair', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.s', 'lte', 10)]), P('v', [c('action.params.amount', 'lte', 500)])] };
    const r = minimalFlip(p, act('/r', { s: 50, amount: 900 }), { ...who, allowSplit: true, changeable: ['s', 'amount'] });
    const split = r.repairs.find((x) => x.repair.kind === 'split' && x.repair.param === 'amount');
    expect(split).toEqual({ repair: { kind: 'split', param: 'amount', parts: [{ amount: 500 }, { amount: 400 }] }, cost: 5, decision: 'allow', action: act('/r', { s: 50, amount: 900 }) });
  });

  it('at most eight parts; the last part is the remainder', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.amount', 'lte', 100)])] };
    const eight = minimalFlip(p, act('/r', { amount: 800 }), { ...who, allowSplit: true });
    const s = eight.repairs.find((x) => x.repair.kind === 'split');
    expect(s?.repair).toEqual({ kind: 'split', param: 'amount', parts: Array.from({ length: 8 }, () => ({ amount: 100 })) });
    expect(s?.cost).toBe(11);
    expect(kinds(minimalFlip(p, act('/r', { amount: 900 }), { ...who, allowSplit: true }))).toEqual(['set_param']);
    const three = minimalFlip({ predicates: [refund(500)] }, { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 1200 } }, { ...who, allowSplit: true, schema: [refundShape] });
    expect(three.repairs.find((x) => x.repair.kind === 'split')).toMatchObject({ repair: { parts: [{ amount: 500 }, { amount: 500 }, { amount: 200 }] }, cost: 6 });
  });

  it('every part must itself reach the wanted decision', () => {
    const r = minimalFlip({ predicates: [P('v', [c('action.params.amount', 'in', [100, 500])])] }, act('/r', { amount: 900 }), { ...who, allowSplit: true });
    expect(kinds(r)).toEqual(['set_param']);
  });

  it('a total bound carried by a delegated policy also blocks splitting', () => {
    const p: PolicyInput = { predicates: [refund(500)], meet: [{ predicates: [refund(500)], caveats: [{ type: 'budget_alloc', limit: 1000 }] as never }] };
    const r = minimalFlip(p, { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 900 } }, { ...who, allowSplit: true });
    expect(kinds(r)).toEqual(['set_param']);
  });
});

describe('minimalFlip candidate order and limit', () => {
  it('cheapest repair first, whatever the parameter order', () => {
    const p: PolicyInput = { predicates: [P('v', [c('action.params.a', 'lte', 1)]), P('v', [c('action.params.b', 'lte', 9)])] };
    const r = minimalFlip(p, act('/r', { a: 100, b: 10 }), { ...who, changeable: ['a', 'b'] });
    expect(r.repairs.map((x) => (x.repair as { param: string }).param)).toEqual(['b', 'a']);
  });

  it('at most eight repairs by default, or maxCandidates', () => {
    const p: PolicyInput = { predicates: Array.from({ length: 10 }, (_, i) => P('v', undefined, `/r${i}`)) };
    expect(minimalFlip(p, act('/x'), who).repairs).toHaveLength(8);
    expect(minimalFlip(p, act('/x'), { ...who, maxCandidates: 3 }).repairs).toHaveLength(3);
    expect(minimalFlip(p, act('/x'), { ...who, maxCandidates: 1 }).repairs).toHaveLength(1);
  });
});

describe('minimalFlip redaction', () => {
  const critical: VerbShape = { verb: 'stripe.refund', params: { amount: { type: 'integer', semantic: 'money.amount', sensitivity: 'critical', min: 0, max: 100000 } } };
  const big: AnalyzerAction = { verb: 'stripe.refund', resource: '/acct/1', params: { amount: 900 } };

  it('redact none shows the value of a critical parameter', () => {
    const r = minimalFlip({ predicates: [refund(500)] }, big, { ...who, schema: [critical], redact: 'none' });
    expect(r.redacted).toBeUndefined();
    expect(r.repairs[0]!.repair).toEqual({ kind: 'set_param', param: 'amount', from: 900, to: 500 });
  });

  it('the default hides a critical parameter value and keeps the original action', () => {
    const r = minimalFlip({ predicates: [refund(500)] }, big, { ...who, schema: [critical] });
    expect(r.redacted).toBe(true);
    expect(r.repairs[0]).toMatchObject({ repair: { kind: 'set_param', param: 'amount', redacted: true }, action: big });
    expect(r.repairs[0]!.action).not.toBe(big);
  });

  it('a non-critical parameter is shown', () => {
    const r = minimalFlip({ predicates: [refund(500)] }, big, { ...who, schema: [refundShape] });
    expect(r.redacted).toBeUndefined();
    expect(r.repairs[0]!.repair).toEqual({ kind: 'set_param', param: 'amount', from: 900, to: 500 });
  });

  it('a parameter the schema does not declare is shown', () => {
    const other: VerbShape = { verb: 'stripe.refund', params: { reason: { type: 'string', sensitivity: 'free' } } };
    const r = minimalFlip({ predicates: [refund(500)] }, big, { ...who, schema: [other], changeable: ['amount'] });
    expect(r.redacted).toBeUndefined();
    expect(r.repairs[0]!.repair).toEqual({ kind: 'set_param', param: 'amount', from: 900, to: 500 });
  });

  it('a resource repair is shown untouched', () => {
    const p: PolicyInput = { predicates: [P('v', undefined, '/ok')] };
    const r = minimalFlip(p, act('/no'), { ...who, schema: [{ verb: 'v', params: {} }] });
    expect(r.repairs.map((x) => x.repair)).toEqual([{ kind: 'set_resource', from: '/no', to: '/ok' }]);
    expect(r.redacted).toBeUndefined();
  });
});

describe('minimalFlip named facts only when they help', () => {
  it('a fact that does not reach the wanted decision is not offered', () => {
    const p: PolicyInput = { predicates: [P('v', [c('subject.kyc', 'eq', 'done'), c('action.params.x', 'lte', 5)])] };
    const r = minimalFlip(p, act('/r', { x: 9 }), who);
    expect(kinds(r)).not.toContain('obtain_fact');
  });
});

describe('minimalFlip waiting: which caveats set the time', () => {
  it('only a not_before still in the future sets the wait; expires does not', () => {
    expect(waits([{ type: 'expires', at: 10000 }, { type: 'not_before', at: 3000 }], 1000).repairs).toEqual([WAIT(3000)]);
  });

  it('a not_before already open gives no earlier time to wait for', () => {
    const r = waits([{ type: 'expires', at: 800 }, { type: 'not_before', at: 500 }], 1000);
    expect(r.repairs).toEqual([]);
    expect(r.repairExists).toBe(false);
  });

  it('only a rate caveat is read as a rate', () => {
    expect(waits([{ type: 'max_blast_radius', max: 1, per_secs: 10 }, { type: 'not_before', at: 5000 }], 1000, [999]).repairs).toEqual([WAIT(5000)]);
  });

  it('actions outside the rate window do not count', () => {
    const r = waits([{ type: 'expires', at: 5000 }, { type: 'rate', max: 2, per_secs: 1 }], 10000, [100, 200, 300]);
    expect(r.repairs).toEqual([]);
  });

  it('a rate that is not full adds no time', () => {
    expect(waits([{ type: 'not_before', at: 5000 }, { type: 'rate', max: 5, per_secs: 10 }], 1000, []).repairs).toEqual([WAIT(5000)]);
  });

  it('the rate window reopens after the oldest relevant action, in time order', () => {
    expect(waits([{ type: 'rate', max: 1, per_secs: 1 }], 10000, [9700, 9500]).repairs).toEqual([WAIT(10700)]);
  });
});
