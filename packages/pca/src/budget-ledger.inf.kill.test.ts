import { describe, expect, it } from 'vitest';
import { emptyBudgetDoc, reserveInDoc } from './budget-ledger';
import type { AccumulatorDecl } from './intent-acc';

const acc = (over: Partial<AccumulatorDecl> = {}): AccumulatorDecl => ({
  id: 'spend',
  agg: 'sum',
  val: 'action.params.amount',
  sel: { verbs: ['pay'] },
  win: { kind: 'task' },
  key: null,
  domain_max: 200,
  holder: { kind: 'site_local' },
  scope: 'principal',
  ...over,
});
const ev = (amount: number) => ({ id: 'e1', verb: 'pay', resource: 'r', params: { amount }, t: 1000 });
const outcome = (amount: number, over: Partial<AccumulatorDecl> = {}): string => {
  try {
    return reserveInDoc(emptyBudgetDoc(), { event: ev(amount), accumulators: [acc(over)] }).outcome;
  } catch {
    return 'threw';
  }
};

describe('a non-finite spend or cap never reserves (budget ledger)', () => {
  it('a finite spend under a finite cap reserves', () => {
    expect(outcome(10)).toBe('reserved');
  });
  // old `post > cap` is false for NaN on either side and for a -Infinity post, so each of these reserved
  it('a NaN cap never reserves', () => {
    expect(outcome(10, { domain_max: Number.NaN })).not.toBe('reserved');
  });
  it('a non-finite amount never reserves', () => {
    for (const a of [Number.NaN, Number.NEGATIVE_INFINITY, Number.POSITIVE_INFINITY]) expect(outcome(a)).not.toBe('reserved');
  });
});
