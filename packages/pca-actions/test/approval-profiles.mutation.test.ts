import { describe, expect, it } from 'vitest';
import { merkleRoot, type ApprovalRender } from '@atlasauth/pca';
import { ActionKitError, approvalBatch, minorToDecimal, psd2Linking, renderApproval, type ActionDef } from '../src';
import { TRANSFER } from './vectors-approval';

const err = (f: () => unknown): { code: string; message: string } => {
  try { f(); } catch (e) { return e instanceof ActionKitError ? { code: e.code, message: e.message } : { code: 'other', message: String(e) }; }
  return { code: 'no error', message: '' };
};
const R = (fields: unknown[], unreviewed = false): ApprovalRender => ({ v: 1, kind: 'pca-approval-render', verb: 'a.b.c', def_digest: 'x', unreviewed, fields }) as unknown as ApprovalRender;
const money = (value: unknown, unit: unknown = { kind: 'money', ccy: 'EUR', exp: 2 }) => ({ id: 'amount', class: 'money.amount', value, ...(unit === null ? {} : { unit }) });
const payee = (value: unknown) => ({ id: 'payee', class: 'party.payee', value });
const U = 'psd2_unlinkable';

describe('psd2Linking refusals', () => {
  it('payee must be exactly one non-empty string', () => {
    const m = 'a payment approval needs exactly one non-empty party.payee parameter';
    expect(err(() => psd2Linking(R([money(5)])))).toEqual({ code: U, message: m });
    expect(err(() => psd2Linking(R([money(5), payee('a'), payee('b')])))).toEqual({ code: U, message: m });
    expect(err(() => psd2Linking(R([money(5), payee('')])))).toEqual({ code: U, message: m });
    expect(err(() => psd2Linking(R([money(5), payee(5)])))).toEqual({ code: U, message: m });
  });
  it('unreviewed and amount-count refusals carry their messages', () => {
    expect(err(() => psd2Linking(R([money(5), payee('a')], true)))).toEqual({ code: U, message: 'an unreviewed definition cannot be a payment approval' });
    const m = 'a payment approval needs exactly one money.amount parameter';
    expect(err(() => psd2Linking(R([payee('a')])))).toEqual({ code: U, message: m });
    expect(err(() => psd2Linking(R([money(5), money(6), payee('a')])))).toEqual({ code: U, message: m });
  });
  it('the amount needs a money unit', () => {
    const m = 'the money.amount parameter has no money unit';
    expect(err(() => psd2Linking(R([money(5, null), payee('a')])))).toEqual({ code: U, message: m });
    expect(err(() => psd2Linking(R([money(5, { kind: 'count' }), payee('a')])))).toEqual({ code: U, message: m });
  });
  it('the amount must be a non-negative safe integer; zero is allowed', () => {
    const m = 'the amount must be a non-negative integer in minor units';
    for (const v of ['5', 1.5, -1, -0, 2 ** 53, NaN, null]) expect(err(() => psd2Linking(R([money(v), payee('a')]))), String(v)).toEqual({ code: U, message: m });
    expect(psd2Linking(R([money(0), payee('a')]))).toEqual({ amount_minor: 0, currency: 'EUR', exp: 2, payee: 'a' });
    expect(psd2Linking(R([money(2 ** 53 - 1), payee('a')])).amount_minor).toBe(2 ** 53 - 1);
  });
});

describe('minorToDecimal', () => {
  it('formats at the boundaries', () => {
    expect(minorToDecimal(0, 2)).toBe('0.00');
    expect(minorToDecimal(0, 0)).toBe('0');
    expect(minorToDecimal(1250, 2)).toBe('12.50');
    expect(minorToDecimal(1, 18)).toBe('0.000000000000000001');
  });
  it('refuses bad input with the exact message', () => {
    const m = 'minor units must be a non-negative safe integer';
    for (const [a, b] of [[-1, 2], [1.5, 2], [1, -1], [1, 19], [1, 1.5], [1, NaN], [2 ** 53, 2]] as const) expect(err(() => minorToDecimal(a, b)), `${a},${b}`).toEqual({ code: U, message: m });
  });
});

describe('approvalBatch', () => {
  const withExp = (exp: number): ActionDef => ({ ...TRANSFER, params: { ...TRANSFER.params, amount: { ...TRANSFER.params.amount!, unit: { kind: 'money', ccy: { from: 'currency' }, exp } } } }) as ActionDef;
  const item = (amount: number, currency: string, p: string, def: ActionDef = TRANSFER) => ({ action_digest: `ad-${amount}-${currency}-${p}`, render: renderApproval(def, { amount, currency, payee: p }, { attestationVerified: () => true }) });
  it('an empty batch is refused', () => {
    expect(err(() => approvalBatch([]))).toEqual({ code: U, message: 'a batch needs at least one payment' });
  });
  it('mixed exponents for one currency are refused', () => {
    expect(err(() => approvalBatch([item(1, 'EUR', 'a'), item(1, 'EUR', 'a', withExp(3))]))).toEqual({ code: U, message: 'currency EUR appears with two exponents' });
  });
  it('a total beyond the safe range is refused', () => {
    expect(err(() => approvalBatch([item(2 ** 53 - 1, 'EUR', 'a'), item(1, 'EUR', 'a')]))).toEqual({ code: U, message: 'the batch total exceeds the safe integer range' });
  });
  it('totals are per currency sorted by code; payees are distinct and sorted', () => {
    const { batch } = approvalBatch([item(100, 'USD', 'Zed'), item(200, 'EUR', 'Acme'), item(50, 'CHF', 'Zed'), item(25, 'EUR', 'Acme')]);
    expect(batch.n).toBe(4);
    expect(batch.totals).toEqual([{ ccy: 'CHF', exp: 2, minor: 50 }, { ccy: 'EUR', exp: 2, minor: 225 }, { ccy: 'USD', exp: 2, minor: 100 }]);
    expect(batch.payees_root).toBe(merkleRoot([{ d: 'atlas-pca/approval-payee/v1', payee: 'Acme' }, { d: 'atlas-pca/approval-payee/v1', payee: 'Zed' }]));
  });
});
