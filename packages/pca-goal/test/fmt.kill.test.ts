import { describe, expect, it } from 'vitest';
import type { Act, Value } from '../src/ir';
import { fmtAct, fmtMoney, fmtQuantity, fmtValue } from '../src/fmt';

describe('fmtMoney', () => {
  it('places the decimal point by the currency exponent and zero-pads short amounts', () => {
    expect(fmtMoney('USD', 12345)).toBe('USD 123.45');
    expect(fmtMoney('USD', 5)).toBe('USD 0.05');
    expect(fmtMoney('USD', 50)).toBe('USD 0.50');
    expect(fmtMoney('JPY', 500)).toBe('JPY 500');
  });
  it('shows an unknown currency in raw minor units', () => {
    expect(fmtMoney('XXX', 7)).toBe('XXX 7 (minor units)');
  });
});

describe('fmtQuantity', () => {
  it('prints every unit', () => {
    expect(fmtQuantity({ u: { k: 'money', ccy: 'EUR' }, n: 250 })).toBe('EUR 2.50');
    expect(fmtQuantity({ u: { k: 'count' }, n: 3 })).toBe('3');
    expect(fmtQuantity({ u: { k: 'duration' }, n: 4 })).toBe('4ms');
    expect(fmtQuantity({ u: { k: 'instant' }, n: 5 })).toBe('@5');
    expect(fmtQuantity({ u: { k: 'bytes' }, n: 6 })).toBe('6B');
    expect(fmtQuantity({ u: { k: 'ratio' }, n: 7 })).toBe('7ppm');
  });
});

describe('fmtValue and fmtAct', () => {
  const c = (x: number): Value => ({ k: 'q', q: { u: { k: 'count' }, n: x } });
  it('prints quantities, strings and sets', () => {
    expect(fmtValue(c(1))).toBe('1');
    expect(fmtValue({ k: 's', s: 'a"b' })).toBe('"a\\"b"');
    expect(fmtValue({ k: 'set', items: [c(1), { k: 's', s: 'x' }] })).toBe('{1, "x"}');
  });
  it('prints an act with its parameters in sorted order, or bare without parameters', () => {
    const act = (params: Record<string, Value>): Act => ({ verb: 'v', res: 'r', params, t: 0, sess: 's', prin: 'p', org: 'o', agent: 'a', depth: 0 });
    expect(fmtAct(act({ b: { k: 's', s: 'x' }, a: c(1) }))).toBe('v on r (a=1, b="x")');
    expect(fmtAct(act({}))).toBe('v on r');
  });
});
