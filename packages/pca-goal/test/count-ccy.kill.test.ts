import { describe, expect, it } from 'vitest';
import { ALL_ONTOLOGIES, extractCandidates } from '../src';

// A number written after a currency code is money, never also a count (else a count slot could be filled from an amount).
const o = ALL_ONTOLOGIES.payments!;
const usd9 = (before: string) => [{ ccy: 'USD', minor: 900, before }];

describe('a currency-coded amount is not a count', () => {
  it('upper-case code', () => {
    const c = extractCandidates('pay USD 9', o);
    expect(c.amounts).toEqual(usd9('pay '));
    expect(c.counts).toEqual([]);
  });
  it('lower-case code', () => {
    const c = extractCandidates('pay usd 9', o);
    expect(c.amounts).toEqual(usd9('pay '));
    expect(c.counts).toEqual([]);
  });
  it('a symbol still excludes the number, as before', () => {
    expect(extractCandidates('pay $ 9', o).counts).toEqual([]);
  });
  it('a code inside a longer word is neither money nor excluded from counts', () => {
    const c = extractCandidates('xUSD 9 times', o);
    expect(c.amounts).toEqual([]);
    expect(c.counts.map((x) => x.n)).toEqual([9]);
  });
  it('a real count next to a coded amount stays a count, and only it', () => {
    const c = extractCandidates('3 transfers of USD 9', o);
    expect(c.amounts).toEqual(usd9('3 transfers of '));
    expect(c.counts.map((x) => x.n)).toEqual([3]);
  });
});
