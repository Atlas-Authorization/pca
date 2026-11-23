/** DoD-8 / B17: the shipped optimistic extension has no in-memory bond ledger; the doubles live behind the testing subpath. */
import { describe, expect, it } from 'vitest';
import * as optimistic from './ext/optimistic';
import * as testing from './ext/optimistic-testing';

describe('B17: no in-memory default in ext/optimistic', () => {
  it('the production entry exports the durable ledger and not the Map-backed doubles', () => {
    expect(typeof optimistic.StoreBondLedger).toBe('function');
    expect(typeof optimistic.KvBondStore).toBe('function');
    expect('BondLedger' in optimistic).toBe(false);
    expect('InMemoryBondAccount' in optimistic).toBe(false);
  });
  it('the doubles are reachable only from the testing entry', () => {
    expect(typeof testing.BondLedger).toBe('function');
    expect(typeof testing.InMemoryBondAccount).toBe('function');
  });
  it('StoreBondLedger refuses to run without a store', () => {
    expect(() => new optimistic.StoreBondLedger({ guardianSecret: new Uint8Array(32).fill(1) } as never)).toThrow('store_missing');
  });
});
