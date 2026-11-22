import { describe, expect, it } from 'vitest';
import type { BondPlan, SettlementRecord } from './bond-settlement';
import { commitBondPlan, emptyBondDoc } from './bond-store';

const rec: SettlementRecord = { claimId: 'b', action: 'open', amount: 5, from: 'a', to: 'escrow', at: 1, evidenceDigest: '', sig: 's' };
const plan = (over: Partial<NonNullable<BondPlan['open']>>): BondPlan => ({
  claimId: 'b',
  expect: 'none',
  next: 'open',
  open: { amount: 5, depositor: 'a', maxOpenClaims: 2, maxOpenAmount: 8, ...over },
  moves: [
    { account: 'a', op: 'debit', amount: 5 },
    { account: 'escrow', op: 'credit', amount: 5 },
  ],
  record: rec,
});
const funded = () => {
  const d = emptyBondDoc();
  d.balances.set('a', 100);
  return d;
};

describe('a non-finite open cap never admits (bond store commit)', () => {
  it('a finite cap commits', () => {
    expect(commitBondPlan(funded(), plan({}), 9).outcome).toBe('committed');
  });
  // old `count + 1 > NaN` and `sum + amount > NaN` were false, so a NaN cap committed the open
  it('a NaN open-claim cap or open-amount cap conflicts', () => {
    expect(commitBondPlan(funded(), plan({ maxOpenClaims: Number.NaN }), 9)).toMatchObject({ outcome: 'conflict', reason: 'depositor open-claim cap reached' });
    expect(commitBondPlan(funded(), plan({ maxOpenAmount: Number.NaN }), 9)).toMatchObject({ outcome: 'conflict', reason: 'depositor aggregate open-bond cap exceeded' });
  });
});
