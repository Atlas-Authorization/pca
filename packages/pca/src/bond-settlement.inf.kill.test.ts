import { describe, expect, it } from 'vitest';
import { applyBondMoves } from './bond-settlement';
import { BondLedger, InMemoryBondAccount } from './bond-ledger-testing';
import { generateKeyPair } from './keys';

const G = generateKeyPair();
const ledger = (bondPolicy: { floor: number; k: number; maxOpenClaims: number; maxOpenAmount: number }, balance = 1_000) =>
  new BondLedger({ guardianSecret: G.secretKey, accounts: new InMemoryBondAccount({ alice: balance }), bondPolicy });
const open = (l: BondLedger) => l.openBond({ claimId: 'c1', amount: 10, depositor: 'alice', exposure: 5 });
const ok = { floor: 0, k: 0, maxOpenClaims: 10, maxOpenAmount: Number.POSITIVE_INFINITY };

describe('a non-finite bond cap, requirement or balance never admits (bond settlement)', () => {
  it('a finite policy opens a bond', () => {
    expect(open(ledger(ok)).action).toBe('open');
  });
  // old `count + 1 > NaN` and `sum + amount > NaN` were false, so a NaN cap admitted
  it('a NaN open-claim cap or open-amount cap refuses', () => {
    expect(() => open(ledger({ ...ok, maxOpenClaims: Number.NaN }))).toThrow(/cap/);
    expect(() => open(ledger({ ...ok, maxOpenAmount: Number.NaN }))).toThrow(/cap/);
  });
  // old `amount < NaN` was false, so a NaN requirement (NaN floor) admitted any bond
  it('a NaN required bond refuses', () => {
    expect(() => open(ledger({ ...ok, floor: Number.NaN }))).toThrow(/below the required bond/);
  });
  // old `balance < amount` was false for NaN and true-negated for +Infinity
  it('a non-finite depositor balance refuses', () => {
    for (const b of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) expect(() => open(ledger(ok, b))).toThrow(/insufficient balance/);
  });
  it('applying moves over a non-finite balance throws', () => {
    for (const b of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(() => applyBondMoves(() => b, [{ account: 'a', op: 'debit', amount: 1 }])).toThrow();
      expect(() => applyBondMoves(() => b, [{ account: 'a', op: 'credit', amount: 1 }])).toThrow(/not finite/);
    }
  });
});
