import { describe, expect, it } from 'vitest';
import {
  BondLedger,
  InMemoryBondAccount,
  InsuranceCapitalPool,
  SETTLEMENT_LEAF_DOMAIN,
  type BondCurve,
  type SettlementRecord,
  appendSettlement,
  bondAmount,
  DEFAULT_BOND_POLICY,
  settlementCommit,
  settlementRecordDigest,
  verifySettlement,
  verifySettlementCommit,
} from './bond-settlement';
import {
  TransparencyLedger,
  signTreeHead,
  verifyTreeHead,
  verifyHeadConsistency,
} from './ledger';
import { encodeKey, generateKeyPair } from './keys';
import type { Reputation } from './reputation';

const G = generateKeyPair();
const Gpub = encodeKey(G.publicKey);
const funded = () => new InMemoryBondAccount({ alice: 1_000_000 });
const mkLedger = (epoch?: number) => new BondLedger({ guardianSecret: G.secretKey, accounts: funded(), guardianEpoch: epoch });

// ---- A3d: guardian_epoch is BOUND INTO the signed record -------------------------------------
describe('A3d: SettlementRecord.guardian_epoch', () => {
  it('stamps and SIGNS the epoch into the body; tampering it breaks verification', () => {
    const rec = mkLedger(42).openBond({ claimId: 'c1', amount: 10, depositor: 'alice', exposure: 5 });
    expect(rec.guardian_epoch).toBe(42);
    expect(verifySettlement(rec, Gpub)).toBe(true);
    const tampered: SettlementRecord = { ...rec, guardian_epoch: 43 };
    expect(verifySettlement(tampered, Gpub)).toBe(false); // epoch is inside the signed body
  });

  it('is absent (byte-identical to pre-epoch) when the ledger has no epoch', () => {
    const rec = mkLedger().openBond({ claimId: 'c1', amount: 10, depositor: 'alice' });
    expect(rec.guardian_epoch).toBeUndefined();
    expect(verifySettlement(rec, Gpub)).toBe(true);
  });

  it('rejects a non-integer / negative epoch at construction', () => {
    expect(() => new BondLedger({ guardianSecret: G.secretKey, guardianEpoch: -1 })).toThrow();
    expect(() => new BondLedger({ guardianSecret: G.secretKey, guardianEpoch: 1.5 })).toThrow();
  });
});

// ---- A3d: settlements are anchored into the transparency ledger (externally auditable) -------
describe('A3d: appendSettlement into the TransparencyLedger', () => {
  it('anchors a record; it is externally verifiable via commit + inclusion + signature', () => {
    const bl = mkLedger(1);
    const rec = bl.openBond({ claimId: 'c1', amount: 10, depositor: 'alice' });
    const tl = new TransparencyLedger('alice');
    const anchor = appendSettlement(tl, rec, { salt: 'fixed-salt' });

    expect(anchor.commit).toBe(settlementCommit('fixed-salt', rec));
    // external audit path: recompute commit, prove inclusion against the (signable) head, verify the money move
    expect(verifySettlementCommit(anchor.commit, anchor.salt, rec)).toBe(true);
    const root = tl.head().root;
    expect(tl.verifyInclusion(root, tl.inclusionProof(anchor.index), anchor.commit)).toBe(true);
    expect(verifySettlement(rec, Gpub)).toBe(true);
  });

  it('TAMPERED settlement is rejected: the commit no longer reproduces', () => {
    const bl = mkLedger(1);
    const rec = bl.openBond({ claimId: 'c1', amount: 10, depositor: 'alice' });
    const tl = new TransparencyLedger('alice');
    const anchor = appendSettlement(tl, rec, { salt: 's' });
    const forged: SettlementRecord = { ...rec, amount: 9999 };
    expect(verifySettlementCommit(anchor.commit, anchor.salt, forged)).toBe(false);
    // and the forged record's own commit is not the one in the log
    expect(settlementCommit('s', forged)).not.toBe(anchor.commit);
    expect(settlementRecordDigest(forged)).not.toBe(settlementRecordDigest(rec));
  });

  it('ROLLBACK that drops an anchored settlement is detectable against a pinned STH', () => {
    const bl = mkLedger(3);
    const r1 = bl.openBond({ claimId: 'a', amount: 10, depositor: 'alice' });
    const r2 = bl.openBond({ claimId: 'b', amount: 10, depositor: 'alice' });
    const tl = new TransparencyLedger('alice');
    appendSettlement(tl, r1, { salt: 's1' });
    const sth1 = signTreeHead(G.secretKey, { instance_id: 'i', principal: 'alice', size: tl.size, root: tl.head().root, prev_root: '', timestamp: 1 });
    appendSettlement(tl, r2, { salt: 's2' });
    const sth2 = signTreeHead(G.secretKey, { instance_id: 'i', principal: 'alice', size: tl.size, root: tl.head().root, prev_root: sth1.root, timestamp: 2 });

    // honest extension verifies (append-only)
    expect(verifyTreeHead(sth2, Gpub)).toBe(true);
    expect(verifyHeadConsistency(sth1, sth2, tl.consistencyProof(1, 2), Gpub)).toBe(true);

    // a rollback log that dropped r2 cannot reproduce the pinned STH2 root → caught
    const rolled = TransparencyLedger.fromEntries([tl.entry(0)], 'alice');
    expect(rolled.head().root).not.toBe(sth2.root);
    expect(rolled.head().root).toBe(sth1.root); // it is stuck at the earlier, smaller head
  });

  it('SETTLEMENT_LEAF_DOMAIN separates the settlement leaf from other commitment domains', () => {
    expect(SETTLEMENT_LEAF_DOMAIN).toBe('atlas-pca/settlement-leaf/v1');
  });
});

// ---- A3c: convex bond curve ------------------------------------------------------------------
describe('A3c: non-linear (convex) bond curve', () => {
  const sweep = [0, 1, 2, 4, 8, 16, 32, 64, 100];

  it('linear is the default and unchanged (max(floor, k·exposure))', () => {
    for (const e of sweep) expect(bondAmount(DEFAULT_BOND_POLICY, e)).toBe(Math.max(1, e));
    // an explicit linear curve equals the default
    expect(bondAmount({ ...DEFAULT_BOND_POLICY, curve: { kind: 'linear' } }, 50)).toBe(50);
  });

  it('power curve (gamma>1) is monotone non-decreasing AND convex', () => {
    const pol = { ...DEFAULT_BOND_POLICY, floor: 0, k: 1, curve: { kind: 'power', gamma: 2 } as BondCurve };
    const ys = sweep.map((e) => bondAmount(pol, e));
    for (let i = 1; i < ys.length; i++) expect(ys[i]!).toBeGreaterThanOrEqual(ys[i - 1]!); // monotone
    // convex: second differences over an evenly-spaced grid are >= 0
    const grid = [0, 1, 2, 3, 4, 5, 6].map((e) => bondAmount(pol, e));
    for (let i = 2; i < grid.length; i++) expect(grid[i]! - 2 * grid[i - 1]! + grid[i - 2]!).toBeGreaterThanOrEqual(-1e-9);
    // disproportionately expensive: doubling exposure more than doubles the bond
    expect(bondAmount(pol, 20)).toBeGreaterThan(2 * bondAmount(pol, 10));
  });

  it('piecewise schedule is convex when marginal rates are non-decreasing; refuses a decreasing one', () => {
    const pol = { ...DEFAULT_BOND_POLICY, floor: 0, k: 1, curve: { kind: 'piecewise', tiers: [{ upTo: 10, marginalK: 1 }, { upTo: 100, marginalK: 3 }] } as BondCurve };
    expect(bondAmount(pol, 5)).toBe(5); // 5·1
    expect(bondAmount(pol, 10)).toBe(10); // 10·1
    expect(bondAmount(pol, 20)).toBe(10 + 10 * 3); // first tier 10, next 10 at marginal 3 = 40
    // beyond the last tier extends the top marginal rate
    expect(bondAmount(pol, 110)).toBe(10 * 1 + 90 * 3 + 10 * 3);
    const grid = [0, 10, 20, 30, 40].map((e) => bondAmount(pol, e));
    for (let i = 2; i < grid.length; i++) expect(grid[i]! - 2 * grid[i - 1]! + grid[i - 2]!).toBeGreaterThanOrEqual(-1e-9);
    const bad = { ...DEFAULT_BOND_POLICY, curve: { kind: 'piecewise', tiers: [{ upTo: 10, marginalK: 5 }, { upTo: 100, marginalK: 1 }] } as BondCurve };
    expect(() => bondAmount(bad, 50)).toThrow(/non-decreasing/);
  });

  it('power curve rejects gamma < 1 (not convex)', () => {
    expect(() => bondAmount({ ...DEFAULT_BOND_POLICY, curve: { kind: 'power', gamma: 0.5 } }, 10)).toThrow();
  });
});

// ---- A3c: insurance capital pool (scarce collateral) -----------------------------------------
describe('A3c: InsuranceCapitalPool', () => {
  const clean: Reputation = { subject: 'good', actions: 1, autos: 1, stepUps: 0, denies: 0, slashes: 0, disputes: 0, score: 1, factors: [] };
  const bad: Reputation = { subject: 'risky', actions: 0, autos: 0, stepUps: 0, denies: 0, slashes: 3, disputes: 3, score: 0.2, factors: [] };

  it('premiums priced via priceCoverage accumulate; accounting conserves', () => {
    const pool = new InsuranceCapitalPool(100);
    const { pricing } = pool.collectPremium(clean, 1000, { baseRate: 0.01 });
    expect(pricing.declined).toBe(false);
    expect(pricing.premium).toBeCloseTo(10, 9); // 0.01 · 1000 · (1 + 4·0) for score 1
    expect(pool.premiumsIn).toBeCloseTo(10, 9);
    expect(pool.balance).toBeCloseTo(110, 9);
    // conservation invariant
    expect(pool.balance).toBeCloseTo(100 + pool.premiumsIn - pool.payoutsOut, 9);
  });

  it('a declined (low-reputation) quote credits nothing', () => {
    const pool = new InsuranceCapitalPool(0);
    const { pricing } = pool.collectPremium(bad, 1000);
    expect(pricing.declined).toBe(true);
    expect(pool.premiumsIn).toBe(0);
    expect(pool.balance).toBe(0);
  });

  it('payouts are capital-constrained: never overdraws (fail closed)', () => {
    const pool = new InsuranceCapitalPool(50);
    pool.collectPremium(clean, 1000, { baseRate: 0.01 }); // +10 → 60
    expect(pool.canCover(60)).toBe(true);
    expect(pool.canCover(61)).toBe(false);
    const st = pool.payClaim(40);
    expect(st.payoutsOut).toBe(40);
    expect(st.balance).toBeCloseTo(20, 9);
    expect(() => pool.payClaim(21)).toThrow(/insufficient pool capital/);
    expect(() => pool.payClaim(0)).toThrow();
    expect(() => pool.payClaim(-5)).toThrow();
    // still conserved after the valid payout
    expect(pool.balance).toBeCloseTo(50 + pool.premiumsIn - pool.payoutsOut, 9);
  });

  it('rejects negative initial capital', () => {
    expect(() => new InsuranceCapitalPool(-1)).toThrow();
  });
});
