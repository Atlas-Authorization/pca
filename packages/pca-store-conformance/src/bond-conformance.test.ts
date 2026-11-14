import { describe, expect, it } from 'vitest';
import {
  BOND_CHECKS,
  amnesiaBondStoreAdapter,
  clockRewindBondStoreAdapter,
  durableBondStoreAdapter,
  formatBondReport,
  lostUpdateBondStoreAdapter,
  memoryBondStoreAdapter,
  noReplayBondStoreAdapter,
  nonAtomicBondStoreAdapter,
  runBondStoreConformance,
  type BondStoreAdapter,
} from './bond-conformance';

const failed = async (a: BondStoreAdapter): Promise<string[]> => (await runBondStoreConformance(a)).checks.filter((c) => c.status === 'fail').map((c) => c.name);

describe('bond store conformance: the reference stores pass every check', () => {
  it('in-memory kv: all checks pass, the two durability checks are reported as skipped', async () => {
    const r = await runBondStoreConformance(memoryBondStoreAdapter());
    expect(r.status).toBe('pass');
    expect(r.checks.filter((c) => c.status === 'skip').map((c) => c.name)).toEqual(['state-survives-reopen', 'acknowledged-commits-survive-a-crash']);
    expect(r.checks.filter((c) => c.status === 'pass')).toHaveLength(BOND_CHECKS.length - 2);
  });
  it('durable-state files: every check passes, durability and crash included', async () => {
    const r = await runBondStoreConformance(durableBondStoreAdapter());
    expect(r.checks.filter((c) => c.status !== 'pass')).toEqual([]);
    expect(r.status).toBe('pass');
  }, 120_000);
});

describe('bond store conformance: positive controls (a suite that passes everything is worthless)', () => {
  it('a store whose moves land before the phase check is caught', async () => {
    expect(await failed(nonAtomicBondStoreAdapter())).toEqual(expect.arrayContaining(['settle-needs-the-expected-phase', 'racing-identical-settles-commit-once']));
  });
  it('a store that conflicts on a retry is caught', async () => {
    expect(await failed(noReplayBondStoreAdapter())).toEqual(expect.arrayContaining(['open-retry-is-replayed-and-different-terms-conflict', 'settle-retry-returns-the-stored-record', 'racing-identical-settles-commit-once']));
  });
  it('a read-await-write store is caught by the racing checks', async () => {
    expect(await failed(lostUpdateBondStoreAdapter())).toEqual(expect.arrayContaining(['racing-identical-settles-commit-once', 'concurrent-deposits-lose-nothing', 'racing-opens-cannot-overdraw']));
  });
  it('a store that claims durability but forgets on reopen is caught', async () => {
    expect(await failed(amnesiaBondStoreAdapter())).toEqual(expect.arrayContaining(['state-survives-reopen', 'acknowledged-commits-survive-a-crash']));
  });
  it('a high-water mark that follows the last call is caught', async () => {
    expect(await failed(clockRewindBondStoreAdapter())).toEqual(['time-high-water-only-moves-forward']);
  });
  it('the report names the first line of each failure', async () => {
    const text = formatBondReport(await runBondStoreConformance(clockRewindBondStoreAdapter()));
    expect(text.split('\n')[0]).toBe('pca-store-conformance (bond store): BAD clock rewind (high-water mark follows the last call) -> FAIL');
    expect(text).toContain('[FAIL] time-high-water-only-moves-forward');
  });
});
