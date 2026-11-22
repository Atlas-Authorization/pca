import { describe, expect, it } from 'vitest';
import {
  LEASE_CHECKS,
  amnesiaLeaseStoreAdapter,
  durableLeaseStoreAdapter,
  epochRegressLeaseStoreAdapter,
  formatLeaseReport,
  lostUpdateLeaseStoreAdapter,
  memoryLeaseStoreAdapter,
  noCasLeaseStoreAdapter,
  runLeaseStoreConformance,
  type LeaseStoreAdapter,
} from './lease-conformance';

const failed = async (a: LeaseStoreAdapter): Promise<string[]> => (await runLeaseStoreConformance(a)).checks.filter((c) => c.status === 'fail').map((c) => c.name);

describe('lease store conformance: the reference stores pass every check', () => {
  it('in-memory kv: all pass, the two durability checks are skipped', async () => {
    const r = await runLeaseStoreConformance(memoryLeaseStoreAdapter());
    expect(r.status).toBe('pass');
    expect(r.checks.filter((c) => c.status === 'skip').map((c) => c.name)).toEqual(['state-survives-reopen', 'acknowledged-lease-survives-a-crash']);
    expect(r.checks.filter((c) => c.status === 'pass')).toHaveLength(LEASE_CHECKS.length - 2);
  });
  it('durable-state files: every check passes', async () => {
    expect((await runLeaseStoreConformance(durableLeaseStoreAdapter())).checks.filter((c) => c.status !== 'pass')).toEqual([]);
  }, 120_000);
});

describe('lease store conformance: positive controls', () => {
  it('no compare-and-swap is caught', async () => {
    expect(await failed(noCasLeaseStoreAdapter())).toEqual(expect.arrayContaining(['wrong-expected-record-never-writes', 'racing-acquirers-have-one-winner']));
  });
  it('an epoch that can go down is caught', async () => {
    expect(await failed(epochRegressLeaseStoreAdapter())).toEqual(['epoch-never-goes-down']);
  });
  it('a read-await-write store is caught by the race', async () => {
    expect(await failed(lostUpdateLeaseStoreAdapter())).toEqual(expect.arrayContaining(['racing-acquirers-have-one-winner']));
  });
  it('a store that forgets on reopen is caught', async () => {
    expect(await failed(amnesiaLeaseStoreAdapter())).toEqual(expect.arrayContaining(['state-survives-reopen', 'acknowledged-lease-survives-a-crash']));
  });
  it('the report names the first line of each failure', async () => {
    const text = formatLeaseReport(await runLeaseStoreConformance(epochRegressLeaseStoreAdapter()));
    expect(text.split('\n')[0]).toBe('pca-store-conformance (lease store): BAD epoch regression (accepts a lower fencing epoch) -> FAIL');
  });
});
