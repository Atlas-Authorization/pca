import { describe, expect, it } from 'vitest';
import {
  LEDGER_CHECKS,
  amnesiaLedgerStoreAdapter,
  checkpointRegressLedgerStoreAdapter,
  durableLedgerStoreAdapter,
  formatLedgerReport,
  lostUpdateLedgerStoreAdapter,
  memoryLedgerStoreAdapter,
  noCasLedgerStoreAdapter,
  noReplayLedgerStoreAdapter,
  partialBatchLedgerStoreAdapter,
  runLedgerStoreConformance,
  type LedgerStoreAdapter,
} from './ledger-conformance';

const failed = async (a: LedgerStoreAdapter): Promise<string[]> => (await runLedgerStoreConformance(a)).checks.filter((c) => c.status === 'fail').map((c) => c.name);

describe('ledger store conformance: the reference stores pass every check', () => {
  it('in-memory kv: all pass, the two durability checks are reported as skipped', async () => {
    const r = await runLedgerStoreConformance(memoryLedgerStoreAdapter());
    expect(r.status).toBe('pass');
    expect(r.checks.filter((c) => c.status === 'skip').map((c) => c.name)).toEqual(['state-survives-reopen', 'acknowledged-writes-survive-a-crash']);
    expect(r.checks.filter((c) => c.status === 'pass')).toHaveLength(LEDGER_CHECKS.length - 2);
  });
  it('durable-state files: every check passes, durability and crash included', async () => {
    const r = await runLedgerStoreConformance(durableLedgerStoreAdapter());
    expect(r.checks.filter((c) => c.status !== 'pass')).toEqual([]);
  }, 120_000);
});

describe('ledger store conformance: positive controls', () => {
  it('a store without compare-and-swap is caught', async () => {
    expect(await failed(noCasLedgerStoreAdapter())).toEqual(expect.arrayContaining(['append-at-another-position-conflicts-without-trace', 'racing-appends-at-one-position-have-one-winner']));
  });
  it('a store that leaves part of a conflicting batch behind is caught', async () => {
    expect(await failed(partialBatchLedgerStoreAdapter())).toEqual(expect.arrayContaining(['a-batch-is-all-or-nothing']));
  });
  it('a read-await-write store is caught by the racing checks', async () => {
    expect(await failed(lostUpdateLedgerStoreAdapter())).toEqual(expect.arrayContaining(['racing-appends-at-one-position-have-one-winner', 'racing-writers-with-retry-fill-every-position-once']));
  });
  it('a store that forgets on reopen is caught', async () => {
    expect(await failed(amnesiaLedgerStoreAdapter())).toEqual(expect.arrayContaining(['state-survives-reopen', 'acknowledged-writes-survive-a-crash']));
  });
  it('a checkpoint that goes backwards is caught', async () => {
    expect(await failed(checkpointRegressLedgerStoreAdapter())).toEqual(expect.arrayContaining(['checkpoints-stay-inside-the-log-and-never-go-back']));
  });
  it('a store that conflicts on a retried batch is caught', async () => {
    expect(await failed(noReplayLedgerStoreAdapter())).toEqual(expect.arrayContaining(['append-retry-is-a-replay']));
  });
  it('the report names the first line of each failure', async () => {
    const text = formatLedgerReport(await runLedgerStoreConformance(noReplayLedgerStoreAdapter()));
    expect(text.split('\n')[0]).toBe('pca-store-conformance (ledger store): BAD no idempotence (a retried batch conflicts) -> FAIL');
    expect(text).toContain('[FAIL] append-retry-is-a-replay');
  });
});
