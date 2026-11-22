import { describe, expect, it } from 'vitest';
import {
  BUDGET_CHECKS,
  BUDGET_REFERENCE_ADAPTERS,
  amnesiaBudgetLedgerAdapter,
  durableBudgetLedgerAdapter,
  expireCommittedBudgetLedgerAdapter,
  expireStartedBudgetLedgerAdapter,
  formatBudgetReport,
  lateCommitBudgetLedgerAdapter,
  lostUpdateBudgetLedgerAdapter,
  memoryBudgetLedgerAdapter,
  noCapBudgetLedgerAdapter,
  noCasBudgetLedgerAdapter,
  noReplayBudgetLedgerAdapter,
  releaseCommittedBudgetLedgerAdapter,
  releaseUnreservedBudgetLedgerAdapter,
  runBudgetLedgerConformance,
  sharedKeysBudgetLedgerAdapter,
  volatileClaimsDurableBudgetLedgerAdapter,
  type BudgetLedgerAdapter,
} from './budget-conformance';

const failed = async (a: BudgetLedgerAdapter): Promise<string[]> => (await runBudgetLedgerConformance(a)).checks.filter((c) => c.status === 'fail').map((c) => c.name);

describe('budget ledger conformance: the reference ledgers pass every check', () => {
  it('in-memory kv: all pass, the two durability checks are reported as skipped', async () => {
    const r = await runBudgetLedgerConformance(memoryBudgetLedgerAdapter());
    expect(r.status).toBe('pass');
    expect(r.checks.filter((c) => c.status === 'skip').map((c) => c.name)).toEqual(['state-survives-reopen', 'acknowledged-writes-survive-a-crash']);
    expect(r.checks.filter((c) => c.status === 'pass')).toHaveLength(BUDGET_CHECKS.length - 2);
  });
  it('durable-state files: every check passes, durability and crash included', async () => {
    const r = await runBudgetLedgerConformance(durableBudgetLedgerAdapter());
    expect(r.checks.filter((c) => c.status !== 'pass')).toEqual([]);
  }, 120_000);
});

describe('budget ledger conformance: every defective ledger is caught, by the check that names its mistake', () => {
  const cases: [string, () => BudgetLedgerAdapter, string[]][] = [
    ['no cap check', noCapBudgetLedgerAdapter, ['reservation-counts-at-once-and-cap-is-inclusive', 'racing-reserves-never-pass-the-cap']],
    ['no compare-and-swap', noCasBudgetLedgerAdapter, ['expected-version-is-compare-and-swap', 'racing-reserves-at-one-version-have-one-winner']],
    ['lost update', lostUpdateBudgetLedgerAdapter, ['racing-reserves-never-pass-the-cap']],
    ['amnesia', amnesiaBudgetLedgerAdapter, ['state-survives-reopen', 'acknowledged-writes-survive-a-crash']],
    ['release without reserve', releaseUnreservedBudgetLedgerAdapter, ['settle-rules', 'release-without-reserve-credits-nothing']],
    ['release of a committed event', releaseCommittedBudgetLedgerAdapter, ['settle-rules']],
    ['late commit', lateCommitBudgetLedgerAdapter, ['a-late-commit-cannot-overspend', 'settle-rules']],
    ['no idempotence', noReplayBudgetLedgerAdapter, ['reserve-retry-is-a-replay']],
    ['shared keys', sharedKeysBudgetLedgerAdapter, ['keys-are-independent']],
    ['expire committed', expireCommittedBudgetLedgerAdapter, ['expiry-releases-only-open-reservations-past-their-deadline']],
    ['expire started', expireStartedBudgetLedgerAdapter, ['expiry-releases-only-open-reservations-past-their-deadline']],
    ['volatile ledger claiming durability', volatileClaimsDurableBudgetLedgerAdapter, ['durable-claim-matches-the-adapter']],
  ];
  for (const [name, make, expected] of cases) {
    it(name, async () => {
      expect(await failed(make())).toEqual(expect.arrayContaining(expected));
    }, 60_000);
  }
  it('every registered bad adapter fails at least one check, every good one none', async () => {
    for (const [n, make] of Object.entries(BUDGET_REFERENCE_ADAPTERS)) {
      const f = await failed(make());
      if (n.startsWith('bad-')) expect(f.length, n).toBeGreaterThan(0);
      else expect(f, n).toEqual([]);
    }
  }, 120_000);
  it('the report names the first line of each failure', async () => {
    const text = formatBudgetReport(await runBudgetLedgerConformance(noReplayBudgetLedgerAdapter()));
    expect(text.split('\n')[0]).toBe('pca-store-conformance (budget ledger): BAD no idempotence (a retried reservation counts twice) -> FAIL');
    expect(text).toContain('[FAIL] reserve-retry-is-a-replay');
  });
});
