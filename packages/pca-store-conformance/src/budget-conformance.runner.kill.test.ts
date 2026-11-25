import { describe, expect, it } from 'vitest';
import { createMemoryDurableKv } from '@atlasauth/pca/durable-state';
import { KvBudgetLedger, type BudgetLedger } from '@atlasauth/pca/ext/intent';
import {
  BUDGET_CHECKS,
  describeBudgetLedgerConformance,
  formatBudgetReport,
  memoryBudgetLedgerAdapter,
  runBudgetLedgerConformance,
  volatileClaimsDurableBudgetLedgerAdapter,
  type BudgetConformanceReport,
  type BudgetLedgerAdapter,
} from './budget-conformance';

/** A durable-declaring adapter with no crash(), counting creates and closes. */
const counting = (withCrash = false) => {
  const n = { created: 0, closed: 0 };
  const a: BudgetLedgerAdapter = {
    name: 'counting',
    durable: true,
    async create() {
      n.created++;
      const kv = createMemoryDurableKv();
      const open = async (): Promise<BudgetLedger> => new KvBudgetLedger(kv, true);
      return { ledger: await open(), reopen: open, ...(withCrash ? { crash: open } : {}), close: async () => void n.closed++ };
    },
  };
  return { a, n };
};

describe('runBudgetLedgerConformance', () => {
  it('runs exactly the checks named by only', async () => {
    const r = await runBudgetLedgerConformance(memoryBudgetLedgerAdapter(), { only: ['empty-key-is-empty', 'settle-rules'] });
    expect(r).toEqual({
      adapter: 'KvBudgetLedger over an in-memory kv',
      status: 'pass',
      checks: [
        { name: 'empty-key-is-empty', status: 'pass' },
        { name: 'settle-rules', status: 'pass' },
      ],
    });
  });
  it('an empty only list runs nothing', async () => {
    expect((await runBudgetLedgerConformance(memoryBudgetLedgerAdapter(), { only: [] })).checks).toEqual([]);
  });
  it('without only, every check is reported in order', async () => {
    const r = await runBudgetLedgerConformance(memoryBudgetLedgerAdapter());
    expect(r.checks.map((c) => c.name)).toEqual(BUDGET_CHECKS.map((c) => c.name));
  });
  it('skips the durable checks of a volatile adapter without creating anything for them', async () => {
    const created: number[] = [];
    const base = memoryBudgetLedgerAdapter();
    const r = await runBudgetLedgerConformance({ ...base, async create() { created.push(1); return base.create(); } });
    expect(r.checks.filter((c) => c.status === 'skip')).toEqual([
      { name: 'state-survives-reopen', status: 'skip', detail: 'the adapter declares durable: false' },
      // the crash check is gated on crash(), not on durability: a handle is created for it and then closed
      { name: 'acknowledged-writes-survive-a-crash', status: 'skip', detail: 'the adapter has no crash()' },
    ]);
    expect(created).toHaveLength(BUDGET_CHECKS.length - 1);
  });
  it('skips the crash check of an adapter with no crash(), and still closes the handle', async () => {
    const { a, n } = counting(false);
    const r = await runBudgetLedgerConformance(a);
    expect(r.checks.filter((c) => c.status === 'skip')).toEqual([{ name: 'acknowledged-writes-survive-a-crash', status: 'skip', detail: 'the adapter has no crash()' }]);
    expect(r.checks.filter((c) => c.status === 'fail')).toEqual([]);
    expect(n.created).toBe(BUDGET_CHECKS.length);
    expect(n.closed).toBe(BUDGET_CHECKS.length);
  });
  it('closes the handle after a passing check too, and runs the crash check when crash() exists', async () => {
    const { a, n } = counting(true);
    const r = await runBudgetLedgerConformance(a);
    expect(r.checks.filter((c) => c.status !== 'pass')).toEqual([]);
    expect(n.closed).toBe(n.created);
    expect(n.closed).toBe(BUDGET_CHECKS.length);
  });
  it('reports a failing check with its message and an overall fail', async () => {
    const r = await runBudgetLedgerConformance(volatileClaimsDurableBudgetLedgerAdapter(), { only: ['durable-claim-matches-the-adapter', 'empty-key-is-empty'] });
    expect(r.status).toBe('fail');
    expect(r.checks.map((c) => [c.name, c.status])).toEqual([['empty-key-is-empty', 'pass'], ['durable-claim-matches-the-adapter', 'fail']]);
    expect(r.checks[0]).not.toHaveProperty('detail');
    // node:assert may append a diff after the message; the message itself is the first line
    expect(r.checks[1]!.detail?.split('\n')[0]).toBe('ledger.durable=true but the adapter declares durable=false');
  });
});

describe('formatBudgetReport', () => {
  it('renders the header, every status, and only the first line of a detail', () => {
    const r: BudgetConformanceReport = {
      adapter: 'x',
      status: 'fail',
      checks: [
        { name: 'one', status: 'pass' },
        { name: 'two', status: 'fail', detail: 'first line\nsecond line' },
        { name: 'three', status: 'skip', detail: 'because' },
      ],
    };
    expect(formatBudgetReport(r)).toBe('pca-store-conformance (budget ledger): x -> FAIL\n  [PASS] one\n  [FAIL] two: first line\n  [SKIP] three: because');
    expect(formatBudgetReport({ adapter: 'y', status: 'pass', checks: [] })).toBe('pca-store-conformance (budget ledger): y -> PASS');
  });
});

type Runner = NonNullable<NonNullable<Parameters<typeof describeBudgetLedgerConformance>[1]>['runner']>;
const recorder = () => {
  const describes: string[] = [];
  const its: { name: string; fn: () => Promise<void>; timeout: number | undefined }[] = [];
  const runner: Runner = {
    describe: (name, fn) => {
      describes.push(name);
      fn();
    },
    it: (name, fn, timeout) => {
      its.push({ name, fn, timeout });
    },
  };
  return { describes, its, runner };
};
const withGlobals = async (d: unknown, i: unknown, fn: () => void | Promise<void>): Promise<void> => {
  const g = globalThis as Record<string, unknown>;
  const had = { describe: 'describe' in g, it: 'it' in g };
  const old = { describe: g.describe, it: g.it };
  g.describe = d;
  g.it = i;
  try {
    await fn();
  } finally {
    if (had.describe) g.describe = old.describe;
    else delete g.describe;
    if (had.it) g.it = old.it;
    else delete g.it;
  }
};

describe('describeBudgetLedgerConformance', () => {
  it('registers one named test per check, with the default and a custom timeout', () => {
    const a = recorder();
    describeBudgetLedgerConformance(memoryBudgetLedgerAdapter(), { runner: a.runner });
    expect(a.describes).toEqual(['PCA budget ledger conformance: KvBudgetLedger over an in-memory kv']);
    expect(a.its.map((x) => x.name)).toEqual(BUDGET_CHECKS.map((c) => `${c.name}: ${c.claim}`));
    expect(new Set(a.its.map((x) => x.timeout))).toEqual(new Set([60000]));
    const b = recorder();
    describeBudgetLedgerConformance(memoryBudgetLedgerAdapter(), { runner: b.runner, timeoutMs: 123 });
    expect(new Set(b.its.map((x) => x.timeout))).toEqual(new Set([123]));
    expect(b.its).toHaveLength(BUDGET_CHECKS.length);
  });
  it('accepts an adapter factory, calling it once to name the suite and once per test run', async () => {
    let calls = 0;
    const a = recorder();
    describeBudgetLedgerConformance(() => {
      calls++;
      return memoryBudgetLedgerAdapter();
    }, { runner: a.runner });
    expect(calls).toBe(1);
    expect(a.describes).toEqual(['PCA budget ledger conformance: KvBudgetLedger over an in-memory kv']);
    await a.its[0]!.fn();
    expect(calls).toBe(2);
  });
  it('a registered test runs only its own check and passes for a passing or skipped one', async () => {
    const a = recorder();
    let created = 0;
    const base = memoryBudgetLedgerAdapter();
    describeBudgetLedgerConformance({ ...base, async create() { created++; return base.create(); } }, { runner: a.runner });
    const byName = (n: string) => a.its.find((x) => x.name.startsWith(`${n}: `))!;
    await expect(byName('empty-key-is-empty').fn()).resolves.toBeUndefined();
    expect(created).toBe(1);
    await expect(byName('state-survives-reopen').fn()).resolves.toBeUndefined();
    expect(created).toBe(1);
  });
  it('a registered test throws the failure detail', async () => {
    const a = recorder();
    describeBudgetLedgerConformance(volatileClaimsDurableBudgetLedgerAdapter(), { runner: a.runner });
    const t = a.its.find((x) => x.name.startsWith('durable-claim-matches-the-adapter: '))!;
    await expect(t.fn()).rejects.toThrow(/^ledger\.durable=true but the adapter declares durable=false(\n|$)/);
    await expect(a.its.find((x) => x.name.startsWith('empty-key-is-empty: '))!.fn()).resolves.toBeUndefined();
  });
  it('uses the global describe and it when no runner is given', async () => {
    const a = recorder();
    await withGlobals(a.runner.describe, a.runner.it, () => describeBudgetLedgerConformance(memoryBudgetLedgerAdapter()));
    expect(a.describes).toEqual(['PCA budget ledger conformance: KvBudgetLedger over an in-memory kv']);
    expect(a.its).toHaveLength(BUDGET_CHECKS.length);
    expect(a.its[0]!.timeout).toBe(60000);
  });
  it('prefers the runner over the globals', async () => {
    const g = recorder();
    const r = recorder();
    await withGlobals(g.runner.describe, g.runner.it, () => describeBudgetLedgerConformance(memoryBudgetLedgerAdapter(), { runner: r.runner }));
    expect(g.describes).toEqual([]);
    expect(r.describes).toHaveLength(1);
  });
  it('refuses to register without describe and it, naming what to pass', async () => {
    const msg = 'describeBudgetLedgerConformance needs describe/it: pass { runner } or enable test globals';
    const r = recorder();
    await withGlobals(undefined, undefined, () => expect(() => describeBudgetLedgerConformance(memoryBudgetLedgerAdapter())).toThrow(new Error(msg)));
    await withGlobals(undefined, r.runner.it, () => expect(() => describeBudgetLedgerConformance(memoryBudgetLedgerAdapter())).toThrow(new Error(msg)));
    await withGlobals(r.runner.describe, undefined, () => expect(() => describeBudgetLedgerConformance(memoryBudgetLedgerAdapter())).toThrow(new Error(msg)));
    expect(r.describes).toEqual([]);
  });
});
