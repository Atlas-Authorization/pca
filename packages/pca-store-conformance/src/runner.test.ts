import { describe, expect, it } from 'vitest';
import type { KeyResult } from './check';
import { inMemoryAdapter, nonStrictCounterAdapter, readThenWriteAdapter, volatileAdapter } from './reference';
import {
  ALL_TESTS,
  describeStoreConformance,
  detectKinds,
  formatReport,
  overall,
  reportJson,
  runConformance,
  runTest,
  type ConformanceReport,
  type TestReport,
} from './runner';
import type { StoreAdapter } from './types';

const quick = { clients: 4, durationMs: 80, rounds: 4, revisitKeys: 20 };

describe('detectKinds', () => {
  it('reads the first client, closes it, and lets declared capabilities win', async () => {
    let closed = 0;
    const a = (caps: StoreAdapter['capabilities'], client: object): StoreAdapter => ({
      name: 'x',
      capabilities: caps,
      open: async () => ({ ...client, close: async () => void closed++ }),
    });
    const both = { consumeOnce: async () => true, advance: async () => true };
    expect(await detectKinds(a(undefined, both))).toEqual(['consume', 'advance']);
    expect(await detectKinds(a({}, { advance: async () => true }))).toEqual(['advance']);
    expect(await detectKinds(a({}, { consumeOnce: async () => true }))).toEqual(['consume']);
    expect(await detectKinds(a({ consumeOnce: false }, both))).toEqual(['advance']);
    expect(await detectKinds(a({ advance: false }, both))).toEqual(['consume']);
    expect(await detectKinds(a({ advance: true }, {}))).toEqual(['advance']);
    expect(closed).toBe(6);
  });
});

describe('runTest / runConformance', () => {
  it('runs every test for every kind, in order', async () => {
    const r = await runConformance(inMemoryAdapter(), quick);
    expect(r.adapter).toBe('in-memory (InMemoryReplayStore)');
    expect(r.tests.map((t) => `${t.test}/${t.kind}`)).toEqual(ALL_TESTS.flatMap((t) => [`${t}/consume`, `${t}/advance`]));
    expect(ALL_TESTS).toEqual(['burst', 'concurrent', 'retention', 'durability', 'crash']);
    const crash = r.tests.find((t) => t.test === 'crash')!;
    expect(crash).toEqual({ test: 'crash', kind: 'consume', status: 'skip', ops: 0, keys: 0, errors: 0, violations: [], unresolved: 0, note: 'needs the adapter module path (the crash test runs the adapter in child processes)' });
    const burst = r.tests[0]!;
    expect(burst).toMatchObject({ status: 'pass', ops: 16, keys: 4, errors: 0, unresolved: 0, violations: [] });
    expect(burst.note).toBeUndefined();
  });
  it('refuses an adapter that implements neither operation', async () => {
    await expect(runConformance({ name: 'empty', open: async () => ({}) })).rejects.toThrow('empty: the client implements neither consumeOnce nor advance');
  });
  it('fail on a violation, unresolved when nothing definite was observed or a key was over budget', async () => {
    const f = await runTest(readThenWriteAdapter(), 'burst', 'consume', quick);
    expect(f.status).toBe('fail');
    expect(f.violations.length).toBeGreaterThan(0);
    const dead: StoreAdapter = { name: 'dead', open: async () => ({ advance: async () => Promise.reject(new Error('down')) }) };
    const u = await runTest(dead, 'burst', 'advance', quick);
    expect(u).toMatchObject({ status: 'unresolved', errors: 16, note: 'no definite answer was observed (every call failed or timed out)' });
    const budget = await runTest(inMemoryAdapter(), 'concurrent', 'advance', { ...quick, budget: 0 });
    // every key decided exactly (no unknown outcomes): the budget is never needed
    expect(budget.status).toBe('pass');
    // every second client fails without effect: the keys carry unknown outcomes, so only the (zero) search budget decides
    const base = inMemoryAdapter();
    let k = 0;
    const flaky: StoreAdapter = {
      name: 'flaky',
      open: async () => {
        const c = await base.open();
        const bad = k++ % 2 === 1;
        return { advance: (s: string, v: number) => (bad ? Promise.reject(new Error('x')) : c.advance!(s, v)) };
      },
    };
    const fu = await runTest(flaky, 'burst', 'advance', { ...quick, budget: 0 });
    expect(fu.status).toBe('unresolved');
    expect(fu.unresolved).toBeGreaterThan(0);
  });
  it('durability is skipped only when declared non-durable, and the note says why', async () => {
    const s = await runTest(inMemoryAdapter(), 'durability', 'consume', quick);
    expect(s).toMatchObject({ status: 'skip', note: expect.stringMatching(/declares durable: false/) });
    const v = await runTest(volatileAdapter(), 'durability', 'consume', quick);
    expect(v.status).toBe('fail');
    expect(v.note).toBe('backend restarted between write and read');
    const nohook: StoreAdapter = { ...inMemoryAdapter(), capabilities: {} };
    const d = await runTest(nohook, 'durability', 'advance', quick);
    expect(d).toMatchObject({ status: 'pass', note: expect.stringMatching(/no restart/) });
  });
  it('retention and concurrent tests dispatch to their workloads', async () => {
    const r = await runTest(inMemoryAdapter(), 'retention', 'consume', quick);
    expect(r).toMatchObject({ status: 'pass', ops: 40, keys: 20 });
    const c = await runTest(inMemoryAdapter(), 'concurrent', 'consume', quick);
    expect(c.status).toBe('pass');
    expect(c.ops).toBeGreaterThan(20);
  });
  it('the crash test runs when given the module (built-in adapters work too)', async () => {
    const r = await runTest(inMemoryAdapter(), 'crash', 'advance', { crash: { module: 'builtin:in-memory', processes: 1, durationMs: 50, killEveryMs: 0, workerPath: '/nonexistent/worker.js' } });
    // the worker entry does not exist: the child exits at once, nothing is recorded -> no definite answer
    expect(r.status).toBe('unresolved');
    expect(r.ops).toBe(0);
  });
  it('a subset of tests', async () => {
    const r = await runConformance(nonStrictCounterAdapter(), { ...quick, values: 2, tests: ['burst'] });
    expect(r.tests).toHaveLength(1);
    expect(r.status).toBe('fail');
  });
});

describe('overall', () => {
  const t = (status: TestReport['status']): TestReport => ({ test: 'burst', kind: 'advance', status, ops: 0, keys: 0, errors: 0, violations: [], unresolved: 0 });
  it('fail beats unresolved beats pass; skip counts as nothing', () => {
    expect(overall([])).toBe('pass');
    expect(overall([t('pass'), t('skip')])).toBe('pass');
    expect(overall([t('pass'), t('unresolved')])).toBe('unresolved');
    expect(overall([t('unresolved'), t('fail'), t('pass')])).toBe('fail');
    expect(overall([t('fail')])).toBe('fail');
  });
});

describe('formatReport / reportJson', () => {
  const v: KeyResult = {
    key: 'ns:advance:3:1',
    kind: 'advance',
    ops: 9,
    searched: 4,
    verdict: 'violation',
    method: 'overlap',
    minimized: true,
    counterexample: [
      { client: 'c1', kind: 'advance', key: 'ns:advance:3:1', lo: 4, w: 4, call: 10, ret: 12, res: 'true' },
      { client: 'c2', kind: 'advance', key: 'ns:advance:3:1', lo: 4, w: 4, call: 11, ret: Infinity, res: 'unknown' },
    ],
  };
  const r: ConformanceReport = {
    adapter: 'my store',
    status: 'fail',
    tests: [
      { test: 'burst', kind: 'consume', status: 'pass', ops: 160, keys: 20, errors: 0, violations: [], unresolved: 0 },
      { test: 'concurrent', kind: 'advance', status: 'fail', ops: 500, keys: 40, errors: 2, violations: [v, { ...v, key: 'k2', minimized: false }, { ...v, key: 'k3' }, { ...v, key: 'k4' }], unresolved: 1, note: 'n' },
      { test: 'durability', kind: 'consume', status: 'skip', ops: 0, keys: 0, errors: 0, violations: [], unresolved: 0, note: 'declared' },
    ],
  };
  it('one line per test, then the counterexamples (at most maxKeys per test)', () => {
    const text = formatReport(r);
    expect(text.split('\n')).toEqual([
      'pca-store-conformance: my store -> FAIL',
      '  [PASS] burst/consumeOnce        160 ops, 20 keys, 0 errors/timeouts',
      '  [FAIL] concurrent/advance       500 ops, 40 keys, 2 errors/timeouts; 4 NON-LINEARIZABLE key(s); 1 unresolved key(s) (over the search budget); n',
      '      key ns:advance:3:1 (9 ops, decided by overlap): minimal counterexample:',
      '        c1: advance(4) [+0.000ms .. +2.000ms] -> TRUE',
      '        c2: advance(4) [+1.000ms .. open] -> unknown',
      '      key k2 (9 ops, decided by overlap): violating history (not shrunk):',
      '        c1: advance(4) [+0.000ms .. +2.000ms] -> TRUE',
      '        c2: advance(4) [+1.000ms .. open] -> unknown',
      '      key k3 (9 ops, decided by overlap): minimal counterexample:',
      '        c1: advance(4) [+0.000ms .. +2.000ms] -> TRUE',
      '        c2: advance(4) [+1.000ms .. open] -> unknown',
      '  [SKIP] durability/consumeOnce   declared',
    ]);
    expect(formatReport(r, 1).split('\n')).toHaveLength(7);
    expect(formatReport({ ...r, tests: [{ ...r.tests[1]!, violations: [{ ...v, counterexample: undefined }] }] }).split('\n')).toHaveLength(3);
  });
  it('JSON with Infinity as null', () => {
    const j = JSON.parse(reportJson(r));
    expect(j.tests[1].violations[0].counterexample[1].ret).toBeNull();
    expect(j.tests[1].violations[0].counterexample[0].ret).toBe(12);
    expect(reportJson(r)).toContain('\n  "adapter": "my store"');
  });
});

describe('describeStoreConformance', () => {
  it('registers one test per conformance test and fails it with the report', async () => {
    const tests: { name: string; fn: () => Promise<void>; timeout?: number }[] = [];
    const suites: string[] = [];
    const runner = { describe: (n: string, f: () => void) => (suites.push(n), f()), it: (name: string, fn: () => Promise<void>, timeout?: number) => tests.push({ name, fn, timeout }) };
    let made = 0;
    let torn = 0;
    describeStoreConformance(
      () => {
        made++;
        return { ...readThenWriteAdapter(), teardown: async () => void torn++ };
      },
      { ...quick, runner, tests: ['burst', 'durability'] },
    );
    expect(suites).toEqual(['PCA store conformance']);
    expect(tests.map((t) => [t.name, t.timeout])).toEqual([
      ['burst', 120_000],
      ['durability', 120_000],
    ]);
    await expect(tests[0]!.fn()).rejects.toThrow(/-> FAIL[\s\S]*NON-LINEARIZABLE/);
    await tests[1]!.fn(); // durability: skipped (declared non-durable) -> the overall status is pass
    expect(made).toBe(2);
    expect(torn).toBe(2);
  });
  it('accepts an adapter object, a timeout, and global describe/it', async () => {
    const tests: { name: string; fn: () => Promise<void>; timeout?: number }[] = [];
    const g = globalThis as Record<string, unknown>;
    const saved = [g.describe, g.it];
    g.describe = (_n: string, f: () => void) => f();
    g.it = (name: string, fn: () => Promise<void>, timeout?: number) => tests.push({ name, fn, timeout });
    try {
      describeStoreConformance(inMemoryAdapter(), { ...quick, timeoutMs: 5 });
    } finally {
      [g.describe, g.it] = saved;
    }
    expect(tests.map((t) => t.name)).toEqual([...ALL_TESTS]);
    expect(tests[0]!.timeout).toBe(5);
    await tests[0]!.fn();
  });
  it('needs describe and it', () => {
    const g = globalThis as Record<string, unknown>;
    const saved = [g.describe, g.it];
    g.describe = undefined;
    g.it = undefined;
    try {
      expect(() => describeStoreConformance(inMemoryAdapter())).toThrow(/needs describe\/it/);
      expect(() => describeStoreConformance(inMemoryAdapter(), { runner: { describe: undefined as never, it: () => 0 } })).toThrow(/needs describe\/it/);
      expect(() => describeStoreConformance(inMemoryAdapter(), { runner: { describe: () => 0, it: undefined as never } })).toThrow(/needs describe\/it/);
    } finally {
      [g.describe, g.it] = saved;
    }
  });
  it('an unresolved result fails the registered test too', async () => {
    const tests: (() => Promise<void>)[] = [];
    const dead: StoreAdapter = { name: 'dead', open: async () => ({ advance: async () => Promise.reject(new Error('down')) }) };
    describeStoreConformance(dead, { ...quick, tests: ['burst'], runner: { describe: (_n, f) => f(), it: (_n, fn) => tests.push(fn) } });
    await expect(tests[0]!()).rejects.toThrow(/-> UNRESOLVED/);
  });
});
