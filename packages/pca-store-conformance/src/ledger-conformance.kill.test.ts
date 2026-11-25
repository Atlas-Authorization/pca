import { createMemoryDurableKv } from '@atlasauth/pca/durable-state';
import { KvLedgerStore, type Checkpoint, type LedgerStore } from '@atlasauth/pca/ext/ledger';
import { describe, expect, it } from 'vitest';
import {
  LEDGER_CHECKS,
  formatLedgerReport,
  memoryLedgerStoreAdapter,
  noReplayLedgerStoreAdapter,
  runLedgerStoreConformance,
  describeLedgerStoreConformance,
  type LedgerConformanceReport,
  type LedgerStoreAdapter,
  type LedgerStoreHandle,
} from './ledger-conformance';
import { show, traceHandle } from './test-support/trace';

const cm = (i: number): string => `commit-${i}-${'x'.repeat(30)}`;
const cp = (size: number, root = `root-${size}`, prev = ''): Checkpoint => ({ sth: { instance_id: 'i', principal: 'p', size, root, prev_root: prev, timestamp: 1, guardian: 'g', sig: 's' } });
const range = (a: number, b: number): string[] => Array.from({ length: b - a }, (_, i) => cm(a + i));
const L = (c: string, m: string, ...a: unknown[]): string => `${c}.${m}(${a.map(show).join(',')})`;

const wrap = (s: LedgerStore, o: Partial<LedgerStore> = {}): LedgerStore => ({
  size: () => s.size(),
  read: (f, t) => s.read(f, t),
  append: (e, c) => s.append(e, c),
  checkpointCount: () => s.checkpointCount(),
  checkpoints: (f) => s.checkpoints(f),
  appendCheckpoint: (e, c) => s.appendCheckpoint(e, c),
  ...o,
});

function memHandle(): LedgerStoreHandle {
  const kv = createMemoryDurableKv();
  return { store: new KvLedgerStore(kv), reopen: async () => new KvLedgerStore(kv) };
}

const base: LedgerStoreAdapter = {
  name: 'm',
  durable: true,
  async create() {
    const h = memHandle();
    return { ...h, crash: h.reopen };
  },
};

async function traced(name: string, adapter: LedgerStoreAdapter = base): Promise<string[]> {
  const log: string[] = [];
  const a: LedgerStoreAdapter = { ...adapter, async create() { return traceHandle(await adapter.create(), 'store', log); } };
  const r = await runLedgerStoreConformance(a, { only: [name] });
  expect(r.checks).toEqual([{ name, status: 'pass' }]);
  return log;
}

/** A crash scenario: 'lost' = the write in flight never lands, 'whole' = it lands before the crash. */
function crashAdapter(mode: 'lost' | 'whole', backOf: (real: LedgerStore) => LedgerStore = (r) => r, durable = true): LedgerStoreAdapter {
  return {
    name: 'crash',
    durable,
    async create() {
      const kv = createMemoryDurableKv();
      const real = new KvLedgerStore(kv);
      let done: Promise<unknown> = Promise.resolve();
      const first = wrap(real, {
        append: (e, c) => {
          if (e !== 3) return real.append(e, c);
          if (mode === 'lost') return new Promise<never>(() => undefined);
          const p = real.append(e, c);
          done = p;
          return p;
        },
      });
      return {
        store: first,
        reopen: async () => new KvLedgerStore(kv),
        crash: async () => {
          await done;
          return backOf(new KvLedgerStore(kv));
        },
      };
    },
  };
}

describe('ledger conformance: exact call traces of every check', () => {
  it('empty-store-is-empty', async () => {
    expect(await traced('empty-store-is-empty')).toEqual([L('c0', 'size'), L('c0', 'read', 0, 0), L('c0', 'checkpointCount'), L('c0', 'checkpoints', 0)]);
  });
  it('append-assigns-the-next-position', async () => {
    expect(await traced('append-assigns-the-next-position')).toEqual([
      L('c0', 'append', 0, [cm(0)]),
      L('c0', 'append', 1, [cm(1), cm(2)]),
      L('c0', 'read', 0, 3),
      L('c0', 'read', 1, 3),
      L('c0', 'read', 3, 3),
    ]);
  });
  it('append-at-another-position-conflicts-without-trace', async () => {
    expect(await traced('append-at-another-position-conflicts-without-trace')).toEqual([
      L('c0', 'append', 0, range(0, 3)),
      L('c0', 'append', 5, [cm(9)]),
      L('c0', 'append', 2, [cm(9)]),
      L('c0', 'size'),
      L('c0', 'read', 0, 3),
    ]);
  });
  it('append-retry-is-a-replay', async () => {
    expect(await traced('append-retry-is-a-replay')).toEqual([
      L('c0', 'append', 0, range(0, 3)),
      L('c0', 'append', 0, range(0, 3)),
      L('c0', 'append', 1, range(1, 3)),
      L('c0', 'append', 0, [cm(0), 'other']),
      L('c0', 'append', 2, [cm(2), cm(3)]),
      L('c0', 'size'),
      L('c0', 'read', 0, 3),
    ]);
  });
  it('invalid-input-is-refused', async () => {
    expect(await traced('invalid-input-is-refused')).toEqual([
      L('c0', 'append', 0, [cm(0)]),
      L('c0', 'append', 1, []),
      L('c0', 'append', 1, ['']),
      L('c0', 'append', 1, [cm(1), 7]),
      L('c0', 'append', 1, 'x'),
      L('c0', 'append', -1, [cm(1)]),
      L('c0', 'append', 1.5, [cm(1)]),
      L('c0', 'append', Number.NaN, [cm(1)]),
      L('c0', 'size'),
      L('c0', 'read', 0, 1),
      L('c0', 'read', -1, 1),
      L('c0', 'read', 1, 0),
      L('c0', 'read', 0, 2),
      L('c0', 'read', 0.5, 1),
    ]);
  });
  it('commit-strings-are-stored-exactly', async () => {
    const odd = ['a"b\\c', 'gränt-\u{1F512}-\u2028-\u0001', 'x'.repeat(5000), '__proto__', ' leading and trailing '];
    expect(await traced('commit-strings-are-stored-exactly')).toEqual([L('c0', 'append', 0, odd), L('c0', 'size'), L('c0', 'read', 0, 5)]);
  });
  it('racing-appends-at-one-position-have-one-winner', async () => {
    expect(await traced('racing-appends-at-one-position-have-one-winner')).toEqual([
      'h.reopen()',
      'h.reopen()',
      'h.reopen()',
      ...Array.from({ length: 8 }, (_, i) => L(`c${i % 4}`, 'append', 0, [cm(100 + i)])),
      L('c0', 'size'),
      L('c0', 'read', 0, 1),
    ]);
  });
  it('racing-writers-with-retry-fill-every-position-once', async () => {
    const log = await traced('racing-writers-with-retry-fill-every-position-once');
    expect(log.slice(0, 18)).toEqual(['h.reopen()', 'h.reopen()', ...Array.from({ length: 16 }, (_, i) => L(`c${i % 3}`, 'size'))]);
    expect(log.slice(-2)).toEqual([L('c0', 'size'), L('c0', 'read', 0, 16)]);
    for (let i = 0; i < 16; i++) expect(log.some((l) => new RegExp(`^c[012]\\.append\\(\\d+,\\["${cm(200 + i)}"\\]\\)$`).test(l))).toBe(true);
  });
  it('a-batch-is-all-or-nothing', async () => {
    expect(await traced('a-batch-is-all-or-nothing')).toEqual([
      L('c0', 'append', 0, range(0, 2)),
      L('c0', 'append', 5, range(10, 14)),
      L('c0', 'size'),
      L('c0', 'read', 0, 2),
      L('c0', 'append', 2, range(10, 14)),
      L('c0', 'size'),
      L('c0', 'read', 0, 6),
    ]);
  });
  it('checkpoints-append-by-count-and-replay', async () => {
    expect(await traced('checkpoints-append-by-count-and-replay')).toEqual([
      L('c0', 'append', 0, range(0, 6)),
      L('c0', 'appendCheckpoint', 0, cp(2)),
      L('c0', 'appendCheckpoint', 0, cp(2)),
      L('c0', 'appendCheckpoint', 0, cp(3)),
      L('c0', 'appendCheckpoint', 2, cp(3)),
      L('c0', 'appendCheckpoint', 1, cp(5, 'root-5', 'root-2')),
      L('c0', 'checkpoints', 0),
      L('c0', 'checkpoints', 1),
      L('c0', 'checkpointCount'),
    ]);
  });
  it('checkpoints-stay-inside-the-log-and-never-go-back', async () => {
    expect(await traced('checkpoints-stay-inside-the-log-and-never-go-back')).toEqual([
      L('c0', 'append', 0, range(0, 4)),
      L('c0', 'appendCheckpoint', 0, cp(5)),
      L('c0', 'appendCheckpoint', 0, cp(3)),
      L('c0', 'appendCheckpoint', 1, cp(2)),
      L('c0', 'appendCheckpoint', 1, cp(3, 'other-root')),
      L('c0', 'appendCheckpoint', 1, cp(3)),
      L('c0', 'appendCheckpoint', 2, null),
      L('c0', 'checkpointCount'),
    ]);
  });
  it('racing-checkpoints-have-one-winner', async () => {
    expect(await traced('racing-checkpoints-have-one-winner')).toEqual([
      L('c0', 'append', 0, range(0, 6)),
      'h.reopen()',
      L('c0', 'appendCheckpoint', 0, cp(2)),
      L('c1', 'appendCheckpoint', 0, cp(3)),
      L('c0', 'appendCheckpoint', 0, cp(4)),
      L('c1', 'appendCheckpoint', 0, cp(5)),
      L('c0', 'checkpointCount'),
    ]);
  });
  it('reads-are-snapshots', async () => {
    expect(await traced('reads-are-snapshots')).toEqual([
      L('c0', 'append', 0, range(0, 3)),
      L('c0', 'appendCheckpoint', 0, cp(2)),
      L('c0', 'read', 0, 3),
      L('c0', 'checkpoints', 0),
      L('c0', 'size'),
      L('c0', 'read', 0, 3),
      L('c0', 'checkpoints', 0),
    ]);
  });
  it('state-survives-reopen', async () => {
    expect(await traced('state-survives-reopen')).toEqual([
      L('c0', 'append', 0, range(0, 5)),
      L('c0', 'appendCheckpoint', 0, cp(3)),
      L('c0', 'append', 5, range(5, 7)),
      'h.reopen()',
      L('c1', 'size'),
      L('c1', 'read', 0, 7),
      L('c1', 'checkpoints', 0),
      L('c1', 'append', 7, [cm(7)]),
    ]);
  });
  it('acknowledged-writes-survive-a-crash: the in-flight batch is lost', async () => {
    expect(await traced('acknowledged-writes-survive-a-crash', crashAdapter('lost'))).toEqual([
      L('c0', 'append', 0, range(0, 3)),
      L('c0', 'appendCheckpoint', 0, cp(2)),
      L('c0', 'append', 3, range(3, 7)),
      'h.crash()',
      L('c1', 'size'),
      L('c1', 'read', 0, 3),
      L('c1', 'checkpoints', 0),
      L('c1', 'append', 3, range(3, 7)),
      L('c1', 'size'),
      L('c1', 'read', 0, 7),
    ]);
  });
  it('acknowledged-writes-survive-a-crash: the in-flight batch landed', async () => {
    expect(await traced('acknowledged-writes-survive-a-crash', crashAdapter('whole'))).toEqual([
      L('c0', 'append', 0, range(0, 3)),
      L('c0', 'appendCheckpoint', 0, cp(2)),
      L('c0', 'append', 3, range(3, 7)),
      'h.crash()',
      L('c1', 'size'),
      L('c1', 'read', 0, 7),
      L('c1', 'checkpoints', 0),
      L('c1', 'append', 3, range(3, 7)),
      L('c1', 'size'),
      L('c1', 'read', 0, 7),
    ]);
  });
});

describe('ledger conformance: scripted faulty stores are caught', () => {
  const once = async (a: LedgerStoreAdapter, name: string) => (await runLedgerStoreConformance(a, { only: [name] })).checks[0]!;

  it('a writer that is told "replayed" stops retrying', async () => {
    let calls = 0;
    const store = wrap(new KvLedgerStore(createMemoryDurableKv()), {
      append: async (e) => {
        if (++calls > 100) throw new Error('runaway');
        return { outcome: 'replayed', size: e };
      },
    });
    const c = await once({ name: 'r', create: async () => ({ store, reopen: async () => store }) }, 'racing-writers-with-retry-fill-every-position-once');
    expect(c.status).toBe('fail');
    expect(calls).toBe(16);
  });

  it('the winner of a one-position race must be one of the raced commits', async () => {
    const real = new KvLedgerStore(createMemoryDurableKv());
    const store = wrap(real, { read: async () => ['bogus'] });
    const c = await once({ name: 'r', create: async () => ({ store, reopen: async () => store }) }, 'racing-appends-at-one-position-have-one-winner');
    expect(c.status).toBe('fail');
    expect(c.detail).toContain('falsy');
  });

  it('retrying writers that land in reverse order still pass (positions are mapped back correctly)', async () => {
    const real = new KvLedgerStore(createMemoryDurableKv());
    const left = new Map<string, number>(Array.from({ length: 16 }, (_, i) => [cm(200 + i), 15 - i] as const));
    const store = wrap(real, {
      append: async (e, c) => {
        const n = left.get(c[0]!) ?? 0;
        if (n > 0) {
          left.set(c[0]!, n - 1);
          return { outcome: 'conflict', size: await real.size() };
        }
        return real.append(e, c);
      },
    });
    const c = await once({ name: 'r', create: async () => ({ store, reopen: async () => store }) }, 'racing-writers-with-retry-fill-every-position-once');
    expect(c).toEqual({ name: 'racing-writers-with-retry-fill-every-position-once', status: 'pass' });
  });

  it('a log whose order does not match the positions the writers were told is caught', async () => {
    const real = new KvLedgerStore(createMemoryDurableKv());
    const store = wrap(real, { read: async (f, t) => (await real.read(f, t)).reverse() });
    const c = await once({ name: 'r', create: async () => ({ store, reopen: async () => store }) }, 'racing-writers-with-retry-fill-every-position-once');
    expect(c.status).toBe('fail');
    expect(c.detail).toContain('strictly equal');
  });

  it('positions that are unique but not contiguous from zero are caught on the positions themselves', async () => {
    const real = new KvLedgerStore(createMemoryDurableKv());
    const store = wrap(real, {
      size: async () => (await real.size()) + 5,
      append: (e, c) => real.append(e - 5, c),
      read: (f, t) => real.read(Math.max(0, f - 5), t - 5),
    });
    const c = await once({ name: 'r', create: async () => ({ store, reopen: async () => store }) }, 'racing-writers-with-retry-fill-every-position-once');
    expect(c.status).toBe('fail');
    expect(c.detail).toContain('strictly deep-equal');
    expect(c.detail).not.toContain('commit-');
  });

  const crashName = 'acknowledged-writes-survive-a-crash';
  it('a crash that leaves a partial batch is caught with its length', async () => {
    let sizes = 0;
    const a = crashAdapter('lost', (real) =>
      wrap(real, {
        size: async () => (sizes++ === 0 ? 5 : 7),
        read: async (f, t) => range(f, t),
        checkpoints: async () => [cp(2)],
        append: async () => ({ outcome: 'replayed', size: 7 }),
      }),
    );
    const c = await once(a, crashName);
    expect(c).toEqual({ name: crashName, status: 'fail', detail: 'log has 5 entries' });
  });
  it('a recovered log with altered content is caught', async () => {
    let reads = 0;
    const a = crashAdapter('lost', (real) => wrap(real, { read: async (f, t) => { const rs = await real.read(f, t); return reads++ === 0 ? rs.map((x, i) => (i === rs.length - 1 ? 'zz' : x)) : rs; } }));
    const c = await once(a, crashName);
    expect(c.status).toBe('fail');
    expect(c.detail).toContain('zz');
  });
  it('lost checkpoints are caught', async () => {
    const c = await once(crashAdapter('lost', (real) => wrap(real, { checkpoints: async () => [] })), crashName);
    expect(c.status).toBe('fail');
  });
  it('a final log that differs from what was written is caught', async () => {
    let reads = 0;
    const c = await once(crashAdapter('whole', (real) => wrap(real, { read: async (f, t) => { const rs = await real.read(f, t); return reads++ === 1 ? [...rs].reverse() : rs; } })), crashName);
    expect(c.status).toBe('fail');
  });
});

describe('ledger conformance: runner', () => {
  it('only filters by exact check name, in registration order', async () => {
    const r = await runLedgerStoreConformance(base, { only: ['a-batch-is-all-or-nothing', 'empty-store-is-empty'] });
    expect(r.checks).toStrictEqual([
      { name: 'empty-store-is-empty', status: 'pass' },
      { name: 'a-batch-is-all-or-nothing', status: 'pass' },
    ]);
    expect((await runLedgerStoreConformance(base, { only: [] })).checks).toEqual([]);
  });

  it('skips durability checks only for an adapter that declares durable: false, without creating a store', async () => {
    let created = 0;
    const mk = (durable: boolean | undefined): LedgerStoreAdapter => ({ name: 'n', ...(durable === undefined ? {} : { durable }), async create() { created++; return memHandle(); } });
    const name = 'state-survives-reopen';
    expect(await runLedgerStoreConformance(mk(false), { only: [name] })).toStrictEqual({ adapter: 'n', status: 'pass', checks: [{ name, status: 'skip', detail: 'the adapter declares durable: false' }] });
    expect(created).toBe(0);
    expect((await runLedgerStoreConformance(mk(undefined), { only: [name] })).checks).toStrictEqual([{ name, status: 'pass' }]);
    expect((await runLedgerStoreConformance(mk(true), { only: [name] })).checks).toStrictEqual([{ name, status: 'pass' }]);
    expect((await runLedgerStoreConformance(mk(false), { only: ['empty-store-is-empty'] })).checks).toStrictEqual([{ name: 'empty-store-is-empty', status: 'pass' }]);
  });

  it('a crash check is skipped when the handle has no crash(), and the handle is still closed', async () => {
    let created = 0;
    let closed = 0;
    const a: LedgerStoreAdapter = { name: 'n', durable: true, async create() { created++; return { ...memHandle(), close: async () => { closed++; } }; } };
    const name = 'acknowledged-writes-survive-a-crash';
    expect(await runLedgerStoreConformance(a, { only: [name] })).toStrictEqual({ adapter: 'n', status: 'pass', checks: [{ name, status: 'skip', detail: 'the adapter has no crash()' }] });
    expect([created, closed]).toEqual([1, 1]);
  });

  it('a durable: false adapter still runs the crash check when it can crash', async () => {
    const name = 'acknowledged-writes-survive-a-crash';
    expect((await runLedgerStoreConformance(crashAdapter('lost', (r) => r, false), { only: [name] })).checks).toStrictEqual([{ name, status: 'pass' }]);
  });

  it('closes the handle after every check, and reports failures with the thrown message (Error or not)', async () => {
    let closed = 0;
    const mk = (err: unknown): LedgerStoreAdapter => ({
      name: 'n',
      async create() {
        const h = memHandle();
        return { store: wrap(h.store, { size: async () => { throw err; } }), reopen: h.reopen, close: async () => { closed++; } };
      },
    });
    const name = 'empty-store-is-empty';
    expect(await runLedgerStoreConformance(mk(new Error('boom\nsecond')), { only: [name] })).toStrictEqual({ adapter: 'n', status: 'fail', checks: [{ name, status: 'fail', detail: 'boom\nsecond' }] });
    expect((await runLedgerStoreConformance(mk('plain'), { only: [name] })).checks).toStrictEqual([{ name, status: 'fail', detail: 'plain' }]);
    expect(closed).toBe(2);
    const ok = await runLedgerStoreConformance({ name: 'n', async create() { const h = memHandle(); return { ...h, close: async () => { closed++; } }; } }, { only: [name, 'append-assigns-the-next-position'] });
    expect(ok.status).toBe('pass');
    expect(closed).toBe(4);
  });

  it('create() failures are not swallowed', async () => {
    await expect(runLedgerStoreConformance({ name: 'n', create: async () => { throw new Error('no backend'); } }, { only: ['empty-store-is-empty'] })).rejects.toThrow('no backend');
  });
});

describe('ledger conformance: report text', () => {
  it('prints header, then one line per check with only the first detail line', () => {
    const r: LedgerConformanceReport = {
      adapter: 'My store',
      status: 'fail',
      checks: [
        { name: 'a', status: 'pass' },
        { name: 'b', status: 'skip', detail: 'why' },
        { name: 'c', status: 'fail', detail: 'first\nsecond' },
        { name: 'd', status: 'pass', detail: '' },
      ],
    };
    expect(formatLedgerReport(r)).toBe(['pca-store-conformance (ledger store): My store -> FAIL', '  [PASS] a', '  [SKIP] b: why', '  [FAIL] c: first', '  [PASS] d'].join('\n'));
    expect(formatLedgerReport({ adapter: 'x', status: 'pass', checks: [] })).toBe('pca-store-conformance (ledger store): x -> PASS');
  });
});

describe('ledger conformance: describe registration', () => {
  type Reg = { describes: string[]; its: { name: string; fn: () => Promise<void>; timeout: number | undefined }[] };
  const recorder = (): { reg: Reg; runner: { describe: (n: string, f: () => void) => void; it: (n: string, f: () => Promise<void>, t?: number) => void } } => {
    const reg: Reg = { describes: [], its: [] };
    return { reg, runner: { describe: (n, f) => { reg.describes.push(n); f(); }, it: (n, fn, timeout) => { reg.its.push({ name: n, fn, timeout }); } } };
  };
  const g = globalThis as Record<string, unknown>;
  async function withGlobals<T>(d: unknown, i: unknown, body: () => Promise<T> | T): Promise<T> {
    const saved = { d: g.describe, i: g.it };
    g.describe = d;
    g.it = i;
    try {
      return await body();
    } finally {
      g.describe = saved.d;
      g.it = saved.i;
    }
  }

  it('registers one test per check with the exact title and the default or given timeout', async () => {
    await withGlobals(undefined, undefined, () => {
      const a = recorder();
      describeLedgerStoreConformance(memoryLedgerStoreAdapter(), { runner: a.runner });
      expect(a.reg.describes).toEqual(['PCA ledger store conformance: KvLedgerStore over an in-memory kv']);
      expect(a.reg.its.map((x) => x.name)).toEqual(LEDGER_CHECKS.map((c) => `${c.name}: ${c.claim}`));
      expect(a.reg.its.map((x) => x.timeout)).toEqual(LEDGER_CHECKS.map(() => 60_000));
      const b = recorder();
      describeLedgerStoreConformance(memoryLedgerStoreAdapter(), { runner: b.runner, timeoutMs: 123 });
      expect(new Set(b.reg.its.map((x) => x.timeout))).toEqual(new Set([123]));
      const z = recorder();
      describeLedgerStoreConformance(memoryLedgerStoreAdapter(), { runner: z.runner, timeoutMs: 0 });
      expect(new Set(z.reg.its.map((x) => x.timeout))).toEqual(new Set([0]));
    });
  });

  it('throws the detail of a failing check, and nothing for passing or skipped ones', async () => {
    await withGlobals(undefined, undefined, async () => {
      const a = recorder();
      describeLedgerStoreConformance(noReplayLedgerStoreAdapter(), { runner: a.runner });
      const failName = 'append-retry-is-a-replay';
      const detail = (await runLedgerStoreConformance(noReplayLedgerStoreAdapter(), { only: [failName] })).checks[0]!.detail!;
      const t = a.reg.its.find((x) => x.name.startsWith(`${failName}:`))!;
      await expect(t.fn()).rejects.toThrow(detail);
      await expect(t.fn()).rejects.toBeInstanceOf(Error);
      await expect(a.reg.its[0]!.fn()).resolves.toBeUndefined();
      const m = recorder();
      describeLedgerStoreConformance(memoryLedgerStoreAdapter(), { runner: m.runner });
      for (const x of m.reg.its) await expect(x.fn()).resolves.toBeUndefined();
    });
  });

  it('accepts an adapter factory: called for the title and again for every test', async () => {
    await withGlobals(undefined, undefined, async () => {
      let calls = 0;
      const a = recorder();
      describeLedgerStoreConformance(() => { calls++; return memoryLedgerStoreAdapter(); }, { runner: a.runner });
      expect(a.reg.describes).toEqual(['PCA ledger store conformance: KvLedgerStore over an in-memory kv']);
      expect(calls).toBe(1);
      await a.reg.its[0]!.fn();
      expect(calls).toBe(2);
    });
  });

  it('uses the global describe/it when no runner is given, and prefers a given runner over them', async () => {
    const globalReg = recorder();
    await withGlobals(globalReg.runner.describe, globalReg.runner.it, () => {
      describeLedgerStoreConformance(memoryLedgerStoreAdapter());
      expect(globalReg.reg.describes).toHaveLength(1);
      expect(globalReg.reg.its).toHaveLength(LEDGER_CHECKS.length);
      const own = recorder();
      describeLedgerStoreConformance(memoryLedgerStoreAdapter(), { runner: own.runner });
      expect(own.reg.its).toHaveLength(LEDGER_CHECKS.length);
      expect(globalReg.reg.its).toHaveLength(LEDGER_CHECKS.length);
    });
  });

  it('refuses to register without describe and it', async () => {
    const msg = 'describeLedgerStoreConformance needs describe/it: pass { runner } or enable test globals';
    await withGlobals(undefined, undefined, () => {
      expect(() => describeLedgerStoreConformance(memoryLedgerStoreAdapter())).toThrow(new Error(msg));
      const r = recorder().runner;
      expect(() => describeLedgerStoreConformance(memoryLedgerStoreAdapter(), { runner: { describe: r.describe, it: undefined as never } })).toThrow(new Error(msg));
      expect(() => describeLedgerStoreConformance(memoryLedgerStoreAdapter(), { runner: { describe: undefined as never, it: r.it } })).toThrow(new Error(msg));
    });
  });
});
