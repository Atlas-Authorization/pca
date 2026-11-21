import { acquireLease, type LeaseRecord, type LeaseStore } from '@atlasauth/pca/ext/research';
import { describe, expect, it } from 'vitest';
import {
  LEASE_CHECKS,
  amnesiaLeaseStoreAdapter,
  describeLeaseStoreConformance,
  durableLeaseStoreAdapter,
  epochRegressLeaseStoreAdapter,
  formatLeaseReport,
  lostUpdateLeaseStoreAdapter,
  memoryLeaseStoreAdapter,
  noCasLeaseStoreAdapter,
  runLeaseStoreConformance,
  type LeaseCheckResult,
  type LeaseConformanceReport,
  type LeaseStoreAdapter,
  type LeaseStoreHandle,
} from './lease-conformance';
import { traceHandle } from './test-support/trace';

const T0 = 1_000_000;
const EXP = T0 + 600_000;
const U = '"<undefined>"';
const rec = (holder: string, epoch: number, expiresAt: number): string => JSON.stringify({ holder, epoch, expiresAt });
const eq = (a?: LeaseRecord, b?: LeaseRecord): boolean => (a && b ? a.holder === b.holder && a.epoch === b.epoch && a.expiresAt === b.expiresAt : a === b);

/** A correct lease store with a fixed, scriptable clock. */
function fake(init?: LeaseRecord): { st: { rec: LeaseRecord | undefined; t: number }; store: LeaseStore } {
  const st = { rec: init, t: T0 };
  const store: LeaseStore = {
    read: async () => (st.rec ? { ...st.rec } : undefined),
    now: async () => st.t,
    cas: async (e, n) => {
      if (!eq(st.rec, e)) return false;
      if (n.epoch < (st.rec?.epoch ?? 0)) return false;
      st.rec = { ...n };
      return true;
    },
  };
  return { st, store };
}
const handle = (store: LeaseStore, extra: Partial<LeaseStoreHandle> = {}): LeaseStoreHandle => ({ store, reopen: async () => store, ...extra });

async function runOne(name: string, h: LeaseStoreHandle): Promise<LeaseCheckResult> {
  const r = await runLeaseStoreConformance({ name: 'x', create: async () => h }, { only: [name] });
  expect(r.checks).toHaveLength(1);
  return r.checks[0]!;
}
async function traced(name: string, f = fake()): Promise<{ res: LeaseCheckResult; log: string[] }> {
  const log: string[] = [];
  const res = await runOne(name, traceHandle(handle(f.store), 'store', log));
  return { res, log };
}
const won = (holder: string, epoch: number, expected: string = U): string[] => ['c0.read()', 'c0.now()', `c0.cas(${expected},${rec(holder, epoch, EXP)})`];

describe('lease checks: exact call sequences against a correct store', () => {
  it('empty-store-has-no-lease reads the record and the clock', async () => {
    const { res, log } = await traced('empty-store-has-no-lease');
    expect(res.status).toBe('pass');
    expect(log).toEqual(['c0.read()', 'c0.now()']);
  });
  it('first-acquire-is-epoch-1 acquires, re-reads and compares with the clock', async () => {
    const { res, log } = await traced('first-acquire-is-epoch-1');
    expect(res).toEqual({ name: 'first-acquire-is-epoch-1', status: 'pass' });
    expect(log).toEqual([...won('a', 1), 'c0.read()', 'c0.now()']);
  });
  it('wrong-expected-record-never-writes', async () => {
    const { res, log } = await traced('wrong-expected-record-never-writes');
    expect(res.status).toBe('pass');
    expect(log).toEqual([`c0.cas(${rec('x', 1, 5)},${rec('y', 2, 9)})`, 'c0.read()', ...won('a', 1), `c0.cas(${U},${rec('y', 2, 9)})`, 'c0.read()']);
  });
  it('racing-acquirers-have-one-winner: 4 clients x 2 holders, each client its own', async () => {
    const { res, log } = await traced('racing-acquirers-have-one-winner');
    expect(res.status).toBe('pass');
    expect(log.filter((l) => l === 'h.reopen()')).toHaveLength(3);
    const holders = ['h0a', 'h0b', 'h1a', 'h1b', 'h2a', 'h2b', 'h3a', 'h3b'];
    expect(log.filter((l) => l.includes('.cas('))).toEqual(holders.map((hd, i) => `c${Math.floor(i / 2)}.cas(${U},${rec(hd, 1, EXP)})`));
    expect(log[log.length - 1]).toBe('c0.read()');
  });
  it('epoch-never-goes-down tries a lower epoch over the matching record, then re-reads', async () => {
    const { res, log } = await traced('epoch-never-goes-down');
    expect(res.status).toBe('pass');
    expect(log).toEqual([
      ...won('a', 1),
      'c0.read()',
      'c0.now()',
      `c0.cas(${rec('a', 1, EXP)},${rec('a', 1, 0)})`,
      ...won('b', 2, rec('a', 1, 0)),
      `c0.cas(${rec('b', 2, EXP)},${rec('z', 1, EXP)})`,
      'c0.read()',
    ]);
  });
  it('stale-holder-cannot-renew-or-release re-reads the record at the end', async () => {
    const { res, log } = await traced('stale-holder-cannot-renew-or-release');
    expect(res.status).toBe('pass');
    expect(log).toEqual([
      ...won('a', 1),
      'c0.read()',
      'c0.now()',
      `c0.cas(${rec('a', 1, EXP)},${rec('a', 1, 0)})`,
      ...won('b', 2, rec('a', 1, 0)),
      'c0.read()',
      'c0.now()',
      'c0.read()',
      'c0.now()',
      'c0.read()',
    ]);
  });
});

describe('lease checks: scripted misbehaving stores', () => {
  it('a store with a leftover released lease does not hand out epoch 1 / epoch 2', async () => {
    const first = await runOne('first-acquire-is-epoch-1', handle(fake({ holder: 'z', epoch: 4, expiresAt: 0 }).store));
    expect(first.status).toBe('fail');
    expect(first.detail).toMatch(/5 !== 1/);
    const take = await runOne('takeover-after-release-bumps-the-epoch', handle(fake({ holder: 'z', epoch: 7, expiresAt: 0 }).store));
    expect(take.status).toBe('fail');
    expect(take.detail).toMatch(/9 !== 2/);
  });
  it('a failed acquire is reported with the reason', async () => {
    const f = fake();
    const r = await runOne('first-acquire-is-epoch-1', handle({ ...f.store, cas: async () => false }));
    expect(r).toEqual({ name: 'first-acquire-is-epoch-1', status: 'fail', detail: 'acquire for a failed: lost-race' });
  });
  it('a read that does not return the acquired lease fails first-acquire', async () => {
    const f = fake();
    const store: LeaseStore = { ...f.store, read: async () => (f.st.rec ? { ...f.st.rec, expiresAt: f.st.rec.expiresAt + 1 } : undefined) };
    expect((await runOne('first-acquire-is-epoch-1', handle(store))).status).toBe('fail');
  });
  it('the expiry must lie strictly after the store clock', async () => {
    for (const [delta, status] of [[-1, 'pass'], [0, 'fail'], [5, 'fail']] as const) {
      const f = fake();
      const store: LeaseStore = {
        ...f.store,
        cas: async (e, n) => {
          const ok = await f.store.cas(e, n);
          if (ok) f.st.t = n.expiresAt + delta;
          return ok;
        },
      };
      expect((await runOne('first-acquire-is-epoch-1', handle(store))).status).toBe(status);
    }
  });
  it('a store that rejects (instead of returning false) a lower epoch passes epoch-never-goes-down', async () => {
    const f = fake();
    const store: LeaseStore = {
      ...f.store,
      cas: async (e, n) => {
        if (n.epoch < (f.st.rec?.epoch ?? 0)) throw new Error('epoch went down');
        return f.store.cas(e, n);
      },
    };
    expect(await runOne('epoch-never-goes-down', handle(store))).toEqual({ name: 'epoch-never-goes-down', status: 'pass' });
  });
  it('a store whose record changes under a stale renew / release fails stale-holder', async () => {
    const f = fake();
    const store: LeaseStore = {
      ...f.store,
      read: async () => {
        const r = await f.store.read();
        return r && r.holder === 'b' ? { ...r, expiresAt: r.expiresAt + 1 } : r;
      },
    };
    expect((await runOne('stale-holder-cannot-renew-or-release', handle(store))).status).toBe('fail');
  });
  it('a read that finds nothing is an assertion failure, not a crash of the check', async () => {
    const f = fake();
    const racing = await runOne('racing-acquirers-have-one-winner', handle({ ...f.store, read: async () => undefined }));
    expect(racing.status).toBe('fail');
    expect(racing.detail).toMatch(/undefined !== 1/);
    expect(racing.detail).not.toMatch(/Cannot read/);
    const crash = await runOne('acknowledged-lease-survives-a-crash', handle(fake().store, { crash: async () => fake().store }));
    expect(crash.status).toBe('fail');
    expect(crash.detail).toMatch(/undefined !== 1/);
    expect(crash.detail).not.toMatch(/Cannot read/);
  });
});

describe('runLeaseStoreConformance', () => {
  it('runs only the named checks, in registry order', async () => {
    const all = await runLeaseStoreConformance(memoryLeaseStoreAdapter());
    expect(all.checks.map((c) => c.name)).toEqual(LEASE_CHECKS.map((c) => c.name));
    const some = await runLeaseStoreConformance(memoryLeaseStoreAdapter(), { only: ['epoch-never-goes-down', 'empty-store-has-no-lease'] });
    expect(some.checks.map((c) => c.name)).toEqual(['empty-store-has-no-lease', 'epoch-never-goes-down']);
    expect((await runLeaseStoreConformance(memoryLeaseStoreAdapter(), { only: [] })).checks).toEqual([]);
  });
  it('reports the skip reasons, creating no handle for a durability skip', async () => {
    let created = 0;
    const closes: string[] = [];
    const a: LeaseStoreAdapter = {
      name: 'n',
      durable: false,
      create: async () => {
        created++;
        return handle(fake().store, { close: async () => void closes.push('close') });
      },
    };
    const r = await runLeaseStoreConformance(a, { only: ['state-survives-reopen', 'acknowledged-lease-survives-a-crash'] });
    expect(r.checks).toEqual([
      { name: 'state-survives-reopen', status: 'skip', detail: 'the adapter declares durable: false' },
      { name: 'acknowledged-lease-survives-a-crash', status: 'skip', detail: 'the adapter has no crash()' },
    ]);
    expect(r.status).toBe('pass');
    expect(created).toBe(1);
    expect(closes).toEqual(['close']);
  });
  it('closes the handle after a pass, after a failure and after a skip', async () => {
    const closes: string[] = [];
    const mk = (f: ReturnType<typeof fake>): LeaseStoreAdapter => ({ name: 'n', create: async () => handle(f.store, { close: async () => void closes.push('close') }) });
    await runLeaseStoreConformance(mk(fake()), { only: ['empty-store-has-no-lease'] });
    expect(closes).toHaveLength(1);
    const bad = await runLeaseStoreConformance(mk(fake({ holder: 'z', epoch: 1, expiresAt: 0 })), { only: ['empty-store-has-no-lease'] });
    expect(bad.status).toBe('fail');
    expect(closes).toHaveLength(2);
    await runLeaseStoreConformance(mk(fake()), { only: ['acknowledged-lease-survives-a-crash'] });
    expect(closes).toHaveLength(3);
  });
  it('names the reference adapters', () => {
    expect(memoryLeaseStoreAdapter().name).toBe('KvLeaseStore over an in-memory kv');
    expect(durableLeaseStoreAdapter().name).toBe('KvLeaseStore over durable-state files');
  });
  it('the in-memory reopen returns a client on the same kv', async () => {
    const h = await memoryLeaseStoreAdapter().create();
    const r = await acquireLease(h.store, 'a', { ttlMs: 600_000, skewMs: 1_000 });
    expect(r.ok).toBe(true);
    expect(await (await h.reopen()).read()).toEqual(r.ok ? r.lease : undefined);
  });
});

describe('formatLeaseReport', () => {
  it('prints one line per check, upper-case status, only the first line of a detail, nothing for no detail', () => {
    const r: LeaseConformanceReport = {
      adapter: 'ad',
      status: 'fail',
      checks: [
        { name: 'n1', status: 'pass' },
        { name: 'n2', status: 'fail', detail: 'line1\nline2' },
        { name: 'n3', status: 'skip', detail: 'why' },
      ],
    };
    expect(formatLeaseReport(r)).toBe('pca-store-conformance (lease store): ad -> FAIL\n  [PASS] n1\n  [FAIL] n2: line1\n  [SKIP] n3: why');
  });
});

describe('describeLeaseStoreConformance', () => {
  interface Reg {
    describes: string[];
    its: { name: string; fn: () => Promise<void>; timeout: number | undefined }[];
  }
  const recorder = (): { reg: Reg; runner: { describe: (n: string, f: () => void) => void; it: (n: string, f: () => Promise<void>, t?: number) => void } } => {
    const reg: Reg = { describes: [], its: [] };
    return {
      reg,
      runner: {
        describe: (n, f) => {
          reg.describes.push(n);
          f();
        },
        it: (n, f, t) => void reg.its.push({ name: n, fn: f, timeout: t }),
      },
    };
  };
  const titles = LEASE_CHECKS.map((c) => `${c.name}: ${c.claim}`);

  it('registers one test per check under a titled suite, default timeout 60000, each passing for a good store', async () => {
    const { reg, runner } = recorder();
    describeLeaseStoreConformance(memoryLeaseStoreAdapter(), { runner });
    expect(reg.describes).toEqual(['PCA lease store conformance: KvLeaseStore over an in-memory kv']);
    expect(reg.its.map((i) => i.name)).toEqual(titles);
    expect(reg.its.map((i) => i.timeout)).toEqual(titles.map(() => 60_000));
    for (const i of reg.its) await expect(i.fn()).resolves.toBeUndefined();
  });
  it('honours a custom timeout', () => {
    const { reg, runner } = recorder();
    describeLeaseStoreConformance(memoryLeaseStoreAdapter(), { runner, timeoutMs: 1234 });
    expect(reg.its.map((i) => i.timeout)).toEqual(titles.map(() => 1234));
  });
  it('a factory is called once for the title and once per test', async () => {
    const { reg, runner } = recorder();
    let calls = 0;
    const factory = (): LeaseStoreAdapter => {
      calls++;
      return memoryLeaseStoreAdapter();
    };
    describeLeaseStoreConformance(factory, { runner });
    expect(calls).toBe(1);
    expect(reg.describes).toEqual(['PCA lease store conformance: KvLeaseStore over an in-memory kv']);
    for (const i of reg.its) await i.fn();
    expect(calls).toBe(1 + LEASE_CHECKS.length);
  });
  it('a failing check rejects with its detail, and only that test', async () => {
    const { reg, runner } = recorder();
    describeLeaseStoreConformance(epochRegressLeaseStoreAdapter(), { runner });
    const detail = (await runLeaseStoreConformance(epochRegressLeaseStoreAdapter(), { only: ['epoch-never-goes-down'] })).checks[0]!.detail!;
    const settled = await Promise.allSettled(reg.its.map((i) => i.fn()));
    const rejected = settled.map((s, i) => [s, reg.its[i]!.name] as const).filter(([s]) => s.status === 'rejected');
    expect(rejected.map(([, n]) => n)).toEqual(titles.filter((t) => t.startsWith('epoch-never-goes-down:')));
    expect(((rejected[0]![0] as PromiseRejectedResult).reason as Error).message).toBe(detail);
  });

  describe('test-runner globals', () => {
    const g = globalThis as unknown as Record<string, unknown>;
    const withGlobals = (d: unknown, i: unknown, fn: () => void): void => {
      const had = { d: 'describe' in g, i: 'it' in g };
      const old = { d: g.describe, i: g.it };
      g.describe = d;
      g.it = i;
      try {
        fn();
      } finally {
        if (had.d) g.describe = old.d;
        else delete g.describe;
        if (had.i) g.it = old.i;
        else delete g.it;
      }
    };
    const MSG = 'describeLeaseStoreConformance needs describe/it: pass { runner } or enable test globals';

    it('falls back to the globals when no runner is given', () => {
      const { reg, runner } = recorder();
      withGlobals(runner.describe, runner.it, () => describeLeaseStoreConformance(memoryLeaseStoreAdapter()));
      expect(reg.describes).toEqual(['PCA lease store conformance: KvLeaseStore over an in-memory kv']);
      expect(reg.its).toHaveLength(LEASE_CHECKS.length);
    });
    it('prefers the runner over the globals', () => {
      const global = recorder();
      const given = recorder();
      withGlobals(global.runner.describe, global.runner.it, () => describeLeaseStoreConformance(memoryLeaseStoreAdapter(), { runner: given.runner }));
      expect(global.reg.describes).toEqual([]);
      expect(given.reg.describes).toHaveLength(1);
    });
    it('throws a clear error unless both describe and it are available', () => {
      const { runner } = recorder();
      withGlobals(undefined, undefined, () => expect(() => describeLeaseStoreConformance(memoryLeaseStoreAdapter())).toThrow(MSG));
      withGlobals(runner.describe, undefined, () => expect(() => describeLeaseStoreConformance(memoryLeaseStoreAdapter())).toThrow(MSG));
      withGlobals(undefined, runner.it, () => expect(() => describeLeaseStoreConformance(memoryLeaseStoreAdapter())).toThrow(MSG));
    });
  });
});

describe('the defective reference stores, driven directly', () => {
  const A: LeaseRecord = { holder: 'h', epoch: 2, expiresAt: 10 };
  const open = async (a: LeaseStoreAdapter): Promise<LeaseStore> => (await a.create()).store;

  it('compare-and-swap compares holder, epoch and expiry, and a missing record only matches a missing expectation', async () => {
    const s = await open(amnesiaLeaseStoreAdapter());
    expect(await s.read()).toBeUndefined();
    expect(await s.cas({ holder: 'x', epoch: 1, expiresAt: 1 }, A)).toBe(false);
    expect(await s.read()).toBeUndefined();
    expect(await s.cas(undefined, A)).toBe(true);
    expect(await s.read()).toEqual(A);
    expect(await s.cas(undefined, { ...A, epoch: 3 })).toBe(false);
    expect(await s.cas({ ...A, holder: 'g' }, { ...A, epoch: 3 })).toBe(false);
    expect(await s.cas({ ...A, epoch: 9 }, { ...A, epoch: 3 })).toBe(false);
    expect(await s.cas({ ...A, expiresAt: 11 }, { ...A, epoch: 3 })).toBe(false);
    expect(await s.read()).toEqual(A);
    expect(await s.cas({ ...A }, { ...A, expiresAt: 20 })).toBe(true);
    expect(await s.read()).toEqual({ ...A, expiresAt: 20 });
  });
  it('the other correct-cas stores refuse a lower epoch; the regressing one accepts it; the unconditional one accepts anything', async () => {
    for (const a of [amnesiaLeaseStoreAdapter(), lostUpdateLeaseStoreAdapter()]) {
      const s = await open(a);
      expect(await s.cas(undefined, A)).toBe(true);
      expect(await s.cas(A, { ...A, epoch: 1 })).toBe(false);
      expect(await s.read()).toEqual(A);
      expect(await s.cas(A, { ...A, epoch: 3 })).toBe(true);
    }
    const r = await open(epochRegressLeaseStoreAdapter());
    expect(await r.cas(undefined, A)).toBe(true);
    expect(await r.cas(A, { ...A, epoch: 1 })).toBe(true);
    expect(await r.read()).toEqual({ ...A, epoch: 1 });
    expect(await r.cas({ ...A, holder: 'g' }, A)).toBe(false);
    const n = await open(noCasLeaseStoreAdapter());
    expect(await n.cas({ holder: 'x', epoch: 1, expiresAt: 1 }, A)).toBe(true);
    expect(await n.read()).toEqual(A);
    expect(await n.cas(undefined, { ...A, epoch: 1 })).toBe(true);
    expect(await n.read()).toEqual({ ...A, epoch: 1 });
  });
  it('only the lost-update store yields between its read and its write', async () => {
    for (const a of [amnesiaLeaseStoreAdapter(), epochRegressLeaseStoreAdapter()]) {
      const s = await open(a);
      const p = s.cas(undefined, A);
      expect(await s.read()).toEqual(A);
      expect(await p).toBe(true);
    }
    const l = await open(lostUpdateLeaseStoreAdapter());
    const p = l.cas(undefined, A);
    expect(await l.read()).toBeUndefined();
    expect(await p).toBe(true);
    expect(await l.read()).toEqual(A);
    const both = await Promise.all([l.cas(A, { ...A, expiresAt: 11 }), l.cas(A, { ...A, expiresAt: 12 })]);
    expect(both).toEqual([true, true]);
    expect(await l.read()).toEqual({ ...A, expiresAt: 12 });
  });
});
