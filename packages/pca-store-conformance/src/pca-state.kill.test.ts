// Exact-behaviour tests for the helpers of the pca-state profile that need no guard: the fixture, the claim-as-advance
// bridge, the report text, the reference adapters' declarations and the adapter loader.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { AtomicPcaStateStore, PcaHolderState, PcaStateStore } from '@atlasauth/pca';
import {
  PCA_STATE_REFERENCE_ADAPTERS,
  claimAsStoreAdapter,
  durableFilePcaStateAdapter,
  formatPcaStateReport,
  getPutPcaStateAdapter,
  loadPcaStateAdapter,
  localLockPcaStateAdapter,
  makePcaStateFixture,
  readThenWriteClaimPcaStateAdapter,
  unsharedPcaStateAdapter,
  volatilePcaStateAdapter,
  type PcaStateAdapter,
  type PcaStateReport,
} from './pca-state';
import type { TestReport } from './runner';

const count = (s: string, needle: string): number => s.split(needle).length - 1;

describe('makePcaStateFixture: caveats', () => {
  it('the grant carries the expiry and delegation-depth caveats, the task one more expiry', () => {
    const now = 1_000_000;
    const fx = makePcaStateFixture(2, now);
    const grant = JSON.stringify(fx.proofs[0]!.cap_chain[0]);
    const task = JSON.stringify(fx.proofs[0]!.cap_chain[1]);
    expect(grant).toContain(String(now + 3_600_000));
    expect(grant).toContain('"max":2');
    expect(count(grant, '"expires"')).toBeGreaterThan(0);
    expect(count(grant, '"delegation_depth"')).toBeGreaterThan(0);
    expect(count(task, '"expires"')).toBe(count(grant, '"expires"') + 1);
    expect(count(task, '"delegation_depth"')).toBe(count(grant, '"delegation_depth"'));
    expect(fx.proofs).toHaveLength(2);
  });
});

function plainStore(log: string[], withLock: boolean, seed: Record<string, PcaHolderState> = {}): PcaStateStore {
  const m = new Map<string, PcaHolderState>(Object.entries(seed));
  const store: PcaStateStore = {
    get: async (k) => {
      log.push(`get ${k}`);
      return m.get(k);
    },
    put: async (k, v) => {
      log.push(`put ${k} ${JSON.stringify(v)}`);
      m.set(k, v);
    },
  };
  if (withLock) {
    store.withKeyLock = (k, fn) => {
      log.push(`lock ${k}`);
      return fn();
    };
  }
  return store;
}

const fakeAdapter = (store: PcaStateStore, extra: Partial<PcaStateAdapter> = {}): PcaStateAdapter => ({ name: 'fake', open: async () => ({ store }), ...extra });

describe('claimAsStoreAdapter', () => {
  it('names the adapter and declares advance only, durable by default', () => {
    const sa = claimAsStoreAdapter(fakeAdapter(plainStore([], false)));
    expect(sa.name).toBe('fake (claim as advance)');
    expect(sa.capabilities).toEqual({ durable: true, consumeOnce: false, advance: true });
    expect(claimAsStoreAdapter(fakeAdapter(plainStore([], false), { capabilities: { durable: false } })).capabilities).toEqual({ durable: false, consumeOnce: false, advance: true });
    expect(claimAsStoreAdapter(fakeAdapter(plainStore([], false), { capabilities: { shared: false } })).capabilities).toEqual({ durable: true, consumeOnce: false, advance: true });
  });

  it('a get/put store: advances only on a strictly greater counter and keeps the other fields', async () => {
    const log: string[] = [];
    const c = await claimAsStoreAdapter(fakeAdapter(plainStore(log, false, { x: { lastEpoch: 7 } }))).open();
    expect(await c.advance!('k', 1)).toBe(true);
    expect(await c.advance!('k', 1)).toBe(false);
    expect(await c.advance!('k', 2)).toBe(true);
    expect(await c.advance!('k', 1)).toBe(false);
    expect(await c.advance!('x', 1)).toBe(true);
    expect(await c.advance!('x', 0)).toBe(false);
    expect(log).toEqual([
      'get k', 'put k {"lastCounter":1}',
      'get k',
      'get k', 'put k {"lastCounter":2}',
      'get k',
      'get x', 'put x {"lastEpoch":7,"lastCounter":1}',
      'get x',
    ]);
  });

  it('a get/put store with withKeyLock: every advance runs under the lock of its key', async () => {
    const log: string[] = [];
    const c = await claimAsStoreAdapter(fakeAdapter(plainStore(log, true))).open();
    expect(await c.advance!('k', 3)).toBe(true);
    expect(await c.advance!('j', 3)).toBe(true);
    expect(await c.advance!('k', 3)).toBe(false);
    expect(log).toEqual(['lock k', 'get k', 'put k {"lastCounter":3}', 'lock j', 'get j', 'put j {"lastCounter":3}', 'lock k', 'get k']);
  });

  it('an atomic store: claims with the counter; replay is false; any other refusal throws', async () => {
    const log: string[] = [];
    const results: Array<{ ok: true } | { ok: false; reason: 'replay'; lastCounter: number } | { ok: false; reason: 'conflict' }> = [
      { ok: true },
      { ok: false, reason: 'replay', lastCounter: 5 },
      { ok: false, reason: 'conflict' },
    ];
    const store = {
      get: async () => {
        log.push('get');
        return undefined;
      },
      put: async () => {
        log.push('put');
      },
      claim: async (k: string, c: unknown) => {
        log.push(`claim ${k} ${JSON.stringify(c)}`);
        return results.shift()!;
      },
      raisePin: async () => undefined,
    } as unknown as AtomicPcaStateStore;
    const c = await claimAsStoreAdapter(fakeAdapter(store)).open();
    expect(await c.advance!('k', 4)).toBe(true);
    expect(await c.advance!('k', 5)).toBe(false);
    const e = await c.advance!('k', 6).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(Error);
    expect((e as Error).message).toBe('claim reported a budget conflict without a budget');
    expect(log).toEqual(['claim k {"counter":4}', 'claim k {"counter":5}', 'claim k {"counter":6}']);
  });

  it('close: resolves with no close on the handle, else returns the handle close promise', async () => {
    const plain = await claimAsStoreAdapter(fakeAdapter(plainStore([], false))).open();
    const p = plain.close!();
    expect(p).toBeInstanceOf(Promise);
    await p;
    const own = Promise.resolve();
    let closed = 0;
    const withClose: PcaStateAdapter = {
      name: 'fake',
      open: async () => ({
        store: plainStore([], false),
        close: () => {
          closed++;
          return own;
        },
      }),
    };
    const c = await claimAsStoreAdapter(withClose).open();
    expect(c.close!()).toBe(own);
    expect(closed).toBe(1);
  });

  it('restart and crash are forwarded only when the adapter has them', async () => {
    const log: string[] = [];
    const none = claimAsStoreAdapter(fakeAdapter(plainStore([], false)));
    expect('crash' in none).toBe(false);
    expect('restart' in none).toBe(false);
    const both = claimAsStoreAdapter(
      fakeAdapter(plainStore([], false), {
        crash: async () => void log.push('crash'),
        restart: async () => void log.push('restart'),
      }),
    );
    await both.crash!();
    await both.restart!();
    expect(log).toEqual(['crash', 'restart']);
  });
});

describe('formatPcaStateReport', () => {
  it('renders the header and one exact line per test', () => {
    const lin = { ops: 12, violations: [{}, {}] } as unknown as TestReport;
    const r: PcaStateReport = {
      adapter: 'A',
      stateMode: 'atomic-claim',
      status: 'fail',
      tests: [
        { test: 'one-instance', status: 'pass', admitted: [1, 1], note: 'n1' },
        { test: 'claim-burst', status: 'fail', linearizability: lin },
        { test: 'processes', status: 'skip', note: 'why' },
        { test: 'instances', status: 'pass' },
        { test: 'retry-after-timeout', status: 'fail', admitted: [0, 2], linearizability: lin, note: 'z' },
      ],
    };
    expect(formatPcaStateReport(r).split('\n')).toEqual([
      'pca-store-conformance (pca-state): A [atomic-claim] -> FAIL',
      `  [PASS] ${'one-instance'.padEnd(20)} admitted per round [1,1]; n1`,
      `  [FAIL] ${'claim-burst'.padEnd(20)} 12 ops, 2 non-linearizable key(s)`,
      `  [SKIP] ${'processes'.padEnd(20)} why`,
      `  [PASS] ${'instances'.padEnd(20)} `,
      `  [FAIL] ${'retry-after-timeout'.padEnd(20)} admitted per round [0,2]; 12 ops, 2 non-linearizable key(s); z`,
    ]);
  });
});

describe('reference adapters declare what they are', () => {
  it('names and capabilities', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-kill-'));
    const durable = durableFilePcaStateAdapter({ dir });
    expect(durable.name).toBe(`durable-state file store, atomic claim (${dir})`);
    expect(durable.capabilities).toEqual({ durable: true, shared: true });
    const bad: Array<[PcaStateAdapter, string, { durable: boolean; shared: boolean }]> = [
      [getPutPcaStateAdapter(), 'BAD get/put without claim or lock', { durable: false, shared: true }],
      [readThenWriteClaimPcaStateAdapter(), 'BAD claim as read, await, write', { durable: false, shared: true }],
      [localLockPcaStateAdapter(), 'BAD per-handle lock passed off as shared', { durable: false, shared: true }],
      [volatilePcaStateAdapter(), 'BAD volatile atomic store (claims lost on restart)', { durable: true, shared: true }],
      [unsharedPcaStateAdapter(), 'BAD per-handle state passed off as shared', { durable: false, shared: true }],
    ];
    for (const [a, name, caps] of bad) {
      expect(a.name).toBe(name);
      expect(a.capabilities).toEqual(caps);
    }
  });
});

describe('loadPcaStateAdapter', () => {
  const fx = (f: string): string => join(__dirname, '..', 'test', 'fixtures', f);
  const registry = PCA_STATE_REFERENCE_ADAPTERS as unknown as Record<string, unknown>;
  const withRegistered = async (name: string, value: unknown, fn: () => Promise<void>): Promise<void> => {
    registry[name] = value;
    try {
      await fn();
    } finally {
      delete registry[name];
    }
  };
  const caught = (p: Promise<unknown>): Promise<Error> => p.then(() => new Error('did not throw'), (e: unknown) => e as Error);

  it('the durable-file built-in gets its dir option', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-kill-'));
    expect((await loadPcaStateAdapter('builtin:durable-file', { dir })).name).toBe(`durable-state file store, atomic claim (${dir})`);
  });

  it('an unknown built-in lists the known ones', async () => {
    const e = await caught(loadPcaStateAdapter('builtin:nope'));
    expect(e.message).toBe(
      "unknown built-in pca-state adapter 'nope' (known: in-memory, durable-file, bad-get-put, bad-read-then-write-claim, bad-local-lock, bad-volatile, bad-unshared)",
    );
  });

  it('refuses something that is not an adapter, with the spec in the message', async () => {
    const open = async () => ({ store: plainStore([], false) });
    const cases: Array<[string, unknown]> = [
      ['t-undefined', () => undefined],
      ['t-no-open', () => ({ name: 'x' })],
      ['t-open-not-fn', () => ({ name: 'x', open: 1 })],
      ['t-no-name', () => ({ open })],
      ['t-name-not-string', () => ({ name: 5, open })],
    ];
    for (const [name, factory] of cases) {
      await withRegistered(name, factory, async () => {
        const e = await caught(loadPcaStateAdapter(`builtin:${name}`));
        expect(e).toBeInstanceOf(TypeError);
        expect(e.message).toBe(`builtin:${name}: does not export a pca-state adapter`);
      });
    }
  });

  it('accepts a factory (sync or async) and a plain object', async () => {
    const open = async () => ({ store: plainStore([], false) });
    const seen: Array<Record<string, string>> = [];
    await withRegistered('t-factory', (o: Record<string, string>) => (seen.push(o), { name: 'made', open }), async () => {
      expect((await loadPcaStateAdapter('builtin:t-factory', { a: '1' })).name).toBe('made');
    });
    expect(seen).toEqual([{ a: '1' }]);
    await withRegistered('t-async', async () => ({ name: 'made async', open }), async () => {
      expect((await loadPcaStateAdapter('builtin:t-async')).name).toBe('made async');
    });
    const obj = { name: 'plain object', open };
    await withRegistered('t-object', obj, async () => {
      expect(await loadPcaStateAdapter('builtin:t-object')).toBe(obj);
    });
  });

  it('module exports: factory, object, skipping junk / null / objects without open, then the base kit picks', async () => {
    expect((await loadPcaStateAdapter(fx('pca-state-load-factory.mjs'), { label: 'L' })).name).toBe('ps factory L');
    expect((await loadPcaStateAdapter(fx('pca-state-load-factory.mjs'))).name).toBe('ps factory none');
    expect((await loadPcaStateAdapter(fx('pca-state-load-object.mjs'))).name).toBe('ps object');
    expect((await loadPcaStateAdapter(fx('pca-state-load-junk-first.mjs'))).name).toBe('ps second');
    expect((await loadPcaStateAdapter(fx('pca-state-load-null-first.mjs'))).name).toBe('ps after null');
    expect((await loadPcaStateAdapter(fx('pca-state-load-no-open.mjs'))).name).toBe('ps default fallback');
    expect((await loadPcaStateAdapter(fx('pca-state-load-default.mjs'))).name).toBe('ps default only');
    const e = await caught(loadPcaStateAdapter(fx('pca-state-load-none.mjs')));
    expect(e).toBeInstanceOf(TypeError);
    expect(e.message).toBe(`${fx('pca-state-load-none.mjs')}: does not export a pca-state adapter`);
  });
});
