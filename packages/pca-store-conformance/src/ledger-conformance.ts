/**
 * Conformance for PCA transparency-log stores (`LedgerStore`, `@atlasauth/pca/ext/ledger`).
 *
 * A ledger store keeps the commits of an append-only log and its signed checkpoints. What it must get right: positions are
 * assigned exactly once (compare-and-swap on the length, so two writers never take one index and the log never has holes),
 * a batch lands entirely or not at all, retrying a committed batch is a replay, checkpoints never move backwards and never
 * point past the log, acknowledged writes survive a restart or a crash, and a write in flight at a crash is either wholly
 * there or wholly absent. Each check is one such claim, driven against YOUR store through a `LedgerStoreAdapter`.
 */
import assert from 'node:assert/strict';
import { createMemoryDurableKv, openDurableState } from '@atlasauth/pca/durable-state';
import { KvLedgerStore, appendToLedgerDoc, emptyLedgerDoc, type Checkpoint, type LedgerDoc, type LedgerStore } from '@atlasauth/pca/ext/ledger';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export interface LedgerStoreHandle {
  store: LedgerStore;
  /** Another client on the SAME backend (the first stays usable). */
  reopen(): Promise<LedgerStore>;
  /** Optional: kill the backend abruptly, then return a client on whatever survived. */
  crash?(): Promise<LedgerStore>;
  close?(): Promise<void>;
}
export interface LedgerStoreAdapter {
  name: string;
  /** Default true. Declare false ONLY for an in-process store; the durability checks are then skipped and reported. */
  durable?: boolean;
  create(): Promise<LedgerStoreHandle>;
}
export interface LedgerCheck {
  name: string;
  claim: string;
  needs?: 'durable' | 'crash';
  run(h: LedgerStoreHandle): Promise<void>;
}

const cm = (i: number): string => `commit-${i}-${'x'.repeat(30)}`;
const cp = (size: number, root = `root-${size}`, prev = ''): Checkpoint => ({ sth: { instance_id: 'i', principal: 'p', size, root, prev_root: prev, timestamp: 1, guardian: 'g', sig: 's' } });
const range = (a: number, b: number): string[] => Array.from({ length: b - a }, (_, i) => cm(a + i));
const all = async (s: LedgerStore): Promise<string[]> => s.read(0, await s.size());
/** A writer that retries until its commit is in, the way a real client does. */
async function appendRetrying(s: LedgerStore, commit: string): Promise<number> {
  for (;;) {
    const size = await s.size();
    const r = await s.append(size, [commit]);
    if (r.outcome === 'appended' || r.outcome === 'replayed') return size;
  }
}

export const LEDGER_CHECKS: readonly LedgerCheck[] = [
  {
    name: 'empty-store-is-empty',
    claim: 'a new store has no entries and no checkpoints, and reads of the empty range succeed',
    async run({ store }) {
      assert.equal(await store.size(), 0);
      assert.deepEqual(await store.read(0, 0), []);
      assert.equal(await store.checkpointCount(), 0);
      assert.deepEqual(await store.checkpoints(0), []);
    },
  },
  {
    name: 'append-assigns-the-next-position',
    claim: 'an append at the current length adds its commits in order at exactly those positions',
    async run({ store }) {
      assert.deepEqual(await store.append(0, [cm(0)]), { outcome: 'appended', size: 1 });
      assert.deepEqual(await store.append(1, [cm(1), cm(2)]), { outcome: 'appended', size: 3 });
      assert.deepEqual(await store.read(0, 3), range(0, 3));
      assert.deepEqual(await store.read(1, 3), range(1, 3));
      assert.deepEqual(await store.read(3, 3), []);
    },
  },
  {
    name: 'append-at-another-position-conflicts-without-trace',
    claim: 'an append whose expected length is not the current length conflicts, reports the real length, and writes nothing',
    async run({ store }) {
      await store.append(0, range(0, 3));
      assert.deepEqual(await store.append(5, [cm(9)]), { outcome: 'conflict', size: 3 });
      assert.deepEqual(await store.append(2, [cm(9)]), { outcome: 'conflict', size: 3 });
      assert.deepEqual(await all(store), range(0, 3));
    },
  },
  {
    name: 'append-retry-is-a-replay',
    claim: 'repeating a batch already stored at that position is a replay (a prefix of it too); a different batch there conflicts',
    async run({ store }) {
      await store.append(0, range(0, 3));
      assert.deepEqual(await store.append(0, range(0, 3)), { outcome: 'replayed', size: 3 });
      assert.deepEqual(await store.append(1, range(1, 3)), { outcome: 'replayed', size: 3 });
      assert.deepEqual(await store.append(0, [cm(0), 'other']), { outcome: 'conflict', size: 3 });
      assert.deepEqual(await store.append(2, [cm(2), cm(3)]), { outcome: 'conflict', size: 3 });
      assert.deepEqual(await all(store), range(0, 3));
    },
  },
  {
    name: 'invalid-input-is-refused',
    claim: 'empty batches, empty or non-string commits and a bad expected length throw and write nothing',
    async run({ store }) {
      await store.append(0, [cm(0)]);
      for (const bad of [[], [''], [cm(1), 7 as never], 'x' as never]) await assert.rejects(store.append(1, bad), RangeError);
      for (const bad of [-1, 1.5, Number.NaN]) await assert.rejects(store.append(bad, [cm(1)]), RangeError);
      assert.deepEqual(await all(store), [cm(0)]);
      for (const [f, t] of [[-1, 1], [1, 0], [0, 2], [0.5, 1]] as const) await assert.rejects(store.read(f, t), RangeError);
    },
  },
  {
    name: 'commit-strings-are-stored-exactly',
    claim: 'unicode, quotes, separators and long commits come back byte for byte',
    async run({ store }) {
      const odd = ['a"b\\c', 'gränt-\u{1F512}- -\u0001', 'x'.repeat(5000), '__proto__', ' leading and trailing '];
      await store.append(0, odd);
      assert.deepEqual(await all(store), odd);
    },
  },
  {
    name: 'racing-appends-at-one-position-have-one-winner',
    claim: 'clients appending at the same expected length: exactly one is appended, none is lost or duplicated, the log is the winner batch',
    async run(h) {
      const others = await Promise.all([h.reopen(), h.reopen(), h.reopen()]);
      const clients = [h.store, ...others];
      const r = await Promise.all(Array.from({ length: 8 }, (_, i) => clients[i % 4]!.append(0, [cm(100 + i)])));
      assert.equal(r.filter((x) => x.outcome === 'appended').length, 1);
      assert.equal(r.filter((x) => x.outcome === 'conflict').length, 7);
      const log = await all(h.store);
      assert.equal(log.length, 1);
      assert.ok(range(100, 108).includes(log[0]!));
    },
  },
  {
    name: 'racing-writers-with-retry-fill-every-position-once',
    claim: 'sixteen writers each retrying until their commit is in: positions are unique, there are no holes, every commit is present exactly once',
    async run(h) {
      const clients = [h.store, await h.reopen(), await h.reopen()];
      const idx = await Promise.all(Array.from({ length: 16 }, (_, i) => appendRetrying(clients[i % 3]!, cm(200 + i))));
      assert.equal(new Set(idx).size, 16);
      assert.deepEqual([...idx].sort((a, b) => a - b), Array.from({ length: 16 }, (_, i) => i));
      const log = await all(h.store);
      assert.deepEqual([...log].sort(), range(200, 216).sort());
      idx.forEach((p, i) => assert.equal(log[p], cm(200 + i)));
    },
  },
  {
    name: 'a-batch-is-all-or-nothing',
    claim: 'a batch that conflicts leaves none of its commits behind, and a batch that lands lands every commit',
    async run({ store }) {
      await store.append(0, range(0, 2));
      assert.equal((await store.append(5, range(10, 14))).outcome, 'conflict');
      assert.deepEqual(await all(store), range(0, 2));
      assert.deepEqual(await store.append(2, range(10, 14)), { outcome: 'appended', size: 6 });
      assert.deepEqual(await all(store), [...range(0, 2), ...range(10, 14)]);
    },
  },
  {
    name: 'checkpoints-append-by-count-and-replay',
    claim: 'a checkpoint appends at the exact count; the same one again is a replay; another at that position conflicts',
    async run({ store }) {
      await store.append(0, range(0, 6));
      assert.deepEqual(await store.appendCheckpoint(0, cp(2)), { outcome: 'appended', count: 1 });
      assert.deepEqual(await store.appendCheckpoint(0, cp(2)), { outcome: 'replayed', count: 1 });
      assert.equal((await store.appendCheckpoint(0, cp(3))).outcome, 'conflict');
      assert.equal((await store.appendCheckpoint(2, cp(3))).outcome, 'conflict');
      assert.deepEqual(await store.appendCheckpoint(1, cp(5, 'root-5', 'root-2')), { outcome: 'appended', count: 2 });
      assert.deepEqual((await store.checkpoints(0)).map((c) => c.sth.size), [2, 5]);
      assert.deepEqual((await store.checkpoints(1)).map((c) => c.sth.size), [5]);
      assert.equal(await store.checkpointCount(), 2);
    },
  },
  {
    name: 'checkpoints-stay-inside-the-log-and-never-go-back',
    claim: 'a checkpoint beyond the end of the log, below the previous one, or equal in size with another root is refused',
    async run({ store }) {
      await store.append(0, range(0, 4));
      assert.equal((await store.appendCheckpoint(0, cp(5))).outcome, 'conflict');
      assert.equal((await store.appendCheckpoint(0, cp(3))).outcome, 'appended');
      assert.equal((await store.appendCheckpoint(1, cp(2))).outcome, 'conflict');
      assert.equal((await store.appendCheckpoint(1, cp(3, 'other-root'))).outcome, 'conflict');
      assert.equal((await store.appendCheckpoint(1, cp(3))).outcome, 'appended'); // equal size, same root: allowed
      assert.equal((await store.appendCheckpoint(2, null as never)).outcome, 'conflict');
      assert.equal(await store.checkpointCount(), 2);
    },
  },
  {
    name: 'racing-checkpoints-have-one-winner',
    claim: 'checkpoints racing for one position: exactly one lands',
    async run(h) {
      await h.store.append(0, range(0, 6));
      const other = await h.reopen();
      const r = await Promise.all([h.store.appendCheckpoint(0, cp(2)), other.appendCheckpoint(0, cp(3)), h.store.appendCheckpoint(0, cp(4)), other.appendCheckpoint(0, cp(5))]);
      assert.equal(r.filter((x) => x.outcome === 'appended').length, 1);
      assert.equal(await h.store.checkpointCount(), 1);
    },
  },
  {
    name: 'reads-are-snapshots',
    claim: 'mutating what a read returned cannot change the store',
    async run({ store }) {
      await store.append(0, range(0, 3));
      await store.appendCheckpoint(0, cp(2));
      (await store.read(0, 3))[0] = 'mutated';
      const c = await store.checkpoints(0);
      c[0]!.sth.size = 99;
      assert.deepEqual(await all(store), range(0, 3));
      assert.equal((await store.checkpoints(0))[0]!.sth.size, 2);
    },
  },
  {
    name: 'state-survives-reopen',
    claim: 'every acknowledged append and checkpoint is visible to a new client after the backend restarts',
    needs: 'durable',
    async run(h) {
      await h.store.append(0, range(0, 5));
      await h.store.appendCheckpoint(0, cp(3));
      await h.store.append(5, range(5, 7));
      const back = await h.reopen();
      assert.deepEqual(await all(back), range(0, 7));
      assert.deepEqual(await back.checkpoints(0), [cp(3)]);
      assert.deepEqual(await back.append(7, [cm(7)]), { outcome: 'appended', size: 8 });
    },
  },
  {
    name: 'acknowledged-writes-survive-a-crash',
    claim: 'after an abrupt kill every acknowledged write is present and the log is a prefix of what was written: no holes, no partial batch',
    needs: 'crash',
    async run(h) {
      await h.store.append(0, range(0, 3));
      await h.store.appendCheckpoint(0, cp(2));
      const inflight = h.store.append(3, range(3, 7)).catch(() => undefined);
      const back = await h.crash!();
      void inflight;
      const log = await all(back);
      assert.ok(log.length === 3 || log.length === 7, `log has ${log.length} entries`); // the batch of four is whole or absent
      assert.deepEqual(log, range(0, log.length));
      assert.deepEqual(await back.checkpoints(0), [cp(2)]);
      if (log.length === 3) assert.deepEqual(await back.append(3, range(3, 7)), { outcome: 'appended', size: 7 });
      else assert.deepEqual(await back.append(3, range(3, 7)), { outcome: 'replayed', size: 7 });
      assert.deepEqual(await all(back), range(0, 7));
    },
  },
];

export interface LedgerCheckResult {
  name: string;
  status: 'pass' | 'fail' | 'skip';
  detail?: string;
}
export interface LedgerConformanceReport {
  adapter: string;
  status: 'pass' | 'fail';
  checks: LedgerCheckResult[];
}

export async function runLedgerStoreConformance(adapter: LedgerStoreAdapter, opts: { only?: readonly string[] } = {}): Promise<LedgerConformanceReport> {
  const checks: LedgerCheckResult[] = [];
  for (const c of LEDGER_CHECKS) {
    if (opts.only && !opts.only.includes(c.name)) continue;
    if (c.needs === 'durable' && adapter.durable === false) {
      checks.push({ name: c.name, status: 'skip', detail: 'the adapter declares durable: false' });
      continue;
    }
    const h = await adapter.create();
    try {
      if (c.needs === 'crash' && !h.crash) {
        checks.push({ name: c.name, status: 'skip', detail: 'the adapter has no crash()' });
        continue;
      }
      await c.run(h);
      checks.push({ name: c.name, status: 'pass' });
    } catch (e) {
      checks.push({ name: c.name, status: 'fail', detail: e instanceof Error ? e.message : String(e) });
    } finally {
      await h.close?.();
    }
  }
  return { adapter: adapter.name, status: checks.some((x) => x.status === 'fail') ? 'fail' : 'pass', checks };
}

export function formatLedgerReport(r: LedgerConformanceReport): string {
  return [`pca-store-conformance (ledger store): ${r.adapter} -> ${r.status.toUpperCase()}`, ...r.checks.map((c) => `  [${c.status.toUpperCase()}] ${c.name}${c.detail ? `: ${c.detail.split('\n')[0]}` : ''}`)].join('\n');
}

type It = (name: string, fn: () => Promise<void>, timeout?: number) => unknown;
type Describe = (name: string, fn: () => void) => unknown;

/** Register one test-runner test per check (vitest / jest globals, or pass `runner`). */
export function describeLedgerStoreConformance(adapter: LedgerStoreAdapter | (() => LedgerStoreAdapter), opts: { runner?: { describe: Describe; it: It }; timeoutMs?: number } = {}): void {
  const g = globalThis as { describe?: Describe; it?: It };
  const describe = opts.runner?.describe ?? g.describe;
  const it = opts.runner?.it ?? g.it;
  if (!describe || !it) throw new Error('describeLedgerStoreConformance needs describe/it: pass { runner } or enable test globals');
  const a = typeof adapter === 'function' ? adapter() : adapter;
  describe(`PCA ledger store conformance: ${a.name}`, () => {
    for (const c of LEDGER_CHECKS) {
      it(
        `${c.name}: ${c.claim}`,
        async () => {
          const x = (await runLedgerStoreConformance(typeof adapter === 'function' ? adapter() : adapter, { only: [c.name] })).checks[0]!;
          if (x.status === 'fail') throw new Error(x.detail);
        },
        opts.timeoutMs ?? 60_000,
      );
    }
  });
}

// ---- reference adapters --------------------------------------------------------------------------------------------------

export function memoryLedgerStoreAdapter(): LedgerStoreAdapter {
  return {
    name: 'KvLedgerStore over an in-memory kv',
    durable: false,
    async create() {
      const kv = createMemoryDurableKv();
      return { store: new KvLedgerStore(kv), reopen: async () => new KvLedgerStore(kv) };
    },
  };
}

export function durableLedgerStoreAdapter(options: { dir?: string } = {}): LedgerStoreAdapter {
  return {
    name: 'KvLedgerStore over durable-state files',
    durable: true,
    async create() {
      const dir = options.dir ?? mkdtempSync(join(tmpdir(), 'pca-ledgersc-'));
      const open = async (): Promise<LedgerStore> => new KvLedgerStore(await openDurableState({ dir, lockTimeoutMs: 30_000 }));
      return { store: await open(), reopen: open, crash: open };
    },
  };
}

/** A document store with a switchable defect, for the positive controls (each reproduces a real mistake). */
function defective(defect: 'no-cas' | 'partial-batch' | 'lost-update' | 'amnesia' | 'checkpoint-regress' | 'no-replay'): LedgerStoreAdapter {
  const names = {
    'no-cas': 'BAD no compare-and-swap (appends at the tail whatever the caller saw)',
    'partial-batch': 'BAD partial batch (a conflicting batch leaves its first commit behind)',
    'lost-update': 'BAD lost update (read, await, write)',
    amnesia: 'BAD amnesia (claims durability, forgets on reopen)',
    'checkpoint-regress': 'BAD checkpoint regression (accepts a checkpoint below the previous one)',
    'no-replay': 'BAD no idempotence (a retried batch conflicts)',
  } as const;
  return {
    name: names[defect],
    durable: true,
    async create() {
      let doc: LedgerDoc = emptyLedgerDoc();
      const clone = (d: LedgerDoc): LedgerDoc => structuredClone(d);
      const client = (): LedgerStore => ({
        size: async () => doc.commits.length,
        read: async (f, t) => {
          if (!Number.isSafeInteger(f) || !Number.isSafeInteger(t) || f < 0 || f > t || t > doc.commits.length) throw new RangeError('read');
          return doc.commits.slice(f, t);
        },
        append: async (expected, commits) => {
          if (!Number.isSafeInteger(expected) || expected < 0 || !Array.isArray(commits) || commits.length === 0 || !commits.every((c) => typeof c === 'string' && c.length > 0)) throw new RangeError('append');
          if (defect === 'no-cas') {
            doc.commits.push(...commits);
            return { outcome: 'appended', size: doc.commits.length };
          }
          if (defect === 'partial-batch' && expected !== doc.commits.length) {
            doc.commits.push(commits[0]!);
            return { outcome: 'conflict', size: doc.commits.length };
          }
          const work = defect === 'lost-update' ? clone(doc) : doc;
          if (defect === 'lost-update') await new Promise((r) => setImmediate(r));
          const out = appendToLedgerDoc(work, expected, commits);
          if (defect === 'lost-update' && out.outcome === 'appended') doc = work;
          if (defect === 'no-replay' && out.outcome === 'replayed') return { outcome: 'conflict', size: out.size };
          return out;
        },
        checkpointCount: async () => doc.checkpoints.length,
        checkpoints: async (from = 0) => structuredClone(doc.checkpoints.slice(from)),
        appendCheckpoint: async (expected, c) => {
          if (defect === 'checkpoint-regress' && expected === doc.checkpoints.length && c?.sth) {
            doc.checkpoints.push(structuredClone(c));
            return { outcome: 'appended', count: doc.checkpoints.length };
          }
          const count = doc.checkpoints.length;
          if (expected !== count) return { outcome: 'conflict', count, reason: 'position' };
          const last = doc.checkpoints[count - 1]?.sth;
          if (!c?.sth || c.sth.size > doc.commits.length || (last && (c.sth.size < last.size || (c.sth.size === last.size && c.sth.root !== last.root)))) return { outcome: 'conflict', count, reason: 'invalid' };
          doc.checkpoints.push(structuredClone(c));
          return { outcome: 'appended', count: doc.checkpoints.length };
        },
      });
      const again = async (): Promise<LedgerStore> => {
        if (defect === 'amnesia') doc = emptyLedgerDoc();
        return client();
      };
      return { store: client(), reopen: again, crash: again };
    },
  };
}
export const noCasLedgerStoreAdapter = (): LedgerStoreAdapter => defective('no-cas');
export const partialBatchLedgerStoreAdapter = (): LedgerStoreAdapter => defective('partial-batch');
export const lostUpdateLedgerStoreAdapter = (): LedgerStoreAdapter => defective('lost-update');
export const amnesiaLedgerStoreAdapter = (): LedgerStoreAdapter => defective('amnesia');
export const checkpointRegressLedgerStoreAdapter = (): LedgerStoreAdapter => defective('checkpoint-regress');
export const noReplayLedgerStoreAdapter = (): LedgerStoreAdapter => defective('no-replay');

export const LEDGER_REFERENCE_ADAPTERS: Readonly<Record<string, () => LedgerStoreAdapter>> = {
  'ledger-memory': memoryLedgerStoreAdapter,
  'ledger-durable-file': () => durableLedgerStoreAdapter(),
  'bad-ledger-no-cas': noCasLedgerStoreAdapter,
  'bad-ledger-partial-batch': partialBatchLedgerStoreAdapter,
  'bad-ledger-lost-update': lostUpdateLedgerStoreAdapter,
  'bad-ledger-amnesia': amnesiaLedgerStoreAdapter,
  'bad-ledger-checkpoint-regress': checkpointRegressLedgerStoreAdapter,
  'bad-ledger-no-replay': noReplayLedgerStoreAdapter,
};
