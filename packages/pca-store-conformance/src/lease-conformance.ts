/**
 * Conformance for PCA guardian lease stores (`LeaseStore`, `@atlasauth/pca/ext/research`).
 *
 * A lease store holds the one record that says who the guardian leader is. What it must get right: the compare-and-swap is
 * linearizable (one winner among racing contenders, a wrong `expected` never writes), the fencing epoch never goes down,
 * a stale holder cannot renew or release after a takeover, its clock is a finite number, and acknowledged leases survive a
 * restart or crash. Each check is one such claim, driven against YOUR store through a `LeaseStoreAdapter`.
 */
import assert from 'node:assert/strict';
import { createMemoryDurableKv, openDurableState } from '@atlasauth/pca/durable-state';
import { KvLeaseStore, acquireLease, releaseLease, renewLease, type LeaseRecord, type LeaseStore } from '@atlasauth/pca/ext/research';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export interface LeaseStoreHandle {
  store: LeaseStore;
  /** Another client on the SAME backend (the first stays usable). */
  reopen(): Promise<LeaseStore>;
  /** Optional: kill the backend abruptly, then return a client on whatever survived. */
  crash?(): Promise<LeaseStore>;
  close?(): Promise<void>;
}
export interface LeaseStoreAdapter {
  name: string;
  /** Default true. Declare false ONLY for an in-process store; the durability checks are then skipped and reported. */
  durable?: boolean;
  create(): Promise<LeaseStoreHandle>;
}
export interface LeaseCheck {
  name: string;
  claim: string;
  needs?: 'durable' | 'crash';
  run(h: LeaseStoreHandle): Promise<void>;
}

const O = { ttlMs: 600_000, skewMs: 1_000 };
const won = async (s: LeaseStore, who: string): Promise<LeaseRecord> => {
  const r = await acquireLease(s, who, O);
  assert.ok(r.ok, `acquire for ${who} failed: ${r.ok ? '' : r.reason}`);
  return r.lease;
};

export const LEASE_CHECKS: readonly LeaseCheck[] = [
  {
    name: 'empty-store-has-no-lease',
    claim: 'a new store has no lease and a finite clock',
    async run({ store }) {
      assert.equal(await store.read(), undefined);
      assert.ok(Number.isFinite(await store.now()));
    },
  },
  {
    name: 'first-acquire-is-epoch-1',
    claim: 'the first holder gets epoch 1 and an expiry from the store clock',
    async run({ store }) {
      const l = await won(store, 'a');
      assert.equal(l.epoch, 1);
      assert.deepEqual(await store.read(), l);
      assert.ok(l.expiresAt > (await store.now()));
    },
  },
  {
    name: 'wrong-expected-record-never-writes',
    claim: 'cas with an expected record that is not the stored one returns false and changes nothing',
    async run({ store }) {
      assert.equal(await store.cas({ holder: 'x', epoch: 1, expiresAt: 5 }, { holder: 'y', epoch: 2, expiresAt: 9 }), false);
      assert.equal(await store.read(), undefined);
      const l = await won(store, 'a');
      assert.equal(await store.cas(undefined, { holder: 'y', epoch: 2, expiresAt: 9 }), false);
      assert.deepEqual(await store.read(), l);
    },
  },
  {
    name: 'racing-acquirers-have-one-winner',
    claim: 'many contenders at once: exactly one acquires, at epoch 1',
    async run({ store, reopen }) {
      const clients = [store, await reopen(), await reopen(), await reopen()];
      const rs = await Promise.all(clients.flatMap((c, i) => [acquireLease(c, `h${i}a`, O), acquireLease(c, `h${i}b`, O)]));
      assert.equal(rs.filter((r) => r.ok).length, 1);
      assert.equal((await store.read())?.epoch, 1);
    },
  },
  {
    name: 'takeover-after-release-bumps-the-epoch',
    claim: 'a released lease is free at once and the next holder gets a strictly higher epoch',
    async run({ store }) {
      const a = await won(store, 'a');
      assert.ok((await releaseLease(store, a)).ok);
      assert.equal((await won(store, 'b')).epoch, 2);
    },
  },
  {
    name: 'epoch-never-goes-down',
    claim: 'cas refuses a record with a lower epoch even when the expected record matches',
    async run({ store }) {
      const a = await won(store, 'a');
      await releaseLease(store, a);
      const b = await won(store, 'b');
      let ok: boolean;
      try {
        ok = await store.cas(b, { holder: 'z', epoch: 1, expiresAt: b.expiresAt });
      } catch {
        ok = false;
      }
      assert.equal(ok, false);
      assert.deepEqual(await store.read(), b);
    },
  },
  {
    name: 'stale-holder-cannot-renew-or-release',
    claim: 'after a takeover the old (holder, epoch) is refused as stale for renew and release',
    async run({ store }) {
      const a = await won(store, 'a');
      await releaseLease(store, a);
      const b = await won(store, 'b');
      assert.deepEqual(await renewLease(store, a, O), { ok: false, reason: 'stale' });
      assert.deepEqual(await releaseLease(store, a), { ok: false, reason: 'stale' });
      assert.deepEqual(await store.read(), b);
    },
  },
  {
    name: 'state-survives-reopen',
    claim: 'an acknowledged lease is there when another client opens the same backend',
    needs: 'durable',
    async run({ store, reopen }) {
      const l = await won(store, 'a');
      assert.deepEqual(await (await reopen()).read(), l);
    },
  },
  {
    name: 'acknowledged-lease-survives-a-crash',
    claim: 'after an abrupt backend kill the lease and its epoch are still there, and the next epoch is higher',
    needs: 'crash',
    async run({ store, crash }) {
      const a = await won(store, 'a');
      await releaseLease(store, a);
      const back = await crash!();
      assert.equal((await back.read())?.epoch, 1);
      assert.equal((await won(back, 'b')).epoch, 2);
    },
  },
];

export interface LeaseCheckResult {
  name: string;
  status: 'pass' | 'fail' | 'skip';
  detail?: string;
}
export interface LeaseConformanceReport {
  adapter: string;
  status: 'pass' | 'fail';
  checks: LeaseCheckResult[];
}

export async function runLeaseStoreConformance(adapter: LeaseStoreAdapter, opts: { only?: readonly string[] } = {}): Promise<LeaseConformanceReport> {
  const checks: LeaseCheckResult[] = [];
  for (const c of LEASE_CHECKS) {
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

export function formatLeaseReport(r: LeaseConformanceReport): string {
  return [`pca-store-conformance (lease store): ${r.adapter} -> ${r.status.toUpperCase()}`, ...r.checks.map((c) => `  [${c.status.toUpperCase()}] ${c.name}${c.detail ? `: ${c.detail.split('\n')[0]}` : ''}`)].join('\n');
}

type It = (name: string, fn: () => Promise<void>, timeout?: number) => unknown;
type Describe = (name: string, fn: () => void) => unknown;

/** Register one test-runner test per check (vitest / jest globals, or pass `runner`). */
export function describeLeaseStoreConformance(adapter: LeaseStoreAdapter | (() => LeaseStoreAdapter), opts: { runner?: { describe: Describe; it: It }; timeoutMs?: number } = {}): void {
  const g = globalThis as { describe?: Describe; it?: It };
  const describe = opts.runner?.describe ?? g.describe;
  const it = opts.runner?.it ?? g.it;
  if (!describe || !it) throw new Error('describeLeaseStoreConformance needs describe/it: pass { runner } or enable test globals');
  const a = typeof adapter === 'function' ? adapter() : adapter;
  describe(`PCA lease store conformance: ${a.name}`, () => {
    for (const c of LEASE_CHECKS) {
      it(
        `${c.name}: ${c.claim}`,
        async () => {
          const x = (await runLeaseStoreConformance(typeof adapter === 'function' ? adapter() : adapter, { only: [c.name] })).checks[0]!;
          if (x.status === 'fail') throw new Error(x.detail);
        },
        opts.timeoutMs ?? 60_000,
      );
    }
  });
}

// ---- reference adapters --------------------------------------------------------------------------------------------------

export function memoryLeaseStoreAdapter(): LeaseStoreAdapter {
  return {
    name: 'KvLeaseStore over an in-memory kv',
    durable: false,
    async create() {
      const kv = createMemoryDurableKv();
      return { store: new KvLeaseStore(kv), reopen: async () => new KvLeaseStore(kv) };
    },
  };
}

export function durableLeaseStoreAdapter(options: { dir?: string } = {}): LeaseStoreAdapter {
  return {
    name: 'KvLeaseStore over durable-state files',
    durable: true,
    async create() {
      const dir = options.dir ?? mkdtempSync(join(tmpdir(), 'pca-leasesc-'));
      const open = async (): Promise<LeaseStore> => new KvLeaseStore(await openDurableState({ dir, lockTimeoutMs: 30_000 }));
      return { store: await open(), reopen: open, crash: open };
    },
  };
}

/** A store with a switchable defect, for the positive controls (each reproduces a real mistake). */
function defective(defect: 'no-cas' | 'epoch-regress' | 'lost-update' | 'amnesia'): LeaseStoreAdapter {
  const names = {
    'no-cas': 'BAD no compare-and-swap (writes whatever the caller expected)',
    'epoch-regress': 'BAD epoch regression (accepts a lower fencing epoch)',
    'lost-update': 'BAD lost update (read, await, write)',
    amnesia: 'BAD amnesia (claims durability, forgets on reopen)',
  } as const;
  return {
    name: names[defect],
    durable: true,
    async create() {
      let rec: LeaseRecord | undefined;
      const same = (a?: LeaseRecord, b?: LeaseRecord): boolean => (a && b ? a.holder === b.holder && a.epoch === b.epoch && a.expiresAt === b.expiresAt : a === b);
      const client = (): LeaseStore => ({
        read: async () => (rec ? { ...rec } : undefined),
        now: async () => Date.now(),
        cas: async (expected, next) => {
          if (defect === 'no-cas') {
            rec = { ...next };
            return true;
          }
          const seen = rec;
          if (defect === 'lost-update') await new Promise((r) => setImmediate(r));
          if (!same(defect === 'lost-update' ? seen : rec, expected)) return false;
          if (defect !== 'epoch-regress' && next.epoch < (rec?.epoch ?? 0)) return false;
          rec = { ...next };
          return true;
        },
      });
      const again = async (): Promise<LeaseStore> => {
        if (defect === 'amnesia') rec = undefined;
        return client();
      };
      return { store: client(), reopen: again, crash: again };
    },
  };
}
export const noCasLeaseStoreAdapter = (): LeaseStoreAdapter => defective('no-cas');
export const epochRegressLeaseStoreAdapter = (): LeaseStoreAdapter => defective('epoch-regress');
export const lostUpdateLeaseStoreAdapter = (): LeaseStoreAdapter => defective('lost-update');
export const amnesiaLeaseStoreAdapter = (): LeaseStoreAdapter => defective('amnesia');

export const LEASE_REFERENCE_ADAPTERS: Readonly<Record<string, () => LeaseStoreAdapter>> = {
  'lease-memory': memoryLeaseStoreAdapter,
  'lease-durable-file': () => durableLeaseStoreAdapter(),
  'bad-lease-no-cas': noCasLeaseStoreAdapter,
  'bad-lease-epoch-regress': epochRegressLeaseStoreAdapter,
  'bad-lease-lost-update': lostUpdateLeaseStoreAdapter,
  'bad-lease-amnesia': amnesiaLeaseStoreAdapter,
};
