/**
 * Conformance for PCA bond-settlement stores (`BondStore`, `@atlasauth/pca/ext/optimistic`).
 *
 * A bond store keeps INTERNAL ACCOUNTING for the optimistic path (escrow, depositors, challengers, treasury); no money
 * moves. What it must get right is atomicity and idempotence: a transition (open, release, slash) applies in full or not
 * at all, a retry of a committed transition returns the stored record and moves nothing, two racing transitions on one bond
 * have exactly one winner, and an acknowledged commit survives a restart or a crash. Each check below is one such
 * claim, driven against YOUR store through a `BondStoreAdapter`; a violation throws with the exact mismatch.
 */
import assert from 'node:assert/strict';
import { createMemoryDurableKv, openDurableState } from '@atlasauth/pca/durable-state';
import { KvBondStore, commitBondPlan, emptyBondDoc, type BondCommitOutcome, type BondDoc, type BondPlan, type BondSnapshot, type BondStore, type SettlementRecord } from '@atlasauth/pca/ext/optimistic';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** One isolated backend plus the means to reconnect to it. */
export interface BondStoreHandle {
  /** A client on the backend. */
  store: BondStore;
  /** Another client on the SAME backend (the first stays usable). After a restart this is how state is read back. */
  reopen(): Promise<BondStore>;
  /** Optional: kill the backend abruptly (no flush, no close), then return a client on whatever survived. */
  crash?(): Promise<BondStore>;
  close?(): Promise<void>;
}

export interface BondStoreAdapter {
  name: string;
  /** Default true. Declare false ONLY for an in-process store; the durability checks are then skipped and reported. */
  durable?: boolean;
  /** A fresh, empty, isolated backend. Called once per check. */
  create(): Promise<BondStoreHandle>;
}

export interface BondCheck {
  name: string;
  /** What the check proves, one sentence. */
  claim: string;
  needs?: 'durable' | 'crash';
  run(h: BondStoreHandle): Promise<void>;
}

// ---- plan builders (the store never verifies signatures; records are opaque to it) ------------------------------

const rec = (claimId: string, action: SettlementRecord['action'], amount: number, from: string, to: string, evidenceDigest = '', split?: SettlementRecord['split']): SettlementRecord => ({
  claimId,
  action,
  amount,
  from,
  to,
  at: 1,
  evidenceDigest,
  ...(split ? { split } : {}),
  sig: 'sig',
});
const openPlan = (id: string, dep: string, amount: number, caps = { maxOpenClaims: 100, maxOpenAmount: 1e9 }): BondPlan => ({
  claimId: id,
  expect: 'none',
  next: 'open',
  open: { amount, depositor: dep, ...caps },
  moves: [
    { account: dep, op: 'debit', amount },
    { account: 'escrow', op: 'credit', amount },
  ],
  record: rec(id, 'open', amount, dep, 'escrow'),
});
const releasePlan = (id: string, dep: string, amount: number): BondPlan => ({
  claimId: id,
  expect: 'open',
  next: 'released',
  moves: [
    { account: 'escrow', op: 'debit', amount },
    { account: dep, op: 'credit', amount },
  ],
  record: rec(id, 'release', amount, 'escrow', dep),
});
const slashPlan = (id: string, amount: number, evidence = 'ev'): BondPlan => ({
  claimId: id,
  expect: 'open',
  next: 'slashed',
  moves: [
    { account: 'escrow', op: 'debit', amount },
    { account: 'chal', op: 'credit', amount: amount / 2 },
    { account: 'treasury', op: 'credit', amount: amount / 2 },
  ],
  record: rec(id, 'slash', amount, 'escrow', 'treasury', evidence, {
    amount,
    challengerReward: amount / 2,
    victimCompensation: 0,
    treasuryRemainder: amount / 2,
    challengerAccount: 'chal',
    victimAccount: 'pool',
    treasuryAccount: 'treasury',
  } as never),
});

const bal = async (s: BondStore, ...accounts: string[]): Promise<number[]> => {
  const out: number[] = [];
  for (const a of accounts) out.push((await s.read({ claimId: '', depositor: a })).balances[0]?.[1] ?? 0);
  return out;
};
const status = async (s: BondStore, id: string): Promise<string> => (await s.read({ claimId: id })).bond?.status ?? 'none';
const ACCOUNTS = ['alice', 'bob', 'escrow', 'chal', 'treasury'];
const total = async (s: BondStore): Promise<number> => (await bal(s, ...ACCOUNTS)).reduce((a, b) => a + b, 0);
const outcomes = (r: BondCommitOutcome[]): string[] => r.map((x) => x.outcome).sort();

export const BOND_CHECKS: readonly BondCheck[] = [
  {
    name: 'empty-store-reads-empty',
    claim: 'an unknown bond reads as absent, an unknown account as balance 0, and the time high-water mark starts at 0',
    async run({ store }) {
      assert.deepEqual(await store.read({ claimId: 'nope', depositor: 'alice' }), { balances: [['alice', 0]], openTotals: { count: 0, sum: 0 }, highWater: 0 });
    },
  },
  {
    name: 'deposit-validates-and-accumulates',
    claim: 'deposit credits exactly, returns the new balance, and refuses a non-positive, non-finite or unnamed deposit',
    async run({ store }) {
      assert.equal(await store.deposit('alice', 2.5), 2.5);
      assert.equal(await store.deposit('alice', 0.5), 3);
      for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) await assert.rejects(store.deposit('alice', bad));
      await assert.rejects(store.deposit('', 1));
      assert.deepEqual(await bal(store, 'alice'), [3]);
    },
  },
  {
    name: 'open-is-atomic-and-recorded',
    claim: 'an open moves the collateral, stores the row with its record, and raises the high-water mark, all together',
    async run({ store }) {
      await store.deposit('alice', 100);
      const plan = openPlan('b1', 'alice', 60);
      assert.deepEqual(await store.commit(plan, 500), { outcome: 'committed', record: plan.record });
      const snap = await store.read({ claimId: 'b1', depositor: 'alice' });
      assert.deepEqual(snap, { bond: { claimId: 'b1', amount: 60, depositor: 'alice', status: 'open', records: [plan.record] }, balances: [['alice', 40]], openTotals: { count: 1, sum: 60 }, highWater: 500 });
      assert.deepEqual(await bal(store, 'escrow'), [60]);
    },
  },
  {
    name: 'open-overdraft-refused-without-trace',
    claim: 'an open the depositor cannot fund is a conflict and leaves balances, bonds and the high-water mark untouched',
    async run({ store }) {
      await store.deposit('alice', 10);
      const out = await store.commit(openPlan('b1', 'alice', 60), 900);
      assert.equal(out.outcome, 'conflict');
      assert.deepEqual(await store.read({ claimId: 'b1', depositor: 'alice' }), { balances: [['alice', 10]], openTotals: { count: 0, sum: 0 }, highWater: 0 });
      assert.deepEqual(await bal(store, 'escrow'), [0]);
    },
  },
  {
    name: 'open-retry-is-replayed-and-different-terms-conflict',
    claim: 'committing the same open again returns the stored record and moves nothing; other terms for that bond conflict',
    async run({ store }) {
      await store.deposit('alice', 100);
      const plan = openPlan('b1', 'alice', 60);
      await store.commit(plan, 1);
      assert.deepEqual(await store.commit(plan, 2), { outcome: 'replayed', record: plan.record });
      assert.equal((await store.commit(openPlan('b1', 'alice', 61), 3)).outcome, 'conflict');
      assert.equal((await store.commit(openPlan('b1', 'bob', 60), 3)).outcome, 'conflict');
      assert.deepEqual(await bal(store, 'alice', 'escrow'), [40, 60]);
      assert.equal((await store.read({ claimId: 'b1' })).bond?.records.length, 1);
    },
  },
  {
    name: 'open-caps-are-rechecked-at-commit',
    claim: 'the per-depositor open-claim and open-amount caps hold inside the store, whatever the planner saw',
    async run({ store }) {
      await store.deposit('alice', 100);
      const caps = { maxOpenClaims: 2, maxOpenAmount: 50 };
      assert.equal((await store.commit(openPlan('c1', 'alice', 30, caps), 1)).outcome, 'committed');
      assert.equal((await store.commit(openPlan('c2', 'alice', 21, caps), 1)).outcome, 'conflict'); // 30 + 21 > 50
      assert.equal((await store.commit(openPlan('c3', 'alice', 20, caps), 1)).outcome, 'committed');
      assert.equal((await store.commit(openPlan('c4', 'alice', 1, caps), 1)).outcome, 'conflict'); // third open claim
      assert.deepEqual(await bal(store, 'alice', 'escrow'), [50, 50]);
    },
  },
  {
    name: 'settle-applies-every-move-once',
    claim: 'a release and a slash apply all their balance moves, store the record, and conserve the total',
    async run({ store }) {
      await store.deposit('alice', 100);
      await store.commit(openPlan('r', 'alice', 20), 1);
      await store.commit(openPlan('s', 'alice', 40), 1);
      const rel = releasePlan('r', 'alice', 20);
      const sl = slashPlan('s', 40);
      assert.deepEqual(await store.commit(rel, 2), { outcome: 'committed', record: rel.record });
      assert.deepEqual(await store.commit(sl, 3), { outcome: 'committed', record: sl.record });
      assert.deepEqual(await bal(store, 'alice', 'escrow', 'chal', 'treasury'), [60, 0, 20, 20]);
      assert.equal(await total(store), 100);
      assert.deepEqual([await status(store, 'r'), await status(store, 's')], ['released', 'slashed']);
      assert.deepEqual((await store.read({ claimId: 's' })).bond?.records, [openPlan('s', 'alice', 40).record, sl.record]);
    },
  },
  {
    name: 'settle-needs-the-expected-phase',
    claim: 'settling an absent bond or from the wrong phase is a conflict that changes nothing, high-water mark included',
    async run({ store }) {
      await store.deposit('alice', 100);
      assert.equal((await store.commit(releasePlan('ghost', 'alice', 5), 9)).outcome, 'conflict');
      await store.commit(openPlan('b', 'alice', 20), 10);
      await store.commit(releasePlan('b', 'alice', 20), 11);
      const before = [await bal(store, 'alice', 'escrow', 'treasury', 'chal'), (await store.read({ claimId: 'b' })).highWater];
      const late = await store.commit(slashPlan('b', 20), 99);
      assert.equal(late.outcome, 'conflict');
      assert.deepEqual([await bal(store, 'alice', 'escrow', 'treasury', 'chal'), (await store.read({ claimId: 'b' })).highWater], before);
      assert.equal(await status(store, 'b'), 'released');
    },
  },
  {
    name: 'settle-overdraw-refused-without-trace',
    claim: 'a settlement whose debit would overdraw an account is refused whole: no credit lands, the phase does not change',
    async run({ store }) {
      await store.deposit('alice', 100);
      await store.commit(openPlan('b', 'alice', 20), 1);
      const greedy = slashPlan('b', 20);
      greedy.moves = [{ account: 'escrow', op: 'debit', amount: 21 }, { account: 'treasury', op: 'credit', amount: 21 }];
      assert.equal((await store.commit(greedy, 5)).outcome, 'conflict');
      assert.deepEqual(await bal(store, 'escrow', 'treasury'), [20, 0]);
      assert.equal(await status(store, 'b'), 'open');
    },
  },
  {
    name: 'settle-retry-returns-the-stored-record',
    claim: 'the same settlement again is replayed with the first record and moves nothing; the same action with other evidence conflicts',
    async run({ store }) {
      await store.deposit('alice', 100);
      await store.commit(openPlan('b', 'alice', 40), 1);
      const sl = slashPlan('b', 40, 'ev-1');
      await store.commit(sl, 2);
      assert.deepEqual(await store.commit({ ...slashPlan('b', 40, 'ev-1'), record: { ...sl.record, at: 77, sig: 'other' } }, 3), { outcome: 'replayed', record: sl.record });
      assert.equal((await store.commit(slashPlan('b', 40, 'ev-2'), 3)).outcome, 'conflict');
      assert.equal((await store.commit(releasePlan('b', 'alice', 40), 3)).outcome, 'conflict');
      assert.deepEqual(await bal(store, 'alice', 'escrow', 'chal', 'treasury'), [60, 0, 20, 20]);
      assert.equal((await store.read({ claimId: 'b' })).bond?.records.length, 2);
    },
  },
  {
    name: 'racing-identical-settles-commit-once',
    claim: 'eight clients racing the same release: one commits, seven are replays, funds move once',
    async run(h) {
      await h.store.deposit('alice', 100);
      await h.store.commit(openPlan('b', 'alice', 40), 1);
      const clients = [h.store, ...(await Promise.all(Array.from({ length: 3 }, () => h.reopen())))];
      const r = await Promise.all(Array.from({ length: 8 }, (_, i) => clients[i % clients.length]!.commit(releasePlan('b', 'alice', 40), 10 + i)));
      assert.deepEqual(outcomes(r), ['committed', ...Array<string>(7).fill('replayed')]);
      assert.deepEqual(await bal(h.store, 'alice', 'escrow'), [100, 0]);
      assert.equal((await h.store.read({ claimId: 'b' })).bond?.records.length, 2);
    },
  },
  {
    name: 'racing-conflicting-settles-have-one-winner',
    claim: 'a release racing a slash on one bond: exactly one commits, the books show only the winner, the total is conserved',
    async run(h) {
      await h.store.deposit('alice', 100);
      await h.store.commit(openPlan('b', 'alice', 40), 1);
      const other = await h.reopen();
      const r = await Promise.all([h.store.commit(releasePlan('b', 'alice', 40), 5), other.commit(slashPlan('b', 40), 5), h.store.commit(slashPlan('b', 40), 5), other.commit(releasePlan('b', 'alice', 40), 5)]);
      assert.equal(r.filter((x) => x.outcome === 'committed').length, 1);
      assert.equal(r.filter((x) => x.outcome === 'conflict').length + r.filter((x) => x.outcome === 'replayed').length, 3);
      const st = await status(h.store, 'b');
      assert.deepEqual(await bal(h.store, 'alice', 'escrow', 'chal', 'treasury'), st === 'released' ? [100, 0, 0, 0] : [60, 0, 20, 20]);
      assert.equal(await total(h.store), 100);
    },
  },
  {
    name: 'racing-opens-for-the-same-bond-commit-once',
    claim: 'concurrent identical opens collect the collateral once; a differing open loses',
    async run(h) {
      await h.store.deposit('alice', 100);
      const other = await h.reopen();
      const r = await Promise.all([h.store.commit(openPlan('b', 'alice', 60), 1), other.commit(openPlan('b', 'alice', 60), 1), h.store.commit(openPlan('b', 'alice', 60), 1), other.commit(openPlan('b', 'alice', 50), 1)]);
      assert.equal(r.filter((x) => x.outcome === 'committed').length, 1);
      assert.deepEqual(await bal(h.store, 'alice', 'escrow'), r[3]!.outcome === 'committed' ? [50, 50] : [40, 60]);
      assert.equal(await total(h.store), 100);
    },
  },
  {
    name: 'racing-opens-cannot-overdraw',
    claim: 'concurrent opens by one depositor that together exceed the balance: the sum committed never exceeds what was deposited',
    async run(h) {
      await h.store.deposit('alice', 100);
      const other = await h.reopen();
      const r = await Promise.all(Array.from({ length: 6 }, (_, i) => (i % 2 ? h.store : other).commit(openPlan(`b${i}`, 'alice', 40), 1)));
      assert.equal(r.filter((x) => x.outcome === 'committed').length, 2);
      assert.deepEqual(await bal(h.store, 'alice', 'escrow'), [20, 80]);
    },
  },
  {
    name: 'concurrent-deposits-lose-nothing',
    claim: 'sixteen racing deposits add up exactly',
    async run(h) {
      const other = await h.reopen();
      await Promise.all(Array.from({ length: 16 }, (_, i) => (i % 2 ? h.store : other).deposit('alice', 1)));
      assert.deepEqual(await bal(h.store, 'alice'), [16]);
    },
  },
  {
    name: 'time-high-water-only-moves-forward',
    claim: 'the recorded time is the maximum of every committed observedAt; a smaller or non-finite one never lowers it',
    async run({ store }) {
      await store.deposit('alice', 100);
      await store.commit(openPlan('a', 'alice', 10), 100);
      await store.commit(openPlan('b', 'alice', 10), 40);
      assert.equal((await store.read({ claimId: '' })).highWater, 100);
      await store.commit(openPlan('c', 'alice', 10), Number.NaN);
      assert.equal((await store.read({ claimId: '' })).highWater, 100);
      await store.commit(openPlan('d', 'alice', 10), 101);
      assert.equal((await store.read({ claimId: '' })).highWater, 101);
    },
  },
  {
    name: 'reads-are-snapshots',
    claim: 'mutating a returned snapshot cannot change the store',
    async run({ store }) {
      await store.deposit('alice', 100);
      await store.commit(openPlan('b', 'alice', 10), 1);
      const snap = await store.read({ claimId: 'b', depositor: 'alice' });
      snap.bond!.amount = 999;
      snap.bond!.records.length = 0;
      snap.balances[0]![1] = 12345;
      const again = await store.read({ claimId: 'b', depositor: 'alice' });
      assert.equal(again.bond?.amount, 10);
      assert.equal(again.bond?.records.length, 1);
      assert.deepEqual(again.balances, [['alice', 90]]);
    },
  },
  {
    name: 'hostile-names-are-plain-keys',
    claim: 'claim and account names such as __proto__, constructor and toString behave like any other name',
    async run({ store }) {
      for (const n of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
        await store.deposit(n, 50);
        assert.equal((await store.commit(openPlan(n, n, 20), 1)).outcome, 'committed', n);
        assert.deepEqual(await bal(store, n), [30], n);
        assert.equal(await status(store, n), 'open', n);
      }
      assert.equal(await status(store, 'valueOf'), 'none');
      assert.deepEqual(await bal(store, 'valueOf'), [0]);
    },
  },
  {
    name: 'state-survives-reopen',
    claim: 'every acknowledged commit and deposit is visible to a new client after the backend restarts',
    needs: 'durable',
    async run(h) {
      await h.store.deposit('alice', 100);
      await h.store.commit(openPlan('a', 'alice', 40), 7);
      await h.store.commit(openPlan('b', 'alice', 20), 8);
      const sl = slashPlan('b', 20);
      await h.store.commit(sl, 9);
      const back = await h.reopen();
      assert.deepEqual(await back.read({ claimId: 'b', depositor: 'alice' }), { bond: { claimId: 'b', amount: 20, depositor: 'alice', status: 'slashed', records: [openPlan('b', 'alice', 20).record, sl.record] }, balances: [['alice', 40]], openTotals: { count: 1, sum: 40 }, highWater: 9 });
      assert.deepEqual(await bal(back, 'escrow', 'chal', 'treasury'), [40, 10, 10]);
      assert.deepEqual((await back.commit(sl, 10)).outcome, 'replayed');
    },
  },
  {
    name: 'acknowledged-commits-survive-a-crash',
    claim: 'after an abrupt kill, every acknowledged transition is present, and a transition that was in flight is applied entirely or not at all',
    needs: 'crash',
    async run(h) {
      await h.store.deposit('alice', 100);
      await h.store.commit(openPlan('a', 'alice', 40), 1);
      await h.store.commit(openPlan('b', 'alice', 30), 2);
      const inflight = h.store.commit(slashPlan('b', 30), 3).catch(() => undefined);
      const back = await h.crash!();
      void inflight;
      assert.equal(await status(back, 'a'), 'open');
      const st = await status(back, 'b');
      assert.ok(st === 'open' || st === 'slashed', `bond b is ${st}`);
      assert.deepEqual(await bal(back, 'alice', 'escrow', 'chal', 'treasury'), st === 'slashed' ? [30, 40, 15, 15] : [30, 70, 0, 0]);
      assert.equal(await total(back), 100);
      assert.deepEqual((await back.commit(slashPlan('b', 30), 4)).outcome, st === 'slashed' ? 'replayed' : 'committed');
      assert.deepEqual(await bal(back, 'alice', 'escrow', 'chal', 'treasury'), [30, 40, 15, 15]);
    },
  },
];

// ---- the run -----------------------------------------------------------------------------------------------------

export interface BondCheckResult {
  name: string;
  status: 'pass' | 'fail' | 'skip';
  detail?: string;
}
export interface BondConformanceReport {
  adapter: string;
  status: 'pass' | 'fail';
  checks: BondCheckResult[];
}

export interface BondConformanceOptions {
  /** Run only these checks (by name). */
  only?: readonly string[];
}

export async function runBondStoreConformance(adapter: BondStoreAdapter, opts: BondConformanceOptions = {}): Promise<BondConformanceReport> {
  const checks: BondCheckResult[] = [];
  for (const c of BOND_CHECKS) {
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

export function formatBondReport(r: BondConformanceReport): string {
  return [`pca-store-conformance (bond store): ${r.adapter} -> ${r.status.toUpperCase()}`, ...r.checks.map((c) => `  [${c.status.toUpperCase()}] ${c.name}${c.detail ? `: ${c.detail.split('\n')[0]}` : ''}`)].join('\n');
}

type It = (name: string, fn: () => Promise<void>, timeout?: number) => unknown;
type Describe = (name: string, fn: () => void) => unknown;

/** Register one test-runner test per check (vitest / jest globals, or pass `runner`). */
export function describeBondStoreConformance(adapter: BondStoreAdapter | (() => BondStoreAdapter), opts: { runner?: { describe: Describe; it: It }; timeoutMs?: number } = {}): void {
  const g = globalThis as { describe?: Describe; it?: It };
  const describe = opts.runner?.describe ?? g.describe;
  const it = opts.runner?.it ?? g.it;
  if (!describe || !it) throw new Error('describeBondStoreConformance needs describe/it: pass { runner } or enable test globals');
  const a = typeof adapter === 'function' ? adapter() : adapter;
  describe(`PCA bond store conformance: ${a.name}`, () => {
    for (const c of BOND_CHECKS) {
      it(
        `${c.name}: ${c.claim}`,
        async () => {
          const r = await runBondStoreConformance(typeof adapter === 'function' ? adapter() : adapter, { only: [c.name] });
          const x = r.checks[0]!;
          if (x.status === 'fail') throw new Error(x.detail);
        },
        opts.timeoutMs ?? 60_000,
      );
    }
  });
}

// ---- reference adapters: GOOD ones must pass, BAD ones are positive controls the suite MUST flag -------------------

/** GOOD, in process: the reference store over an in-memory kv. Not durable (declared). */
export function memoryBondStoreAdapter(): BondStoreAdapter {
  return {
    name: 'KvBondStore over an in-memory kv',
    durable: false,
    async create() {
      const kv = createMemoryDurableKv();
      return { store: new KvBondStore(kv), reopen: async () => new KvBondStore(kv) };
    },
  };
}

/** GOOD, durable: the reference store over the crash-safe file state (`@atlasauth/pca/durable-state`), one handle per client. */
export function durableBondStoreAdapter(options: { dir?: string } = {}): BondStoreAdapter {
  return {
    name: 'KvBondStore over durable-state files',
    durable: true,
    async create() {
      const dir = options.dir ?? mkdtempSync(join(tmpdir(), 'pca-bondsc-'));
      const open = async (): Promise<BondStore> => new KvBondStore(await openDurableState({ dir, lockTimeoutMs: 30_000 }));
      return { store: await open(), reopen: open, crash: open };
    },
  };
}

/** A document store with a switchable defect, for the positive controls. */
function defective(defect: 'non-atomic' | 'no-replay' | 'lost-update' | 'amnesia' | 'clock-rewind'): BondStoreAdapter {
  const names = {
    'non-atomic': 'BAD non-atomic (moves land before the phase check)',
    'no-replay': 'BAD no idempotence (a retried transition conflicts)',
    'lost-update': 'BAD lost update (read, await, write)',
    amnesia: 'BAD amnesia (claims durability, forgets on reopen)',
    'clock-rewind': 'BAD clock rewind (high-water mark follows the last call)',
  } as const;
  return {
    name: names[defect],
    durable: true,
    async create() {
      let doc: BondDoc = emptyBondDoc();
      const clone = (d: BondDoc): BondDoc => ({ v: 1, balances: new Map(d.balances), bonds: new Map([...d.bonds].map(([k, v]) => [k, structuredClone(v)])), highWater: d.highWater });
      const snap = (scope: { claimId: string; depositor?: string }) => {
        const d = clone(doc);
        let count = 0;
        let sum = 0;
        const balances: Array<[string, number]> = [];
        if (scope.depositor !== undefined) {
          for (const b of d.bonds.values()) if (b.status === 'open' && b.depositor === scope.depositor) (count += 1), (sum += b.amount);
          balances.push([scope.depositor, d.balances.get(scope.depositor) ?? 0]);
        }
        const bond = d.bonds.get(scope.claimId);
        return { ...(bond ? { bond } : {}), balances, openTotals: { count, sum }, highWater: d.highWater } as BondSnapshot;
      };
      const client = (): BondStore => ({
        read: async (scope) => snap(scope),
        deposit: async (account, amount) => {
          if (!(amount > 0) || !Number.isFinite(amount) || !account) throw new RangeError('deposit');
          const base = defect === 'lost-update' ? clone(doc) : doc;
          if (defect === 'lost-update') await new Promise((r) => setImmediate(r));
          base.balances.set(account, (base.balances.get(account) ?? 0) + amount);
          if (defect === 'lost-update') doc = base;
          return base.balances.get(account)!;
        },
        commit: async (plan, observedAt) => {
          if (defect === 'non-atomic') {
            // applies the balance moves first, then checks the phase: a conflict leaves the money moved
            for (const m of plan.moves) doc.balances.set(m.account, (doc.balances.get(m.account) ?? 0) + (m.op === 'credit' ? m.amount : -m.amount));
            const b = doc.bonds.get(plan.claimId);
            if (plan.expect === 'none' ? b : !b || b.status !== plan.expect) return { outcome: 'conflict', reason: 'phase', current: b?.status ?? 'none' };
            if (plan.open) doc.bonds.set(plan.claimId, { claimId: plan.claimId, amount: plan.open.amount, depositor: plan.open.depositor, status: 'open', records: [plan.record] });
            else {
              b!.status = plan.next;
              b!.records.push(plan.record);
            }
            doc.highWater = Math.max(doc.highWater, observedAt);
            return { outcome: 'committed', record: plan.record };
          }
          const working = defect === 'lost-update' ? clone(doc) : doc;
          if (defect === 'lost-update') await new Promise((r) => setImmediate(r));
          const out = commitBondPlan(working, plan, observedAt);
          if (defect === 'lost-update' && out.outcome === 'committed') doc = working;
          if (defect === 'no-replay' && out.outcome === 'replayed') return { outcome: 'conflict', reason: 'already applied', current: 'open' };
          if (defect === 'clock-rewind' && out.outcome === 'committed') doc.highWater = observedAt;
          return out;
        },
      });
      return { store: client(), reopen: async () => (defect === 'amnesia' ? ((doc = emptyBondDoc()), client()) : client()), crash: async () => (defect === 'amnesia' ? ((doc = emptyBondDoc()), client()) : client()) };
    },
  };
}

export const nonAtomicBondStoreAdapter = (): BondStoreAdapter => defective('non-atomic');
export const noReplayBondStoreAdapter = (): BondStoreAdapter => defective('no-replay');
export const lostUpdateBondStoreAdapter = (): BondStoreAdapter => defective('lost-update');
export const amnesiaBondStoreAdapter = (): BondStoreAdapter => defective('amnesia');
export const clockRewindBondStoreAdapter = (): BondStoreAdapter => defective('clock-rewind');

/** Built-in adapters by name. */
export const BOND_REFERENCE_ADAPTERS: Readonly<Record<string, () => BondStoreAdapter>> = {
  'bond-memory': memoryBondStoreAdapter,
  'bond-durable-file': () => durableBondStoreAdapter(),
  'bad-bond-non-atomic': nonAtomicBondStoreAdapter,
  'bad-bond-no-replay': noReplayBondStoreAdapter,
  'bad-bond-lost-update': lostUpdateBondStoreAdapter,
  'bad-bond-amnesia': amnesiaBondStoreAdapter,
  'bad-bond-clock-rewind': clockRewindBondStoreAdapter,
};
