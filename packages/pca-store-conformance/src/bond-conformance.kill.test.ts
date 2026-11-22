import { describe, expect, it } from 'vitest';
import { createMemoryDurableKv } from '@atlasauth/pca/durable-state';
import { KvBondStore, type BondCommitOutcome, type BondPlan, type BondReadScope, type BondSnapshot, type BondStore } from '@atlasauth/pca/ext/optimistic';
import {
  BOND_CHECKS,
  BOND_REFERENCE_ADAPTERS,
  amnesiaBondStoreAdapter,
  clockRewindBondStoreAdapter,
  describeBondStoreConformance,
  durableBondStoreAdapter,
  formatBondReport,
  lostUpdateBondStoreAdapter,
  memoryBondStoreAdapter,
  noReplayBondStoreAdapter,
  nonAtomicBondStoreAdapter,
  runBondStoreConformance,
  type BondStoreAdapter,
  type BondStoreHandle,
} from './bond-conformance';
import { show, traceHandle } from './test-support/trace';

// ---- plan builders, written out independently of the module under test (same key order as the stored JSON) ---------

const caps0 = { maxOpenClaims: 100, maxOpenAmount: 1e9 };
const R = (claimId: string, action: string, amount: number, from: string, to: string, evidenceDigest = '', split?: object) => ({
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
const O = (id: string, dep: string, amount: number, caps = caps0) => ({
  claimId: id,
  expect: 'none',
  next: 'open',
  open: { amount, depositor: dep, ...caps },
  moves: [
    { account: dep, op: 'debit', amount },
    { account: 'escrow', op: 'credit', amount },
  ],
  record: R(id, 'open', amount, dep, 'escrow'),
});
const Rel = (id: string, dep: string, amount: number) => ({
  claimId: id,
  expect: 'open',
  next: 'released',
  moves: [
    { account: 'escrow', op: 'debit', amount },
    { account: dep, op: 'credit', amount },
  ],
  record: R(id, 'release', amount, 'escrow', dep),
});
const Sl = (id: string, amount: number, evidence = 'ev') => ({
  claimId: id,
  expect: 'open',
  next: 'slashed',
  moves: [
    { account: 'escrow', op: 'debit', amount },
    { account: 'chal', op: 'credit', amount: amount / 2 },
    { account: 'treasury', op: 'credit', amount: amount / 2 },
  ],
  record: R(id, 'slash', amount, 'escrow', 'treasury', evidence, {
    amount,
    challengerReward: amount / 2,
    victimCompensation: 0,
    treasuryRemainder: amount / 2,
    challengerAccount: 'chal',
    victimAccount: 'pool',
    treasuryAccount: 'treasury',
  }),
});

// ---- trace line builders ------------------------------------------------------------------------------------------

const dep = (c: number, account: string, amount: number): string => `c${c}.deposit(${show(account)},${show(amount)})`;
const cm = (c: number, plan: object, at: number): string => `c${c}.commit(${show(plan)},${show(at)})`;
const rd = (c: number, claimId: string, depositor?: string): string => `c${c}.read(${show(depositor === undefined ? { claimId } : { claimId, depositor })})`;
const bals = (c: number, ...accounts: string[]): string[] => accounts.map((a) => rd(c, '', a));
const total = (c: number): string[] => bals(c, 'alice', 'bob', 'escrow', 'chal', 'treasury');
const reopens = (n: number): string[] => Array.from({ length: n }, () => 'h.reopen()');

// ---- adapters and variants ----------------------------------------------------------------------------------------

/** Durable-declared, crash-capable, in-memory: a crash returns a client on whatever is stored. */
function memAdapter(): BondStoreAdapter {
  return {
    name: 'mem',
    durable: true,
    async create() {
      const kv = createMemoryDurableKv();
      return { store: new KvBondStore(kv), reopen: async () => new KvBondStore(kv), crash: async () => new KvBondStore(kv) };
    },
  };
}

interface Mod {
  /** Replaces the commit of the first (primary) client when `primaryOnly`, else of every client. */
  commit?: (inner: BondStore, plan: BondPlan, at: number) => Promise<BondCommitOutcome>;
  primaryOnly?: boolean;
  read?: (inner: BondStore, scope: BondReadScope, n: number) => Promise<BondSnapshot>;
  beforeCrash?: (pending: Promise<unknown>[]) => Promise<void>;
}

function variant(base: BondStoreAdapter, mod: Mod): BondStoreAdapter {
  return {
    ...base,
    async create() {
      const h = await base.create();
      let reads = 0;
      const pending: Promise<unknown>[] = [];
      const wrap = (s: BondStore, primary: boolean): BondStore => ({
        deposit: (a, n) => s.deposit(a, n),
        read: (scope) => {
          const n = reads++;
          return mod.read ? mod.read(s, scope, n) : s.read(scope);
        },
        commit: (plan, at) => {
          const p = mod.commit && (primary || !mod.primaryOnly) ? mod.commit(s, plan, at) : s.commit(plan, at);
          pending.push(p);
          return p;
        },
      });
      const out: BondStoreHandle = { store: wrap(h.store, true), reopen: async () => wrap(await h.reopen(), false) };
      if (h.crash) {
        out.crash = async () => {
          await mod.beforeCrash?.(pending);
          return wrap(await h.crash!(), false);
        };
      }
      return out;
    },
  };
}

const tick = (): Promise<void> => new Promise((r) => setImmediate(r));

function traced(a: BondStoreAdapter, log: string[]): BondStoreAdapter {
  return {
    ...a,
    async create() {
      return traceHandle(await a.create(), 'store', log);
    },
  };
}

async function run(a: BondStoreAdapter, name: string) {
  return (await runBondStoreConformance(a, { only: [name] })).checks;
}

const readCount = (golden: string[]): number => golden.filter((l) => l.includes('.read(')).length;

// ---- 1. every check, call for call --------------------------------------------------------------------------------

const GOLDEN: Record<string, string[]> = {
  'empty-store-reads-empty': [rd(0, 'nope', 'alice')],
  'deposit-validates-and-accumulates': [dep(0, 'alice', 2.5), dep(0, 'alice', 0.5), dep(0, 'alice', 0), dep(0, 'alice', -1), dep(0, 'alice', Number.NaN), dep(0, 'alice', Number.POSITIVE_INFINITY), dep(0, '', 1), ...bals(0, 'alice')],
  'open-is-atomic-and-recorded': [dep(0, 'alice', 100), cm(0, O('b1', 'alice', 60), 500), rd(0, 'b1', 'alice'), ...bals(0, 'escrow')],
  'open-overdraft-refused-without-trace': [dep(0, 'alice', 10), cm(0, O('b1', 'alice', 60), 900), rd(0, 'b1', 'alice'), ...bals(0, 'escrow')],
  'open-retry-is-replayed-and-different-terms-conflict': [
    dep(0, 'alice', 100),
    cm(0, O('b1', 'alice', 60), 1),
    cm(0, O('b1', 'alice', 60), 2),
    cm(0, O('b1', 'alice', 61), 3),
    cm(0, O('b1', 'bob', 60), 3),
    ...bals(0, 'alice', 'escrow'),
    rd(0, 'b1'),
  ],
  'open-caps-are-rechecked-at-commit': [
    dep(0, 'alice', 100),
    cm(0, O('c1', 'alice', 30, { maxOpenClaims: 2, maxOpenAmount: 50 }), 1),
    cm(0, O('c2', 'alice', 21, { maxOpenClaims: 2, maxOpenAmount: 50 }), 1),
    cm(0, O('c3', 'alice', 20, { maxOpenClaims: 2, maxOpenAmount: 50 }), 1),
    cm(0, O('c4', 'alice', 1, { maxOpenClaims: 2, maxOpenAmount: 50 }), 1),
    ...bals(0, 'alice', 'escrow'),
  ],
  'settle-applies-every-move-once': [
    dep(0, 'alice', 100),
    cm(0, O('r', 'alice', 20), 1),
    cm(0, O('s', 'alice', 40), 1),
    cm(0, Rel('r', 'alice', 20), 2),
    cm(0, Sl('s', 40), 3),
    ...bals(0, 'alice', 'escrow', 'chal', 'treasury'),
    ...total(0),
    rd(0, 'r'),
    rd(0, 's'),
    rd(0, 's'),
  ],
  'settle-needs-the-expected-phase': [
    dep(0, 'alice', 100),
    cm(0, Rel('ghost', 'alice', 5), 9),
    cm(0, O('b', 'alice', 20), 10),
    cm(0, Rel('b', 'alice', 20), 11),
    ...bals(0, 'alice', 'escrow', 'treasury', 'chal'),
    rd(0, 'b'),
    cm(0, Sl('b', 20), 99),
    ...bals(0, 'alice', 'escrow', 'treasury', 'chal'),
    rd(0, 'b'),
    rd(0, 'b'),
  ],
  'settle-overdraw-refused-without-trace': [
    dep(0, 'alice', 100),
    cm(0, O('b', 'alice', 20), 1),
    cm(0, { ...Sl('b', 20), moves: [{ account: 'escrow', op: 'debit', amount: 21 }, { account: 'treasury', op: 'credit', amount: 21 }] }, 5),
    ...bals(0, 'escrow', 'treasury'),
    rd(0, 'b'),
  ],
  'settle-retry-returns-the-stored-record': [
    dep(0, 'alice', 100),
    cm(0, O('b', 'alice', 40), 1),
    cm(0, Sl('b', 40, 'ev-1'), 2),
    cm(0, { ...Sl('b', 40, 'ev-1'), record: { ...Sl('b', 40, 'ev-1').record, at: 77, sig: 'other' } }, 3),
    cm(0, Sl('b', 40, 'ev-2'), 3),
    cm(0, Rel('b', 'alice', 40), 3),
    ...bals(0, 'alice', 'escrow', 'chal', 'treasury'),
    rd(0, 'b'),
  ],
  'racing-identical-settles-commit-once': [
    dep(0, 'alice', 100),
    cm(0, O('b', 'alice', 40), 1),
    ...reopens(3),
    ...Array.from({ length: 8 }, (_, i) => cm(i % 4, Rel('b', 'alice', 40), 10 + i)),
    ...bals(0, 'alice', 'escrow'),
    rd(0, 'b'),
  ],
  'racing-conflicting-settles-have-one-winner': [
    dep(0, 'alice', 100),
    cm(0, O('b', 'alice', 40), 1),
    ...reopens(1),
    cm(0, Rel('b', 'alice', 40), 5),
    cm(1, Sl('b', 40), 5),
    cm(0, Sl('b', 40), 5),
    cm(1, Rel('b', 'alice', 40), 5),
    rd(0, 'b'),
    ...bals(0, 'alice', 'escrow', 'chal', 'treasury'),
    ...total(0),
  ],
  'racing-opens-for-the-same-bond-commit-once': [
    dep(0, 'alice', 100),
    ...reopens(1),
    cm(0, O('b', 'alice', 60), 1),
    cm(1, O('b', 'alice', 60), 1),
    cm(0, O('b', 'alice', 60), 1),
    cm(1, O('b', 'alice', 50), 1),
    ...bals(0, 'alice', 'escrow'),
    ...total(0),
  ],
  'racing-opens-cannot-overdraw': [dep(0, 'alice', 100), ...reopens(1), ...Array.from({ length: 6 }, (_, i) => cm(i % 2 ? 0 : 1, O(`b${i}`, 'alice', 40), 1)), ...bals(0, 'alice', 'escrow')],
  'concurrent-deposits-lose-nothing': [...reopens(1), ...Array.from({ length: 16 }, (_, i) => dep(i % 2 ? 0 : 1, 'alice', 1)), ...bals(0, 'alice')],
  'time-high-water-only-moves-forward': [
    dep(0, 'alice', 100),
    cm(0, O('a', 'alice', 10), 100),
    cm(0, O('b', 'alice', 10), 40),
    rd(0, ''),
    cm(0, O('c', 'alice', 10), Number.NaN),
    rd(0, ''),
    cm(0, O('d', 'alice', 10), 101),
    rd(0, ''),
  ],
  'reads-are-snapshots': [dep(0, 'alice', 100), cm(0, O('b', 'alice', 10), 1), rd(0, 'b', 'alice'), rd(0, 'b', 'alice')],
  'hostile-names-are-plain-keys': [
    ...['__proto__', 'constructor', 'toString', 'hasOwnProperty'].flatMap((n) => [dep(0, n, 50), cm(0, O(n, n, 20), 1), ...bals(0, n), rd(0, n)]),
    rd(0, 'valueOf'),
    ...bals(0, 'valueOf'),
  ],
  'state-survives-reopen': [
    dep(0, 'alice', 100),
    cm(0, O('a', 'alice', 40), 7),
    cm(0, O('b', 'alice', 20), 8),
    cm(0, Sl('b', 20), 9),
    ...reopens(1),
    rd(1, 'b', 'alice'),
    ...bals(1, 'escrow', 'chal', 'treasury'),
    cm(1, Sl('b', 20), 10),
  ],
  'acknowledged-commits-survive-a-crash': [
    dep(0, 'alice', 100),
    cm(0, O('a', 'alice', 40), 1),
    cm(0, O('b', 'alice', 30), 2),
    cm(0, Sl('b', 30), 3),
    'h.crash()',
    rd(1, 'a'),
    rd(1, 'b'),
    ...bals(1, 'alice', 'escrow', 'chal', 'treasury'),
    ...total(1),
    cm(1, Sl('b', 30), 4),
    ...bals(1, 'alice', 'escrow', 'chal', 'treasury'),
  ],
};

describe('bond conformance checks: the exact calls each check makes against the store', () => {
  it('has a golden trace for every check', () => {
    expect(Object.keys(GOLDEN)).toEqual(BOND_CHECKS.map((c) => c.name));
  });
  for (const c of BOND_CHECKS) {
    it(`${c.name}`, async () => {
      const log: string[] = [];
      // the in-flight commit of the crash check is awaited before the crash, so the history is deterministic
      const base = c.name === 'acknowledged-commits-survive-a-crash' ? variant(memAdapter(), { beforeCrash: async (p) => void (await Promise.all(p)) }) : memAdapter();
      const res = await run(traced(base, log), c.name);
      expect(res).toEqual([{ name: c.name, status: 'pass' }]);
      expect(log).toEqual(GOLDEN[c.name]);
    });
  }
});

// ---- 2. the answer a check expects depends on which transition won / what state the store is in -------------------

describe('bond conformance checks: expectations that depend on the outcome of a race or a crash', () => {
  it('racing identical settles: a winner that is not the first caller is still accepted (outcomes are compared sorted)', async () => {
    const a = variant(memAdapter(), { commit: async (s, plan, at) => (at === 10 ? (await tick(), s.commit(plan, at)) : s.commit(plan, at)) });
    expect(await run(a, 'racing-identical-settles-commit-once')).toEqual([{ name: 'racing-identical-settles-commit-once', status: 'pass' }]);
  });
  it('racing conflicting settles: when the slash wins the slashed balances are expected', async () => {
    const a = variant(memAdapter(), { commit: async (s, plan, at) => (plan.next === 'released' ? (await tick(), s.commit(plan, at)) : s.commit(plan, at)) });
    expect(await run(a, 'racing-conflicting-settles-have-one-winner')).toEqual([{ name: 'racing-conflicting-settles-have-one-winner', status: 'pass' }]);
  });
  it('racing conflicting settles: a store that answers a twin with a conflict instead of a replay is still within the contract', async () => {
    expect(await run(noReplayBondStoreAdapter(), 'racing-conflicting-settles-have-one-winner')).toEqual([{ name: 'racing-conflicting-settles-have-one-winner', status: 'pass' }]);
  });
  it('racing opens for one bond: when the differing open wins, 50 is escrowed', async () => {
    const a = variant(memAdapter(), { commit: async (s, plan, at) => (plan.open?.amount === 60 ? (await tick(), s.commit(plan, at)) : s.commit(plan, at)) });
    expect(await run(a, 'racing-opens-for-the-same-bond-commit-once')).toEqual([{ name: 'racing-opens-for-the-same-bond-commit-once', status: 'pass' }]);
  });
  it('crash check: a slash that survived is expected to be replayed and the slashed balances to stand', async () => {
    const a = variant(memAdapter(), { beforeCrash: async (p) => void (await Promise.all(p)) });
    expect(await run(a, 'acknowledged-commits-survive-a-crash')).toEqual([{ name: 'acknowledged-commits-survive-a-crash', status: 'pass' }]);
  });
  it('crash check: a slash that was lost is expected to commit and the open balances to stand', async () => {
    const a = variant(memAdapter(), { commit: (s, plan, at) => (plan.next === 'slashed' ? new Promise<BondCommitOutcome>(() => undefined) : s.commit(plan, at)), primaryOnly: true });
    expect(await run(a, 'acknowledged-commits-survive-a-crash')).toEqual([{ name: 'acknowledged-commits-survive-a-crash', status: 'pass' }]);
  });
  it('crash check: any other phase after the crash fails and names it', async () => {
    const a = variant(memAdapter(), {
      commit: async (s, plan, at) => (plan.next === 'slashed' ? s.commit(Rel(plan.claimId, 'alice', 30) as unknown as BondPlan, at) : s.commit(plan, at)),
      primaryOnly: true,
      beforeCrash: async (p) => void (await Promise.all(p)),
    });
    expect(await run(a, 'acknowledged-commits-survive-a-crash')).toEqual([{ name: 'acknowledged-commits-survive-a-crash', status: 'fail', detail: 'bond b is released' }]);
  });
  it('crash check: a lost acknowledged open fails on the first bond', async () => {
    const a = variant(memAdapter(), { read: async (s, scope) => (scope.claimId === 'a' ? { balances: [], openTotals: { count: 0, sum: 0 }, highWater: 0 } : s.read(scope)) });
    const [r] = await run(a, 'acknowledged-commits-survive-a-crash');
    expect(r!.status).toBe('fail');
  });
});

// ---- 3. a store that returns less than usual: the helpers tolerate it, the failure is an assertion, not a crash -------

describe('bond conformance checks: helpers on thin snapshots', () => {
  const noBond = (snap: BondSnapshot): BondSnapshot => ({ balances: snap.balances, openTotals: snap.openTotals, highWater: snap.highWater });
  const bondAfter = (snap: BondSnapshot, undefinedOn: number): BondSnapshot => {
    let n = 0;
    return {
      get bond() {
        n += 1;
        return n === undefinedOn ? undefined : snap.bond;
      },
      balances: snap.balances,
      openTotals: snap.openTotals,
      highWater: snap.highWater,
    } as BondSnapshot;
  };

  it('a balance read with no entry counts as zero', async () => {
    const a = variant(memAdapter(), { read: async (s, scope) => (scope.depositor === 'escrow' ? { ...(await s.read(scope)), balances: [] } : s.read(scope)) });
    expect(await run(a, 'open-overdraft-refused-without-trace')).toEqual([{ name: 'open-overdraft-refused-without-trace', status: 'pass' }]);
  });

  const lastReadFails = (name: string): void => {
    it(`${name}: a missing bond on the last read is reported as a failed expectation`, async () => {
      const last = readCount(GOLDEN[name]!) - 1;
      const a = variant(memAdapter(), { read: async (s, scope, n) => (n === last ? noBond(await s.read(scope)) : s.read(scope)) });
      const [r] = await run(a, name);
      expect(r!.status).toBe('fail');
      expect(r!.detail).toMatch(/^Expected values to be strictly (deep-)?equal/);
    });
  };
  lastReadFails('open-retry-is-replayed-and-different-terms-conflict');
  lastReadFails('settle-applies-every-move-once');
  lastReadFails('settle-retry-returns-the-stored-record');
  lastReadFails('racing-identical-settles-commit-once');

  it('reads-are-snapshots: an absent bond fails on its amount, then on its record count', async () => {
    for (const undefinedOn of [1, 2]) {
      const a = variant(memAdapter(), { read: async (s, scope, n) => (n === 1 ? bondAfter(await s.read(scope), undefinedOn) : s.read(scope)) });
      const [r] = await run(a, 'reads-are-snapshots');
      expect(r!.status).toBe('fail');
      expect(r!.detail).toMatch(/^Expected values to be strictly equal/);
    }
  });
});

// ---- 4. the runner, the report and the test-runner glue -----------------------------------------------------------

describe('runBondStoreConformance', () => {
  it('runs exactly the named checks; an empty list runs none', async () => {
    const a = memoryBondStoreAdapter();
    expect(await runBondStoreConformance(a, { only: [] })).toEqual({ adapter: 'KvBondStore over an in-memory kv', status: 'pass', checks: [] });
    const r = await runBondStoreConformance(a, { only: ['empty-store-reads-empty', 'state-survives-reopen'] });
    expect(r.checks).toEqual([
      { name: 'empty-store-reads-empty', status: 'pass' },
      { name: 'state-survives-reopen', status: 'skip', detail: 'the adapter declares durable: false' },
    ]);
    const all = await runBondStoreConformance(a);
    expect(all.checks.map((c) => c.name)).toEqual(BOND_CHECKS.map((c) => c.name));
  });

  it('skips the crash check, with its reason, when the adapter has no crash(), and still closes the handle', async () => {
    let closed = 0;
    const a: BondStoreAdapter = {
      name: 'x',
      durable: true,
      async create() {
        const kv = createMemoryDurableKv();
        return { store: new KvBondStore(kv), reopen: async () => new KvBondStore(kv), close: async () => void (closed += 1) };
      },
    };
    const r = await runBondStoreConformance(a, { only: ['acknowledged-commits-survive-a-crash', 'state-survives-reopen'] });
    expect(r.checks).toEqual([
      { name: 'state-survives-reopen', status: 'pass' },
      { name: 'acknowledged-commits-survive-a-crash', status: 'skip', detail: 'the adapter has no crash()' },
    ]);
    expect(closed).toBe(2);
  });

  it('reports a failing check with its message and the run as failed', async () => {
    const r = await runBondStoreConformance(clockRewindBondStoreAdapter(), { only: ['time-high-water-only-moves-forward'] });
    expect(r.status).toBe('fail');
    expect(r.adapter).toBe('BAD clock rewind (high-water mark follows the last call)');
    expect(r.checks).toHaveLength(1);
    expect(r.checks[0]!.status).toBe('fail');
    expect(r.checks[0]!.detail).toMatch(/^Expected values to be strictly equal/);
  });

  it('names the reference adapters', () => {
    expect(memoryBondStoreAdapter().name).toBe('KvBondStore over an in-memory kv');
    expect(durableBondStoreAdapter().name).toBe('KvBondStore over durable-state files');
    expect(Object.keys(BOND_REFERENCE_ADAPTERS)).toEqual(['bond-memory', 'bond-durable-file', 'bad-bond-non-atomic', 'bad-bond-no-replay', 'bad-bond-lost-update', 'bad-bond-amnesia', 'bad-bond-clock-rewind']);
  });
});

describe('formatBondReport', () => {
  it('prints one line per check, with only the first line of a detail', () => {
    const text = formatBondReport({
      adapter: 'a',
      status: 'fail',
      checks: [
        { name: 'p', status: 'pass' },
        { name: 'f', status: 'fail', detail: 'first\nsecond' },
        { name: 's', status: 'skip', detail: 'why' },
      ],
    });
    expect(text).toBe(['pca-store-conformance (bond store): a -> FAIL', '  [PASS] p', '  [FAIL] f: first', '  [SKIP] s: why'].join('\n'));
  });
});

function withGlobals(d: unknown, i: unknown, fn: () => void): void {
  const g = globalThis as unknown as Record<string, unknown>;
  const had = { describe: 'describe' in g, it: 'it' in g };
  const old = { describe: g.describe, it: g.it };
  g.describe = d;
  g.it = i;
  try {
    fn();
  } finally {
    if (had.describe) g.describe = old.describe;
    else delete g.describe;
    if (had.it) g.it = old.it;
    else delete g.it;
  }
}
interface Reg {
  describes: string[];
  its: Array<{ name: string; fn: () => Promise<void>; timeout: number | undefined }>;
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

describe('describeBondStoreConformance', () => {
  it('registers one test per check, named name: claim, under the adapter name, with the default timeout', () => {
    const { reg, runner } = recorder();
    describeBondStoreConformance(memoryBondStoreAdapter(), { runner });
    expect(reg.describes).toEqual(['PCA bond store conformance: KvBondStore over an in-memory kv']);
    expect(reg.its.map((x) => x.name)).toEqual(BOND_CHECKS.map((c) => `${c.name}: ${c.claim}`));
    expect(reg.its.every((x) => x.timeout === 60_000)).toBe(true);
  });
  it('passes a custom timeout through', () => {
    const { reg, runner } = recorder();
    describeBondStoreConformance(memoryBondStoreAdapter(), { runner, timeoutMs: 1234 });
    expect(reg.its.every((x) => x.timeout === 1234)).toBe(true);
  });
  it('accepts an adapter factory: called once to name the suite and once per test run', async () => {
    const { reg, runner } = recorder();
    let calls = 0;
    describeBondStoreConformance(() => (calls += 1, memoryBondStoreAdapter()), { runner });
    expect(calls).toBe(1);
    await reg.its[0]!.fn();
    expect(calls).toBe(2);
  });
  it('a test passes for a passing check and for a skipped one', async () => {
    const { reg, runner } = recorder();
    describeBondStoreConformance(memoryBondStoreAdapter(), { runner });
    await expect(reg.its[0]!.fn()).resolves.toBeUndefined();
    const skipped = reg.its.find((x) => x.name.startsWith('state-survives-reopen'))!;
    await expect(skipped.fn()).resolves.toBeUndefined();
  });
  it('a test runs only its own check and throws the failure detail', async () => {
    const { reg, runner } = recorder();
    describeBondStoreConformance(clockRewindBondStoreAdapter(), { runner });
    const target = reg.its.find((x) => x.name.startsWith('time-high-water-only-moves-forward'))!;
    const direct = (await runBondStoreConformance(clockRewindBondStoreAdapter(), { only: ['time-high-water-only-moves-forward'] })).checks[0]!;
    await expect(target.fn()).rejects.toThrow(direct.detail!);
    await expect(target.fn()).rejects.toBeInstanceOf(Error);
  });
  it('uses the global describe / it when no runner is given', () => {
    const { reg, runner } = recorder();
    withGlobals(runner.describe, runner.it, () => describeBondStoreConformance(memoryBondStoreAdapter()));
    expect(reg.its).toHaveLength(BOND_CHECKS.length);
  });
  it('prefers the runner over the globals', () => {
    const mine = recorder();
    const other = recorder();
    withGlobals(other.runner.describe, other.runner.it, () => describeBondStoreConformance(memoryBondStoreAdapter(), { runner: mine.runner }));
    expect(mine.reg.its).toHaveLength(BOND_CHECKS.length);
    expect(other.reg.its).toHaveLength(0);
  });
  it('mixes a runner describe with a global it', () => {
    const mine = recorder();
    const other = recorder();
    withGlobals(other.runner.describe, other.runner.it, () => describeBondStoreConformance(memoryBondStoreAdapter(), { runner: { describe: mine.runner.describe } as never }));
    expect(mine.reg.describes).toHaveLength(1);
    expect(mine.reg.its).toHaveLength(0);
    expect(other.reg.its).toHaveLength(BOND_CHECKS.length);
  });
  it('refuses to register without a describe and an it, naming the fix', () => {
    const msg = 'describeBondStoreConformance needs describe/it: pass { runner } or enable test globals';
    const { runner } = recorder();
    withGlobals(undefined, undefined, () => expect(() => describeBondStoreConformance(memoryBondStoreAdapter())).toThrow(msg));
    withGlobals(runner.describe, undefined, () => expect(() => describeBondStoreConformance(memoryBondStoreAdapter())).toThrow(msg));
    withGlobals(undefined, runner.it, () => expect(() => describeBondStoreConformance(memoryBondStoreAdapter())).toThrow(msg));
  });
});

// ---- 5. the reference and the defective stores themselves --------------------------------------------------------

const BAD = {
  'non-atomic': nonAtomicBondStoreAdapter,
  'no-replay': noReplayBondStoreAdapter,
  'lost-update': lostUpdateBondStoreAdapter,
  amnesia: amnesiaBondStoreAdapter,
  'clock-rewind': clockRewindBondStoreAdapter,
} as const;

describe('defective bond stores: the part of the contract each one keeps', () => {
  for (const [kind, make] of Object.entries(BAD)) {
    it(`${kind}: reads, deposits, opens and releases behave like the reference`, async () => {
      const h = await make().create();
      const s = h.store;
      expect(await s.read({ claimId: 'x' })).toEqual({ balances: [], openTotals: { count: 0, sum: 0 }, highWater: 0 });
      for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
        await expect(s.deposit('alice', bad)).rejects.toThrow(new RangeError('deposit'));
        await expect(s.deposit('alice', bad)).rejects.toBeInstanceOf(RangeError);
      }
      await expect(s.deposit('', 1)).rejects.toThrow(new RangeError('deposit'));
      expect(await s.deposit('alice', 100)).toBe(100);
      expect(await s.deposit('bob', 50)).toBe(50);
      const open = O('b1', 'alice', 60) as unknown as BondPlan;
      expect(await s.commit(open, 500)).toEqual({ outcome: 'committed', record: open.record });
      const other = O('b2', 'bob', 20) as unknown as BondPlan;
      expect(await s.commit(other, 100)).toEqual({ outcome: 'committed', record: other.record });
      expect(await s.read({ claimId: 'b1', depositor: 'alice' })).toEqual({
        bond: { claimId: 'b1', amount: 60, depositor: 'alice', status: 'open', records: [open.record] },
        balances: [['alice', 40]],
        openTotals: { count: 1, sum: 60 },
        highWater: kind === 'clock-rewind' ? 100 : 500,
      });
      expect((await s.read({ claimId: 'b2', depositor: 'bob' })).openTotals).toEqual({ count: 1, sum: 20 });
      const rel = Rel('b1', 'alice', 60) as unknown as BondPlan;
      expect(await s.commit(rel, 600)).toEqual({ outcome: 'committed', record: rel.record });
      expect((await s.read({ claimId: 'b1', depositor: 'alice' })).bond).toEqual({ claimId: 'b1', amount: 60, depositor: 'alice', status: 'released', records: [open.record, rel.record] });
      const refused = kind === 'no-replay' ? { outcome: 'conflict', reason: 'already applied', current: 'open' } : { outcome: 'conflict', reason: 'phase', current: 'released' };
      expect(await s.commit(rel, 1)).toEqual(kind === 'no-replay' || kind === 'non-atomic' ? refused : { outcome: 'replayed', record: rel.record });
      expect(await s.commit(open, 1)).toEqual(kind === 'no-replay' || kind === 'non-atomic' ? refused : { outcome: 'replayed', record: open.record });
    });

    it(`${kind}: a deposit is ${kind === 'lost-update' ? 'not yet' : 'already'} visible before it is awaited`, async () => {
      const s = (await make().create()).store;
      const p = s.deposit('a', 5);
      expect((await s.read({ claimId: '', depositor: 'a' })).balances).toEqual([['a', kind === 'lost-update' ? 0 : 5]]);
      expect(await p).toBe(5);
      expect((await s.read({ claimId: '', depositor: 'a' })).balances).toEqual([['a', 5]]);
    });
  }

  it('lost-update: two racing deposits lose one, two racing opens can both pass the balance check', async () => {
    const h = await lostUpdateBondStoreAdapter().create();
    const c1 = await h.reopen();
    await Promise.all([h.store.deposit('a', 1), c1.deposit('a', 1)]);
    expect((await h.store.read({ claimId: '', depositor: 'a' })).balances).toEqual([['a', 1]]);
  });
  it('the other stores lose nothing to racing deposits', async () => {
    for (const kind of ['non-atomic', 'no-replay', 'amnesia', 'clock-rewind'] as const) {
      const h = await BAD[kind]().create();
      const c1 = await h.reopen();
      await Promise.all([h.store.deposit('a', 1), c1.deposit('a', 1)]);
      expect((await h.store.read({ claimId: '', depositor: 'a' })).balances).toEqual([['a', 2]]);
    }
  });
  it('lost-update: a refused commit that finishes late does not roll back a deposit that finished first', async () => {
    const h = await lostUpdateBondStoreAdapter().create();
    const c1 = await h.reopen();
    const deposited = c1.deposit('x', 5);
    const refused = h.store.commit(Rel('ghost', 'x', 1) as unknown as BondPlan, 1);
    expect((await refused).outcome).toBe('conflict');
    await deposited;
    expect((await h.store.read({ claimId: '', depositor: 'x' })).balances).toEqual([['x', 5]]);
  });
  it('lost-update: an acknowledged commit is stored', async () => {
    const s = (await lostUpdateBondStoreAdapter().create()).store;
    await s.deposit('alice', 100);
    await s.commit(O('b1', 'alice', 60) as unknown as BondPlan, 7);
    expect((await s.read({ claimId: 'b1', depositor: 'alice' })).bond?.status).toBe('open');
    expect((await s.read({ claimId: 'b1', depositor: 'alice' })).highWater).toBe(7);
  });
  it('amnesia forgets on reopen and on crash', async () => {
    for (const how of ['reopen', 'crash'] as const) {
      const h = await amnesiaBondStoreAdapter().create();
      await h.store.deposit('a', 1);
      const back = await h[how]!();
      expect(await back.read({ claimId: '', depositor: 'a' })).toEqual({ balances: [['a', 0]], openTotals: { count: 0, sum: 0 }, highWater: 0 });
    }
  });
  it('the other defective stores keep their state on reopen and on crash', async () => {
    for (const kind of ['non-atomic', 'no-replay', 'lost-update', 'clock-rewind'] as const) {
      for (const how of ['reopen', 'crash'] as const) {
        const h = await BAD[kind]().create();
        await h.store.deposit('a', 1);
        const back = await h[how]!();
        expect((await back.read({ claimId: '', depositor: 'a' })).balances).toEqual([['a', 1]]);
      }
    }
  });

  it('non-atomic: the moves land before the phase is checked, and the phase conflict says which phase it found', async () => {
    const s = (await nonAtomicBondStoreAdapter().create()).store;
    const open = O('b1', 'alice', 60) as unknown as BondPlan;
    const reads = async (...accts: string[]): Promise<number[]> => Promise.all(accts.map(async (a) => (await s.read({ claimId: '', depositor: a })).balances[0]![1]));
    await s.deposit('alice', 100);
    expect(await s.commit(open, 500)).toEqual({ outcome: 'committed', record: open.record });
    expect(await reads('alice', 'escrow')).toEqual([40, 60]);
    expect((await s.read({ claimId: '' })).highWater).toBe(500);
    // the bond exists, so an open is refused, but its moves have already landed
    expect(await s.commit(open, 100)).toEqual({ outcome: 'conflict', reason: 'phase', current: 'open' });
    expect(await reads('alice', 'escrow')).toEqual([-20, 120]);
    // an absent bond
    expect(await s.commit(Rel('ghost', 'alice', 5) as unknown as BondPlan, 100)).toEqual({ outcome: 'conflict', reason: 'phase', current: 'none' });
    expect(await reads('alice', 'escrow')).toEqual([-15, 115]);
    // the right phase
    const rel = Rel('b1', 'alice', 60) as unknown as BondPlan;
    expect(await s.commit(rel, 100)).toEqual({ outcome: 'committed', record: rel.record });
    expect(await reads('alice', 'escrow')).toEqual([45, 55]);
    expect(await s.read({ claimId: 'b1', depositor: 'alice' })).toEqual({
      bond: { claimId: 'b1', amount: 60, depositor: 'alice', status: 'released', records: [open.record, rel.record] },
      balances: [['alice', 45]],
      openTotals: { count: 0, sum: 0 },
      highWater: 500,
    });
    // a settlement of a bond that is no longer in the expected phase
    expect(await s.commit(Sl('b1', 60) as unknown as BondPlan, 100)).toEqual({ outcome: 'conflict', reason: 'phase', current: 'released' });
    expect(await reads('escrow', 'chal', 'treasury')).toEqual([-5, 30, 30]);
  });
});
