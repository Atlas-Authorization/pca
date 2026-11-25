import { describe, expect, it } from 'vitest';
import type { AccumulatorDecl, BudgetLedger, ReserveRequest } from '@atlasauth/pca/ext/intent';
import {
  amnesiaBudgetLedgerAdapter,
  durableBudgetLedgerAdapter,
  expireCommittedBudgetLedgerAdapter,
  expireStartedBudgetLedgerAdapter,
  lateCommitBudgetLedgerAdapter,
  lostUpdateBudgetLedgerAdapter,
  memoryBudgetLedgerAdapter,
  noCapBudgetLedgerAdapter,
  noCasBudgetLedgerAdapter,
  noReplayBudgetLedgerAdapter,
  releaseCommittedBudgetLedgerAdapter,
  releaseUnreservedBudgetLedgerAdapter,
  sharedKeysBudgetLedgerAdapter,
  volatileClaimsDurableBudgetLedgerAdapter,
  type BudgetLedgerAdapter,
} from './budget-conformance';

const K = 'principal/alice';
const K2 = 'principal/bob';
const SPEND: AccumulatorDecl = {
  id: 'spend',
  agg: 'sum',
  val: 'action.params.amount',
  sel: { verbs: ['pay'] },
  win: { kind: 'task' },
  key: null,
  domain_max: 200,
  holder: { kind: 'site_local' },
  scope: 'principal',
};
const R = (id: string, amount = 10, extra: Partial<ReserveRequest> = {}): ReserveRequest => ({
  event: { id, verb: 'pay', resource: 'r', params: { amount }, t: 1000 },
  accumulators: [SPEND],
  ...extra,
});
const open = async (f: () => BudgetLedgerAdapter): Promise<BudgetLedger> => (await f().create()).ledger;
const states = async (l: BudgetLedger, key = K): Promise<[string, string][]> => (await l.snapshot(key)).events.map((e): [string, string] => [e.id, e.status]);

describe('defective ledgers carry their documented names', () => {
  const cases: [() => BudgetLedgerAdapter, string][] = [
    [noCapBudgetLedgerAdapter, 'BAD no cap check (records every reservation)'],
    [noCasBudgetLedgerAdapter, 'BAD no compare-and-swap (ignores expectedVersion)'],
    [lostUpdateBudgetLedgerAdapter, 'BAD lost update (read, await, write)'],
    [amnesiaBudgetLedgerAdapter, 'BAD amnesia (claims durability, forgets on reopen)'],
    [releaseUnreservedBudgetLedgerAdapter, 'BAD release without reserve (credits budget for an unknown id)'],
    [releaseCommittedBudgetLedgerAdapter, 'BAD release of a committed event (frees spent budget)'],
    [lateCommitBudgetLedgerAdapter, 'BAD late commit (a released reservation can be committed again)'],
    [noReplayBudgetLedgerAdapter, 'BAD no idempotence (a retried reservation counts twice)'],
    [sharedKeysBudgetLedgerAdapter, 'BAD one state for every key (keys leak into each other)'],
    [expireCommittedBudgetLedgerAdapter, 'BAD expiry releases committed events'],
    [expireStartedBudgetLedgerAdapter, 'BAD expiry releases started reservations (an effect that ran stops counting)'],
    [volatileClaimsDurableBudgetLedgerAdapter, 'BAD in-process ledger that claims durable: true'],
  ];
  for (const [f, name] of cases) it(name, () => expect(f().name).toBe(name));
  it('the reference adapters carry theirs', () => {
    expect(memoryBudgetLedgerAdapter().name).toBe('KvBudgetLedger over an in-memory kv');
    expect(durableBudgetLedgerAdapter().name).toBe('KvBudgetLedger over durable-state files');
  });
});

describe('the in-memory reference ledger', () => {
  it('claims no durability on either client', async () => {
    const h = await memoryBudgetLedgerAdapter().create();
    expect(h.ledger.durable).toBe(false);
    expect((await h.reopen()).durable).toBe(false);
  });
});

describe('the defective document ledger behaves like a document ledger apart from its one defect', () => {
  it('keeps one document per key and returns snapshots as plain {version, events}', async () => {
    const l = await open(noCasBudgetLedgerAdapter);
    expect(await l.snapshot(K)).toEqual({ version: 0, events: [] });
    await l.reserve(K, R('a'));
    const s = await l.snapshot(K);
    expect(s.version).toBe(1);
    expect(s.events.map((e) => e.id)).toEqual(['a']);
    expect(await l.snapshot(K2)).toEqual({ version: 0, events: [] });
    expect(await states(l)).toEqual([['a', 'reserved']]);
  });
  it('shares one document across keys only for the shared-keys defect', async () => {
    const l = await open(sharedKeysBudgetLedgerAdapter);
    await l.reserve(K, R('a'));
    expect((await l.snapshot(K2)).events.map((e) => e.id)).toEqual(['a']);
  });
  it('a reopened client sees the same state unless the defect is amnesia', async () => {
    for (const f of [noCasBudgetLedgerAdapter, noCapBudgetLedgerAdapter]) {
      const h = await f().create();
      await h.ledger.reserve(K, R('a'));
      expect((await (await h.reopen()).snapshot(K)).events).toHaveLength(1);
      expect((await (await h.crash!()).snapshot(K)).events).toHaveLength(1);
    }
    const h = await amnesiaBudgetLedgerAdapter().create();
    await h.ledger.reserve(K, R('a'));
    expect(await (await h.reopen()).snapshot(K)).toEqual({ version: 0, events: [] });
    await h.ledger.reserve(K, R('b'));
    expect(await (await h.crash!()).snapshot(K)).toEqual({ version: 0, events: [] });
  });
  it('only the volatile-claims-durable ledger lies about durability; the others claim it', async () => {
    const v = await volatileClaimsDurableBudgetLedgerAdapter().create();
    expect(volatileClaimsDurableBudgetLedgerAdapter().durable).toBe(false);
    expect(v.ledger.durable).toBe(true);
    expect((await v.reopen()).durable).toBe(true);
    for (const f of [noCapBudgetLedgerAdapter, amnesiaBudgetLedgerAdapter, expireStartedBudgetLedgerAdapter]) {
      expect(f().durable).toBe(true);
      expect((await f().create()).ledger.durable).toBe(true);
    }
  });
});

describe('lost update', () => {
  it('applies a reservation only after yielding to the event loop, then keeps it', async () => {
    const l = await open(lostUpdateBudgetLedgerAdapter);
    const p = l.reserve(K, R('a'));
    await Promise.resolve();
    expect((await l.snapshot(K)).events).toEqual([]);
    expect(await p).toEqual({ outcome: 'reserved', version: 1, post: { spend: 10 } });
    expect(await states(l)).toEqual([['a', 'reserved']]);
  });
  it('loses one of two racing reservations although both are acknowledged', async () => {
    const l = await open(lostUpdateBudgetLedgerAdapter);
    const [x, y] = await Promise.all([l.reserve(K, R('a')), l.reserve(K, R('b'))]);
    expect([x.outcome, y.outcome]).toEqual(['reserved', 'reserved']);
    expect((await l.snapshot(K)).events).toHaveLength(1);
  });
});

describe('no compare-and-swap, no cap', () => {
  it('no-cas ignores a stale expected version', async () => {
    const l = await open(noCasBudgetLedgerAdapter);
    await l.reserve(K, R('a', 10, { expectedVersion: 0 }));
    expect(await l.reserve(K, R('b', 10, { expectedVersion: 0 }))).toEqual({ outcome: 'reserved', version: 2, post: { spend: 20 } });
  });
  it('the other defects still honour the expected version', async () => {
    const l = await open(noCapBudgetLedgerAdapter);
    await l.reserve(K, R('a', 10, { expectedVersion: 0 }));
    expect(await l.reserve(K, R('b', 10, { expectedVersion: 0 }))).toEqual({ outcome: 'conflict', version: 1 });
  });
  it('no-cap admits a reservation past the cap', async () => {
    const l = await open(noCapBudgetLedgerAdapter);
    await l.reserve(K, R('a', 150));
    expect(await l.reserve(K, R('b', 100))).toEqual({ outcome: 'reserved', version: 2, post: { spend: 250 } });
    expect((await l.snapshot(K)).events).toHaveLength(2);
  });
  it('the other defects still enforce the cap', async () => {
    const l = await open(noCasBudgetLedgerAdapter);
    await l.reserve(K, R('a', 150));
    expect(await l.reserve(K, R('b', 100))).toEqual({ outcome: 'over_cap', version: 1, acc: 'spend', post: 250, cap: 200 });
  });
});

describe('no replay', () => {
  it('a first and a new reservation are real ones', async () => {
    const l = await open(noReplayBudgetLedgerAdapter);
    expect(await l.reserve(K, R('a', 150))).toEqual({ outcome: 'reserved', version: 1, post: { spend: 150 } });
    expect(await l.reserve(K, R('b', 50))).toEqual({ outcome: 'reserved', version: 2, post: { spend: 200 } });
  });
  it('a repeated id appends a copy of that very event under a #dup id and bumps the version', async () => {
    const l = await open(noReplayBudgetLedgerAdapter);
    await l.reserve(K, R('a', 150));
    await l.reserve(K, R('b', 50));
    expect(await l.reserve(K, R('b', 50))).toEqual({ outcome: 'reserved', version: 3, post: {} });
    const s = await l.snapshot(K);
    expect(s.version).toBe(3);
    expect(s.events.map((e) => e.id)).toEqual(['a', 'b', 'b#dup']);
    expect(s.events[2]).toEqual({ ...s.events[1], id: 'b#dup' });
    expect(s.events[2]!.params).toEqual({ amount: 50 });
    expect(await l.reserve(K, R('a', 150))).toEqual({ outcome: 'reserved', version: 4, post: {} });
    const t = await l.snapshot(K);
    expect(t.events[3]).toEqual({ ...t.events[0], id: 'a#dup' });
  });
  it('the other defects replay a repeated id', async () => {
    const l = await open(noCasBudgetLedgerAdapter);
    expect(await l.reserve(K, R('a', 150))).toEqual({ outcome: 'reserved', version: 1, post: { spend: 150 } });
    expect(await l.reserve(K, R('a', 150))).toEqual({ outcome: 'replayed', version: 1, status: 'reserved' });
  });
});

describe('late commit', () => {
  it('commits a released event again', async () => {
    const l = await open(lateCommitBudgetLedgerAdapter);
    await l.reserve(K, R('a', 200));
    await l.release(K, 'a');
    expect(await l.commit(K, 'a')).toEqual({ outcome: 'settled', version: 3 });
    expect(await states(l)).toEqual([['a', 'committed']]);
    expect((await l.snapshot(K)).version).toBe(3);
  });
  it('still answers unknown for an unknown id and replayed for a committed one', async () => {
    const l = await open(lateCommitBudgetLedgerAdapter);
    expect(await l.commit(K, 'ghost')).toEqual({ outcome: 'unknown', version: 0 });
    await l.reserve(K, R('b'));
    expect(await l.commit(K, 'b')).toEqual({ outcome: 'settled', version: 2 });
    expect(await l.commit(K, 'b')).toEqual({ outcome: 'replayed', version: 2 });
  });
  it('the other defects refuse a late commit', async () => {
    const l = await open(noCapBudgetLedgerAdapter);
    await l.reserve(K, R('a', 200));
    await l.release(K, 'a');
    expect(await l.commit(K, 'a')).toEqual({ outcome: 'refused', version: 2, status: 'released' });
  });
});

describe('release defects', () => {
  it('release-unreserved books a committed credit for an id nobody reserved', async () => {
    const l = await open(releaseUnreservedBudgetLedgerAdapter);
    expect(await l.release(K, 'ghost')).toEqual({ outcome: 'settled', version: 1 });
    expect((await l.snapshot(K)).events).toEqual([{ id: 'ghost', verb: 'pay', resource: 'r', params: { amount: -200 }, t: 0, status: 'committed' }]);
  });
  it('release-unreserved releases a real reservation normally', async () => {
    const l = await open(releaseUnreservedBudgetLedgerAdapter);
    await l.reserve(K, R('a'));
    expect(await l.release(K, 'a')).toEqual({ outcome: 'settled', version: 2 });
    expect(await states(l)).toEqual([['a', 'released']]);
  });
  it('the other defects answer unknown for an unreserved id', async () => {
    for (const f of [noCapBudgetLedgerAdapter, releaseCommittedBudgetLedgerAdapter]) {
      const l = await open(f);
      expect(await l.release(K, 'ghost')).toEqual({ outcome: 'unknown', version: 0 });
      expect((await l.snapshot(K)).events).toEqual([]);
    }
  });
  it('release-committed frees a committed event and releases an open one normally', async () => {
    const l = await open(releaseCommittedBudgetLedgerAdapter);
    await l.reserve(K, R('a'));
    await l.commit(K, 'a');
    expect(await l.release(K, 'a')).toEqual({ outcome: 'settled', version: 3 });
    await l.reserve(K, R('b'));
    expect(await l.release(K, 'b')).toEqual({ outcome: 'settled', version: 5 });
    expect(await states(l)).toEqual([['a', 'released'], ['b', 'released']]);
  });
  it('the other defects refuse to release a committed event', async () => {
    const l = await open(noCapBudgetLedgerAdapter);
    await l.reserve(K, R('a'));
    await l.commit(K, 'a');
    expect(await l.release(K, 'a')).toEqual({ outcome: 'refused', version: 2, status: 'committed' });
    expect(await states(l)).toEqual([['a', 'committed']]);
  });
});

describe('expiry defects', () => {
  /** a: open past 500; b: committed; c: no deadline; d: deadline 600; e: released; g: started. */
  const seed = async (l: BudgetLedger): Promise<number> => {
    await l.reserve(K, R('a', 10, { expiresAt: 500 }));
    await l.reserve(K, R('b', 10, { expiresAt: 500 }));
    await l.reserve(K, R('c'));
    await l.reserve(K, R('d', 10, { expiresAt: 600 }));
    await l.reserve(K, R('e', 10, { expiresAt: 500 }));
    await l.reserve(K, R('g', 10, { expiresAt: 500 }));
    await l.commit(K, 'b');
    await l.release(K, 'e');
    await l.start(K, 'g');
    return (await l.snapshot(K)).version;
  };

  it('expire-committed releases every event with a deadline reached, committed and started ones included', async () => {
    const l = await open(expireCommittedBudgetLedgerAdapter);
    const v = await seed(l);
    expect(await l.expire(K, 499)).toEqual({ released: [], version: v });
    expect(await l.expire(K, 500)).toEqual({ released: ['a', 'b', 'g'], version: v + 1 });
    expect(await states(l)).toEqual([['a', 'released'], ['b', 'released'], ['c', 'reserved'], ['d', 'reserved'], ['e', 'released'], ['g', 'released']]);
    expect(await l.expire(K, 500)).toEqual({ released: [], version: v + 1 });
    expect(await l.expire(K, 600)).toEqual({ released: ['d'], version: v + 2 });
  });
  it('expire-started releases reserved events at the deadline, started ones included, never committed or released ones', async () => {
    const l = await open(expireStartedBudgetLedgerAdapter);
    const v = await seed(l);
    expect(await l.expire(K, 499)).toEqual({ released: [], version: v });
    expect(await l.expire(K, 500)).toEqual({ released: ['a', 'g'], version: v + 1 });
    expect(await states(l)).toEqual([['a', 'released'], ['b', 'committed'], ['c', 'reserved'], ['d', 'reserved'], ['e', 'released'], ['g', 'released']]);
    expect(await l.expire(K, 500)).toEqual({ released: [], version: v + 1 });
    expect(await l.expire(K, 600)).toEqual({ released: ['d'], version: v + 2 });
  });
  it('the other defects expire only open, unstarted reservations', async () => {
    const l = await open(noCapBudgetLedgerAdapter);
    const v = await seed(l);
    expect(await l.expire(K, 500)).toEqual({ released: ['a'], version: v + 1 });
    expect(await states(l)).toEqual([['a', 'released'], ['b', 'committed'], ['c', 'reserved'], ['d', 'reserved'], ['e', 'released'], ['g', 'reserved']]);
  });
});
