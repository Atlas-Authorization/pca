import { describe, expect, it } from 'vitest';
import type { Checkpoint, LedgerStore } from '@atlasauth/pca/ext/ledger';
import {
  LEDGER_REFERENCE_ADAPTERS,
  amnesiaLedgerStoreAdapter,
  checkpointRegressLedgerStoreAdapter,
  durableLedgerStoreAdapter,
  lostUpdateLedgerStoreAdapter,
  memoryLedgerStoreAdapter,
  noCasLedgerStoreAdapter,
  noReplayLedgerStoreAdapter,
  partialBatchLedgerStoreAdapter,
  type LedgerStoreAdapter,
} from './ledger-conformance';

const cp = (size: number, root = `root-${size}`): Checkpoint => ({ sth: { instance_id: 'i', principal: 'p', size, root, prev_root: '', timestamp: 1, guardian: 'g', sig: 's' } });
const open = async (a: LedgerStoreAdapter): Promise<LedgerStore> => (await a.create()).store;
const refuses = async (p: Promise<unknown>, message: string): Promise<void> => {
  const e = await p.then(() => undefined, (x: unknown) => x);
  expect(e).toBeInstanceOf(RangeError);
  expect((e as RangeError).message).toBe(message);
};

describe('reference and defective ledger adapters: identity', () => {
  it('names and durability flags', () => {
    expect([memoryLedgerStoreAdapter().name, memoryLedgerStoreAdapter().durable]).toEqual(['KvLedgerStore over an in-memory kv', false]);
    expect([durableLedgerStoreAdapter().name, durableLedgerStoreAdapter().durable]).toEqual(['KvLedgerStore over durable-state files', true]);
    const bad = [
      [noCasLedgerStoreAdapter(), 'BAD no compare-and-swap (appends at the tail whatever the caller saw)'],
      [partialBatchLedgerStoreAdapter(), 'BAD partial batch (a conflicting batch leaves its first commit behind)'],
      [lostUpdateLedgerStoreAdapter(), 'BAD lost update (read, await, write)'],
      [amnesiaLedgerStoreAdapter(), 'BAD amnesia (claims durability, forgets on reopen)'],
      [checkpointRegressLedgerStoreAdapter(), 'BAD checkpoint regression (accepts a checkpoint below the previous one)'],
      [noReplayLedgerStoreAdapter(), 'BAD no idempotence (a retried batch conflicts)'],
    ] as const;
    for (const [a, name] of bad) expect([a.name, a.durable]).toEqual([name, true]);
    expect(Object.keys(LEDGER_REFERENCE_ADAPTERS)).toEqual(['ledger-memory', 'ledger-durable-file', 'bad-ledger-no-cas', 'bad-ledger-partial-batch', 'bad-ledger-lost-update', 'bad-ledger-amnesia', 'bad-ledger-checkpoint-regress', 'bad-ledger-no-replay']);
  });

  it('the in-memory reference reopens onto the same data', async () => {
    const h = await memoryLedgerStoreAdapter().create();
    await h.store.append(0, ['a']);
    expect(await (await h.reopen()).size()).toBe(1);
  });
});

describe('defective ledger adapters: shared read and append validation', () => {
  it('read accepts exactly the ranges inside the log', async () => {
    const s = await open(noReplayLedgerStoreAdapter());
    expect(await s.read(0, 0)).toEqual([]);
    await s.append(0, ['a', 'b']);
    expect(await s.read(0, 2)).toEqual(['a', 'b']);
    expect(await s.read(0, 1)).toEqual(['a']);
    expect(await s.read(1, 2)).toEqual(['b']);
    expect(await s.read(1, 1)).toEqual([]);
    expect(await s.read(2, 2)).toEqual([]);
    for (const [f, t] of [[-1, 1], [1, 0], [0, 3], [0.5, 1], [0, 1.5], [Number.NaN, 1], [0, Number.NaN], [0, Number.POSITIVE_INFINITY]] as const) await refuses(s.read(f, t), 'read');
  });

  it('append refuses bad lengths and bad batches, and accepts expected length 0', async () => {
    const s = await open(noReplayLedgerStoreAdapter());
    for (const e of [-1, 1.5, Number.NaN]) await refuses(s.append(e, ['a']), 'append');
    for (const bad of [[], [''], [7], ['a', 7], ['a', ''], [7, 'a'], 'x']) await refuses(s.append(0, bad as never), 'append');
    expect(await s.size()).toBe(0);
    expect(await s.append(0, ['a'])).toEqual({ outcome: 'appended', size: 1 });
  });
});

describe('defective ledger adapters: each defect', () => {
  it('no-cas appends at the tail whatever the caller expected', async () => {
    const s = await open(noCasLedgerStoreAdapter());
    expect(await s.append(0, ['a'])).toEqual({ outcome: 'appended', size: 1 });
    expect(await s.append(9, ['b'])).toEqual({ outcome: 'appended', size: 2 });
    expect(await s.append(0, ['a'])).toEqual({ outcome: 'appended', size: 3 });
    expect(await s.read(0, 3)).toEqual(['a', 'b', 'a']);
  });

  it('partial-batch leaves the first commit of a conflicting batch behind and behaves otherwise', async () => {
    const s = await open(partialBatchLedgerStoreAdapter());
    expect(await s.append(0, ['a'])).toEqual({ outcome: 'appended', size: 1 });
    expect(await s.append(5, ['x', 'y'])).toEqual({ outcome: 'conflict', size: 2 });
    expect(await s.read(0, 2)).toEqual(['a', 'x']);
    expect(await s.append(2, ['z'])).toEqual({ outcome: 'appended', size: 3 });
  });

  it('the other defects keep conflicts atomic and replays idempotent where they are not the defect', async () => {
    const s = await open(lostUpdateLedgerStoreAdapter());
    expect(await s.append(0, ['a'])).toEqual({ outcome: 'appended', size: 1 });
    expect(await s.append(5, ['x'])).toEqual({ outcome: 'conflict', size: 1 });
    expect(await s.append(0, ['a'])).toEqual({ outcome: 'replayed', size: 1 });
    expect(await s.read(0, 1)).toEqual(['a']);
    expect(await s.size()).toBe(1);
  });

  it('lost-update: two writers at one position both succeed and the later one wins; a conflict never overwrites', async () => {
    const s = await open(lostUpdateLedgerStoreAdapter());
    expect(await Promise.all([s.append(0, ['a']), s.append(0, ['b'])])).toEqual([
      { outcome: 'appended', size: 1 },
      { outcome: 'appended', size: 1 },
    ]);
    expect(await s.read(0, 1)).toEqual(['b']);
    const t = await open(lostUpdateLedgerStoreAdapter());
    expect(await Promise.all([t.append(0, ['a']), t.append(1, ['z'])])).toEqual([
      { outcome: 'appended', size: 1 },
      { outcome: 'conflict', size: 0 },
    ]);
    expect(await t.read(0, 1)).toEqual(['a']);
    expect(await t.size()).toBe(1);
  });

  it('only lost-update yields between reading and writing; the others commit synchronously', async () => {
    const s = await open(noReplayLedgerStoreAdapter());
    const p = s.append(0, ['a']);
    expect(await s.size()).toBe(1);
    await p;
    const l = await open(lostUpdateLedgerStoreAdapter());
    const q = l.append(0, ['a']);
    expect(await l.size()).toBe(0);
    await q;
    expect(await l.size()).toBe(1);
  });

  it('no-replay turns a replay into a conflict and nothing else', async () => {
    const s = await open(noReplayLedgerStoreAdapter());
    expect(await s.append(0, ['a'])).toEqual({ outcome: 'appended', size: 1 });
    expect(await s.append(0, ['a'])).toEqual({ outcome: 'conflict', size: 1 });
    expect(await s.append(5, ['x'])).toEqual({ outcome: 'conflict', size: 1 });
    expect(await s.append(1, ['b'])).toEqual({ outcome: 'appended', size: 2 });
    expect(await s.append(0, ['a', 'b'])).toEqual({ outcome: 'conflict', size: 2 });
    expect(await s.read(0, 2)).toEqual(['a', 'b']);
  });

  it('amnesia forgets on reopen and on crash; the others keep their data', async () => {
    for (const how of ['reopen', 'crash'] as const) {
      const h = await amnesiaLedgerStoreAdapter().create();
      await h.store.append(0, ['a']);
      expect(await h.store.size()).toBe(1);
      const back = await h[how]!();
      expect(await back.size()).toBe(0);
      const k = await noReplayLedgerStoreAdapter().create();
      await k.store.append(0, ['a']);
      expect(await (await k[how]!()).size()).toBe(1);
    }
  });
});

describe('defective ledger adapters: checkpoints', () => {
  it('the normal checkpoint rules, with exact refusal reasons', async () => {
    const s = await open(noReplayLedgerStoreAdapter());
    await s.append(0, ['a', 'b', 'c']);
    expect(await s.appendCheckpoint(1, cp(2))).toEqual({ outcome: 'conflict', count: 0, reason: 'position' });
    expect(await s.appendCheckpoint(0, null as never)).toEqual({ outcome: 'conflict', count: 0, reason: 'invalid' });
    expect(await s.appendCheckpoint(0, {} as never)).toEqual({ outcome: 'conflict', count: 0, reason: 'invalid' });
    expect(await s.appendCheckpoint(0, cp(4))).toEqual({ outcome: 'conflict', count: 0, reason: 'invalid' });
    expect(await s.appendCheckpoint(0, cp(3))).toEqual({ outcome: 'appended', count: 1 });
    expect(await s.appendCheckpoint(1, cp(2))).toEqual({ outcome: 'conflict', count: 1, reason: 'invalid' });
    expect(await s.appendCheckpoint(1, cp(3, 'other'))).toEqual({ outcome: 'conflict', count: 1, reason: 'invalid' });
    expect(await s.appendCheckpoint(1, cp(3))).toEqual({ outcome: 'appended', count: 2 });
    await s.append(3, ['d']);
    expect(await s.appendCheckpoint(2, cp(4))).toEqual({ outcome: 'appended', count: 3 });
    expect(await s.appendCheckpoint(0, cp(4))).toEqual({ outcome: 'conflict', count: 3, reason: 'position' });
    expect(await s.checkpointCount()).toBe(3);
    expect((await s.checkpoints()).map((c) => c.sth.size)).toEqual([3, 3, 4]);
    expect((await s.checkpoints(0)).map((c) => c.sth.size)).toEqual([3, 3, 4]);
    expect((await s.checkpoints(1)).map((c) => c.sth.size)).toEqual([3, 4]);
    expect((await s.checkpoints(2)).map((c) => c.sth.size)).toEqual([4]);
    const copy = await s.checkpoints(2);
    copy[0]!.sth.size = 99;
    expect((await s.checkpoints(2))[0]!.sth.size).toBe(4);
  });

  it('checkpoint-regress accepts a checkpoint below the previous and beyond the log, but only at the right position and only well-formed', async () => {
    const s = await open(checkpointRegressLedgerStoreAdapter());
    await s.append(0, ['a', 'b', 'c']);
    expect(await s.appendCheckpoint(0, cp(3))).toEqual({ outcome: 'appended', count: 1 });
    expect(await s.appendCheckpoint(1, cp(2))).toEqual({ outcome: 'appended', count: 2 });
    expect(await s.appendCheckpoint(2, cp(9))).toEqual({ outcome: 'appended', count: 3 });
    expect(await s.appendCheckpoint(7, cp(1))).toEqual({ outcome: 'conflict', count: 3, reason: 'position' });
    expect(await s.appendCheckpoint(3, null as never)).toEqual({ outcome: 'conflict', count: 3, reason: 'invalid' });
    expect(await s.appendCheckpoint(3, {} as never)).toEqual({ outcome: 'conflict', count: 3, reason: 'invalid' });
    expect((await s.checkpoints()).map((c) => c.sth.size)).toEqual([3, 2, 9]);
  });
});
