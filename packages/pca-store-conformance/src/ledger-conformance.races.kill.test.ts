import { describe, expect, it } from 'vitest';
import { appendToLedgerDoc, checkpointToLedgerDoc, emptyLedgerDoc, type Checkpoint, type LedgerStore } from '@atlasauth/pca/ext/ledger';
import {
  LEDGER_CHECKS,
  amnesiaLedgerStoreAdapter,
  checkpointRegressLedgerStoreAdapter,
  lostUpdateLedgerStoreAdapter,
  memoryLedgerStoreAdapter,
  noCasLedgerStoreAdapter,
  noReplayLedgerStoreAdapter,
  partialBatchLedgerStoreAdapter,
  type LedgerStoreHandle,
} from './ledger-conformance';

const check = (name: string) => LEDGER_CHECKS.find((c) => c.name === name)!;

/** A correct in-memory handle whose clients are all passed through `wrap`. */
async function wrapped(wrap: (inner: LedgerStore) => LedgerStore): Promise<LedgerStoreHandle> {
  const base = await memoryLedgerStoreAdapter().create();
  return { store: wrap(base.store), reopen: async () => wrap(await base.reopen()) };
}
const over = (inner: LedgerStore, patch: Partial<LedgerStore>): LedgerStore => ({
  size: () => inner.size(),
  read: (f, t) => inner.read(f, t),
  append: (e, c) => inner.append(e, c),
  checkpointCount: () => inner.checkpointCount(),
  checkpoints: (f) => inner.checkpoints(f),
  appendCheckpoint: (e, c) => inner.appendCheckpoint(e, c),
  ...patch,
});

describe('ledger checks reject stores that break one claim', () => {
  it('a race winner whose commit is not one of the competing commits', async () => {
    const h = await wrapped((s) => over(s, { append: (e, c) => s.append(e, c.map((x) => `tampered-${x}`)) }));
    await expect(check('racing-appends-at-one-position-have-one-winner').run(h)).rejects.toThrow();
  });

  it('positions reported by retrying writers must hold their own commit', async () => {
    const h = await wrapped((s) => over(s, { read: async (f, t) => (await s.read(f, t)).reverse() }));
    await expect(check('racing-writers-with-retry-fill-every-position-once').run(h)).rejects.toThrow();
  });

  it('a read that hands out the stored array, or checkpoints that share state with the store', async () => {
    const make = (alias: 'read' | 'checkpoints'): LedgerStore => {
      const doc = emptyLedgerDoc();
      return {
        size: async () => doc.commits.length,
        read: async (f, t) => (alias === 'read' && f === 0 && t === doc.commits.length ? doc.commits : doc.commits.slice(f, t)),
        append: async (e, c) => appendToLedgerDoc(doc, e, c),
        checkpointCount: async () => doc.checkpoints.length,
        checkpoints: async (f = 0) => (alias === 'checkpoints' ? doc.checkpoints.slice(f) : structuredClone(doc.checkpoints.slice(f))),
        appendCheckpoint: async (e, c: Checkpoint) => checkpointToLedgerDoc(doc, e, c),
      };
    };
    for (const alias of ['read', 'checkpoints'] as const) {
      const s = make(alias);
      await expect(check('reads-are-snapshots').run({ store: s, reopen: async () => s })).rejects.toThrow();
    }
  });
});

describe('ledger checks fail on the exact claim a defect breaks', () => {
  it('a store that keeps the first commit of every losing batch has one winner but a log of eight', async () => {
    const h = await partialBatchLedgerStoreAdapter().create();
    await expect(check('racing-appends-at-one-position-have-one-winner').run(h)).rejects.toThrow('8 !== 1');
  });

  it('a read that hands out the stored array shows the overwritten first commit in the failure', async () => {
    const doc = emptyLedgerDoc();
    const s: LedgerStore = {
      size: async () => doc.commits.length,
      read: async (f, t) => (f === 0 && t === doc.commits.length ? doc.commits : doc.commits.slice(f, t)),
      append: async (e, c) => appendToLedgerDoc(doc, e, c),
      checkpointCount: async () => doc.checkpoints.length,
      checkpoints: async (f = 0) => structuredClone(doc.checkpoints.slice(f)),
      appendCheckpoint: async (e, c: Checkpoint) => checkpointToLedgerDoc(doc, e, c),
    };
    await expect(check('reads-are-snapshots').run({ store: s, reopen: async () => s })).rejects.toThrow("'mutated'");
  });
});

describe('the defective reference adapters', () => {
  const adapters = {
    'no-cas': noCasLedgerStoreAdapter,
    'partial-batch': partialBatchLedgerStoreAdapter,
    'lost-update': lostUpdateLedgerStoreAdapter,
    amnesia: amnesiaLedgerStoreAdapter,
    'checkpoint-regress': checkpointRegressLedgerStoreAdapter,
    'no-replay': noReplayLedgerStoreAdapter,
  };

  it('still refuse a batch with a commit that is not a non-empty string', async () => {
    for (const [name, make] of Object.entries(adapters)) {
      const { store } = await make().create();
      for (const bad of [[7], [''], ['a', 7]]) {
        const e = await store.append(0, bad as never).then(() => undefined, (x: unknown) => x);
        expect(e, `${name} ${JSON.stringify(bad)}`).toBeInstanceOf(RangeError);
        expect((e as RangeError).message).toBe('append');
      }
    }
  });

  it('only the no-replay adapter turns a replay into a conflict; a first append lands everywhere', async () => {
    for (const [name, make] of Object.entries(adapters)) {
      const { store } = await make().create();
      expect(await store.append(0, ['a']), name).toEqual({ outcome: 'appended', size: 1 });
      const again = await store.append(0, ['a']);
      if (name === 'no-replay') expect(again).toEqual({ outcome: 'conflict', size: 1 });
      else if (name === 'no-cas') expect(again).toEqual({ outcome: 'appended', size: 2 });
      else if (name === 'partial-batch') expect(again).toEqual({ outcome: 'conflict', size: 2 });
      else expect(again, name).toEqual({ outcome: 'replayed', size: 1 });
    }
  });
});
