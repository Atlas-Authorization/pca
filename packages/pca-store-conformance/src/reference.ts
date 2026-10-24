/**
 * Reference adapters. The GOOD ones must pass the kit; the BAD ones are positive controls the kit MUST flag (a checker that
 * passes everything is worthless). Each bad adapter reproduces one real mistake from the replay-store verification work.
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { InMemoryReplayStore } from '@atlasauth/pca';
import { openDurableState } from '@atlasauth/pca/durable-state';
import type { StoreAdapter } from './types';

/** GOOD for ONE process: the library's in-memory store. Not durable (declared), not shared between processes. */
export function inMemoryAdapter(): StoreAdapter {
  const store = new InMemoryReplayStore({ maxEntries: 1_000_000 });
  return {
    name: 'in-memory (InMemoryReplayStore)',
    capabilities: { durable: false },
    open: async () => ({
      consumeOnce: (k, r, n) => store.consumeOnce(k, r, n),
      advance: (k, c) => store.advance(k, c),
    }),
  };
}

/** GOOD: the crash-safe, multi-process file store (`@atlasauth/pca/durable-state`), one handle per client, atomic `update`. */
export function durableFileAdapter(options: { dir?: string } = {}): StoreAdapter {
  const dir = options.dir ?? mkdtempSync(join(tmpdir(), 'pcasc-durable-'));
  return {
    name: `durable-state file store (${dir})`,
    capabilities: { durable: true },
    async open() {
      const st = await openDurableState({ dir });
      return {
        async consumeOnce(key, retainUntilMs, nowMs) {
          if (!(retainUntilMs >= nowMs)) throw new RangeError('consumeOnce: retainUntilMs is before nowMs');
          let first = false;
          await st.update(`n:${key}`, (prev) => {
            if (typeof prev === 'number' && prev >= nowMs) return undefined;
            first = true;
            // any old horizon is < now <= retainUntil here, so the new horizon is the larger one
            return retainUntilMs;
          });
          return first;
        },
        async advance(key, counter) {
          let ok = false;
          await st.update(`c:${key}`, (prev) => {
            if (typeof prev === 'number' && !(counter > prev)) return undefined;
            ok = true;
            return counter;
          });
          return ok;
        },
      };
    },
    // Everything is on disk and every client re-opens the directory: a restart loses nothing by construction.
    restart: async () => undefined,
  };
}

const yieldTurn = (): Promise<void> => new Promise((r) => setImmediate(r));

/** BAD: read, then write after an await (no transaction / no compare-and-set). Two clients both read "absent". */
export function readThenWriteAdapter(): StoreAdapter {
  const seen = new Map<string, number>();
  const counters = new Map<string, number>();
  return {
    name: 'BAD read-then-write (await between check and set)',
    capabilities: { durable: false },
    open: async () => ({
      async consumeOnce(k, r, now) {
        const until = seen.get(k);
        await yieldTurn();
        if (until !== undefined && until >= now) return false;
        seen.set(k, r);
        return true;
      },
      async advance(k, c) {
        const last = counters.get(k);
        await yieldTurn();
        if (last !== undefined && !(c > last)) return false;
        counters.set(k, c);
        return true;
      },
    }),
  };
}

/** BAD: claims durability but keeps state in process memory, so a restart forgets every consumed key and counter. */
export function volatileAdapter(): StoreAdapter {
  let store = new InMemoryReplayStore();
  return {
    name: 'BAD volatile (state lost on restart)',
    capabilities: { durable: true },
    open: async () => ({
      consumeOnce: (k, r, n) => store.consumeOnce(k, r, n),
      advance: (k, c) => store.advance(k, c),
    }),
    restart: async () => {
      store = new InMemoryReplayStore();
    },
  };
}

/** BAD: a bounded cache that evicts the oldest record when full, LIVE or not (capacity eviction / early prune). */
export function evictingAdapter(options: { capacity?: number | string } = {}): StoreAdapter {
  const capacity = Number(options.capacity ?? 64);
  const seen = new Map<string, number>();
  const counters = new Map<string, number>();
  const evict = (m: Map<string, number>): void => {
    while (m.size > capacity) m.delete(m.keys().next().value as string);
  };
  return {
    name: `BAD evicting cache (capacity ${capacity}, evicts live records)`,
    capabilities: { durable: false },
    open: async () => ({
      async consumeOnce(k, r, now) {
        const until = seen.get(k);
        if (until !== undefined && until >= now) return false;
        seen.set(k, r);
        evict(seen);
        return true;
      },
      async advance(k, c) {
        const last = counters.get(k);
        if (last !== undefined && !(c > last)) return false;
        counters.set(k, c);
        evict(counters);
        return true;
      },
    }),
  };
}

/** BAD: a counter that accepts a value EQUAL to the last one (`>=` instead of `>`), so one counter is accepted twice. */
export function nonStrictCounterAdapter(): StoreAdapter {
  const counters = new Map<string, number>();
  return {
    name: 'BAD non-strict counter (accepts an equal value)',
    capabilities: { durable: false, consumeOnce: false },
    open: async () => ({
      async advance(k, c) {
        const last = counters.get(k);
        if (last !== undefined && c < last) return false;
        counters.set(k, c);
        return true;
      },
    }),
  };
}

/** Built-in adapters by name (`--adapter builtin:<name>`); each takes the `--option k=v` pairs. */
export const REFERENCE_ADAPTERS: Readonly<Record<string, (options: Record<string, string>) => StoreAdapter>> = {
  'in-memory': () => inMemoryAdapter(),
  'durable-file': (o) => durableFileAdapter({ dir: o.dir }),
  'bad-read-then-write': () => readThenWriteAdapter(),
  'bad-volatile': () => volatileAdapter(),
  'bad-evicting': (o) => evictingAdapter({ capacity: o.capacity }),
  'bad-non-strict-counter': () => nonStrictCounterAdapter(),
};
