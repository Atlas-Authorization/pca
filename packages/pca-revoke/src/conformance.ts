/**
 * Conformance cases for a {@link RevocationStore}. Run them against your own store:
 *
 * ```ts
 * for (const c of revocationStoreCases(() => new MyStore())) it(c.name, c.run);
 * ```
 *
 * Each case throws (an `AssertionError`) when the store breaks the contract. A store that passes
 * keeps `(kind, value)` keys apart, replaces rather than duplicates, hands out snapshots, and loses
 * nothing under interleaved writes. Durability across a restart is checked with `reopen`.
 */
import { deepStrictEqual, strictEqual } from 'node:assert';
import type { RevocationEntry, RevocationStore, RevocationTargetKind } from './index';

export interface RevocationStoreCase {
  name: string;
  run: () => Promise<void>;
}

const entry = (kind: RevocationTargetKind, value: string, extra: Partial<RevocationEntry> = {}): RevocationEntry => ({
  kind,
  value,
  reason: `r-${kind}-${value}`,
  revokedAt: 1_000,
  ...(kind === 'prefix' ? { prefix: value.split(',') } : {}),
  ...extra,
});

const sorted = (xs: RevocationEntry[]): RevocationEntry[] =>
  [...xs].sort((a, b) => `${a.kind}${a.value}`.localeCompare(`${b.kind}${b.value}`));

/**
 * @param make a fresh, empty store each call. For stores that persist, pass the same backing location
 *   on a second call to `reopen` and the durability case runs; omit `reopen` to skip it.
 */
export function revocationStoreCases(
  make: () => RevocationStore,
  reopen?: (previous: RevocationStore) => RevocationStore,
): RevocationStoreCase[] {
  const cases: RevocationStoreCase[] = [
    {
      name: 'starts empty',
      run: async () => {
        deepStrictEqual(await make().all(), []);
        strictEqual(await make().get('cap', 'x'), undefined);
      },
    },
    {
      name: 'add then get returns the whole entry, including notBefore',
      run: async () => {
        const s = make();
        const e = entry('cap', 'c1', { notBefore: 5_000 });
        await s.add(e);
        deepStrictEqual(await s.get('cap', 'c1'), e);
      },
    },
    {
      name: 'the same value under different kinds is kept apart',
      run: async () => {
        const s = make();
        await s.add(entry('cap', 'k'));
        await s.add(entry('holder', 'k'));
        await s.add(entry('issuer', 'k'));
        strictEqual((await s.all()).length, 3);
        strictEqual(await s.remove('holder', 'k'), true);
        strictEqual((await s.get('cap', 'k'))?.kind, 'cap');
        strictEqual((await s.get('issuer', 'k'))?.kind, 'issuer');
        strictEqual(await s.get('holder', 'k'), undefined);
      },
    },
    {
      name: 'add at an existing key replaces, it does not duplicate',
      run: async () => {
        const s = make();
        await s.add(entry('cap', 'c', { reason: 'first' }));
        await s.add(entry('cap', 'c', { reason: 'second' }));
        strictEqual((await s.all()).length, 1);
        strictEqual((await s.get('cap', 'c'))?.reason, 'second');
      },
    },
    {
      name: 'remove reports whether something was removed, and only once',
      run: async () => {
        const s = make();
        await s.add(entry('cap', 'c'));
        strictEqual(await s.remove('cap', 'c'), true);
        strictEqual(await s.remove('cap', 'c'), false);
        strictEqual(await s.remove('cap', 'never-added'), false);
      },
    },
    {
      name: 'prefix paths that differ stay distinct',
      run: async () => {
        const s = make();
        await s.add(entry('prefix', 'a,b'));
        await s.add(entry('prefix', 'a'));
        await s.add(entry('prefix', 'b,a'));
        strictEqual((await s.all()).length, 3);
        strictEqual(await s.remove('prefix', 'a'), true);
        deepStrictEqual(sorted(await s.all()).map((e) => e.value), ['a,b', 'b,a']);
      },
    },
    {
      name: 'all() is a snapshot: changing it does not change the store',
      run: async () => {
        const s = make();
        await s.add(entry('cap', 'c'));
        const snap = await s.all();
        snap.pop();
        snap.push(entry('cap', 'forged'));
        strictEqual((await s.all()).length, 1);
        strictEqual(await s.get('cap', 'forged'), undefined);
      },
    },
    {
      name: 'clear drops everything',
      run: async () => {
        const s = make();
        await s.add(entry('cap', 'c'));
        await s.add(entry('prefix', 'a,b'));
        await s.clear();
        deepStrictEqual(await s.all(), []);
        strictEqual(await s.get('cap', 'c'), undefined);
      },
    },
    {
      name: 'interleaved adds and removes from many tasks lose nothing',
      run: async () => {
        const s = make();
        const n = 200;
        await Promise.all(
          Array.from({ length: n }, async (_, i) => {
            await Promise.resolve();
            await s.add(entry('cap', `c${i}`));
            if (i % 2 === 1) await s.remove('cap', `c${i - 1}`);
          }),
        );
        const left = new Set((await s.all()).map((e) => e.value));
        strictEqual(left.size, n / 2);
        for (let i = 0; i < n; i++) strictEqual(left.has(`c${i}`), i % 2 === 1);
      },
    },
  ];
  if (reopen) {
    cases.push({
      name: 'entries survive reopening the store',
      run: async () => {
        const s = make();
        const a = entry('cap', 'durable', { notBefore: 9_000 });
        const b = entry('prefix', 'r,m');
        await s.add(a);
        await s.add(b);
        await s.add(entry('holder', 'gone'));
        await s.remove('holder', 'gone');
        const again = reopen(s);
        deepStrictEqual(sorted(await again.all()), sorted([a, b]));
      },
    });
  }
  return cases;
}
