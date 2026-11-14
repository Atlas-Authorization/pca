/** Every accepted kind loads from disk and is keyed by kind and value; the store cases catch a store with the wrong members. */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { FileRevocationStore } from './file-store';
import { InMemoryRevocationStore, type RevocationEntry, type RevocationStore } from './index';
import { revocationStoreCases } from './conformance';

const dir = mkdtempSync(join(tmpdir(), 'pca-revoke-kinds-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('FileRevocationStore loads every kind', () => {
  it('loads cap, holder, issuer and prefix entries and keys them by kind and value', async () => {
    const entries: RevocationEntry[] = [
      { kind: 'cap', value: 'v', reason: 'r', revokedAt: 1 },
      { kind: 'holder', value: 'v', reason: 'r', revokedAt: 2 },
      { kind: 'issuer', value: 'v', reason: 'r', revokedAt: 3 },
      { kind: 'prefix', value: 'a,b', prefix: ['a', 'b'], reason: 'r', revokedAt: 4 },
    ];
    const p = join(dir, 'kinds.json');
    writeFileSync(p, JSON.stringify({ v: 1, entries }));
    const s = new FileRevocationStore(p);
    expect(await s.all()).toEqual(entries);
    for (const e of entries) expect(await s.get(e.kind, e.value)).toEqual(e);
    expect(await s.remove('holder', 'v')).toBe(true);
    expect((await s.all()).map((e) => e.kind)).toEqual(['cap', 'issuer', 'prefix']);
  });
});

describe('FileRevocationStore loads every kind (module loaded fresh: the kind list and the key function are built at load)', () => {
  it('the same entries load and stay apart by kind', async () => {
    vi.resetModules();
    const { FileRevocationStore: Fresh } = await import('./file-store');
    const entries: RevocationEntry[] = [
      { kind: 'cap', value: 'v', reason: 'r', revokedAt: 1 },
      { kind: 'holder', value: 'v', reason: 'r', revokedAt: 2 },
      { kind: 'issuer', value: 'v', reason: 'r', revokedAt: 3 },
      { kind: 'prefix', value: 'a,b', prefix: ['a', 'b'], reason: 'r', revokedAt: 4 },
    ];
    const p = join(dir, 'kinds-fresh.json');
    writeFileSync(p, JSON.stringify({ v: 1, entries }));
    const s = new Fresh(p);
    expect(await s.all()).toEqual(entries);
    for (const e of entries) expect(await s.get(e.kind, e.value)).toEqual(e);
    expect(await s.get('cap', 'w')).toBeUndefined();
  });
});

describe('revocationStoreCases', () => {
  const INTERLEAVED = 'interleaved adds and removes from many tasks lose nothing';
  it('has no reopen case unless a reopen function is given', () => {
    const names = revocationStoreCases(() => new InMemoryRevocationStore()).map((c) => c.name);
    expect(names).not.toContain('entries survive reopening the store');
    const withReopen = revocationStoreCases(() => new InMemoryRevocationStore(), (s) => s).map((c) => c.name);
    expect(withReopen).toContain('entries survive reopening the store');
  });
  it('the interleaved case fails a store that keeps the right number of entries but the wrong ones', async () => {
    const mk = (): RevocationStore => {
      const inner = new InMemoryRevocationStore();
      return {
        add: (e) => inner.add(e),
        remove: (k, v) => inner.remove(k, v),
        get: (k, v) => inner.get(k, v),
        // reports the removed (even) values instead of the surviving (odd) ones
        all: async () => (await inner.all()).length === 100 ? Array.from({ length: 100 }, (_, i) => ({ kind: 'cap' as const, value: `c${i * 2}`, reason: 'r', revokedAt: 1 })) : inner.all(),
        clear: () => inner.clear(),
      };
    };
    const c = revocationStoreCases(mk).find((x) => x.name === INTERLEAVED)!;
    await expect(c.run()).rejects.toMatchObject({ code: 'ERR_ASSERTION' });
  });
});
