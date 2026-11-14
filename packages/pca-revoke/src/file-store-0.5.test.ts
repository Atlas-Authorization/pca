/** Kills for the file-backed store: entry validation, null documents, rollback of memory after a failed flush. */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { FileRevocationStore } from './file-store';

const dir = mkdtempSync(join(tmpdir(), 'pca-revoke-kill-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));
let n = 0;
const fresh = (): string => join(dir, `r${n++}.json`);
const NOT_LIST = 'FileRevocationStore: the revocation file is not a valid entry list; refusing to start empty';
const good = { kind: 'cap', value: 'c', reason: 'r', revokedAt: 1 };
const load = (raw: string): void => {
  const p = fresh();
  writeFileSync(p, raw);
  new FileRevocationStore(p);
};
const doc = (entries: unknown[]): string => JSON.stringify({ v: 1, entries });

describe('FileRevocationStore validation', () => {
  it('accepts a well-formed document', () => {
    expect(() => load(doc([good, { ...good, kind: 'prefix', value: 'a,b', prefix: ['a', 'b'] }, { ...good, notBefore: 5 }]))).not.toThrow();
  });
  it.each([
    ['a null document', 'null'],
    ['a null entry', doc([null])],
    ['a non-object entry', doc([5])],
    ['an unknown kind', doc([{ ...good, kind: 'nope' }])],
    ['a non-string value', doc([{ ...good, value: 5 }])],
    ['an empty value', doc([{ ...good, value: '' }])],
    ['a non-string reason', doc([{ ...good, reason: 5 }])],
    ['a missing reason', doc([{ kind: 'cap', value: 'c', revokedAt: 1 }])],
    ['a non-finite revokedAt', `{"entries":[{"kind":"cap","value":"c","reason":"r","revokedAt":1e999}]}`],
    ['a string revokedAt', doc([{ ...good, revokedAt: '1' }])],
    ['a non-finite notBefore', `{"entries":[{"kind":"cap","value":"c","reason":"r","revokedAt":1,"notBefore":1e999}]}`],
    ['a string notBefore', doc([{ ...good, notBefore: '1' }])],
    ['a prefix entry without a path', doc([{ ...good, kind: 'prefix', value: 'a' }])],
    ['a prefix entry with an empty path', doc([{ ...good, kind: 'prefix', value: 'a', prefix: [] }])],
    ['a prefix path holding an empty element', doc([{ ...good, kind: 'prefix', value: 'a,', prefix: ['a', ''] }])],
    ['a prefix path holding a non-string', doc([{ ...good, kind: 'prefix', value: '5', prefix: [5] }])],
    ['a prefix path that does not match the value', doc([{ ...good, kind: 'prefix', value: 'a,c', prefix: ['a', 'b'] }])],
    ['entries that are not a list', JSON.stringify({ entries: {} })],
  ])('refuses %s', (_n, raw) => {
    expect(() => load(raw)).toThrow(NOT_LIST);
  });
});

describe('FileRevocationStore rollback', () => {
  it('a failed flush puts the earlier entries back in memory', async () => {
    const p = fresh();
    const s = new FileRevocationStore(p);
    const a = { kind: 'cap', value: 'a', reason: 'r', revokedAt: 1 } as const;
    await s.add(a);
    mkdirSync(`${p}.tmp`); // the temporary file can no longer be created
    await expect(s.add({ kind: 'cap', value: 'b', reason: 'r', revokedAt: 2 })).rejects.toThrow();
    expect(await s.all()).toEqual([a]);
    expect(await s.get('cap', 'b')).toBeUndefined();
    await expect(s.remove('cap', 'a')).rejects.toThrow();
    expect(await s.all()).toEqual([a]);
  });
});
