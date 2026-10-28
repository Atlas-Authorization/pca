import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import type { PCActn, VerifyResult } from '@atlasauth/pca';
import { revocationStoreCases } from './conformance';
import { FileRevocationStore } from './file-store';
import {
  InMemoryRevocationStore,
  RevocationRegistry,
  type RevocationEntry,
  checkRevocation,
  isActiveAt,
  verifyWithRevocation,
} from './index';

const dir = mkdtempSync(join(tmpdir(), 'pca-revoke-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));
let n = 0;
const fresh = () => join(dir, `r${n++}.json`);

const act = (...hops: Array<[string, string, string]>): PCActn =>
  ({ cap_chain: hops.map(([id, issuer, holder]) => ({ id, issuer, holder })) }) as unknown as PCActn;
const OK = { allow: true, reasons: [] } as unknown as VerifyResult;
const DENY = { allow: false, reason: 'core says no' } as unknown as VerifyResult;

describe('store conformance', () => {
  describe('in-memory store', () => {
    for (const c of revocationStoreCases(() => new InMemoryRevocationStore())) it(c.name, c.run);
  });
  describe('file store', () => {
    const paths = new Map<object, string>();
    const make = () => {
      const p = fresh();
      const s = new FileRevocationStore(p);
      paths.set(s, p);
      return s;
    };
    for (const c of revocationStoreCases(make, (prev) => new FileRevocationStore(paths.get(prev) as string))) it(c.name, c.run);
  });
});

describe('file store fail-closed', () => {
  it('refuses to start on a corrupt file instead of starting empty', async () => {
    const p = fresh();
    writeFileSync(p, '{not json');
    expect(() => new FileRevocationStore(p)).toThrow(
      'FileRevocationStore: the revocation file cannot be read as JSON; refusing to start empty',
    );
  });
  it.each([
    ['not an object', '[]'],
    ['entries not a list', '{"entries":{}}'],
    ['unknown kind', '{"entries":[{"kind":"zzz","value":"a","reason":"","revokedAt":1}]}'],
    ['empty value', '{"entries":[{"kind":"cap","value":"","reason":"","revokedAt":1}]}'],
    ['non-finite time', '{"entries":[{"kind":"cap","value":"a","reason":"","revokedAt":"x"}]}'],
    ['bad notBefore', '{"entries":[{"kind":"cap","value":"a","reason":"","revokedAt":1,"notBefore":"soon"}]}'],
    ['prefix without path', '{"entries":[{"kind":"prefix","value":"a","reason":"","revokedAt":1}]}'],
    ['prefix value not the path', '{"entries":[{"kind":"prefix","value":"a","prefix":["b"],"reason":"","revokedAt":1}]}'],
    ['one bad entry among good ones', '{"entries":[{"kind":"cap","value":"a","reason":"","revokedAt":1},7]}'],
  ])('rejects a file that is %s', (_name, body) => {
    const p = fresh();
    writeFileSync(p, body);
    expect(() => new FileRevocationStore(p)).toThrow(
      'FileRevocationStore: the revocation file is not a valid entry list; refusing to start empty',
    );
  });
  it('a missing file is a fresh store', async () => {
    expect(await new FileRevocationStore(fresh()).all()).toEqual([]);
  });
  it('a write that cannot reach disk throws and leaves memory matching disk', async () => {
    const s = new FileRevocationStore(join(dir, 'no-such-dir', 'r.json'));
    const e: RevocationEntry = { kind: 'cap', value: 'c', reason: '', revokedAt: 1 };
    await expect(s.add(e)).rejects.toThrow();
    expect(await s.get('cap', 'c')).toBeUndefined();
    expect(await s.all()).toEqual([]);
  });
  it('writes the file with the entries on disk after every change', async () => {
    const p = fresh();
    const s = new FileRevocationStore(p);
    const e: RevocationEntry = { kind: 'holder', value: 'h', reason: 'x', revokedAt: 7 };
    await s.add(e);
    expect(JSON.parse(readFileSync(p, 'utf8'))).toEqual({ v: 1, entries: [e] });
    await s.remove('holder', 'h');
    expect(JSON.parse(readFileSync(p, 'utf8'))).toEqual({ v: 1, entries: [] });
  });
  it('a registry over a reopened file store still denies', async () => {
    const p = fresh();
    await new RevocationRegistry(new FileRevocationStore(p)).killAgent('agent-1', { reason: 'runaway', revokedAt: 5 });
    const r = await checkRevocation(act(['g', 'p', 'agent-1']), new RevocationRegistry(new FileRevocationStore(p)), { now: 10 });
    expect(r.revoked).toBe(true);
    expect(r.reason).toBe('holder agent-1 is revoked: runaway');
  });
});

describe('revoke input validation', () => {
  const reg = () => new RevocationRegistry();
  it('rejects a non-finite notBefore (it would otherwise never bite)', async () => {
    await expect(reg().revoke({ kind: 'cap', value: 'c', notBefore: Number.NaN })).rejects.toThrow('revoke: notBefore must be a finite number');
    await expect(reg().revoke({ kind: 'cap', value: 'c', notBefore: '5' as unknown as number })).rejects.toThrow('notBefore must be a finite number');
  });
  it('rejects a non-finite revokedAt and a non-string reason', async () => {
    await expect(reg().revoke({ kind: 'cap', value: 'c', revokedAt: Infinity })).rejects.toThrow('revoke: revokedAt must be a finite number');
    await expect(reg().revoke({ kind: 'cap', value: 'c', reason: 5 as unknown as string })).rejects.toThrow('revoke: reason must be a string');
  });
  it('rejects prefix elements that would alias another path', async () => {
    const msg = "revoke: every prefix element must be a non-empty string without ','";
    await expect(reg().revoke({ kind: 'prefix', prefix: ['a,b'] })).rejects.toThrow(msg);
    await expect(reg().revoke({ kind: 'prefix', prefix: ['a', ''] })).rejects.toThrow(msg);
    await expect(reg().revoke({ kind: 'prefix', prefix: [1 as unknown as string] })).rejects.toThrow(msg);
  });
  it('nothing is stored when validation fails', async () => {
    const r = reg();
    await expect(r.revoke({ kind: 'cap', value: 'c', notBefore: Number.NaN })).rejects.toThrow();
    expect(await r.list()).toEqual([]);
  });
});

describe('clock handling fails closed', () => {
  const e = (notBefore?: number): RevocationEntry => ({ kind: 'cap', value: 'c', reason: '', revokedAt: 0, ...(notBefore === undefined ? {} : { notBefore }) });
  it('keeps the scheduled behaviour for finite clocks', async () => {
    expect(isActiveAt(e(100), 99)).toBe(false);
    expect(isActiveAt(e(100), 100)).toBe(true);
    expect(isActiveAt(e(), 0)).toBe(true);
  });
  it('a NaN clock or a NaN schedule bites', async () => {
    expect(isActiveAt(e(100), Number.NaN)).toBe(true);
    expect(isActiveAt(e(Number.NaN), 5)).toBe(true);
  });
  it('a scheduled revocation is not skipped when the caller passes a NaN clock', async () => {
    const reg = new RevocationRegistry();
    await reg.revoke({ kind: 'cap', value: 'c', notBefore: 1e15 });
    expect((await checkRevocation(act(['c', 'p', 'h']), reg, { now: Number.NaN })).revoked).toBe(true);
  });
});

describe('checkRevocation never says "not revoked" because it could not look', () => {
  const reg = new RevocationRegistry();
  const closed = (why: string) => ({ revoked: true, reason: `revocation check failed closed: ${why}` });
  it('allows a clean, well-formed chain', async () => {
    expect(await checkRevocation(act(['g', 'p', 'a']), reg, { now: 1 })).toEqual({ revoked: false });
  });
  it('denies a missing or empty chain', async () => {
    expect(await checkRevocation({} as PCActn, reg)).toEqual(closed('the action carries no capability chain'));
    expect(await checkRevocation(undefined as unknown as PCActn, reg)).toEqual(closed('the action carries no capability chain'));
    expect(await checkRevocation({ cap_chain: [] } as unknown as PCActn, reg)).toEqual(closed('the action carries no capability chain'));
    expect(await checkRevocation({ cap_chain: 'x' } as unknown as PCActn, reg)).toEqual(closed('the action carries no capability chain'));
  });
  it('denies a hop that lacks id, issuer or holder', async () => {
    expect(await checkRevocation({ cap_chain: [{ issuer: 'p', holder: 'a' }] } as unknown as PCActn, reg)).toEqual(closed('a chain hop has no id'));
    expect(await checkRevocation({ cap_chain: [{ id: 'g', holder: 'a' }] } as unknown as PCActn, reg)).toEqual(closed('a chain hop has no issuer'));
    expect(await checkRevocation({ cap_chain: [{ id: 'g', issuer: 'p', holder: '' }] } as unknown as PCActn, reg)).toEqual(closed('a chain hop has no holder'));
    expect(await checkRevocation({ cap_chain: [null] } as unknown as PCActn, reg)).toEqual(closed('a chain hop has no id'));
  });
  it('denies a non-finite clock', async () => {
    expect(await checkRevocation(act(['g', 'p', 'a']), reg, { now: Number.NaN })).toEqual(closed('clock is not a finite number'));
  });
  it('denies when the store throws, and does not leak the store error text', async () => {
    const boom = new RevocationRegistry({
      add: async () => {}, remove: async () => false, all: async () => [], clear: async () => {},
      get: async () => {
        throw new Error('redis://user:hunter2@host');
      },
    });
    const r = await checkRevocation(act(['g', 'p', 'a']), boom, { now: 1 });
    expect(r).toEqual(closed('the revocation store failed (Error)'));
    expect(JSON.stringify(r)).not.toContain('hunter2');
  });
  it('still reports the real match when the chain is revoked', async () => {
    const r = new RevocationRegistry();
    await r.revoke({ kind: 'issuer', value: 'p', reason: 'stolen', revokedAt: 3 });
    const out = await checkRevocation(act(['g', 'p', 'a']), r, { now: 4 });
    expect(out.revoked).toBe(true);
    expect(out.reason).toBe('issuer p is revoked: stolen');
    expect(out.matched?.revokedAt).toBe(3);
  });
});

describe('verifyWithRevocation', () => {
  const reg = new RevocationRegistry();
  it('a core allow on an action with no chain is denied', async () => {
    expect(await verifyWithRevocation({} as PCActn, OK, reg)).toEqual({
      allow: false,
      coreAllow: true,
      revocation: { revoked: true, reason: 'revocation check failed closed: the action carries no capability chain' },
      reason: 'revocation check failed closed: the action carries no capability chain',
    });
  });
  it('a core denial keeps the core reason', async () => {
    const out = await verifyWithRevocation(act(['g', 'p', 'a']), DENY, reg, { now: 1 });
    expect(out).toEqual({ allow: false, coreAllow: false, revocation: { revoked: false }, reason: 'core says no' });
  });
  it('a malformed core result denies', async () => {
    expect((await verifyWithRevocation(act(['g', 'p', 'a']), null as unknown as VerifyResult, reg, { now: 1 })).allow).toBe(false);
    expect((await verifyWithRevocation(act(['g', 'p', 'a']), { allow: 'yes' } as unknown as VerifyResult, reg, { now: 1 })).allow).toBe(false);
  });
  it('a clean chain with a core allow is allowed', async () => {
    expect(await verifyWithRevocation(act(['g', 'p', 'a']), OK, reg, { now: 1 })).toEqual({ allow: true, coreAllow: true, revocation: { revoked: false } });
  });
  it('a revoked chain with a core allow is denied with the revocation reason', async () => {
    const r = new RevocationRegistry();
    await r.killAgent('a', { revokedAt: 1 });
    const out = await verifyWithRevocation(act(['g', 'p', 'a']), OK, r, { now: 2 });
    expect(out.allow).toBe(false);
    expect(out.reason).toBe('holder a is revoked: kill-switch: agent killed');
  });
});

describe('subtree revocation is atomic', () => {
  it('a prefix revoke is one store write that denies every chain below it and none beside it', async () => {
    const r = new RevocationRegistry();
    await r.revokeSubtree(['g', 'm'], { revokedAt: 1 });
    expect((await r.list()).length).toBe(1);
    expect((await checkRevocation(act(['g', 'p', 'a'], ['m', 'a', 'b'], ['l', 'b', 'c']), r, { now: 2 })).revoked).toBe(true);
    expect((await checkRevocation(act(['g', 'p', 'a'], ['s', 'a', 'z']), r, { now: 2 })).revoked).toBe(false);
  });
});

describe('an asynchronous store', () => {
  const slow = (inner: InMemoryRevocationStore) => {
    const d = <T>(f: () => Promise<T>) => new Promise<T>((res, rej) => setTimeout(() => f().then(res, rej), 3));
    return {
      add: (e: RevocationEntry) => d(() => inner.add(e)),
      remove: (k: never, v: string) => d(() => inner.remove(k, v)),
      get: (k: never, v: string) => d(() => inner.get(k, v)),
      all: () => d(() => inner.all()),
      clear: () => d(() => inner.clear()),
    };
  };
  it('a revocation is visible to the very next check once revoke has resolved', async () => {
    const reg = new RevocationRegistry(slow(new InMemoryRevocationStore()) as never);
    const p = act(['g', 'p', 'a']);
    expect(await checkRevocation(p, reg, { now: 1 })).toEqual({ revoked: false });
    await reg.killAgent('a', { revokedAt: 1 });
    expect((await checkRevocation(p, reg, { now: 2 })).revoked).toBe(true);
  });
  it('a store that rejects makes the check deny, not throw', async () => {
    const reg = new RevocationRegistry({ ...slow(new InMemoryRevocationStore()), all: () => Promise.reject(new Error('down')) } as never);
    const r = await checkRevocation(act(['g', 'p', 'a']), reg, { now: 1 });
    expect(r).toEqual({ revoked: true, reason: 'revocation check failed closed: the revocation store failed (Error)' });
  });
  it('concurrent writers to the file store are applied in order and all reach disk', async () => {
    const p = fresh();
    const s = new FileRevocationStore(p);
    await Promise.all(Array.from({ length: 40 }, (_, i) => s.add({ kind: 'cap', value: `c${i}`, reason: '', revokedAt: i })));
    expect((await new FileRevocationStore(p).all()).length).toBe(40);
  });
});
