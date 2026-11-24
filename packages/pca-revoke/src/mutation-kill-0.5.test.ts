/** Kills for the revocation registry, the check, the CAEP bridge and the shipped store-conformance cases. */
import { describe, expect, it } from 'vitest';
import type { PCActn, VerifyResult } from '@atlasauth/pca';
import {
  CAEP_EVENT_TYPES,
  InMemoryRevocationStore,
  RevocationRegistry,
  checkRevocation,
  ingestCaepEvent,
  isActiveAt,
  verifyWithRevocation,
  type IngestableCaepEvent,
  type RevocationEntry,
  type RevocationStore,
} from './index';
import { revocationStoreCases } from './conformance';

const chainOf = (...hops: Array<[string, string, string]>): PCActn =>
  ({ cap_chain: hops.map(([id, issuer, holder]) => ({ id, issuer, holder })) }) as unknown as PCActn;
const ONE = chainOf(['c1', 'i1', 'h1']);

describe('isActiveAt', () => {
  it('no schedule bites; a scheduled revocation bites from notBefore; a non-finite clock or schedule bites', () => {
    const e = (notBefore?: number): RevocationEntry => ({ kind: 'cap', value: 'c', reason: '', revokedAt: 1, ...(notBefore !== undefined ? { notBefore } : {}) });
    expect(isActiveAt(e(), 0)).toBe(true);
    expect(isActiveAt(e(100), 99)).toBe(false);
    expect(isActiveAt(e(100), 100)).toBe(true);
    expect(isActiveAt(e(100), NaN)).toBe(true);
    expect(isActiveAt(e(Infinity), 5)).toBe(true);
  });
});

describe('RevocationRegistry.revoke', () => {
  it('stores an empty reason by default and carries notBefore only when given', async () => {
    const r = new RevocationRegistry();
    const a = await r.revoke({ kind: 'cap', value: 'c', revokedAt: 5 });
    expect(a).toStrictEqual({ kind: 'cap', value: 'c', reason: '', revokedAt: 5 });
    expect('notBefore' in a).toBe(false);
    const b = await r.revoke({ kind: 'holder', value: 'h', revokedAt: 5, notBefore: 9 });
    expect(b.notBefore).toBe(9);
  });
  it('refuses bad input with the exact messages', async () => {
    const r = new RevocationRegistry();
    const bad = async (i: unknown) => (await r.revoke(i as never).then(() => null, (e: unknown) => e)) as Error;
    for (const k of ['cap', 'holder', 'issuer'] as const) {
      const e = await bad({ kind: k });
      expect(e).toBeInstanceOf(TypeError);
      expect(e.message).toBe(`revoke: a ${k} revocation requires a non-empty value`);
      expect((await bad({ kind: k, value: '' })).message).toBe(`revoke: a ${k} revocation requires a non-empty value`);
    }
    expect((await bad({ kind: 'prefix', prefix: [] })).message).toBe('revoke: a prefix revocation requires a non-empty cap-id path');
    expect((await bad({ kind: 'prefix' })).message).toBe('revoke: a prefix revocation requires a non-empty cap-id path');
    expect((await bad({ kind: 'cap', value: 'c', revokedAt: 'x' })).message).toBe('revoke: revokedAt must be a finite number');
    expect((await bad({ kind: 'cap', value: 'c', notBefore: 'x' })).message).toBe('revoke: notBefore must be a finite number');
    expect((await bad({ kind: 'cap', value: 'c', reason: 5 })).message).toBe('revoke: reason must be a string');
  });
});

describe('unrevoke of a prefix', () => {
  it('a missing or empty prefix path never reaches the store', async () => {
    const calls: unknown[][] = [];
    const store: RevocationStore = { ...new InMemoryRevocationStore(), add: async () => {}, get: async () => undefined, all: async () => [], clear: async () => {}, remove: async (...a) => (calls.push(a), true) };
    const r = new RevocationRegistry(store);
    expect(await r.unrevoke({ kind: 'prefix', prefix: [] })).toBe(false);
    expect(await r.unrevoke({ kind: 'prefix' } as never)).toBe(false);
    expect(calls).toEqual([]);
    expect(await r.unrevoke({ kind: 'prefix', prefix: ['a', 'b'] })).toBe(true);
    expect(calls).toEqual([['prefix', 'a,b']]);
  });
});

describe('prefixes and kill-switches', () => {
  it('prefixes() returns only subtree entries', async () => {
    const r = new RevocationRegistry();
    await r.revoke({ kind: 'cap', value: 'c', revokedAt: 1 });
    const p = await r.revokeSubtree(['a', 'b'], { revokedAt: 1 });
    await r.revoke({ kind: 'holder', value: 'h', revokedAt: 1 });
    expect(await r.prefixes()).toEqual([p]);
  });
  it('kill-switch reasons: defaults and caller-supplied', async () => {
    const r = new RevocationRegistry();
    expect((await r.killAgent('h', { revokedAt: 1 })).reason).toBe('kill-switch: agent killed');
    expect((await r.killAgent('h', { revokedAt: 1, reason: 'why' })).reason).toBe('why');
    expect((await r.killSubtree('c', { revokedAt: 1 })).reason).toBe('kill-switch: subtree killed');
    expect((await r.killSubtree('c', { revokedAt: 1, reason: 'why' })).reason).toBe('why');
  });
});

describe('checkRevocation', () => {
  it('names the reason with or without an operator reason', async () => {
    const r = new RevocationRegistry();
    await r.revoke({ kind: 'cap', value: 'c1', revokedAt: 1 });
    expect((await checkRevocation(ONE, r, { now: 5 })).reason).toBe('cap c1 is revoked');
    await r.revoke({ kind: 'cap', value: 'c1', revokedAt: 1, reason: 'abuse' });
    expect((await checkRevocation(ONE, r, { now: 5 })).reason).toBe('cap c1 is revoked: abuse');
  });
  it('subtree prefix matching: exact path, longer chain, shorter chain, other path, empty stored path', async () => {
    const r = new RevocationRegistry();
    await r.revokeSubtree(['a', 'b'], { revokedAt: 1 });
    const hit = (...ids: string[]) => checkRevocation(chainOf(...ids.map((i): [string, string, string] => [i, `iss-${i}`, `hld-${i}`])), r, { now: 5 }).then((x) => x.revoked);
    expect(await hit('a', 'b')).toBe(true);
    expect(await hit('a', 'b', 'c')).toBe(true);
    expect(await hit('a')).toBe(false);
    expect(await hit('a', 'x')).toBe(false);
    expect(await hit('b', 'a')).toBe(false);
  });
  it('a stored subtree entry with an empty path matches nothing', async () => {
    const empty: RevocationEntry = { kind: 'prefix', value: '', prefix: [], reason: '', revokedAt: 1 };
    const store = new InMemoryRevocationStore();
    await store.add(empty);
    expect((await checkRevocation(ONE, new RevocationRegistry(store), { now: 5 })).revoked).toBe(false);
  });
  it('fails closed on a malformed chain, hop and clock, and on a throwing store, with exact reasons', async () => {
    const r = new RevocationRegistry();
    const reason = async (p: unknown, o?: { now?: number }) => (await checkRevocation(p as PCActn, r, o)).reason;
    expect(await reason(ONE, { now: NaN })).toBe('revocation check failed closed: clock is not a finite number');
    expect(await reason(ONE, { now: '5' as never })).toBe('revocation check failed closed: clock is not a finite number');
    expect(await reason({})).toBe('revocation check failed closed: the action carries no capability chain');
    expect(await reason(null)).toBe('revocation check failed closed: the action carries no capability chain');
    expect(await reason({ cap_chain: [] })).toBe('revocation check failed closed: the action carries no capability chain');
    for (const k of ['id', 'issuer', 'holder']) {
      for (const v of [undefined, '', 5]) {
        const hop = { id: 'c', issuer: 'i', holder: 'h', [k]: v };
        expect(await reason({ cap_chain: [hop] })).toBe(`revocation check failed closed: a chain hop has no ${k}`);
      }
    }
    expect(await reason({ cap_chain: [null] })).toBe('revocation check failed closed: a chain hop has no id');
    const boom = new RevocationRegistry({ ...new InMemoryRevocationStore(), get: async () => { throw new RangeError('x'); } } as unknown as RevocationStore);
    expect((await checkRevocation(ONE, boom, { now: 5 })).reason).toBe('revocation check failed closed: the revocation store failed (RangeError)');
    const boom2 = new RevocationRegistry({ get: async () => { throw 'str'; } } as unknown as RevocationStore);
    expect((await checkRevocation(ONE, boom2, { now: 5 })).reason).toBe('revocation check failed closed: the revocation store failed (string)');
  });
});

describe('verifyWithRevocation', () => {
  it('a core result that is missing or malformed denies with the default reason', async () => {
    const r = new RevocationRegistry();
    for (const bad of [undefined, null, 'x', 5, {}, { allow: 'true' }]) {
      const out = await verifyWithRevocation(ONE, bad as unknown as VerifyResult, r, { now: 5 });
      expect(out.allow).toBe(false);
      expect(out.coreAllow).toBe(false);
      expect(out.reason).toBe('core verification failed');
    }
    expect((await verifyWithRevocation(ONE, { allow: false, reason: 'nope' } as VerifyResult, r, { now: 5 })).reason).toBe('nope');
    const ok = await verifyWithRevocation(ONE, { allow: true } as VerifyResult, r, { now: 5 });
    expect(ok).toEqual({ allow: true, coreAllow: true, revocation: { revoked: false } });
  });
});

describe('ingestCaepEvent', () => {
  const ev = (type: string, payload: unknown) => ({ type, payload }) as unknown as IngestableCaepEvent;
  const GR = CAEP_EVENT_TYPES.grantRevoked;
  const KS = CAEP_EVENT_TYPES.killSwitch;
  const SR = CAEP_EVENT_TYPES.sessionRevoked;

  it('grant-revoked: needs a non-empty string grant_ref; default and given reason; seconds become ms', async () => {
    const r = new RevocationRegistry();
    for (const g of [undefined, '', 5]) expect(await ingestCaepEvent(ev(GR, { grant_ref: g }), r)).toEqual([]);
    const [a] = await ingestCaepEvent(ev(GR, { grant_ref: 'g', event_timestamp: 1.0004 }), r);
    expect(a).toEqual({ kind: 'cap', value: 'g', reason: 'CAEP grant-revoked', revokedAt: 1000 });
    const [b] = await ingestCaepEvent(ev(GR, { grant_ref: 'g', reason: 'bad', event_timestamp: 2 }), r);
    expect(b).toEqual({ kind: 'cap', value: 'g', reason: 'bad', revokedAt: 2000 });
  });
  it('a non-finite event_timestamp falls back to the clock instead of poisoning the entry', async () => {
    const r = new RevocationRegistry();
    for (const t of [NaN, Infinity, undefined, '5' as unknown as number]) {
      const [a] = await ingestCaepEvent(ev(GR, { grant_ref: 'g', event_timestamp: t }), r);
      expect(Number.isFinite(a!.revokedAt)).toBe(true);
      expect(a!.revokedAt).toBeGreaterThan(1_000_000_000_000);
    }
  });
  it('kill-switch: agent and grant_ref each need a non-empty string; reasons; timestamps', async () => {
    const r = new RevocationRegistry();
    for (const v of [undefined, '', 5]) expect(await ingestCaepEvent(ev(KS, { agent: v, grant_ref: v }), r)).toEqual([]);
    const both = await ingestCaepEvent(ev(KS, { agent: 'h', grant_ref: 'g', event_timestamp: 3 }), r);
    expect(both).toEqual([
      { kind: 'holder', value: 'h', reason: 'CAEP kill-switch', revokedAt: 3000 },
      { kind: 'cap', value: 'g', reason: 'CAEP kill-switch', revokedAt: 3000 },
    ]);
    const given = await ingestCaepEvent(ev(KS, { agent: 'h', grant_ref: 'g', reason: 'r', event_timestamp: 3 }), r);
    expect(given.map((e) => e.reason)).toEqual(['r', 'r']);
    expect(await ingestCaepEvent(ev(KS, { agent: 'h', event_timestamp: 3 }), r)).toHaveLength(1);
    expect(await ingestCaepEvent(ev(KS, { grant_ref: 'g', event_timestamp: 3 }), r)).toHaveLength(1);
  });
  it('session-revoked: kills the first string holder/agent/id of the subject; no subject does nothing', async () => {
    const r = new RevocationRegistry();
    expect(await ingestCaepEvent(ev(SR, {}), r)).toEqual([]);
    expect(await ingestCaepEvent(ev(SR, { subject: { format: 'opaque' } }), r)).toEqual([]);
    const v = async (subject: unknown) => (await ingestCaepEvent(ev(SR, { subject, event_timestamp: 4 }), r)).map((e) => e.value);
    expect(await v({ format: 'x', holder: 'H', agent: 'A', id: 'I' })).toEqual(['H']);
    expect(await v({ format: 'x', holder: 5, agent: 'A', id: 'I' })).toEqual(['A']);
    expect(await v({ format: 'x', holder: '', agent: 'A' })).toEqual(['A']);
    expect(await v({ format: 'x', agent: 'A', id: 'I' })).toEqual(['A']);
    expect(await v({ format: 'x', id: 'I' })).toEqual(['I']);
    expect(await v({ format: 'x', holder: '', agent: '', id: '' })).toEqual([]);
    const [e] = await ingestCaepEvent(ev(SR, { subject: { format: 'x', id: 'I' } }), r);
    expect(e!.reason).toBe('CAEP session-revoked');
    expect((await ingestCaepEvent(ev(SR, { subject: { format: 'x', id: 'I' }, reason_user: 'u' }), r))[0]!.reason).toBe('u');
  });
});

// ---- conformance cases: each case, run against a recording store, makes exactly the calls below ----
type Call = unknown[];
function recorder(log: Call[]): () => RevocationStore {
  return () => {
    const inner = new InMemoryRevocationStore();
    return {
      add: (e) => (log.push(['add', structuredClone(e)]), inner.add(e)),
      remove: (k, v) => (log.push(['remove', k, v]), inner.remove(k, v)),
      get: (k, v) => (log.push(['get', k, v]), inner.get(k, v)),
      all: () => (log.push(['all']), inner.all()),
      clear: () => (log.push(['clear']), inner.clear()),
    };
  };
}
const ent = (kind: string, value: string, extra: Record<string, unknown> = {}) => ({ kind, value, reason: `r-${kind}-${value}`, revokedAt: 1000, ...(kind === 'prefix' ? { prefix: value.split(',') } : {}), ...extra });

describe('revocationStoreCases: exact transcript of every case', () => {
  const run = async (name: string, reopen = false) => {
    const log: Call[] = [];
    const make = recorder(log);
    const cases = revocationStoreCases(make, reopen ? (p) => p : undefined);
    const c = cases.find((x) => x.name === name);
    if (!c) throw new Error(`no case ${name}`);
    await c.run();
    return log;
  };
  it('starts empty', async () => {
    expect(await run('starts empty')).toEqual([['all'], ['get', 'cap', 'x']]);
  });
  it('add then get', async () => {
    expect(await run('add then get returns the whole entry, including notBefore')).toEqual([['add', ent('cap', 'c1', { notBefore: 5000 })], ['get', 'cap', 'c1']]);
  });
  it('kinds apart', async () => {
    expect(await run('the same value under different kinds is kept apart')).toEqual([
      ['add', ent('cap', 'k')], ['add', ent('holder', 'k')], ['add', ent('issuer', 'k')], ['all'],
      ['remove', 'holder', 'k'], ['get', 'cap', 'k'], ['get', 'issuer', 'k'], ['get', 'holder', 'k'],
    ]);
  });
  it('replace', async () => {
    expect(await run('add at an existing key replaces, it does not duplicate')).toEqual([
      ['add', ent('cap', 'c', { reason: 'first' })], ['add', ent('cap', 'c', { reason: 'second' })], ['all'], ['get', 'cap', 'c'],
    ]);
  });
  it('remove', async () => {
    expect(await run('remove reports whether something was removed, and only once')).toEqual([
      ['add', ent('cap', 'c')], ['remove', 'cap', 'c'], ['remove', 'cap', 'c'], ['remove', 'cap', 'never-added'],
    ]);
  });
  it('prefix paths', async () => {
    expect(await run('prefix paths that differ stay distinct')).toEqual([
      ['add', ent('prefix', 'a,b')], ['add', ent('prefix', 'a')], ['add', ent('prefix', 'b,a')], ['all'], ['remove', 'prefix', 'a'], ['all'],
    ]);
  });
  it('snapshot', async () => {
    expect(await run('all() is a snapshot: changing it does not change the store')).toEqual([['add', ent('cap', 'c')], ['all'], ['all'], ['get', 'cap', 'forged']]);
  });
  it('clear', async () => {
    expect(await run('clear drops everything')).toEqual([['add', ent('cap', 'c')], ['add', ent('prefix', 'a,b')], ['clear'], ['all'], ['get', 'cap', 'c']]);
  });
  it('interleaved: 200 adds, 100 removes, one final all()', async () => {
    const log = await run('interleaved adds and removes from many tasks lose nothing');
    expect(log.filter((c) => c[0] === 'add')).toHaveLength(200);
    expect(log.filter((c) => c[0] === 'remove')).toHaveLength(100);
    expect(log.filter((c) => c[0] === 'all')).toHaveLength(1);
    expect(log).toHaveLength(301);
  });
  it('reopen', async () => {
    expect(await run('entries survive reopening the store', true)).toEqual([
      ['add', ent('cap', 'durable', { notBefore: 9000 })], ['add', ent('prefix', 'r,m')], ['add', ent('holder', 'gone')], ['remove', 'holder', 'gone'], ['all'],
    ]);
  });
});

describe('revocationStoreCases: each case fails against a store that breaks its rule', () => {
  type Over = Partial<RevocationStore>;
  const faulty = (over: (inner: InMemoryRevocationStore) => Over) => () => {
    const inner = new InMemoryRevocationStore();
    const base: RevocationStore = { add: (e) => inner.add(e), remove: (k, v) => inner.remove(k, v), get: (k, v) => inner.get(k, v), all: () => inner.all(), clear: () => inner.clear() };
    return { ...base, ...over(inner) } as RevocationStore;
  };
  const verdict = async (make: () => RevocationStore, name: string): Promise<unknown> => {
    const c = revocationStoreCases(make).find((x) => x.name === name)!;
    return c.run().then(() => 'passed', (e: { code?: string }) => e.code);
  };
  const KINDS = 'the same value under different kinds is kept apart';
  const REPL = 'add at an existing key replaces, it does not duplicate';
  const PFX = 'prefix paths that differ stay distinct';
  const SNAP = 'all() is a snapshot: changing it does not change the store';

  it('an all() that drops an entry once three are held fails the length checks', async () => {
    const mk = faulty((i) => ({ all: async () => { const a = await i.all(); return a.length === 3 ? a.slice(1) : a; } }));
    expect(await verdict(mk, KINDS)).toBe('ERR_ASSERTION');
    expect(await verdict(mk, PFX)).toBe('ERR_ASSERTION');
  });
  it('an all() that reports nothing fails the one-entry length checks', async () => {
    const mk = faulty(() => ({ all: async () => [] }));
    expect(await verdict(mk, REPL)).toBe('ERR_ASSERTION');
    expect(await verdict(mk, SNAP)).toBe('ERR_ASSERTION');
  });
  it('a store that lists a replaced key twice fails the replace case on the length check', async () => {
    const mk = faulty((i) => ({ all: async () => { const a = await i.all(); return [...a, ...a]; } }));
    expect(await verdict(mk, REPL)).toBe('ERR_ASSERTION');
  });
  it('a get() that finds nothing fails with an assertion, not a TypeError', async () => {
    expect(await verdict(faulty(() => ({ get: async () => undefined })), KINDS)).toBe('ERR_ASSERTION');
    expect(await verdict(faulty(() => ({ get: async () => undefined })), REPL)).toBe('ERR_ASSERTION');
    expect(await verdict(faulty((i) => ({ get: async (k, v) => (k === 'issuer' ? undefined : i.get(k, v)) })), KINDS)).toBe('ERR_ASSERTION');
  });
  it('a store whose all() hands out its live list fails the snapshot case when its lookups see that list', async () => {
    const mk = (): RevocationStore => {
      const live: RevocationEntry[] = [];
      return {
        add: async (e) => { live.push(e); },
        remove: async () => false,
        get: async (k, v) => live.find((e) => e.kind === k && e.value === v),
        all: async () => live,
        clear: async () => { live.length = 0; },
      };
    };
    expect(await verdict(mk, SNAP)).toBe('ERR_ASSERTION');
  });
  it('a live list that the store looks up elsewhere is caught only by the length check after the pop and push', async () => {
    const mk = (): RevocationStore => {
      const live: RevocationEntry[] = [];
      const by = new Map<string, RevocationEntry>();
      return {
        add: async (e) => { live.push(e); by.set(`${e.kind}/${e.value}`, e); },
        remove: async () => false,
        get: async (k, v) => by.get(`${k}/${v}`),
        all: async () => live,
        clear: async () => { live.length = 0; by.clear(); },
      };
    };
    expect(await verdict(mk, SNAP)).toBe('passed');
  });
  it('an order-unstable all() still passes the cases that sort', async () => {
    const mk = faulty((i) => ({ all: async () => (await i.all()).reverse() }));
    expect(await verdict(mk, PFX)).toBe('passed');
    const reopenable = revocationStoreCases(mk, (p) => p).find((x) => x.name === 'entries survive reopening the store')!;
    await expect(reopenable.run()).resolves.toBeUndefined();
  });
});
