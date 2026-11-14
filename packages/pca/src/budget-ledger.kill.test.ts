// Exact-outcome tests for the aggregate budget ledger: every refusal carries its exact class and message, every version
// bump is checked by value, the reference store writes only when an operation changed something, and the signed release
// is checked against an independently built message.
import { describe, expect, it } from 'vitest';
import { createMemoryDurableKv, type DurableKv } from './durable-state';
import { b64u, canonicalBytesStrict, hashCanonical, utf8 } from './hash';
import { generateKeyPair, sign, verifyB64u } from './keys';
import { type AccumulatorDecl } from './intent-acc';
import type { LedgerStore } from './ledger-store';
import {
  BudgetLedgerError,
  KvBudgetLedger,
  RELEASE_DOMAIN,
  admitAggregateAction,
  aggregateKeyOf,
  anchorRelease,
  commitInDoc,
  emptyBudgetDoc,
  expireInDoc,
  releaseCommit,
  releaseDigest,
  releaseInDoc,
  reserveInDoc,
  scopeKey,
  signRelease,
  startAggregate,
  startInDoc,
  verifyRelease,
  type BudgetLedger,
  type ReleaseEvent,
  type ReserveOutcome,
} from './budget-ledger';

const acc = (over: Partial<AccumulatorDecl> = {}): AccumulatorDecl => ({
  id: 'spend',
  agg: 'sum',
  val: 'action.params.amount',
  sel: { verbs: ['pay'] },
  win: { kind: 'task' },
  key: null,
  domain_max: 200,
  holder: { kind: 'site_local' },
  scope: 'principal',
  ...over,
});
const ev = (id: string, amount: number, t = 1000) => ({ id, verb: 'pay', resource: 'r', params: { amount }, t });
const ok = async () => ({ allow: true as const });
const ledger = (): KvBudgetLedger => new KvBudgetLedger(createMemoryDurableKv(), true);
const KEY = 'principal/alice';

function thrown(f: () => unknown): unknown {
  try {
    f();
  } catch (e) {
    return e;
  }
  throw new Error('expected a throw');
}
function expectThrow(f: () => unknown, ctor: new (...a: never[]) => Error, message: string): void {
  const e = thrown(f);
  expect(e).toBeInstanceOf(ctor);
  expect((e as Error).message).toBe(message);
}
async function rejection(p: Promise<unknown>): Promise<Error> {
  try {
    await p;
  } catch (e) {
    return e as Error;
  }
  throw new Error('expected a rejection');
}

describe('BudgetLedgerError and scope keys', () => {
  it('the error carries its code, a prefixed message and its name', () => {
    const e = new BudgetLedgerError('invalid', 'm');
    expect([e.code, e.message, e.name]).toEqual(['invalid', 'invalid: m', 'BudgetLedgerError']);
  });
  it('a scope id is a string of 1..256 characters', () => {
    expect(scopeKey('principal', 'x'.repeat(256))).toBe(`principal/${'x'.repeat(256)}`);
    const msg = 'invalid: a scope id is a non-empty string of at most 256 characters without control characters';
    expectThrow(() => scopeKey('principal', 'x'.repeat(257)), BudgetLedgerError, msg);
    expectThrow(() => scopeKey('principal', ['ab'] as never), BudgetLedgerError, msg);
    expect((thrown(() => scopeKey('org', '')) as BudgetLedgerError).code).toBe('invalid');
  });
  it('aggregateKeyOf: absent and session scope have no key, a bound scope is encoded, an unbound one throws', () => {
    expect(aggregateKeyOf({ id: 'x' }, {})).toBeNull();
    expect(aggregateKeyOf({ id: 'x', scope: 'session' }, {})).toBeNull();
    expect(aggregateKeyOf({ id: 'x', scope: 'org' }, { org: 'a b' })).toBe('org/a%20b');
    expectThrow(() => aggregateKeyOf({ id: 'x', scope: 'org' }, {}), BudgetLedgerError, 'scope_unbound: accumulator x is org-scoped but no org id was given');
  });
});

describe('reserveInDoc: malformed requests', () => {
  const d = () => emptyBudgetDoc();
  const bad = 'reserve: a malformed event';
  it('each malformed event field is refused on its own', () => {
    expectThrow(() => reserveInDoc(d(), undefined as never), RangeError, bad);
    expectThrow(() => reserveInDoc(d(), { event: { ...ev('a', 1), verb: 5 as never }, accumulators: [] }), RangeError, bad);
    expectThrow(() => reserveInDoc(d(), { event: { ...ev('a', 1), resource: 5 as never }, accumulators: [] }), RangeError, bad);
    expectThrow(() => reserveInDoc(d(), { event: { ...ev('a', 1), params: null as never }, accumulators: [] }), RangeError, bad);
    expectThrow(() => reserveInDoc(d(), { event: { ...ev('a', 1), params: 5 as never }, accumulators: [] }), RangeError, bad);
    expect(reserveInDoc(d(), { event: ev('a', 1), accumulators: [] })).toEqual({ outcome: 'reserved', version: 1, post: {} });
  });
  it('accumulators, expiresAt and domain_max', () => {
    expectThrow(() => reserveInDoc(d(), { event: ev('a', 1), accumulators: 'x' as never }), RangeError, 'reserve: accumulators must be an array');
    expectThrow(() => reserveInDoc(d(), { event: ev('a', 1), accumulators: [], expiresAt: 1.5 }), RangeError, 'reserve: expiresAt must be a safe integer');
    expectThrow(() => reserveInDoc(d(), { event: ev('a', 1), accumulators: [acc({ domain_max: undefined })] }), RangeError, 'reserve: accumulator spend has no domain_max (the cap)');
  });
  it('an accumulator that does not select the verb gets no post value at all', () => {
    expect(reserveInDoc(d(), { event: { ...ev('a', 5), verb: 'read' }, accumulators: [acc()] })).toEqual({ outcome: 'reserved', version: 1, post: {} });
    expect(reserveInDoc(d(), { event: ev('a', 5), accumulators: [acc()] })).toEqual({ outcome: 'reserved', version: 1, post: { spend: 5 } });
  });
  it('an accumulator the history cannot be folded under is a corrupt store, with the thrown text or a fixed one', () => {
    const e1 = thrown(() => reserveInDoc(d(), { event: ev('a', 5), accumulators: [acc({ agg: 'bogus' as never })] }));
    expect(e1).toBeInstanceOf(BudgetLedgerError);
    expect([(e1 as BudgetLedgerError).code, (e1 as Error).message]).toEqual(['store_corrupt', 'store_corrupt: accPost: unknown agg']);
    const a = acc();
    Object.defineProperty(a, 'agg', { get() { throw 'not an error'; } });
    const e2 = thrown(() => reserveInDoc(d(), { event: ev('a', 5), accumulators: [a] }));
    expect(e2).toBeInstanceOf(BudgetLedgerError);
    expect((e2 as Error).message).toBe('store_corrupt: unreadable history');
  });
  it('the entry carries exp only when expiresAt was given', () => {
    const x = d();
    reserveInDoc(x, { event: ev('a', 1), accumulators: [] });
    reserveInDoc(x, { event: ev('b', 1), accumulators: [], expiresAt: 9 });
    expect(Object.keys(x.events[0]!)).toEqual(['id', 'verb', 'resource', 'params', 't', 'status']);
    expect(Object.keys(x.events[1]!)).toEqual(['id', 'verb', 'resource', 'params', 't', 'status', 'exp']);
    expect(x.events[1]!.exp).toBe(9);
  });
});

describe('the pure transitions: exact outcomes and versions', () => {
  const doc3 = () => {
    const d = emptyBudgetDoc();
    for (const id of ['a', 'b', 'c']) reserveInDoc(d, { event: ev(id, 1), accumulators: [] });
    return d;
  };
  it('start: refused once released, replayed when started or committed, else settled with a version bump', () => {
    const d = doc3();
    expect(releaseInDoc(d, KEY, 'c')).toEqual({ outcome: 'settled', version: 4 });
    expect(startInDoc(d, 'c')).toEqual({ outcome: 'refused', version: 4, status: 'released' });
    expect(startInDoc(d, 'a')).toEqual({ outcome: 'settled', version: 5 });
    expect(startInDoc(d, 'a')).toEqual({ outcome: 'replayed', version: 5 });
    expect(commitInDoc(d, 'b')).toEqual({ outcome: 'settled', version: 6 });
    expect(startInDoc(d, 'b')).toEqual({ outcome: 'replayed', version: 6 });
    expect(d.events.map((e) => e.started)).toEqual([true, undefined, undefined]);
  });
  it('release: no evidence stores no rel; evidence for another key is refused', () => {
    const d = doc3();
    expect(releaseInDoc(d, KEY, 'a')).toEqual({ outcome: 'settled', version: 4 });
    expect('rel' in d.events[0]!).toBe(false);
    const evd: ReleaseEvent = { v: 1, key: 'principal/bob', id: 'b', reason: 'rollback', at: 1, signer: 's', sig: 's' };
    expectThrow(() => releaseInDoc(d, KEY, 'b', evd), RangeError, 'release: the evidence is for another reservation');
    expect(releaseInDoc(d, KEY, 'b', { ...evd, key: KEY })).toEqual({ outcome: 'settled', version: 5 });
    expect(d.events[1]!.rel).toEqual({ ...evd, key: KEY });
  });
  it('expire: bumps the version only when something was released, and records why and when', () => {
    const d = emptyBudgetDoc();
    reserveInDoc(d, { event: ev('a', 1), accumulators: [], expiresAt: 10 });
    expect(expireInDoc(d, 9)).toEqual({ released: [], version: 1 });
    expect(d.ver).toBe(1);
    expect(expireInDoc(d, 10)).toEqual({ released: ['a'], version: 2 });
    expect(d.events[0]!.rel).toEqual({ reason: 'expired', at: 10 });
    expect(expireInDoc(d, 11)).toEqual({ released: [], version: 2 });
    expectThrow(() => expireInDoc(d, 1.5), RangeError, 'expire: now must be a safe integer');
  });
});

/** A kv that records what every update callback returned (undefined = nothing written). */
function spyKv() {
  const m = new Map<string, unknown>();
  const writes: unknown[] = [];
  const kv: DurableKv = {
    get: async (k) => structuredClone(m.get(k)),
    set: async (k, v) => void m.set(k, v),
    update: async (k, fn) => {
      const r = fn(structuredClone(m.get(k)));
      writes.push(r);
      if (r !== undefined) m.set(k, structuredClone(r));
      return m.get(k);
    },
    keys: async () => [...m.keys()],
  };
  return { kv, writes };
}
/** A kv whose stored value is exactly `raw`. */
const rawKv = (raw: unknown): DurableKv => ({ get: async () => raw, set: async () => undefined, update: async (_k, fn) => fn(raw), keys: async () => [] });

describe('KvBudgetLedger', () => {
  it('the constructor names a missing kv and an undeclared durability', () => {
    const fn = async () => undefined;
    expectThrow(() => new KvBudgetLedger({ update: fn } as never, true), BudgetLedgerError, 'store_missing: KvBudgetLedger needs a DurableKv');
    expectThrow(() => new KvBudgetLedger({ get: fn } as never, true), BudgetLedgerError, 'store_missing: KvBudgetLedger needs a DurableKv');
    expectThrow(() => new KvBudgetLedger(createMemoryDurableKv(), 'yes' as never), BudgetLedgerError, 'invalid: say whether the kv is durable (true or false)');
  });
  it('a malformed key is refused before the kv is touched', async () => {
    const e = await rejection(ledger().snapshot(''));
    expect(e).toBeInstanceOf(RangeError);
    expect(e.message).toBe('a ledger key is a non-empty string without control characters');
  });
  it('every malformed stored document is store_corrupt', async () => {
    const shapes: unknown[] = [
      null,
      Object.assign(function stored() {}, { v: 1, ver: 0, events: [] }),
      Object.assign([], { v: 1, ver: 0, events: [] }),
      { v: 2, ver: 0, events: [] },
      { v: 1, ver: 0, events: [5] },
      { v: 1, ver: 0, events: [{ id: 5 }] },
    ];
    for (const raw of shapes) {
      const e = await rejection(new KvBudgetLedger(rawKv(raw), true).snapshot(KEY));
      expect(e, String(raw)).toBeInstanceOf(BudgetLedgerError);
      expect([(e as BudgetLedgerError).code, e.message]).toEqual(['store_corrupt', 'store_corrupt: budget document has the wrong shape']);
    }
    expect(await new KvBudgetLedger(rawKv({ v: 1, ver: 3, events: [{ id: 'a' }] }), true).snapshot(KEY)).toEqual({ version: 3, events: [{ id: 'a' }] });
  });
  it('expire reads a stored deadline once it is known to be present', async () => {
    let reads = 0;
    const entry = { id: 'a', verb: 'pay', resource: 'r', params: {}, t: 1, status: 'reserved', get exp(): number { return reads++ === 0 ? 5 : 1000; } };
    expect(await new KvBudgetLedger(rawKv({ v: 1, ver: 0, events: [entry] }), true).expire(KEY, 10)).toEqual({ released: [], version: 0 });
  });
  it('writes only when the operation changed the document', async () => {
    const { kv, writes } = spyKv();
    const l = new KvBudgetLedger(kv, true);
    const wrote = () => writes.map((w) => w !== undefined);
    await l.reserve(KEY, { event: ev('big', 201), accumulators: [acc()] }); // over_cap
    await l.start(KEY, 'ghost');
    await l.commit(KEY, 'ghost');
    await l.release(KEY, 'ghost');
    await l.expire(KEY, 5);
    expect(wrote()).toEqual([false, false, false, false, false]);
    writes.length = 0;
    await l.reserve(KEY, { event: ev('a', 1), accumulators: [acc()], expiresAt: 5 });
    await l.reserve(KEY, { event: ev('b', 1), accumulators: [acc()] });
    await l.reserve(KEY, { event: ev('c', 1), accumulators: [acc()] });
    await l.start(KEY, 'b');
    await l.commit(KEY, 'b');
    await l.release(KEY, 'c');
    await l.expire(KEY, 5);
    expect(wrote()).toEqual([true, true, true, true, true, true, true]);
    expect((await l.snapshot(KEY)).version).toBe(7);
  });
});

describe('signed releases', () => {
  const k = generateKeyPair();
  const pub = b64u(k.publicKey);
  const msgOf = (b: Record<string, unknown>): Uint8Array => {
    const dom = utf8(RELEASE_DOMAIN);
    const body = canonicalBytesStrict({ v: b.v, key: b.key, id: b.id, reason: b.reason, at: b.at, signer: b.signer });
    const out = new Uint8Array(dom.length + body.length);
    out.set(dom);
    out.set(body, dom.length);
    return out;
  };
  const forged = (over: Record<string, unknown>): ReleaseEvent => {
    const b = { v: 1, key: KEY, id: 'a', reason: 'rollback', at: 5, signer: pub, ...over };
    return { ...b, sig: b64u(sign(k.secretKey, msgOf(b))) } as unknown as ReleaseEvent;
  };
  it('the signature covers the domain-separated canonical body', () => {
    const rel = signRelease({ key: KEY, id: 'a', reason: 'effect_failed', at: 5 }, k.secretKey);
    expect(verifyB64u(pub, msgOf(rel as unknown as Record<string, unknown>), rel.sig)).toBe(true);
    expect(verifyRelease(forged({}), pub)).toBe(true);
  });
  it('signRelease refuses each malformed field on its own', () => {
    const base = { key: KEY, id: 'a', reason: 'rollback' as const, at: 5 };
    for (const over of [{ reason: 'bogus' }, { at: 1.5 }, { key: '' }, { id: '' }]) {
      expectThrow(() => signRelease({ ...base, ...over } as never, k.secretKey), RangeError, 'signRelease: a malformed release');
    }
  });
  it('a correctly signed release still fails on the wrong version, signer field or reason, or when it is not a plain object', () => {
    expect(verifyRelease(forged({ v: 2 }), pub)).toBe(false);
    expect(verifyRelease(forged({ signer: 'someone-else' }), pub)).toBe(false);
    expect(verifyRelease(forged({ reason: 'bogus' }), pub)).toBe(false);
    expect(verifyRelease(Object.assign([], forged({})) as unknown as ReleaseEvent, pub)).toBe(false);
  });
  it('the signature is checked as first read: a sig that changes between reads is refused', () => {
    const good = forged({});
    let reads = 0;
    const { sig: _sig, ...rest } = good;
    void _sig;
    const r = { ...rest, get sig(): string { return reads++ === 0 ? 'AAAA' : good.sig; } } as unknown as ReleaseEvent;
    expect(verifyRelease(r, pub)).toBe(false);
  });
  it('a release that throws while being read is false, never a throw', () => {
    const r = { get v(): number { throw new Error('boom'); } } as unknown as ReleaseEvent;
    expect(verifyRelease(r, pub)).toBe(false);
  });
  it('digest and leaf are domain-separated hashes', () => {
    const r = forged({});
    expect(releaseDigest(r)).toBe(hashCanonical({ d: 'atlas-pca/budget-release-ref/v1', r }));
    expect(releaseCommit(r)).toBe(hashCanonical({ d: 'atlas-pca/budget-release-leaf/v1', digest: hashCanonical({ d: 'atlas-pca/budget-release-ref/v1', r }) }));
  });
});

describe('anchorRelease against a moving log', () => {
  const r = { v: 1, key: KEY, id: 'a', reason: 'rollback', at: 5, signer: 's', sig: 's' } as ReleaseEvent;
  const log = (sizes: number[], outcomes: string[]) => {
    let s = 0;
    let a = 0;
    const store = {
      size: async () => sizes[Math.min(s++, sizes.length - 1)]!,
      append: async (size: number) => {
        if (++a > 64) throw new Error('runaway');
        return { outcome: outcomes[Math.min(a - 1, outcomes.length - 1)]!, size };
      },
    };
    return { store: store as unknown as LedgerStore, appends: () => a };
  };
  it('a conflict retries at the new size; appended and replayed both return the position used', async () => {
    expect(await anchorRelease(log([10, 11], ['conflict', 'appended']).store, r)).toBe(11);
    expect(await anchorRelease(log([7, 8], ['replayed', 'appended']).store, r)).toBe(7);
  });
  it('gives up after exactly 64 conflicts', async () => {
    const l = log([0], ['conflict']);
    const e = await rejection(anchorRelease(l.store, r));
    expect(e).toBeInstanceOf(BudgetLedgerError);
    expect([(e as BudgetLedgerError).code, e.message]).toEqual(['conflict_exhausted', 'conflict_exhausted: could not anchor the release: the log kept moving']);
    expect(l.appends()).toBe(64);
  });
});

describe('admitAggregateAction: exact refusals and ordering', () => {
  it('a missing ledger is not durable', async () => {
    const e = await rejection(admitAggregateAction(undefined as never, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('a', 1), verify: ok }));
    expect(e).toBeInstanceOf(BudgetLedgerError);
    expect(e.message).toBe('not_durable: a principal, org or fleet aggregate needs a durable BudgetLedger (a restart would reset every cap)');
  });
  it('an accumulator without a scope is session-scoped: no durable ledger needed', async () => {
    const volatile = new KvBudgetLedger(createMemoryDurableKv(), false);
    expect(await admitAggregateAction(volatile, { ids: {}, accumulators: [acc({ scope: undefined })], event: ev('a', 1), verify: ok })).toEqual({ admitted: true, verdict: { allow: true }, reservations: [], state: {} });
  });
  it('an unbound scope is a deny with the exact reason; an invalid scope id is thrown', async () => {
    expect(await admitAggregateAction(ledger(), { ids: {}, accumulators: [acc()], event: ev('a', 1), verify: ok })).toEqual({
      admitted: false,
      reason: 'scope_unbound: scope_unbound: accumulator spend is principal-scoped but no principal id was given',
    });
    const e = await rejection(admitAggregateAction(ledger(), { ids: { principal: '' }, accumulators: [acc()], event: ev('a', 1), verify: ok }));
    expect(e).toBeInstanceOf(BudgetLedgerError);
    expect((e as BudgetLedgerError).code).toBe('invalid');
  });
  it('a verifier deny carries its verdict', async () => {
    expect(await admitAggregateAction(ledger(), { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('a', 1), verify: async () => ({ allow: false }) })).toEqual({ admitted: false, reason: 'verifier denied', verdict: { allow: false } });
  });
  it('reservations are made in sorted key order', async () => {
    const r = await admitAggregateAction(ledger(), { ids: { principal: 'alice', org: 'acme' }, accumulators: [acc({ id: 'p' }), acc({ id: 'o', scope: 'org' })], event: ev('a', 1), verify: ok });
    expect(r.admitted && r.reservations).toEqual([{ key: 'org/acme', id: 'a' }, { key: 'principal/alice', id: 'a' }]);
  });
  it('over_cap, id_conflict and a committed replay each deny with their own reason', async () => {
    const l = ledger();
    await l.reserve(KEY, { event: ev('a', 10), accumulators: [acc()] });
    await l.commit(KEY, 'a');
    const admit = (e: ReturnType<typeof ev>) => admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: e, verify: ok });
    expect(await admit(ev('a', 10))).toEqual({ admitted: false, reason: 'aggregate: already committed', verdict: { allow: true } });
    expect(await admit(ev('a', 11))).toEqual({ admitted: false, reason: 'aggregate: id_conflict', verdict: { allow: true } });
    expect(await admit(ev('b', 191))).toEqual({ admitted: false, reason: 'aggregate: over_cap: spend would reach 201 (cap 200)', verdict: { allow: true } });
    await l.reserve(KEY, { event: ev('c', 5), accumulators: [acc()] });
    expect(await admit(ev('c', 5))).toMatchObject({ admitted: true, reservations: [{ key: KEY, id: 'c' }] });
  });
  it('only a reserved outcome (or a replay of a reservation) counts as reserved', async () => {
    const real = ledger();
    const odd: BudgetLedger = {
      durable: true,
      snapshot: (key) => real.snapshot(key),
      reserve: async () => ({ outcome: 'id_conflict', version: 0, status: 'reserved' }) as unknown as ReserveOutcome,
      start: (key, id) => real.start(key, id),
      commit: (key, id) => real.commit(key, id),
      release: (key, id, e) => real.release(key, id, e),
      expire: (key, now) => real.expire(key, now),
    };
    expect(await admitAggregateAction(odd, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('a', 1), verify: ok })).toEqual({ admitted: false, reason: 'aggregate: id_conflict', verdict: { allow: true } });
  });
  it('the pre-state reads only what the accumulators need: no monitor folds over the history', async () => {
    const real = ledger();
    const unreadable = { id: 'z', verb: 'pay', params: { amount: 1 }, t: 1, status: 'reserved', get resource(): string { throw new Error('resource read'); } };
    const l: BudgetLedger = {
      durable: true,
      snapshot: async () => ({ version: 0, events: [unreadable as never] }),
      reserve: (key, req) => real.reserve(key, req),
      start: (key, id) => real.start(key, id),
      commit: (key, id) => real.commit(key, id),
      release: (key, id, e) => real.release(key, id, e),
      expire: (key, now) => real.expire(key, now),
    };
    let seen: unknown;
    const r = await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('a', 2), verify: async (st) => ((seen = st), { allow: true }) });
    expect(r).toMatchObject({ admitted: true, reservations: [{ key: KEY, id: 'a' }] });
    expect(seen).toEqual({ spend: { sum: 1 } });
  });
  it('a key that keeps moving exhausts exactly maxAttempts rounds', async () => {
    const real = ledger();
    let snaps = 0;
    const moving: BudgetLedger = {
      durable: true,
      snapshot: async (key) => {
        if (++snaps > 2) throw new Error('runaway');
        return real.snapshot(key);
      },
      reserve: async () => ({ outcome: 'conflict', version: 0 }),
      start: (key, id) => real.start(key, id),
      commit: (key, id) => real.commit(key, id),
      release: (key, id, e) => real.release(key, id, e),
      expire: (key, now) => real.expire(key, now),
    };
    const e = await rejection(admitAggregateAction(moving, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('a', 1), verify: ok, maxAttempts: 2 }));
    expect(e).toBeInstanceOf(BudgetLedgerError);
    expect([(e as BudgetLedgerError).code, e.message]).toEqual(['conflict_exhausted', 'conflict_exhausted: the aggregate kept moving under this admission']);
    expect(snaps).toBe(2);
  });
});

describe('startAggregate', () => {
  it('a reservation already started is fine; an unknown one is not', async () => {
    const l = ledger();
    await l.reserve(KEY, { event: ev('a', 1), accumulators: [acc()] });
    expect(await startAggregate(l, [{ key: KEY, id: 'a' }])).toBe(true);
    expect(await startAggregate(l, [{ key: KEY, id: 'a' }])).toBe(true);
    expect(await startAggregate(l, [{ key: KEY, id: 'ghost' }])).toBe(false);
  });
});
