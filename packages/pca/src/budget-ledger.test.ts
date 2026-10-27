import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createMemoryDurableKv } from './durable-state';
import { b64u } from './hash';
import { generateKeyPair } from './keys';
import { type AccumulatorDecl, accumulatorDeclError } from './intent-acc';
import { MemoryIntentSessionStore, admitIntentAction } from './intent-history';
import { KvLedgerStore } from './ledger-store';
import {
  BudgetLedgerError,
  KvBudgetLedger,
  admitAggregateAction,
  anchorRelease,
  emptyBudgetDoc,
  expireInDoc,
  openDurableBudgetLedger,
  releaseCommit,
  reserveInDoc,
  scopeKey,
  settleAggregate,
  startAggregate,
  startInDoc,
  signRelease,
  verifyRelease,
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
/** A kv-backed ledger that claims durability: the kv is in-process, but nothing here restarts it. */
const ledger = (): KvBudgetLedger => new KvBudgetLedger(createMemoryDurableKv(), true);
const KEY = scopeKey('principal', 'alice');

describe('reserveInDoc: the pure transitions', () => {
  it('a reservation counts at once and the cap is inclusive', () => {
    const d = emptyBudgetDoc();
    expect(reserveInDoc(d, { event: ev('a', 150), accumulators: [acc()] })).toMatchObject({ outcome: 'reserved', version: 1, post: { spend: 150 } });
    expect(reserveInDoc(d, { event: ev('b', 51), accumulators: [acc()] })).toMatchObject({ outcome: 'over_cap', acc: 'spend', post: 201, cap: 200 });
    expect(reserveInDoc(d, { event: ev('c', 50), accumulators: [acc()] })).toMatchObject({ outcome: 'reserved', post: { spend: 200 } });
    expect(d.ver).toBe(2);
  });
  it('the same reservation again is a replay; another event under the same id conflicts; neither writes', () => {
    const d = emptyBudgetDoc();
    reserveInDoc(d, { event: ev('a', 10), accumulators: [acc()] });
    expect(reserveInDoc(d, { event: ev('a', 10), accumulators: [acc()] })).toEqual({ outcome: 'replayed', version: 1, status: 'reserved' });
    expect(reserveInDoc(d, { event: ev('a', 11), accumulators: [acc()] })).toEqual({ outcome: 'id_conflict', version: 1 });
    expect(d.events).toHaveLength(1);
  });
  it('expectedVersion is a compare-and-swap, but a replay wins over a stale version (a lost acknowledgement)', () => {
    const d = emptyBudgetDoc();
    reserveInDoc(d, { event: ev('a', 10), accumulators: [acc()], expectedVersion: 0 });
    expect(reserveInDoc(d, { event: ev('b', 10), accumulators: [acc()], expectedVersion: 0 })).toEqual({ outcome: 'conflict', version: 1 });
    expect(reserveInDoc(d, { event: ev('a', 10), accumulators: [acc()], expectedVersion: 0 })).toMatchObject({ outcome: 'replayed' });
  });
  it('commit and release: only a reservation settles, and never the other way round', () => {
    const k = ledger();
    return (async () => {
      await k.reserve(KEY, { event: ev('a', 10), accumulators: [acc()] });
      await k.reserve(KEY, { event: ev('b', 10), accumulators: [acc()] });
      expect(await k.release(KEY, 'ghost')).toMatchObject({ outcome: 'unknown' });
      expect(await k.commit(KEY, 'ghost')).toMatchObject({ outcome: 'unknown' });
      expect(await k.commit(KEY, 'a')).toMatchObject({ outcome: 'settled' });
      expect(await k.commit(KEY, 'a')).toMatchObject({ outcome: 'replayed' });
      expect(await k.release(KEY, 'a')).toMatchObject({ outcome: 'refused', status: 'committed' });
      expect(await k.release(KEY, 'b')).toMatchObject({ outcome: 'settled' });
      expect(await k.release(KEY, 'b')).toMatchObject({ outcome: 'replayed' });
      expect(await k.commit(KEY, 'b')).toMatchObject({ outcome: 'refused', status: 'released' });
      // the release freed b's 10, the commit kept a's 10
      expect(await k.reserve(KEY, { event: ev('c', 190), accumulators: [acc()] })).toMatchObject({ outcome: 'reserved', post: { spend: 200 } });
    })();
  });
  it('a release of something never reserved credits nothing', async () => {
    const k = ledger();
    await k.release(KEY, 'ghost');
    expect(await k.reserve(KEY, { event: ev('a', 201), accumulators: [acc()] })).toMatchObject({ outcome: 'over_cap' });
  });
  it('expire releases only reservations past their deadline, never a committed one', () => {
    const d = emptyBudgetDoc();
    reserveInDoc(d, { event: ev('a', 10), accumulators: [acc()], expiresAt: 100 });
    reserveInDoc(d, { event: ev('b', 10), accumulators: [acc()], expiresAt: 200 });
    reserveInDoc(d, { event: ev('c', 10), accumulators: [acc()] });
    d.events[0]!.status = 'committed';
    expect(expireInDoc(d, 150)).toMatchObject({ released: [] });
    expect(expireInDoc(d, 200)).toMatchObject({ released: ['b'] });
    expect(d.events.map((e) => e.status)).toEqual(['committed', 'released', 'reserved']);
    expect(() => expireInDoc(d, 1.5)).toThrow(RangeError);
  });
  it('a period window resets the count, a task window never does', () => {
    const d = emptyBudgetDoc();
    const day = acc({ win: { kind: 'period', ms: 1000, t0: 0 } });
    reserveInDoc(d, { event: ev('a', 200, 100), accumulators: [day] });
    expect(reserveInDoc(d, { event: ev('b', 1, 900), accumulators: [day] })).toMatchObject({ outcome: 'over_cap' });
    expect(reserveInDoc(d, { event: ev('c', 200, 1100), accumulators: [day] })).toMatchObject({ outcome: 'reserved' });
  });
  it('count, max and distinct accumulators are capped the same way', () => {
    const d = emptyBudgetDoc();
    const n = acc({ id: 'n', agg: 'count', val: undefined, domain_max: 2 });
    reserveInDoc(d, { event: ev('a', 1), accumulators: [n] });
    reserveInDoc(d, { event: ev('b', 1), accumulators: [n] });
    expect(reserveInDoc(d, { event: ev('c', 1), accumulators: [n] })).toMatchObject({ outcome: 'over_cap', acc: 'n', post: 3, cap: 2 });
    const mx = acc({ id: 'm', agg: 'max', domain_max: 50 });
    expect(reserveInDoc(emptyBudgetDoc(), { event: ev('x', 51), accumulators: [mx] })).toMatchObject({ outcome: 'over_cap', acc: 'm' });
  });
  it('a verb the accumulator does not select leaves it alone; a malformed request throws', () => {
    const d = emptyBudgetDoc();
    expect(reserveInDoc(d, { event: { ...ev('a', 999), verb: 'read' }, accumulators: [acc()] })).toMatchObject({ outcome: 'reserved', post: {} });
    expect(() => reserveInDoc(d, { event: ev('', 1), accumulators: [acc()] })).toThrow(RangeError);
    expect(() => reserveInDoc(d, { event: ev('y', 1), accumulators: [acc({ domain_max: undefined })] })).toThrow(RangeError);
    expect(() => reserveInDoc(d, { event: ev('w', 1), accumulators: [acc()], expectedVersion: -1 })).toThrow(RangeError);
    expect(() => reserveInDoc(d, { event: { ...ev('v', 1), t: 0.5 }, accumulators: [acc()] })).toThrow(RangeError);
  });
});

describe('scopes: declaration and keys', () => {
  it('a scoped accumulator needs a site_local holder and a domain_max', () => {
    expect(accumulatorDeclError(acc())).toBeNull();
    expect(accumulatorDeclError(acc({ scope: 'session', domain_max: undefined }))).toBeNull();
    expect(accumulatorDeclError(acc({ domain_max: undefined }))).toMatch(/needs domain_max/);
    expect(accumulatorDeclError(acc({ holder: { kind: 'wallet' } }))).toBeTruthy();
    expect(accumulatorDeclError(acc({ scope: 'galaxy' as never }))).toMatch(/unknown scope/);
    for (const s of ['org', 'fleet'] as const) expect(accumulatorDeclError(acc({ scope: s }))).toBeNull();
  });
  it('keys are injective in the scope and the id', () => {
    expect(scopeKey('principal', 'a/b')).not.toBe(scopeKey('principal', 'a'));
    expect(scopeKey('org', 'x')).not.toBe(scopeKey('principal', 'x'));
    expect(() => scopeKey('org', '')).toThrow(BudgetLedgerError);
    expect(() => scopeKey('org', 'a\nb')).toThrow(BudgetLedgerError);
  });
});

describe('admitAggregateAction: refusals', () => {
  it('refuses a volatile ledger for any non-session scope', async () => {
    const volatile = new KvBudgetLedger(createMemoryDurableKv(), false);
    await expect(admitAggregateAction(volatile, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('a', 1), verify: ok })).rejects.toMatchObject({ code: 'not_durable' });
  });
  it('a session-only root needs no aggregate ledger', async () => {
    const volatile = new KvBudgetLedger(createMemoryDurableKv(), false);
    const r = await admitAggregateAction(volatile, { ids: {}, accumulators: [acc({ scope: 'session' })], event: ev('a', 1), verify: ok });
    expect(r).toMatchObject({ admitted: true, reservations: [] });
  });
  it('denies when the scope id is not bound, and reserves nothing', async () => {
    const l = ledger();
    const r = await admitAggregateAction(l, { ids: { org: 'acme' }, accumulators: [acc()], event: ev('a', 1), verify: ok });
    expect(r).toMatchObject({ admitted: false, reason: expect.stringContaining('scope_unbound') });
    expect((await l.snapshot(KEY)).events).toEqual([]);
  });
  it('a verifier deny reserves nothing', async () => {
    const l = ledger();
    const r = await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('a', 1), verify: async () => ({ allow: false }) });
    expect(r).toMatchObject({ admitted: false });
    expect((await l.snapshot(KEY)).version).toBe(0);
  });
  it('the verifier sees the cross-session pre-state', async () => {
    const l = ledger();
    await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('a', 70), verify: ok });
    let seen: unknown;
    await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('b', 5), verify: async (s) => ((seen = s), { allow: true }) });
    expect(seen).toEqual({ spend: { sum: 70 } });
  });
});

describe('W8: salami across sessions and agents is stopped at principal scope', () => {
  it('100 x $19 from 100 different sessions under a $200 principal cap: exactly 10 are admitted, however they interleave', async () => {
    const l = ledger();
    const run = (i: number) => admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev(`e${i}`, 19), verify: async () => (await Promise.resolve(), { allow: true }) });
    const rs = await Promise.all(Array.from({ length: 100 }, (_, i) => run(i)));
    expect(rs.filter((r) => r.admitted)).toHaveLength(10);
    const snap = await l.snapshot(KEY);
    expect(snap.events.filter((e) => e.status === 'reserved')).toHaveLength(10);
  });
  it('the same cap holds when each session also has its own session store (the session count cannot widen it)', async () => {
    const l = ledger();
    const root = { accumulators: [acc()], monitors: [] };
    let admitted = 0;
    for (let i = 0; i < 30; i++) {
      const sessions = new MemoryIntentSessionStore();
      const e = ev(`s${i}`, 19);
      const v = await admitIntentAction(sessions, {
        session: `sess-${i}`,
        root,
        event: e,
        verify: async (sessionAcc) => {
          const a = await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: root.accumulators, event: e, verify: async (st) => (Object.assign(sessionAcc.state, st), { allow: true }) });
          return { allow: a.admitted };
        },
      });
      if (v.allow) admitted++;
    }
    expect(admitted).toBe(10);
  });
});

describe('W9: one principal, N sessions and N delegated agents share one cap', () => {
  it('sessions, grants and agents do not appear in the key: only the principal does', async () => {
    const l = ledger();
    const a = await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: { ...ev('agent-1-call', 120), resource: 'grant-1' }, verify: ok });
    const b = await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: { ...ev('agent-2-call', 120), resource: 'grant-2' }, verify: ok });
    expect([a.admitted, b.admitted]).toEqual([true, false]);
  });
  it('another principal has its own state', async () => {
    const l = ledger();
    await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('a', 200), verify: ok });
    const r = await admitAggregateAction(l, { ids: { principal: 'bob' }, accumulators: [acc()], event: ev('b', 200), verify: ok });
    expect(r.admitted).toBe(true);
  });
  it('org and principal caps hold together; a deny at the second key frees the first key again', async () => {
    const l = ledger();
    const accs = [acc({ id: 'p', domain_max: 100 }), acc({ id: 'o', scope: 'org', domain_max: 150 })];
    const ids = (p: string) => ({ principal: p, org: 'acme' });
    expect((await admitAggregateAction(l, { ids: ids('alice'), accumulators: accs, event: ev('a', 100), verify: ok })).admitted).toBe(true);
    const denied = await admitAggregateAction(l, { ids: ids('bob'), accumulators: accs, event: ev('b', 60), verify: ok });
    expect(denied).toMatchObject({ admitted: false, reason: expect.stringContaining('over_cap: o') });
    // bob's principal reservation (made first: keys sort org/ before principal/) is not left counting
    const bob = (await l.snapshot(scopeKey('principal', 'bob'))).events.filter((e) => e.status === 'reserved');
    expect(bob).toEqual([]);
    expect((await admitAggregateAction(l, { ids: ids('bob'), accumulators: accs, event: ev('c', 50), verify: ok })).admitted).toBe(true);
  });
  it('a fleet cap spans orgs', async () => {
    const l = ledger();
    const f = acc({ scope: 'fleet', domain_max: 100 });
    await admitAggregateAction(l, { ids: { fleet: 'f1', org: 'a' }, accumulators: [f], event: ev('a', 60), verify: ok });
    const r = await admitAggregateAction(l, { ids: { fleet: 'f1', org: 'b' }, accumulators: [f], event: ev('b', 60), verify: ok });
    expect(r.admitted).toBe(false);
  });
  it('a retried admission of the same action does not count twice', async () => {
    const l = ledger();
    const e = ev('a', 150);
    await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: e, verify: ok });
    const again = await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: e, verify: ok });
    expect(again.admitted).toBe(true);
    expect((await l.snapshot(KEY)).events).toHaveLength(1);
    expect((await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('b', 50), verify: ok })).admitted).toBe(true);
    expect((await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('c', 1), verify: ok })).admitted).toBe(false);
  });
});

describe('two phases, crash and expiry', () => {
  it('an unsettled reservation keeps counting (over-restricts), a release frees it, a commit keeps it', async () => {
    const l = ledger();
    const a = await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('a', 150), verify: ok });
    const b = await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('b', 50), verify: ok });
    if (!a.admitted || !b.admitted) throw new Error('setup');
    expect((await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('c', 1), verify: ok })).admitted).toBe(false);
    expect(await settleAggregate(l, a.reservations, 'released')).toEqual([expect.objectContaining({ outcome: 'settled' })]);
    await settleAggregate(l, b.reservations, 'committed');
    expect((await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('d', 150), verify: ok })).admitted).toBe(true);
    expect((await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('e', 1), verify: ok })).admitted).toBe(false);
  });
  it('a started reservation is never expired by any clock; an expired one can never start (the ledger orders them)', async () => {
    const l = ledger();
    const a = await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('a', 100), verify: ok, expiresAt: 10 });
    const b = await admitAggregateAction(l, { ids: { principal: 'alice' }, accumulators: [acc()], event: ev('b', 100), verify: ok, expiresAt: 10 });
    if (!a.admitted || !b.admitted) throw new Error('setup');
    expect(await startAggregate(l, a.reservations)).toBe(true);
    // a caller whose clock is far in the future frees only what never started
    expect(await l.expire(KEY, Number.MAX_SAFE_INTEGER)).toMatchObject({ released: ['b'] });
    expect(await startAggregate(l, b.reservations)).toBe(false);
    expect((await l.snapshot(KEY)).events.map((e) => [e.id, e.status, e.started])).toEqual([['a', 'reserved', true], ['b', 'released', undefined]]);
    // a crash after the effect: the reservation keeps counting, so the cap cannot be re-spent
    expect((await l.reserve(KEY, { event: ev('c', 101), accumulators: [acc()] })).outcome).toBe('over_cap');
    expect(startInDoc(emptyBudgetDoc(), 'x')).toMatchObject({ outcome: 'unknown' });
  });
  it('an expired reservation frees its budget, and a late commit of it is refused', async () => {
    const l = ledger();
    await l.reserve(KEY, { event: ev('a', 200), accumulators: [acc()], expiresAt: 500 });
    expect((await l.reserve(KEY, { event: ev('b', 1), accumulators: [acc()] })).outcome).toBe('over_cap');
    expect(await l.expire(KEY, 499)).toMatchObject({ released: [] });
    expect(await l.expire(KEY, 500)).toMatchObject({ released: ['a'] });
    expect((await l.reserve(KEY, { event: ev('b', 200), accumulators: [acc()] })).outcome).toBe('reserved');
    expect(await l.commit(KEY, 'a')).toMatchObject({ outcome: 'refused', status: 'released' });
  });
  it('state survives a restart of the durable file store', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pca-budget-'));
    const first = await openDurableBudgetLedger({ dir });
    await first.reserve(KEY, { event: ev('a', 200), accumulators: [acc()] });
    const second = await openDurableBudgetLedger({ dir });
    expect(second.durable).toBe(true);
    expect((await second.reserve(KEY, { event: ev('b', 1), accumulators: [acc()] })).outcome).toBe('over_cap');
    expect((await second.snapshot(KEY)).events.map((e) => e.id)).toEqual(['a']);
  });
  it('KvBudgetLedger demands an explicit durability declaration', () => {
    expect(() => new KvBudgetLedger(createMemoryDurableKv(), undefined as never)).toThrow(BudgetLedgerError);
    expect(() => new KvBudgetLedger(undefined as never, true)).toThrow(BudgetLedgerError);
  });
});

describe('signed, anchored releases', () => {
  const k = generateKeyPair();
  const sec = k.secretKey;
  const pub = b64u(k.publicKey);
  it('a release is signed, bound to its reservation, stored, and verifiable', async () => {
    const l = ledger();
    await l.reserve(KEY, { event: ev('a', 10), accumulators: [acc()] });
    const rel = signRelease({ key: KEY, id: 'a', reason: 'effect_failed', at: 5 }, sec);
    expect(verifyRelease(rel, pub)).toBe(true);
    expect(await l.release(KEY, 'a', rel)).toMatchObject({ outcome: 'settled' });
    expect((await l.snapshot(KEY)).events[0]!.rel).toEqual(rel);
  });
  it('a tampered, re-keyed or wrong-signer release does not verify', () => {
    const rel = signRelease({ key: KEY, id: 'a', reason: 'effect_failed', at: 5 }, sec);
    expect(verifyRelease({ ...rel, id: 'b' }, pub)).toBe(false);
    expect(verifyRelease({ ...rel, reason: 'rollback' }, pub)).toBe(false);
    expect(verifyRelease({ ...rel, at: 6 }, pub)).toBe(false);
    expect(verifyRelease(rel, b64u(generateKeyPair().publicKey))).toBe(false);
    expect(verifyRelease({ ...rel, sig: 'AAAA' }, pub)).toBe(false);
    expect(verifyRelease(null as never, pub)).toBe(false);
  });
  it('evidence for another reservation is refused', async () => {
    const l = ledger();
    await l.reserve(KEY, { event: ev('a', 10), accumulators: [acc()] });
    await expect(l.release(KEY, 'a', signRelease({ key: KEY, id: 'zzz', reason: 'effect_failed', at: 5 }, sec))).rejects.toThrow(RangeError);
  });
  it('anchoring appends the release leaf to a transparency log store, and appends again on a repeat (the log is append-only)', async () => {
    const log = new KvLedgerStore(createMemoryDurableKv());
    const rel = signRelease({ key: KEY, id: 'a', reason: 'effect_not_run', at: 5 }, sec);
    expect(await anchorRelease(log, rel)).toBe(0);
    expect(await log.read(0, 1)).toEqual([releaseCommit(rel)]);
    expect(await anchorRelease(log, rel)).toBe(1);
  });
});
