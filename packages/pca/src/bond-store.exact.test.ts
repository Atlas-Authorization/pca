// Exact-outcome tests for bond-store.ts: error texts, both sides of every boundary, each validator one field at a time.
import { describe, expect, it } from 'vitest';
import { createMemoryDurableKv, type DurableKv } from './durable-state';
import { mintGrant } from './envelope';
import { buildPCActn, type PCActn } from './pcactn';
import { decide, type DecideInput } from './policy-vm';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY } from './risk';
import type { Capability } from './capability';
import type { PlanNode } from './merkle';
import { fileFraudProof, openOptimistic } from './optimistic';
import type { BondPlan, BondRow, SettlementRecord } from './bond-settlement';
import {
  BondStoreError,
  KvBondStore,
  StoreBondLedger,
  commitBondPlan,
  emptyBondDoc,
  isBondStore,
  sameSettlement,
  snapshotOf,
  type BondStore,
} from './bond-store';

const P = generateKeyPair();
const A = generateKeyPair();
const G = generateKeyPair();
const apk = encodeKey(A.publicKey);
const NOW = 1_700_000_000_000;
const W = 60_000;
const GRANT: Capability = mintGrant({
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: apk,
  goal: 'g',
  envelope: { predicates: [{ verb: 'revoke_session', resource: '/acct/*' }], caveats: [{ type: 'expires', at: 9e15 }], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
}).grant;
function actn(verb: string): PCActn {
  const nodes: PlanNode[] = [{ id: 'n1', verb, resource: '/acct/1/s', reversibility_class: 'reversible' }];
  return buildPCActn({ aud: 'a', grant: GRANT, chain: [GRANT], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: A.secretKey });
}
const decideInput = (p: PCActn): DecideInput => ({
  grant: GRANT,
  chain: [GRANT],
  action: { action: { verb: p.action.verb, resource: p.action.resource, params: {}, reversibility_class: p.action.reversibility_class } },
  risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 },
  budget: { B: 1, tau: NOW, asOf: NOW },
  now: NOW,
  nodeId: p.plan.node_id,
});

const msgOf = async (p: Promise<unknown> | (() => unknown)): Promise<string> => {
  try {
    await (typeof p === 'function' ? p() : p);
  } catch (e) {
    return (e as Error).message;
  }
  return 'none';
};
const clockBox = (t = NOW) => {
  const c = { t };
  return { c, fn: () => c.t };
};
async function rig(o: { verb?: string; bondRef?: string; windowMs?: number; store?: BondStore } = {}) {
  const kv = createMemoryDurableKv();
  const store = o.store ?? new KvBondStore(kv);
  const clk = clockBox();
  const L = new StoreBondLedger({ guardianSecret: G.secretKey, store, clock: clk.fn });
  await L.deposit('alice', 1000);
  const p = actn(o.verb ?? 'revoke_session');
  const claim = openOptimistic(p, { bondRef: o.bondRef ?? 'b1', claimedR: 0, challengeWindowMs: o.windowMs ?? W, issuedAt: NOW, serverNow: NOW }, A.secretKey);
  const open = (amount = 100) => L.openClaim({ claim, pcactn: p, signerPublic: apk, amount, depositor: 'alice' });
  return { L, kv, clk: clk.c, p, claim, open, store };
}
const stubKv = (raw: unknown): DurableKv => ({ get: async () => raw, set: async () => undefined, keys: async () => [], update: async (_k, fn) => fn(raw) });

const rec = (over: Partial<SettlementRecord> = {}): SettlementRecord => ({ claimId: 'b', action: 'release', amount: 5, from: 'escrow', to: 'a', at: 1, evidenceDigest: '', sig: 's', ...over });
const split = { amount: 5, challengerReward: 1, victimCompensation: 1, treasuryRemainder: 3, challengerAccount: 'c', victimAccount: 'v', treasuryAccount: 't' };
const win = { registeredAt: 10, windowMs: 100, claimDigest: 'd' };
const openPlan = (over: Partial<NonNullable<BondPlan['open']>> = {}, record = rec({ action: 'open', from: 'a', to: 'escrow' })): BondPlan => ({
  claimId: 'b',
  expect: 'none',
  next: 'open',
  open: { amount: 5, depositor: 'a', maxOpenClaims: 10, maxOpenAmount: 100, ...over },
  moves: [{ account: 'a', op: 'debit', amount: 5 }, { account: 'escrow', op: 'credit', amount: 5 }],
  record,
});
const row = (over: Partial<BondRow> = {}): BondRow => ({ claimId: 'b', amount: 5, depositor: 'a', status: 'open', records: [rec({ action: 'open' })], ...over });

describe('BondStoreError and isBondStore', () => {
  it('carries code, name, prefixed message and cause', () => {
    const cause = new Error('x');
    const e = new BondStoreError('conflict', 'boom', { cause });
    expect([e.name, e.code, e.message, e.cause, e instanceof Error]).toEqual(['BondStoreError', 'conflict', 'conflict: boom', cause, true]);
  });
  it('needs every one of read, commit and deposit, on an object', () => {
    const ok = { read: () => 1, commit: () => 1, deposit: () => 1 };
    expect(isBondStore(ok)).toBe(true);
    for (const k of ['read', 'commit', 'deposit']) expect(isBondStore({ ...ok, [k]: 1 }), k).toBe(false);
    expect(isBondStore(null)).toBe(false);
    expect(isBondStore(undefined)).toBe(false);
    expect(isBondStore('read')).toBe(false);
    const f = Object.assign(() => 1, ok);
    expect(isBondStore(f)).toBe(false); // a function is not an object here
  });
});

describe('sameSettlement', () => {
  it('ignores time and signature, and compares every other field', () => {
    const base = rec({ action: 'slash', evidenceDigest: 'e', split });
    expect(sameSettlement(base, { ...base, at: 99, sig: 'other' })).toBe(true);
    for (const patch of [{ claimId: 'z' }, { action: 'release' as const }, { amount: 6 }, { from: 'z' }, { to: 'z' }, { evidenceDigest: 'z' }, { split: { ...split, victimCompensation: 2 } }, { split: undefined }]) {
      expect(sameSettlement(base, { ...base, ...patch }), JSON.stringify(patch)).toBe(false);
    }
    expect(sameSettlement(rec(), rec({ split: undefined }))).toBe(true);
  });
});

describe('commitBondPlan: replays and conflicts, exactly', () => {
  const docWith = (b: BondRow) => {
    const d = emptyBondDoc();
    d.balances.set('a', 100);
    d.bonds.set('b', b);
    return d;
  };
  it('an open replays only when depositor, amount, window and record all agree', () => {
    const base = row({ window: win });
    const first = base.records[0]!;
    const same = openPlan({ window: win }, first);
    expect(commitBondPlan(docWith(base), same, 1)).toEqual({ outcome: 'replayed', record: first });
    for (const [label, plan] of [
      ['depositor', openPlan({ window: win, depositor: 'x' }, first)],
      ['amount', openPlan({ window: win, amount: 6 }, first)],
      ['window ms', openPlan({ window: { ...win, windowMs: 101 } }, first)],
      ['window digest', openPlan({ window: { ...win, claimDigest: 'e' } }, first)],
      ['window absent', openPlan({}, first)],
      ['record', openPlan({ window: win }, { ...first, amount: 9 })],
    ] as const) {
      expect(commitBondPlan(docWith(base), plan, 1), label).toEqual({ outcome: 'conflict', reason: 'bond b already exists', current: 'open' });
    }
    // registeredAt is the first call's: a retry may carry a later one
    expect(commitBondPlan(docWith(base), openPlan({ window: { ...win, registeredAt: 999 } }, first), 1).outcome).toBe('replayed');
    // both windows absent replay; a stored window with the plan's absent conflicts (covered above); stored absent, plan present conflicts
    expect(commitBondPlan(docWith(row()), openPlan({}, row().records[0]), 1).outcome).toBe('replayed');
    expect(commitBondPlan(docWith(row()), openPlan({ window: win }, row().records[0]), 1).outcome).toBe('conflict');
    // a stored row with no records cannot replay
    expect(commitBondPlan(docWith(row({ records: [] })), openPlan({}, rec({ action: 'open' })), 1)).toEqual({ outcome: 'conflict', reason: 'bond b already exists', current: 'open' });
  });
  it('a settle plan in the wrong phase replays only when already in plan.next via the same settlement', () => {
    const slashed = row({ status: 'slashed', records: [rec({ action: 'open' }), rec({ action: 'slash', evidenceDigest: 'e', split })] });
    const plan: BondPlan = { claimId: 'b', expect: 'open', next: 'slashed', moves: [], record: rec({ action: 'slash', evidenceDigest: 'e', split, at: 77 }) };
    expect(commitBondPlan(docWith(slashed), plan, 1)).toEqual({ outcome: 'replayed', record: slashed.records[1] });
    expect(commitBondPlan(docWith(slashed), { ...plan, record: rec({ action: 'slash', evidenceDigest: 'z', split }) }, 1)).toEqual({ outcome: 'conflict', reason: 'bond b is already slashed', current: 'slashed' });
    expect(commitBondPlan(docWith(slashed), { ...plan, next: 'released' }, 1)).toEqual({ outcome: 'conflict', reason: 'bond b is already slashed', current: 'slashed' });
    expect(commitBondPlan(docWith(row({ status: 'slashed', records: [] })), plan, 1)).toEqual({ outcome: 'conflict', reason: 'bond b is already slashed', current: 'slashed' });
  });
  it('caps are inclusive at the limit and count only the depositor\'s open bonds', () => {
    const d = emptyBondDoc();
    d.balances.set('a', 100);
    d.bonds.set('x', row({ claimId: 'x', amount: 3 }));
    d.bonds.set('y', row({ claimId: 'y', amount: 50, depositor: 'other' }));
    d.bonds.set('z', row({ claimId: 'z', amount: 40, status: 'released' }));
    // sum 3 + 5 = 8 == limit: allowed; count 1 + 1 == 2: allowed
    expect(commitBondPlan(d, openPlan({ maxOpenAmount: 8, maxOpenClaims: 2 }), 1).outcome).toBe('committed');
    const d2 = emptyBondDoc();
    d2.balances.set('a', 100);
    d2.bonds.set('x', row({ claimId: 'x', amount: 3 }));
    expect(commitBondPlan(d2, openPlan({ maxOpenAmount: 7, maxOpenClaims: 2 }), 1)).toEqual({ outcome: 'conflict', reason: 'depositor aggregate open-bond cap exceeded', current: 'none' });
    expect(commitBondPlan(d2, openPlan({ maxOpenAmount: 100, maxOpenClaims: 1 }), 1)).toEqual({ outcome: 'conflict', reason: 'depositor open-claim cap reached', current: 'none' });
  });
  it('time is the maximum of observed times: equal keeps, greater raises, non-finite and negative are ignored', () => {
    const d = emptyBondDoc();
    d.balances.set('a', 100);
    commitBondPlan(d, openPlan(), 50);
    expect(d.highWater).toBe(50);
    commitBondPlan(d, { ...openPlan(), claimId: 'c' }, 50);
    expect(d.highWater).toBe(50);
    commitBondPlan(d, { ...openPlan(), claimId: 'e' }, Number.NaN);
    expect(d.highWater).toBe(50);
    commitBondPlan(d, { ...openPlan(), claimId: 'f' }, -5);
    expect(d.highWater).toBe(50);
    commitBondPlan(d, { ...openPlan(), claimId: 'g' }, 51);
    expect(d.highWater).toBe(51);
  });
  it('a refused move reports the move error text and the current phase', () => {
    const d = emptyBondDoc();
    expect(commitBondPlan(d, openPlan(), 1)).toEqual({ outcome: 'conflict', reason: 'debit: insufficient balance for a', current: 'none' });
    const bad = { ...openPlan(), moves: [{ account: 'a', op: 'credit' as const, amount: Number.NaN }] };
    expect(commitBondPlan(d, bad, 1)).toEqual({ outcome: 'conflict', reason: 'credit: invalid amount', current: 'none' });
  });
});

describe('snapshotOf', () => {
  it('totals only the depositor\'s open bonds and returns copies', () => {
    const d = emptyBondDoc();
    d.balances.set('a', 7);
    d.bonds.set('b', row());
    d.bonds.set('x', row({ claimId: 'x', amount: 2 }));
    d.bonds.set('y', row({ claimId: 'y', amount: 50, depositor: 'other' }));
    d.bonds.set('z', row({ claimId: 'z', amount: 40, status: 'slashed' }));
    d.highWater = 9;
    const s = snapshotOf(d, { claimId: 'b', depositor: 'a' });
    expect(s).toEqual({ bond: row(), balances: [['a', 7]], openTotals: { count: 2, sum: 7 }, highWater: 9 });
    expect(s.bond).not.toBe(d.bonds.get('b'));
    expect(snapshotOf(d, { claimId: 'nope', depositor: 'q' })).toEqual({ balances: [['q', 0]], openTotals: { count: 0, sum: 0 }, highWater: 9 });
    expect(snapshotOf(d, { claimId: 'b' })).toEqual({ bond: row(), balances: [], openTotals: { count: 0, sum: 0 }, highWater: 9 });
  });
});

describe('KvBondStore: document decoding, one field at a time', () => {
  const good = { v: 1, balances: [['a', 1]], bonds: [row()], highWater: 0 };
  const read = (raw: unknown) => msgOf(new KvBondStore(stubKv(raw)).read({ claimId: 'b' }));
  const shape = 'store_corrupt: bond document has the wrong shape';
  it('accepts the good document and an absent one', async () => {
    expect(await new KvBondStore(stubKv(good)).read({ claimId: 'b', depositor: 'a' })).toEqual({ bond: row(), balances: [['a', 1]], openTotals: { count: 1, sum: 5 }, highWater: 0 });
    expect(await new KvBondStore(stubKv(undefined)).read({ claimId: 'b' })).toEqual({ balances: [], openTotals: { count: 0, sum: 0 }, highWater: 0 });
  });
  it('wrong top-level shape', async () => {
    for (const raw of [null, 'x', 5, [], { ...good, v: 2 }, { ...good, balances: {} }, { ...good, bonds: 'x' }, { ...good, highWater: '0' }, { v: 1, balances: [], bonds: [] }]) {
      expect(await read(raw), JSON.stringify(raw)).toBe(shape);
    }
  });
  it('highWater must be finite and non-negative', async () => {
    for (const hw of [-1, Number.NaN, Number.POSITIVE_INFINITY]) expect(await read({ ...good, highWater: hw })).toBe('store_corrupt: highWater is not a non-negative number');
  });
  it('every balance entry', async () => {
    for (const e of [null, 'ab', ['a'], ['a', 1, 2], [1, 1], ['a', '1'], ['a', Number.NaN], ['a', Number.POSITIVE_INFINITY], ['a', -1]]) {
      expect(await read({ ...good, balances: [e] }), JSON.stringify(e)).toBe('store_corrupt: malformed balance entry');
    }
    expect(await read({ ...good, balances: [['a', 0]] })).toBe('none');
  });
  it('every bond row field', async () => {
    const bad = (patch: Record<string, unknown>) => read({ ...good, bonds: [{ ...row(), ...patch }] });
    for (const patch of [{ claimId: 1 }, { depositor: 1 }, { amount: '5' }, { amount: Number.NaN }, { amount: Number.POSITIVE_INFINITY }, { status: 'weird' }, { status: undefined }, { records: 'x' }, { records: [] }]) {
      expect(await bad(patch), JSON.stringify(patch)).toBe('store_corrupt: malformed bond row');
    }
    for (const b of [null, 'x', 5, []]) expect(await read({ ...good, bonds: [b] })).toBe('store_corrupt: malformed bond row');
    expect(await read({ ...good, bonds: [row(), row()] })).toBe('store_corrupt: duplicate bond row');
    for (const status of ['open', 'released', 'slashed']) expect(await bad({ status })).toBe('none');
  });
  it('the constructor needs a kv with get and update', () => {
    for (const kv of [undefined, null, {}, { get: () => 1 }, { update: () => 1 }]) expect(() => new KvBondStore(kv as never)).toThrow('store_missing: KvBondStore needs a DurableKv');
    expect(() => new KvBondStore(stubKv(undefined))).not.toThrow();
  });
  it('a refused commit writes nothing, a committed one writes the document', async () => {
    const kv = createMemoryDurableKv();
    const s = new KvBondStore(kv);
    expect((await s.commit(openPlan(), 1)).outcome).toBe('conflict'); // no balance
    expect(await kv.keys()).toEqual([]);
    await s.deposit('a', 10);
    expect(await s.commit(openPlan(), 5)).toEqual({ outcome: 'committed', record: rec({ action: 'open', from: 'a', to: 'escrow' }) });
    expect((await s.read({ claimId: '' })).highWater).toBe(5);
  });
  it('deposit validates and reports exact messages', async () => {
    const s = new KvBondStore(createMemoryDurableKv());
    for (const a of ['', 5, null, undefined]) await expect(s.deposit(a as never, 1)).rejects.toThrow('deposit: account is required');
    for (const n of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) await expect(s.deposit('a', n)).rejects.toThrow('deposit: amount must be a positive finite number');
    expect(await s.deposit('a', 0.25)).toBe(0.25);
  });
});

describe('StoreBondLedger: construction and plumbing', () => {
  it('exact constructor messages and the guardian key', () => {
    const store = new KvBondStore(createMemoryDurableKv());
    expect(() => new StoreBondLedger(undefined as never)).toThrow('store_missing: a BondStore is required (there is no in-memory default)');
    expect(() => new StoreBondLedger({ guardianSecret: G.secretKey } as never)).toThrow('store_missing: a BondStore is required');
    expect(() => new StoreBondLedger({ store } as never)).toThrow('guardian_key_missing: a guardian secret key is required');
    expect(() => new StoreBondLedger({ store, guardianSecret: new Uint8Array(0) })).toThrow('guardian_key_missing: a guardian secret key is required');
    expect(new StoreBondLedger({ store, guardianSecret: G.secretKey }).guardianPublicKey).toBe(encodeKey(G.publicKey));
  });
  it('a clock that returns a non-number or non-finite value is clock_invalid with its text', async () => {
    const store = new KvBondStore(createMemoryDurableKv());
    for (const v of [Number.NaN, Number.POSITIVE_INFINITY, '5']) {
      const L = new StoreBondLedger({ store, guardianSecret: G.secretKey, clock: () => v as never });
      expect(await msgOf(L.bondStatus('x')), String(v)).toBe('none'); // bondStatus does not read the clock
      expect(await msgOf(L.challengeStatus('x')), String(v)).toBe('clock_invalid: the clock returned a non-finite time');
    }
  });
  it('a failing store: Error keeps its text, a non-Error gets the fallback; both keep the cause', async () => {
    const mk = (thrown: unknown): BondStore => ({ read: async () => { throw thrown; }, commit: async () => { throw thrown; }, deposit: async () => { throw thrown; } });
    const boom = new Error('disk gone');
    const L = new StoreBondLedger({ store: mk(boom), guardianSecret: G.secretKey });
    const e1 = (await L.bondStatus('x').catch((e: unknown) => e)) as BondStoreError;
    expect([e1.code, e1.message, e1.cause]).toEqual(['store_unavailable', 'store_unavailable: disk gone', boom]);
    const e2 = (await new StoreBondLedger({ store: mk('plain'), guardianSecret: G.secretKey }).deposit('a', 1).catch((e: unknown) => e)) as BondStoreError;
    expect([e2.code, e2.message, e2.cause]).toEqual(['store_unavailable', 'store_unavailable: store failed', 'plain']);
  });
  it('a conflict from the store surfaces with its reason', async () => {
    const r = await rig();
    const store: BondStore = { read: (s) => r.store.read(s), deposit: (a, n) => r.store.deposit(a, n), commit: async () => ({ outcome: 'conflict', reason: 'because', current: 'none' }) };
    const L = new StoreBondLedger({ store, guardianSecret: G.secretKey, clock: () => NOW });
    expect(await msgOf(L.openBond({ claimId: 'q', amount: 10, depositor: 'alice' }))).toBe('conflict: because');
  });
  it('balanceOf reads the named account and defaults to 0 when the store returns none', async () => {
    const reads: unknown[] = [];
    const store: BondStore = { read: async (s) => { reads.push(s); return { balances: [], openTotals: { count: 0, sum: 0 }, highWater: 0 }; }, commit: async () => ({ outcome: 'conflict', reason: '', current: 'none' }), deposit: async () => 0 };
    const L = new StoreBondLedger({ store, guardianSecret: G.secretKey });
    expect(await L.balanceOf('zed')).toBe(0);
    expect(reads).toEqual([{ claimId: '', depositor: 'zed' }]);
  });
  it('the planner sees the depositor balance: an unfunded open is refused by the planner, before the store', async () => {
    const r = await rig();
    await r.L.deposit('bob', 5);
    expect(await msgOf(r.L.openBond({ claimId: 'q', amount: 10, depositor: 'bob' }))).toBe('openBond: insufficient balance for the bond');
    expect(await msgOf(r.L.openBond({ claimId: 'q', amount: 10, depositor: 'nobody' }))).toBe('openBond: insufficient balance for the bond');
  });
});

describe('StoreBondLedger: claims, windows and gates, exact', () => {
  it('challengeStatus: unknown bond and unregistered bond are unregistered; boundary instants', async () => {
    const r = await rig();
    expect(await msgOf(r.L.challengeStatus('nope'))).toBe('unregistered: bond nope has no registered claim');
    await r.L.openBond({ claimId: 'plain', amount: 5, depositor: 'alice' });
    expect(await msgOf(r.L.challengeStatus('plain'))).toBe('unregistered: bond plain has no registered claim');
    await r.open();
    expect(await r.L.challengeStatus('b1')).toEqual({ phase: 'open', endsAt: NOW + W, now: NOW });
  });
  it('getBond returns the row, bondStatus the phase, both absent for an unknown bond', async () => {
    const r = await rig();
    expect(await r.L.getBond('b1')).toBeUndefined();
    expect(await r.L.bondStatus('b1')).toBe('none');
    const o = await r.open();
    expect((await r.L.getBond('b1'))?.records).toEqual([o]);
    expect(await r.L.bondStatus('b1')).toBe('open');
  });
  it('openClaim refuses a missing or empty bond_ref, a short window, a bad claim: exact texts', async () => {
    const r = await rig();
    const p = r.p;
    const mk = (bondRef: unknown, windowMs = W) => openOptimistic(p, { bondRef: bondRef as string, claimedR: 0, challengeWindowMs: windowMs, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    const go = (claim: ReturnType<typeof mk>) => msgOf(r.L.openClaim({ claim, pcactn: p, signerPublic: apk, amount: 10, depositor: 'alice' }));
    expect(await go(mk(''))).toBe('invalid_claim: claim has no bond_ref');
    expect(await go(mk(7))).toBe('invalid_claim: claim has no bond_ref');
    expect(await go(mk('s', 29_999))).toBe('invalid_claim: challenge window 29999 ms is below the 30000 ms floor');
    expect(await go(mk('s', 30_000))).toBe('none');
    const bad = { ...mk('t'), claimed_r: 0.5 };
    expect(await go(bad)).toBe('invalid_claim: claim signature does not verify');
  });
  it('a retried open needs the same depositor, amount, window length and claim digest', async () => {
    const r = await rig();
    const o = await r.open(100);
    const again = (patch: { amount?: number; depositor?: string } = {}) => r.L.openClaim({ claim: r.claim, pcactn: r.p, signerPublic: apk, amount: patch.amount ?? 100, depositor: patch.depositor ?? 'alice' });
    expect(await again()).toEqual(o);
    expect(await msgOf(again({ amount: 101 }))).toBe('conflict: openBond: bond b1 already exists (double-open refused)');
    expect(await msgOf(again({ depositor: 'bob' }))).toBe('conflict: openBond: bond b1 already exists (double-open refused)');
    // same bond id, same terms, but a different claim (different digest) conflicts
    const other = openOptimistic(r.p, { bondRef: 'b1', claimedR: 0.5, challengeWindowMs: W, issuedAt: NOW, serverNow: NOW }, A.secretKey);
    expect(await msgOf(r.L.openClaim({ claim: other, pcactn: r.p, signerPublic: apk, amount: 100, depositor: 'alice' }))).toBe('conflict: openBond: bond b1 already exists (double-open refused)');
    // same claim digest, different window length is impossible via one claim; a plain retry of an unregistered bond is checked below
    expect(await r.L.balanceOf('alice')).toBe(900);
  });
  it('a retried plain open matches only the same depositor and amount, and a plain open does not match a registered one', async () => {
    const r = await rig();
    const o = await r.L.openBond({ claimId: 'plain', amount: 5, depositor: 'alice' });
    expect(await r.L.openBond({ claimId: 'plain', amount: 5, depositor: 'alice' })).toEqual(o);
    expect(await msgOf(r.L.openBond({ claimId: 'plain', amount: 6, depositor: 'alice' }))).toBe('conflict: openBond: bond plain already exists (double-open refused)');
    expect(await msgOf(r.L.openBond({ claimId: 'plain', amount: 5, depositor: 'bob' }))).toBe('conflict: openBond: bond plain already exists (double-open refused)');
    await r.open();
    expect(await msgOf(r.L.openBond({ claimId: 'b1', amount: 100, depositor: 'alice' }))).toBe('conflict: openBond: bond b1 already exists (double-open refused)');
  });
  it('release: exact refusal texts and the inclusive boundary', async () => {
    const r = await rig();
    await r.open();
    r.clk.t = NOW + W;
    expect(await msgOf(r.L.release('b1'))).toBe(`window_open: the challenge window of b1 closes at ${NOW + W}`);
    r.clk.t = NOW + W + 1;
    expect((await r.L.release('b1')).action).toBe('release');
    await r.L.openBond({ claimId: 'plain', amount: 5, depositor: 'alice' });
    expect(await msgOf(r.L.release('plain'))).toBe('unregistered: bond plain has no registered claim; use releaseUnregistered for a counter-bond');
    const r2 = await rig();
    await r2.open();
    expect(await msgOf(r2.L.releaseUnregistered('b1'))).toBe('conflict: bond b1 backs a registered claim; use release');
  });
  it('slashes: gate texts, the inclusive window end, and the claim binding', async () => {
    const r = await rig({ verb: 'exfiltrate' });
    await r.open(250);
    const di = decideInput(r.p);
    const proof = fileFraudProof({ claim: r.claim, pcactn: r.p, grant: GRANT, actualDecision: decide(di), decideInput: di })!;
    const s = { claimId: 'b1', claim: r.claim, fraudProof: proof, grant: GRANT, openSnapshot: di, treasury: 'treasury' };
    const other = { ...r.claim, claimed_r: 0.5 };
    expect(await msgOf(r.L.slashBond({ ...s, claim: other }))).toBe('claim_mismatch: the claim is not the one registered for b1');
    expect(await msgOf(r.L.slashBondOnRevocation({ claimId: 'b1', claim: other, revokedCapId: 'c', treasury: 't' }))).toBe('claim_mismatch: the claim is not the one registered for b1');
    r.clk.t = NOW + W + 1;
    expect(await msgOf(r.L.slashBond(s))).toBe(`window_closed: the challenge window of b1 closed at ${NOW + W}`);
    r.clk.t = NOW + W; // the last instant a challenge is accepted
    expect((await r.L.slashBond(s)).action).toBe('slash');
  });
  it('a challenger slash of an unregistered bond names the bond; revocation slash of an unregistered bond is allowed', async () => {
    const r = await rig({ verb: 'exfiltrate' });
    await r.L.openBond({ claimId: 'b1', amount: 20, depositor: 'alice' });
    const di = decideInput(r.p);
    const proof = fileFraudProof({ claim: r.claim, pcactn: r.p, grant: GRANT, actualDecision: decide(di), decideInput: di })!;
    expect(await msgOf(r.L.slashBond({ claimId: 'b1', claim: r.claim, fraudProof: proof, grant: GRANT, openSnapshot: di, treasury: 'treasury' }))).toBe('unregistered: bond b1 has no registered claim');
    expect((await r.L.slashBondOnRevocation({ claimId: 'b1', claim: r.claim, revokedCapId: 'c', treasury: 'treasury' })).action).toBe('slash');
  });
  it('a retry after settlement returns the stored record even for a different bond view', async () => {
    const r = await rig();
    await r.open();
    r.clk.t = NOW + W + 1;
    const a = await r.L.release('b1');
    expect(await r.L.release('b1')).toEqual(a);
  });
});
