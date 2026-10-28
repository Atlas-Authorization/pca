// Exact outcomes of ledger-store.ts: every error text, every boundary of the transition functions, the retry and catch-up paths.
import { describe, expect, it } from 'vitest';
import { createMemoryDurableKv, type DurableKv } from './durable-state';
import { appendToLedgerDoc, checkpointToLedgerDoc, emptyLedgerDoc, KvLedgerStore, LedgerStoreError, StoredLedger, type LedgerStore } from './ledger-store';
import type { Checkpoint } from './ledger';
import { encodeKey, generateKeyPair } from './keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';

const G = generateKeyPair();
const KEY = 'pca-ledger-store/v1';
const c = (i: number) => `commit-${i}-padding-padding-padding-xx`;
const base = { instanceId: 'i', principal: 'p', guardianSecret: G.secretKey, clock: () => 1000 };
const msg = async (p: Promise<unknown> | (() => unknown)): Promise<string> => {
  try {
    await (typeof p === 'function' ? p() : p);
  } catch (e) {
    return (e as Error).message;
  }
  return 'none';
};
const cp = (size: number, root = `r${size}`): Checkpoint => ({ sth: { instance_id: 'i', principal: 'p', size, root, prev_root: '', timestamp: 1, guardian: 'g', sig: 's' } });
const mk = async (o: { store?: LedgerStore; kv?: DurableKv } = {}) => {
  const kv = o.kv ?? createMemoryDurableKv();
  const kvs = new KvLedgerStore(kv);
  const L = await StoredLedger.open({ ...base, store: o.store ?? kvs });
  return { kv, kvs, L };
};
const rewrite = async (kv: DurableKv, f: (d: any) => void) => {
  const d = structuredClone((await kv.get(KEY)) as any);
  f(d);
  await kv.set(KEY, d);
};

describe('LedgerStoreError', () => {
  it('prefixes the code, names itself and keeps the cause', () => {
    const cause = new Error('x');
    const e = new LedgerStoreError('rollback', 'detail', { cause });
    expect([e.message, e.name, e.code, e.cause]).toEqual(['rollback: detail', 'LedgerStoreError', 'rollback', cause]);
  });
});

describe('appendToLedgerDoc: exact messages and replay boundaries', () => {
  it('validation messages', () => {
    const d = emptyLedgerDoc();
    expect(() => appendToLedgerDoc(d, -1, ['a'])).toThrow('append: expectedSize must be a non-negative safe integer');
    expect(() => appendToLedgerDoc(d, 0, [])).toThrow('append: commits must be a non-empty array of non-empty strings');
  });
  it('a batch that runs past the end of what is stored is a conflict, not a replay', () => {
    const d = emptyLedgerDoc();
    appendToLedgerDoc(d, 0, ['a', 'b']);
    expect(appendToLedgerDoc(d, 1, ['b', 'c'])).toEqual({ outcome: 'conflict', size: 2 });
    expect(appendToLedgerDoc(d, 1, ['b'])).toEqual({ outcome: 'replayed', size: 2 });
    expect(d.commits).toEqual(['a', 'b']);
  });
});

describe('checkpointToLedgerDoc: shape and boundaries', () => {
  const doc = () => {
    const d = emptyLedgerDoc();
    d.commits.push('a', 'b', 'c');
    return d;
  };
  const bad = { outcome: 'conflict', count: 0, reason: 'malformed checkpoint' };
  it('validation message', () => {
    expect(() => checkpointToLedgerDoc(doc(), -1, cp(1))).toThrow('appendCheckpoint: expectedCount must be a non-negative safe integer');
  });
  it('every malformed shape is refused', () => {
    const sth = cp(1).sth;
    for (const x of [null, undefined, {}, { sth: null }, { sth: 'x' }, { sth: { ...sth, size: -1 } }, { sth: { ...sth, size: Number.NaN } }, { sth: { ...sth, size: 1.5 } }, { sth: { ...sth, root: 7 } }, { sth: { ...sth, root: undefined } }]) {
      expect(checkpointToLedgerDoc(doc(), 0, x as never), JSON.stringify(x)).toEqual(bad);
    }
  });
  it('size 0 and a size equal to the log length are accepted; one past is refused', () => {
    expect(checkpointToLedgerDoc(doc(), 0, cp(0))).toEqual({ outcome: 'appended', count: 1 });
    expect(checkpointToLedgerDoc(doc(), 0, cp(3))).toEqual({ outcome: 'appended', count: 1 });
    expect(checkpointToLedgerDoc(doc(), 0, cp(4))).toEqual({ outcome: 'conflict', count: 0, reason: 'the checkpoint is beyond the end of the log' });
  });
});

describe('KvLedgerStore guards and ranges', () => {
  it('constructor needs get and update', () => {
    const kv = createMemoryDurableKv();
    for (const bad of [undefined, {}, { get: kv.get }, { update: kv.update }, { get: 1, update: kv.update }, { get: kv.get, update: 1 }]) {
      expect(() => new KvLedgerStore(bad as never), JSON.stringify(bad)).toThrow('store_missing: KvLedgerStore needs a DurableKv');
    }
  });
  it('decode messages', async () => {
    const kv = createMemoryDurableKv();
    const s = new KvLedgerStore(kv);
    await kv.set(KEY, { v: 1, commits: 'x', checkpoints: [] });
    expect(await msg(s.size())).toBe('store_corrupt: ledger document has the wrong shape');
    await kv.set(KEY, { v: 1, commits: [], checkpoints: [{ sth: 1 }] });
    expect(await msg(s.size())).toBe('store_corrupt: malformed checkpoint entry');
  });
  it('read range messages and boundaries', async () => {
    const s = new KvLedgerStore(createMemoryDurableKv());
    await s.append(0, ['a', 'b']);
    for (const [f, t] of [[-1, 1], [1, 0], [0, 3], [0.5, 1], [0, 1.5], [Number.NaN, 1]] as const) expect(await msg(s.read(f, t)), `${f},${t}`).toBe('read: range is not inside the log');
    expect(await s.read(0, 0)).toEqual([]);
    expect(await s.read(2, 2)).toEqual([]);
    expect(await s.read(0, 2)).toEqual(['a', 'b']);
  });
  it('checkpoints range and slicing', async () => {
    const s = new KvLedgerStore(createMemoryDurableKv());
    await s.append(0, ['a', 'b', 'c']);
    await s.appendCheckpoint(0, cp(1));
    await s.appendCheckpoint(1, cp(2));
    for (const f of [-1, 3, 0.5, Number.NaN]) expect(await msg(s.checkpoints(f)), String(f)).toBe('checkpoints: from is not inside the list');
    expect((await s.checkpoints(1)).map((x) => x.sth.size)).toEqual([2]);
    expect((await s.checkpoints(0)).map((x) => x.sth.size)).toEqual([1, 2]);
    expect(await s.checkpoints(2)).toEqual([]);
    expect((await s.checkpoints()).length).toBe(2);
  });
  it('a replayed or conflicting write does not rewrite the document', async () => {
    const kv = createMemoryDurableKv();
    let writes = 0;
    const counting: DurableKv = { ...kv, get: kv.get, set: kv.set, keys: kv.keys, update: async (k, fn) => kv.update(k, (p) => { const n = fn(p); if (n !== undefined) writes++; return n; }) };
    const s = new KvLedgerStore(counting);
    await s.append(0, ['a']);
    await s.append(0, ['a']);
    await s.append(5, ['z']);
    expect(writes).toBe(1);
    await s.appendCheckpoint(0, cp(1));
    await s.appendCheckpoint(0, cp(1));
    await s.appendCheckpoint(0, cp(9));
    expect(writes).toBe(2);
  });
});

describe('StoredLedger.open guards', () => {
  const store = (o: Record<string, unknown> = {}) => ({ ...new KvLedgerStore(createMemoryDurableKv()), size: async () => 0, read: async () => [], append: async () => ({ outcome: 'appended' as const, size: 1 }), appendCheckpoint: async () => ({ outcome: 'appended' as const, count: 1 }), checkpoints: async () => [], checkpointCount: async () => 0, ...o });
  const missing = 'store_missing: a LedgerStore is required (there is no in-memory default)';
  it('each missing store method or option is refused with its text', async () => {
    expect(await msg(StoredLedger.open(null as never))).toBe(missing);
    expect(await msg(StoredLedger.open({ ...base } as never))).toBe(missing);
    for (const m of ['append', 'read', 'appendCheckpoint']) expect(await msg(StoredLedger.open({ ...base, store: store({ [m]: undefined }) } as never)), m).toBe(missing);
    expect(await msg(StoredLedger.open({ ...base, store: store() } as never))).toBe('none');
    expect(await msg(StoredLedger.open({ ...base, guardianSecret: undefined, store: store() } as never))).toBe('guardian_key_missing: a guardian secret key is required');
    expect(await msg(StoredLedger.open({ ...base, guardianSecret: new Uint8Array(0), store: store() }))).toBe('guardian_key_missing: a guardian secret key is required');
  });
  it('an empty store reads size 0 through read(0, 0)', async () => {
    const calls: unknown[] = [];
    const L = await StoredLedger.open({ ...base, store: store({ read: async (...a: unknown[]) => (calls.push(a), []) }) });
    expect([L.size, calls]).toEqual([0, [[0, 0]]]);
  });
  it('non-Error failures become store_unavailable with the fallback text and the cause', async () => {
    const e: any = await StoredLedger.open({ ...base, store: store({ size: async () => Promise.reject('boom') }) }).catch((x) => x);
    expect([e.message, e.code, e.cause]).toEqual(['store_unavailable: store failed', 'store_unavailable', 'boom']);
    const e2: any = await StoredLedger.open({ ...base, store: store({ size: async () => Promise.reject(new Error('disk')) }) }).catch((x) => x);
    expect([e2.message, e2.cause?.message]).toEqual(['store_unavailable: disk', 'disk']);
  });
});

describe('StoredLedger.open: checkpoint verification texts', () => {
  const seeded = async () => {
    const r = await mk();
    for (let i = 0; i < 5; i++) await r.L.append(c(i));
    await r.L.checkpoint();
    for (let i = 5; i < 8; i++) await r.L.append(c(i));
    await r.L.checkpoint();
    return r;
  };
  const reopen = (kv: DurableKv) => StoredLedger.open({ ...base, store: new KvLedgerStore(kv) });
  it('rollback text', async () => {
    const r = await seeded();
    await rewrite(r.kv, (d) => d.commits.splice(6));
    expect(await msg(reopen(r.kv))).toBe('rollback: the log has 6 entries but a checkpoint attests 8');
  });
  it('another log: either the instance or the principal differs', async () => {
    for (const f of [(d: any) => (d.checkpoints[0].sth.instance_id = 'other'), (d: any) => (d.checkpoints[0].sth.principal = 'other')]) {
      const r = await seeded();
      await rewrite(r.kv, f);
      expect(await msg(reopen(r.kv))).toBe('forged_checkpoint: checkpoint 0 belongs to another log');
    }
  });
  it('tamper text names the checkpoint and its size', async () => {
    const r = await seeded();
    await rewrite(r.kv, (d) => (d.commits[1] = c(99)));
    expect(await msg(reopen(r.kv))).toBe('tamper: the stored entries do not reproduce the root of checkpoint 0 (size 5)');
  });
  it('chain failures carry the index and the reason', async () => {
    const r = await seeded();
    await rewrite(r.kv, (d) => delete d.checkpoints[1].proof);
    expect(await msg(reopen(r.kv))).toBe('forged_checkpoint: checkpoint 1: proof_missing');
    const r2 = await seeded();
    await rewrite(r2.kv, (d) => (d.checkpoints[1].proof.path = []));
    expect(await msg(reopen(r2.kv))).toBe('inconsistent: checkpoint 1: inconsistent');
  });
  it('a checkpoint with a non-integer size does not count toward the attested size', async () => {
    const r = await seeded();
    await rewrite(r.kv, (d) => (d.checkpoints[0].sth.size = 'x'));
    expect(await msg(reopen(r.kv))).not.toMatch(/^rollback/);
  });
});

describe('StoredLedger.append: retry loop and catch-up', () => {
  it('the invalid-commit text', async () => {
    const { L } = await mk();
    expect(await msg(L.append('' as never))).toBe('invalid_commit: a commit must be a non-empty string');
  });
  const conflicting = (kvs: KvLedgerStore, n: number) => {
    let calls = 0;
    const store: LedgerStore = { size: () => kvs.size(), read: (a, b) => kvs.read(a, b), append: async (e, cs) => (++calls <= n ? { outcome: 'conflict', size: e } : kvs.append(e, cs)), checkpointCount: () => kvs.checkpointCount(), checkpoints: (f) => kvs.checkpoints(f), appendCheckpoint: (a, b) => kvs.appendCheckpoint(a, b) };
    return { store, calls: () => calls };
  };
  it('succeeds on the 16th attempt, gives up with conflict after 16', async () => {
    const kvs = new KvLedgerStore(createMemoryDurableKv());
    const ok = conflicting(kvs, 15);
    const L = await StoredLedger.open({ ...base, store: ok.store });
    expect(await L.append(c(0))).toEqual({ index: 0, commit: c(0) });
    expect(ok.calls()).toBe(16);
    const never = conflicting(new KvLedgerStore(createMemoryDurableKv()), 1000);
    const L2 = await StoredLedger.open({ ...base, store: never.store });
    expect(await msg(L2.append(c(0)))).toBe('conflict: the log kept moving; could not append');
    expect(never.calls()).toBe(16);
    expect(L2.size).toBe(0);
  });
  it('another writer first: its entries are picked up once and the commit lands after them', async () => {
    const { kv, kvs, L } = await mk();
    const other = await StoredLedger.open({ ...base, store: new KvLedgerStore(kv) });
    await other.append(c(0));
    await other.append(c(1));
    expect(await L.append(c(2))).toEqual({ index: 2, commit: c(2) });
    expect(L.commits()).toEqual([c(0), c(1), c(2)]);
    expect(await kvs.size()).toBe(3);
  });
  it('catchUp picks up entries once, is a no-op when nothing changed, and reads exactly the new range', async () => {
    const { kv, L } = await mk();
    const reads: unknown[] = [];
    const spy: LedgerStore = new KvLedgerStore(kv);
    const orig = spy.read.bind(spy);
    spy.read = async (a, b) => (reads.push([a, b]), orig(a, b));
    const L2 = await StoredLedger.open({ ...base, store: spy });
    reads.length = 0;
    await L.append(c(0));
    await L2.catchUp();
    await L2.catchUp();
    expect(L2.commits()).toEqual([c(0)]);
    expect(reads).toEqual([[0, 1], [1, 1]]);
  });
  it('catchUp picks up checkpoints another writer made and re-verifies them', async () => {
    const { kv, L } = await mk();
    const L2 = await StoredLedger.open({ ...base, store: new KvLedgerStore(kv) });
    for (let i = 0; i < 3; i++) await L.append(c(i));
    const sth = await L.checkpoint();
    await L2.catchUp();
    expect(L2.latestCheckpoint()).toEqual(sth);
    expect(L2.checkpointChain()).toHaveLength(1);
    await L.append(c(3));
    await L.checkpoint();
    await rewrite(kv, (d) => (d.checkpoints[1].sth.principal = 'other')); // the re-verification inside catchUp must notice
    expect(await msg(L2.catchUp())).toBe('forged_checkpoint: checkpoint 1 belongs to another log');
  });
  it('catchUp: a shrunk store is a rollback with both sizes', async () => {
    const { kv, L } = await mk();
    for (let i = 0; i < 3; i++) await L.append(c(i));
    await rewrite(kv, (d) => d.commits.splice(1));
    expect(await msg(L.catchUp())).toBe('rollback: the store shrank from 3 to 1 entries');
  });
});

describe('StoredLedger.checkpoint', () => {
  it('an unchanged head returns the existing checkpoint and writes nothing', async () => {
    const { kv, L } = await mk();
    await L.append(c(0));
    const a = await L.checkpoint();
    let writes = 0;
    const orig = kv.update.bind(kv);
    kv.update = async (k, f) => (writes++, orig(k, f));
    expect(await L.checkpoint()).toEqual(a);
    expect(writes).toBe(0);
  });
  it('an empty log checkpoints at size 0 (nothing to read)', async () => {
    const { L } = await mk();
    expect((await L.checkpoint()).size).toBe(0);
  });
  it('refuses to sign over entries that differ in length or in content', async () => {
    const t = 'tamper: the stored entries no longer match this handle; refusing to sign a checkpoint over them';
    const a = await mk();
    for (let i = 0; i < 2; i++) await a.L.append(c(i));
    const orig = a.kvs.read.bind(a.kvs);
    const shortStore: LedgerStore = { ...a.kvs, size: () => a.kvs.size(), read: async (f, to) => (await orig(f, to)).slice(0, -1), append: (x, y) => a.kvs.append(x, y), checkpointCount: () => a.kvs.checkpointCount(), checkpoints: (f) => a.kvs.checkpoints(f), appendCheckpoint: (x, y) => a.kvs.appendCheckpoint(x, y) };
    const L = await StoredLedger.open({ ...base, store: a.kvs });
    (L as any).opts.store = shortStore;
    (L as any).catchUpLocked = async () => undefined;
    expect(await msg(L.checkpoint())).toBe(t);
    const b = await mk();
    for (let i = 0; i < 2; i++) await b.L.append(c(i));
    await rewrite(b.kv, (d) => (d.commits[1] = c(50)));
    expect(await msg(b.L.checkpoint())).toBe(t);
    // a read failure while comparing is store_unavailable
    const c2 = await mk();
    await c2.L.append(c(0));
    (c2.L as any).opts.store = { ...c2.kvs, size: () => c2.kvs.size(), read: async () => Promise.reject(new Error('gone')), append: () => 0, checkpointCount: () => 0, checkpoints: async () => [], appendCheckpoint: () => 0 };
    (c2.L as any).catchUpLocked = async () => undefined;
    expect(await msg(c2.L.checkpoint())).toBe('store_unavailable: gone');
  });
  it('clock_invalid for a non-number and for NaN, with its text; nothing is stored', async () => {
    for (const bad of ['now', Number.NaN, Infinity]) {
      const kv = createMemoryDurableKv();
      const L = await StoredLedger.open({ ...base, clock: () => bad as never, store: new KvLedgerStore(kv) });
      await L.append(c(0));
      expect(await msg(L.checkpoint()), String(bad)).toBe('clock_invalid: the clock returned a non-finite time');
      expect(await new KvLedgerStore(kv).checkpointCount()).toBe(0);
    }
  });
  it('a head that is not consistent with the previous checkpoint is refused as inconsistent, naming it', async () => {
    const { L } = await mk();
    for (let i = 0; i < 2; i++) await L.append(c(i));
    await L.checkpoint();
    await L.append(c(2));
    (L as any).log.consistencyProof = () => ({ oldSize: 2, newSize: 3, path: [] });
    expect(await msg(L.checkpoint())).toBe('inconsistent: the new head is not consistent with checkpoint 0');
  });
  it('a store that conflicts or fails on appendCheckpoint', async () => {
    const { kvs, L } = await mk();
    await L.append(c(0));
    (L as any).opts.store = { size: () => kvs.size(), read: (a: number, b: number) => kvs.read(a, b), append: (a: number, b: string[]) => kvs.append(a, b), checkpointCount: () => kvs.checkpointCount(), checkpoints: (f: number) => kvs.checkpoints(f), appendCheckpoint: async () => ({ outcome: 'conflict', count: 0, reason: 'busy' }) };
    expect(await msg(L.checkpoint())).toBe('conflict: busy');
    expect(L.checkpointChain()).toEqual([]);
    (L as any).opts.store.appendCheckpoint = async () => Promise.reject(new Error('io'));
    expect(await msg(L.checkpoint())).toBe('store_unavailable: io');
  });
  it('a replayed appendCheckpoint (lost acknowledgement) is accepted', async () => {
    const { kvs, L } = await mk();
    await L.append(c(0));
    (L as any).opts.store = { size: () => kvs.size(), read: (a: number, b: number) => kvs.read(a, b), append: (a: number, b: string[]) => kvs.append(a, b), checkpointCount: () => kvs.checkpointCount(), checkpoints: (f: number) => kvs.checkpoints(f), appendCheckpoint: async () => ({ outcome: 'replayed', count: 1 }) };
    const s = await L.checkpoint();
    expect(L.latestCheckpoint()).toEqual(s);
  });
});

describe('StoredLedger.append: store outcomes', () => {
  it('a replayed outcome is a success; a store failure is store_unavailable and leaves the handle unchanged', async () => {
    const { kvs, L } = await mk();
    (L as any).opts.store = { ...kvs, size: () => kvs.size(), read: (a: number, b: number) => kvs.read(a, b), append: async () => ({ outcome: 'replayed', size: 1 }), checkpointCount: () => kvs.checkpointCount(), checkpoints: (f: number) => kvs.checkpoints(f), appendCheckpoint: (a: number, b: Checkpoint) => kvs.appendCheckpoint(a, b) };
    expect(await L.append(c(0))).toEqual({ index: 0, commit: c(0) });
    expect(L.size).toBe(1);
    (L as any).opts.store.append = async () => Promise.reject(new Error('io'));
    expect(await msg(L.append(c(1)))).toBe('store_unavailable: io');
    expect(L.size).toBe(1);
  });
});

describe('StoredLedger: guardian getter and PQ pin texts', () => {
  it('exposes the guardian public key', async () => {
    const { L } = await mk();
    expect(L.guardian).toBe(encodeKey(G.publicKey));
  });
  it('pin_missing text; forged_checkpoint text on a mismatching pin', async () => {
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(3));
    const suite = { alg: 'hybrid-ed25519-ml-dsa-65' as const, mlDsa: ml };
    const kv = createMemoryDurableKv();
    expect(await msg(StoredLedger.open({ ...base, suite, store: new KvLedgerStore(kv) }))).toBe('pin_missing: a post-quantum or hybrid checkpoint suite needs a PQ pin for the guardian (and a known suite name)');
    const other = mlDsa65Keygen(new Uint8Array(32).fill(4));
    const L = await StoredLedger.open({ ...base, suite, pin: { pqPins: { [encodeKey(G.publicKey)]: encodeMlDsaPublicKey(other.publicKey) } }, store: new KvLedgerStore(kv) });
    await L.append(c(0));
    expect(await msg(L.checkpoint())).toBe('forged_checkpoint: the new checkpoint does not verify under the pinned guardian identity (check the guardian key and the PQ pin)');
  });
});
