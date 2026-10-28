import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createMemoryDurableKv, openDurableState, type DurableKv } from './durable-state';
import { appendToLedgerDoc, checkpointToLedgerDoc, emptyLedgerDoc, KvLedgerStore, LedgerStoreError, StoredLedger, type LedgerStoreErrorCode } from './ledger-store';
import { verifyCheckpointChain, verifyLedgerConsistency, verifyLedgerInclusion, verifyTreeHead, type Checkpoint } from './ledger';
import { b64u, hashCanonicalLenient } from './hash';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';
import { generateKeyPair, encodeKey } from './keys';

const G = generateKeyPair();
const OTHER = generateKeyPair();
const gpk = encodeKey(G.publicKey);
const NOW = 1_700_000_000_000;
const KEY = 'pca-ledger-store/v1';
const c = (i: number): string => b64u(new TextEncoder().encode(`commit-${i}-padding-padding`)).slice(0, 43);

const mk = async (kv: DurableKv = createMemoryDurableKv(), o: { clock?: () => number; secret?: Uint8Array } = {}) => {
  const store = new KvLedgerStore(kv);
  const L = await StoredLedger.open({ store, guardianSecret: o.secret ?? G.secretKey, instanceId: 'inst-1', principal: 'grant-1', clock: o.clock ?? (() => NOW) });
  return { kv, store, L, reopen: () => StoredLedger.open({ store: new KvLedgerStore(kv), guardianSecret: o.secret ?? G.secretKey, instanceId: 'inst-1', principal: 'grant-1', clock: o.clock ?? (() => NOW) }) };
};
async function codeOf(p: Promise<unknown> | (() => unknown)): Promise<LedgerStoreErrorCode | string> {
  try {
    await (typeof p === 'function' ? p() : p);
  } catch (e) {
    return e instanceof LedgerStoreError ? e.code : `plain:${(e as Error).message}`;
  }
  return 'none';
}
const fill = async (L: StoredLedger, from: number, to: number) => {
  for (let i = from; i < to; i++) await L.append(c(i));
};
const docOf = async (kv: DurableKv) => structuredClone((await kv.get(KEY)) as { v: 1; commits: string[]; checkpoints: Checkpoint[] });

describe('StoredLedger: fail closed when a required component is missing', () => {
  it('no store, a non-store or no guardian key refuses to open', async () => {
    const store = new KvLedgerStore(createMemoryDurableKv());
    const base = { instanceId: 'i', principal: 'p' };
    expect(await codeOf(StoredLedger.open({ ...base, guardianSecret: G.secretKey } as never))).toBe('store_missing');
    expect(await codeOf(StoredLedger.open({ ...base, guardianSecret: G.secretKey, store: {} as never }))).toBe('store_missing');
    expect(await codeOf(StoredLedger.open(undefined as never))).toBe('store_missing');
    expect(await codeOf(StoredLedger.open({ ...base, store } as never))).toBe('guardian_key_missing');
    expect(await codeOf(StoredLedger.open({ ...base, store, guardianSecret: new Uint8Array(0) }))).toBe('guardian_key_missing');
    expect(await codeOf(() => new KvLedgerStore(undefined as never))).toBe('store_missing');
  });
  it('a clock that returns a non-finite time refuses to checkpoint and writes nothing', async () => {
    const r = await mk(undefined, { clock: () => Number.NaN });
    await fill(r.L, 0, 2);
    expect(await codeOf(r.L.checkpoint())).toBe('clock_invalid');
    expect(await r.store.checkpointCount()).toBe(0);
  });
  it('a store that fails surfaces as store_unavailable; a write that never persisted leaves the log as it was', async () => {
    const kv = createMemoryDurableKv();
    let fail = false;
    const flaky: DurableKv = { get: (k) => kv.get(k), set: (k, v) => kv.set(k, v), keys: () => kv.keys(), update: (k, fn) => (fail ? Promise.reject(new Error('disk gone')) : kv.update(k, fn)) };
    const r = await mk(flaky);
    await r.L.append(c(0));
    fail = true;
    expect(await codeOf(r.L.append(c(1)))).toBe('store_unavailable');
    expect(r.L.size).toBe(1);
    expect(await r.store.size()).toBe(1);
    fail = false;
    expect(await r.L.append(c(1))).toEqual({ index: 1, commit: c(1) });
  });
  it('a lost acknowledgement (committed, the call failed) is repaired by the retry: one entry, same index', async () => {
    const kv = createMemoryDurableKv();
    let lose = false;
    const flaky: DurableKv = { get: (k) => kv.get(k), set: (k, v) => kv.set(k, v), keys: () => kv.keys(), update: async (k, fn) => { const o = await kv.update(k, fn); if (lose) throw new Error('reset'); return o; } };
    const r = await mk(flaky);
    await r.L.append(c(0));
    lose = true;
    expect(await codeOf(r.L.append(c(1)))).toBe('store_unavailable');
    expect(await r.store.size()).toBe(2); // it DID commit
    lose = false;
    expect(await r.L.append(c(1))).toEqual({ index: 1, commit: c(1) });
    expect(r.L.commits()).toEqual([c(0), c(1)]);
    expect(await r.store.size()).toBe(2);
  });
  it('malformed stored documents are refused, never read as an empty log', async () => {
    for (const d of ['x', { v: 2, commits: [], checkpoints: [] }, { v: 1, commits: 'a', checkpoints: [] }, { v: 1, commits: [''], checkpoints: [] }, { v: 1, commits: [1], checkpoints: [] }, { v: 1, commits: [], checkpoints: [null] }, { v: 1, commits: [], checkpoints: [{ sth: 'x' }] }]) {
      const kv = createMemoryDurableKv();
      await kv.set(KEY, d);
      expect(await codeOf(mk(kv)), JSON.stringify(d)).toBe('store_corrupt');
    }
  });
});

describe('StoredLedger: post-quantum checkpoints need a PQ pin', () => {
  const ml = mlDsa65Keygen(new Uint8Array(32).fill(7));
  const HYBRID = 'hybrid-ed25519-ml-dsa-65' as const;
  const suite = { alg: HYBRID, mlDsa: ml };
  const pins = { pqPins: { [gpk]: encodeMlDsaPublicKey(ml.publicKey) } };
  const open = (kv: DurableKv, o: Record<string, unknown> = {}) => StoredLedger.open({ store: new KvLedgerStore(kv), guardianSecret: G.secretKey, instanceId: 'inst-1', principal: 'grant-1', clock: () => NOW, suite, pin: pins, ...o });

  it('a hybrid-signed chain verifies on reopen and by an auditor with the pin', async () => {
    const kv = createMemoryDurableKv();
    const L = await open(kv);
    await fill(L, 0, 3);
    const a = await L.checkpoint();
    await fill(L, 3, 6);
    const b = await L.checkpoint();
    expect([a.alg, b.alg]).toEqual([HYBRID, HYBRID]);
    expect(verifyCheckpointChain(L.checkpointChain(), gpk, undefined, pins)).toMatchObject({ ok: true });
    expect(verifyCheckpointChain(L.checkpointChain(), gpk)).toEqual({ ok: false, at: 0, reason: 'head' }); // no pin: refused
    expect((await open(kv)).latestCheckpoint()).toEqual(b);
  });
  it('a PQ suite without a pin, or an unknown suite name, refuses to open', async () => {
    const kv = createMemoryDurableKv();
    expect(await codeOf(open(kv, { pin: undefined }))).toBe('pin_missing');
    expect(await codeOf(open(kv, { suite: { alg: 'bogus' }, pin: pins }))).toBe('pin_missing');
    expect(await codeOf(open(kv, { suite: { alg: 'ed25519' }, pin: undefined }))).toBe('none');
  });
  it('a pin that does not match the signing key is refused when signing: nothing is stored', async () => {
    const kv = createMemoryDurableKv();
    const other = mlDsa65Keygen(new Uint8Array(32).fill(9));
    const L = await open(kv, { pin: { pqPins: { [gpk]: encodeMlDsaPublicKey(other.publicKey) } } });
    await fill(L, 0, 2);
    expect(await codeOf(L.checkpoint())).toBe('forged_checkpoint');
    expect(await new KvLedgerStore(kv).checkpointCount()).toBe(0);
    expect((await open(kv)).latestCheckpoint()).toBeUndefined();
  });
});

describe('StoredLedger: append, checkpoint, reopen', () => {
  it('assigns sequential indexes, serves proofs that verify against the head, and rejects an invalid commit', async () => {
    const { L } = await mk();
    expect(await L.append(c(0))).toEqual({ index: 0, commit: c(0) });
    expect(await L.append(c(1))).toEqual({ index: 1, commit: c(1) });
    await fill(L, 2, 7);
    const head = L.head();
    expect(head.size).toBe(7);
    for (let i = 0; i < 7; i++) expect(verifyLedgerInclusion(head.root, L.inclusionProof(i), c(i))).toBe(true);
    for (const bad of ['', 5, null, undefined]) expect(await codeOf(L.append(bad as never))).toBe('invalid_commit');
    expect(L.size).toBe(7);
  });

  it('checkpoints chain: each is signed, prev_root-linked and consistent; reopening restores the same head and chain', async () => {
    let t = NOW;
    const r = await mk(undefined, { clock: () => t++ });
    await fill(r.L, 0, 2);
    const a = await r.L.checkpoint();
    await fill(r.L, 2, 5);
    const b = await r.L.checkpoint();
    await fill(r.L, 5, 9);
    const d = await r.L.checkpoint();
    expect([a.size, b.size, d.size]).toEqual([2, 5, 9]);
    expect([a.prev_root, b.prev_root, d.prev_root]).toEqual(['', a.root, b.root]);
    expect([a.timestamp, b.timestamp, d.timestamp]).toEqual([NOW, NOW + 1, NOW + 2]);
    expect(a).toMatchObject({ instance_id: 'inst-1', principal: 'grant-1', guardian: gpk });
    for (const s of [a, b, d]) expect(verifyTreeHead(s, gpk)).toBe(true);
    expect(await r.L.checkpoint()).toEqual(d); // nothing new: the existing checkpoint
    const chain = r.L.checkpointChain();
    expect(verifyCheckpointChain(chain, gpk)).toEqual({ ok: true, head: d });
    const back = await r.reopen();
    expect(back.head()).toEqual(r.L.head());
    expect(back.checkpointChain()).toEqual(chain);
    expect(back.latestCheckpoint()).toEqual(d);
    expect(back.commits()).toEqual(r.L.commits());
  });

  it('an auditor holding an old checkpoint gets a proof that verifies against the current head', async () => {
    const r = await mk();
    await fill(r.L, 0, 3);
    const old = await r.L.checkpoint();
    await fill(r.L, 3, 11);
    const now = r.L.head();
    expect(verifyLedgerConsistency(old.root, now.root, r.L.consistencyProofFrom(old.size))).toBe(true);
    expect(verifyLedgerConsistency(old.root, now.root, r.L.consistencyProofFrom(old.size - 1))).toBe(false);
  });

  it('two writers on one store never assign an index twice and lose no entry', async () => {
    const r = await mk();
    const other = await r.reopen();
    const results = await Promise.all(Array.from({ length: 10 }, (_, i) => (i % 2 ? r.L : other).append(c(100 + i))));
    expect(new Set(results.map((x) => x.index)).size).toBe(10);
    await r.L.catchUp();
    await other.catchUp();
    expect([...r.L.commits()].sort()).toEqual(Array.from({ length: 10 }, (_, i) => c(100 + i)).sort());
    expect(other.commits()).toEqual(r.L.commits());
    expect(r.L.head()).toEqual(other.head());
  });
});

describe('StoredLedger.open: a store that lies is refused', () => {
  const seeded = async () => {
    const r = await mk();
    await fill(r.L, 0, 3);
    await r.L.checkpoint();
    await fill(r.L, 3, 8);
    await r.L.checkpoint();
    return r;
  };
  const rewrite = async (kv: DurableKv, f: (d: { commits: string[]; checkpoints: Checkpoint[] }) => void) => {
    const d = await docOf(kv);
    f(d);
    await kv.set(KEY, d);
  };

  it('rollback: entries missing after a checkpoint', async () => {
    const r = await seeded();
    await rewrite(r.kv, (d) => d.commits.splice(5));
    expect(await codeOf(r.reopen())).toBe('rollback');
    await rewrite(r.kv, (d) => d.commits.splice(0));
    expect(await codeOf(r.reopen())).toBe('rollback');
  });
  it('tamper: an entry edited, inserted or reordered no longer reproduces a checkpoint root', async () => {
    for (const f of [(d: { commits: string[] }) => (d.commits[1] = c(999)), (d: { commits: string[] }) => d.commits.splice(1, 0, c(998)), (d: { commits: string[] }) => d.commits.reverse(), (d: { commits: string[] }) => (d.commits[7] = c(997))]) {
      const r = await seeded();
      await rewrite(r.kv, f);
      expect(await codeOf(r.reopen())).toMatch(/^(tamper|rollback)$/);
    }
    const r = await seeded();
    await rewrite(r.kv, (d) => (d.commits[1] = c(999)));
    expect(await codeOf(r.reopen())).toBe('tamper');
  });
  it('forged checkpoint: a bad signature, another log, or the wrong guardian pin', async () => {
    const r = await seeded();
    await rewrite(r.kv, (d) => (d.checkpoints[1]!.sth.sig = d.checkpoints[1]!.sth.sig.replace(/^./, (x) => (x === 'A' ? 'B' : 'A'))));
    expect(await codeOf(r.reopen())).toBe('forged_checkpoint');
    const r2 = await seeded();
    await rewrite(r2.kv, (d) => (d.checkpoints[0]!.sth.principal = 'grant-2'));
    expect(await codeOf(r2.reopen())).toBe('forged_checkpoint');
    const r3 = await seeded();
    expect(await codeOf(mk(r3.kv, { secret: OTHER.secretKey }))).toBe('forged_checkpoint');
  });
  it('inconsistent: a chain whose boundary proof does not connect the two checkpoints', async () => {
    const r = await seeded();
    await rewrite(r.kv, (d) => (d.checkpoints[1]!.proof!.path[0] = d.checkpoints[1]!.proof!.path[0]!.replace(/^./, (x) => (x === 'A' ? 'B' : 'A'))));
    expect(await codeOf(r.reopen())).toBe('inconsistent');
    const r2 = await seeded();
    await rewrite(r2.kv, (d) => delete d.checkpoints[1]!.proof);
    expect(await codeOf(r2.reopen())).toBe('forged_checkpoint'); // proof_missing is reported as a forged chain
  });
  it('an honest store opens and a store with no checkpoint yet opens too', async () => {
    const r = await seeded();
    expect((await r.reopen()).size).toBe(8);
    const fresh = await mk();
    await fresh.L.append(c(0));
    expect((await fresh.reopen()).latestCheckpoint()).toBeUndefined();
  });
  it('checkpoint() refuses to sign over entries another writer rewrote since this handle loaded them', async () => {
    const r = await seeded();
    await rewrite(r.kv, (d) => (d.commits[2] = c(996)));
    expect(await codeOf(r.L.checkpoint())).toBe('tamper');
    expect(await r.store.checkpointCount()).toBe(2);
  });
  it('a store that shrinks under a running handle is a rollback', async () => {
    const r = await seeded();
    await rewrite(r.kv, (d) => d.commits.splice(6));
    expect(await codeOf(r.L.catchUp())).toBe('rollback');
  });
});

describe('the store transition functions: exact outcomes', () => {
  it('append: CAS on the length, all or none, replay of the same batch, empty and invalid input refused', () => {
    const d = emptyLedgerDoc();
    expect(appendToLedgerDoc(d, 0, ['a', 'b'])).toEqual({ outcome: 'appended', size: 2 });
    expect(appendToLedgerDoc(d, 0, ['a', 'b'])).toEqual({ outcome: 'replayed', size: 2 });
    expect(appendToLedgerDoc(d, 0, ['a'])).toEqual({ outcome: 'replayed', size: 2 }); // a prefix of what is stored there
    expect(appendToLedgerDoc(d, 1, ['b'])).toEqual({ outcome: 'replayed', size: 2 });
    expect(appendToLedgerDoc(d, 0, ['a', 'x'])).toEqual({ outcome: 'conflict', size: 2 });
    expect(appendToLedgerDoc(d, 1, ['b', 'c'])).toEqual({ outcome: 'conflict', size: 2 }); // runs past the end: not the same batch
    expect(appendToLedgerDoc(d, 5, ['z'])).toEqual({ outcome: 'conflict', size: 2 });
    expect(d.commits).toEqual(['a', 'b']);
    for (const bad of [[], [''], ['ok', 3 as never], 'x' as never]) expect(() => appendToLedgerDoc(d, 2, bad)).toThrow(RangeError);
    for (const bad of [-1, 1.5, Number.NaN, 2 ** 53]) expect(() => appendToLedgerDoc(d, bad, ['q'])).toThrow(RangeError);
    expect(d.commits).toEqual(['a', 'b']);
  });
  it('checkpoint: CAS on the count, within the log, never backwards, replay of the same checkpoint', () => {
    const d = emptyLedgerDoc();
    d.commits.push('a', 'b', 'c');
    const cp = (size: number, root: string): Checkpoint => ({ sth: { instance_id: 'i', principal: 'p', size, root, prev_root: '', timestamp: 1, guardian: 'g', sig: 's' } });
    expect(checkpointToLedgerDoc(d, 0, cp(4, 'r4'))).toEqual({ outcome: 'conflict', count: 0, reason: 'the checkpoint is beyond the end of the log' });
    expect(checkpointToLedgerDoc(d, 0, cp(2, 'r2'))).toEqual({ outcome: 'appended', count: 1 });
    expect(checkpointToLedgerDoc(d, 0, cp(2, 'r2'))).toEqual({ outcome: 'replayed', count: 1 });
    expect(checkpointToLedgerDoc(d, 0, cp(3, 'r3'))).toEqual({ outcome: 'conflict', count: 1, reason: 'another checkpoint holds that position' });
    expect(checkpointToLedgerDoc(d, 2, cp(3, 'r3'))).toEqual({ outcome: 'conflict', count: 1, reason: 'the checkpoint position is ahead of the log' });
    expect(checkpointToLedgerDoc(d, 1, cp(1, 'r1'))).toEqual({ outcome: 'conflict', count: 1, reason: 'the checkpoint does not extend the previous one' });
    expect(checkpointToLedgerDoc(d, 1, cp(2, 'other'))).toEqual({ outcome: 'conflict', count: 1, reason: 'the checkpoint does not extend the previous one' });
    expect(checkpointToLedgerDoc(d, 1, cp(2, 'r2'))).toEqual({ outcome: 'appended', count: 2 });
    expect(checkpointToLedgerDoc(d, 2, null as never)).toEqual({ outcome: 'conflict', count: 2, reason: 'malformed checkpoint' });
    expect(checkpointToLedgerDoc(d, 2, { sth: { ...cp(3, 'r3').sth, size: -1 } })).toEqual({ outcome: 'conflict', count: 2, reason: 'malformed checkpoint' });
    expect(() => checkpointToLedgerDoc(d, -1, cp(3, 'r3'))).toThrow(RangeError);
    expect(d.checkpoints).toHaveLength(2);
    expect(hashCanonicalLenient(d.checkpoints[0])).not.toBe('');
  });
  it('KvLedgerStore reads: ranges are validated and snapshots are copies', async () => {
    const s = new KvLedgerStore(createMemoryDurableKv());
    await s.append(0, ['a', 'b', 'c']);
    expect(await s.read(1, 3)).toEqual(['b', 'c']);
    expect(await s.read(3, 3)).toEqual([]);
    for (const [f, t] of [[-1, 1], [2, 1], [0, 4], [0.5, 1]] as const) await expect(s.read(f, t)).rejects.toThrow(RangeError);
    await expect(s.checkpoints(1)).rejects.toThrow(RangeError);
    (await s.read(0, 3))[0] = 'mutated';
    expect(await s.read(0, 1)).toEqual(['a']);
  });
});

// ---- crash recovery on the durable-state store ------------------------------------------------------------------------

const PKG = resolve(__dirname, '..');
const WORKER = join(__dirname, 'test-support', 'ledger-crash-worker.ts');
const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), 'pca-ledger-'));
  dirs.push(d);
  return d;
};
const killed = (dir: string, crashAt: string, mode: string) =>
  new Promise<{ signal: NodeJS.Signals | null; out: string }>((res) => {
    const ch = spawn(process.execPath, ['--import', 'tsx', WORKER, dir, crashAt, b64u(G.secretKey), mode, String(NOW + 5)], { cwd: PKG });
    let out = '';
    ch.stdout.on('data', (b: Buffer) => (out += b.toString()));
    ch.on('close', (_c, signal) => res({ signal, out }));
  });

describe('crash recovery (durable-state store)', () => {
  it('a process that dies after an acknowledged append or checkpoint comes back with exactly that state, verified', async () => {
    const dir = tmp();
    const r = await mk(await openDurableState({ dir }));
    await fill(r.L, 0, 4);
    const sth = await r.L.checkpoint();
    await fill(r.L, 4, 6);
    const back = await StoredLedger.open({ store: new KvLedgerStore(await openDurableState({ dir })), guardianSecret: G.secretKey, instanceId: 'inst-1', principal: 'grant-1' });
    expect(back.size).toBe(6);
    expect(back.latestCheckpoint()).toEqual(sth);
    expect(back.head()).toEqual(r.L.head());
  });

  for (const [mode, crashAt, applied] of [['append', 'after-temp-write', false], ['append', 'after-journal-rename', true], ['checkpoint', 'after-temp-write', false], ['checkpoint', 'after-journal-rename', true]] as const) {
    it(`SIGKILL during ${mode} (${crashAt}): the write is ${applied ? 'fully there' : 'wholly absent'} after recovery, the log still verifies, and retrying finishes it`, async () => {
      const dir = tmp();
      const r = await mk(await openDurableState({ dir }));
      await fill(r.L, 0, 3);
      if (mode === 'append') await r.L.checkpoint();
      const run = await killed(dir, crashAt, mode);
      expect(run.signal).toBe('SIGKILL');
      expect(run.out).toBe('');
      const L = await StoredLedger.open({ store: new KvLedgerStore(await openDurableState({ dir })), guardianSecret: G.secretKey, instanceId: 'inst-1', principal: 'grant-1', clock: () => NOW + 9 });
      if (mode === 'append') {
        expect([L.size, L.commits().includes('crash-commit')]).toEqual(applied ? [4, true] : [3, false]);
        // a restarted caller does not know its old position: it looks for the entry, and appends only if it is absent
        if (!applied) expect(await L.append('crash-commit')).toEqual({ index: 3, commit: 'crash-commit' });
        expect(L.commits()).toEqual([c(0), c(1), c(2), 'crash-commit']);
        expect(L.latestCheckpoint()!.size).toBe(3);
      } else {
        expect(L.checkpointChain().length).toBe(applied ? 1 : 0);
        const sth = await L.checkpoint();
        expect(sth.size).toBe(3);
        expect(verifyCheckpointChain(L.checkpointChain(), gpk)).toEqual({ ok: true, head: sth });
      }
    }, 60_000);
  }
});
