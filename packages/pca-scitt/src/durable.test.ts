import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { DurableTransparencyService, ScittLogError, checkScittLogStore, signStatement, verifyConsistencyProof, verifyReceipt, type ScittLogStore } from './index';
import { MemoryScittLogStore, TransparencyService } from './testing';

const ts = generateKeyPairSync('ed25519');
const issuer = generateKeyPairSync('ed25519');
const stmt = (i: number) => signStatement({ n: i }, { alg: 'EdDSA', key: issuer.privateKey, issuer: 'rs' });
const mk = (store: ScittLogStore = new MemoryScittLogStore()) => new DurableTransparencyService({ store, alg: 'EdDSA', key: ts.privateKey, issuer: 'ts' });

describe('the durable log agrees with the RFC 9162 reference at every size', () => {
  it('roots, inclusion receipts and consistency proofs for 1..70 entries', async () => {
    const d = mk();
    const ref = new TransparencyService({ alg: 'EdDSA', key: ts.privateKey, issuer: 'ts' });
    const statements: Uint8Array[] = [];
    const oldRoots: string[] = [];
    for (let i = 0; i < 70; i++) {
      const st = stmt(i);
      statements.push(st);
      const a = await d.register(st);
      const b = ref.register(st);
      expect(a.index).toBe(i);
      expect(a.root).toBe(b.root);
      expect(await d.root()).toBe(ref.root);
      expect(verifyReceipt(a.receipt, st, { verificationKey: ts.publicKey, statementKey: issuer.publicKey })).toBe(true);
      oldRoots.push(a.root);
    }
    for (const idx of [0, 1, 2, 31, 32, 33, 63, 64, 69]) {
      const r = await d.getReceipt(idx);
      expect(r.root).toBe(ref.root);
      expect(verifyReceipt(r.receipt, statements[idx]!, { verificationKey: ts.publicKey, treeRoot: ref.root })).toBe(true);
      expect(verifyReceipt(r.receipt, statements[(idx + 1) % 70]!, { treeRoot: ref.root })).toBe(false);
    }
    for (let m = 1; m <= 70; m++) {
      const c = await d.consistencyProof(m);
      expect(c.oldRoot).toBe(oldRoots[m - 1]);
      expect(c.newRoot).toBe(ref.root);
      expect(verifyConsistencyProof(c.proof, c.oldRoot, c.newRoot)).toBe(true);
      expect(Buffer.from(c.proof).equals(Buffer.from(ref.consistencyProof(m).proof))).toBe(true);
    }
    expect(await d.consistencyProof(70).then((c) => verifyConsistencyProof(c.proof, c.oldRoot, c.newRoot))).toBe(true);
  });
  it('an empty log has the empty-tree root', async () => {
    expect(await mk().root()).toBe(new TransparencyService({ alg: 'EdDSA', key: ts.privateKey }).root);
  });
});

describe('durability: all state is in the store', () => {
  it('a new service over the same store continues the same log (restart)', async () => {
    const store = new MemoryScittLogStore();
    const a = mk(store);
    const sts = Array.from({ length: 10 }, (_, i) => stmt(i));
    for (let i = 0; i < 9; i++) await a.register(sts[i]!);
    const root = await a.root();
    const b = mk(store);
    expect(await b.root()).toBe(root);
    expect(await b.size()).toBe(9);
    const r = await b.register(sts[9]!);
    expect(r.index).toBe(9);
    expect(verifyConsistencyProof((await b.consistencyProof(9)).proof, root, r.root)).toBe(true);
    expect(Buffer.from(await b.getEntry(3)).equals(Buffer.from(sts[3]!))).toBe(true);
  });
  it('concurrent registrations get distinct indexes and a consistent log', async () => {
    const d = mk();
    const rs = await Promise.all(Array.from({ length: 8 }, (_, i) => d.register(stmt(i))));
    expect(rs.map((r) => r.index).sort((x, y) => x - y)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
    expect(await d.size()).toBe(8);
  });
  it('appends and proofs do not read the whole log: store reads stay logarithmic at 1024 entries', async () => {
    const inner = new MemoryScittLogStore();
    let reads = 0;
    const counting: ScittLogStore = {
      size: () => inner.size(),
      getEntry: (i) => inner.getEntry(i),
      getNode: (l, i) => { reads++; return inner.getNode(l, i); },
      append: (n, e, nodes) => inner.append(n, e, nodes),
    };
    const d = mk(counting);
    for (let i = 0; i < 1024; i++) await d.register(stmt(i % 3));
    reads = 0;
    await d.register(stmt(1));
    expect(reads).toBeLessThan(200); // an O(n) implementation reads ~1000+
    reads = 0;
    await d.getReceipt(517);
    expect(reads).toBeLessThan(200);
  });
});

describe('fail closed', () => {
  it('a store is required, with the right shape', () => {
    for (const store of [undefined, null, {}, { size: async () => 0 }]) {
      expect(() => new DurableTransparencyService({ store: store as never, alg: 'EdDSA', key: ts.privateKey })).toThrow(ScittLogError);
    }
    try { new DurableTransparencyService({ store: undefined as never, alg: 'EdDSA', key: ts.privateKey }); } catch (e) { expect((e as ScittLogError).code).toBe('store_required'); }
  });
  it('a malformed or detached statement is refused before it enters the log', async () => {
    const d = mk();
    await expect(d.register(Uint8Array.of(1, 2, 3))).rejects.toMatchObject({ code: 'bad_statement' });
    expect(await d.size()).toBe(0);
  });
  it('a missing subtree hash is store_corrupt, never a wrong root', async () => {
    const inner = new MemoryScittLogStore();
    let broken = false;
    const holes: ScittLogStore = { size: () => inner.size(), getEntry: (i) => inner.getEntry(i), append: (n, e, nodes) => inner.append(n, e, nodes), getNode: async (l, i) => (broken ? undefined : inner.getNode(l, i)) };
    const d = mk(holes);
    await d.register(stmt(0));
    broken = true;
    await expect(d.register(stmt(1))).rejects.toMatchObject({ code: 'store_corrupt' });
    await expect(d.root()).rejects.toMatchObject({ code: 'store_corrupt' });
  });
  it('a store that never accepts the append ends in append_contention', async () => {
    const inner = new MemoryScittLogStore();
    const never: ScittLogStore = { size: () => inner.size(), getEntry: (i) => inner.getEntry(i), getNode: (l, i) => inner.getNode(l, i), append: async () => false };
    await expect(mk(never).register(stmt(0))).rejects.toMatchObject({ code: 'append_contention' });
  });
  it('a store that reports an invalid size is store_corrupt', async () => {
    const bad: ScittLogStore = { size: async () => -1, getEntry: async () => undefined, getNode: async () => undefined, append: async () => true };
    await expect(mk(bad).root()).rejects.toMatchObject({ code: 'store_corrupt' });
  });
  it('out-of-range reads are refused', async () => {
    const d = mk();
    await d.register(stmt(0));
    for (const i of [-1, 1, 1.5, NaN]) {
      await expect(d.getReceipt(i)).rejects.toMatchObject({ code: 'out_of_range' });
      await expect(d.getEntry(i)).rejects.toMatchObject({ code: 'out_of_range' });
    }
    for (const m of [0, 2, -1, 0.5]) await expect(d.consistencyProof(m)).rejects.toMatchObject({ code: 'out_of_range' });
  });
});

describe('checkScittLogStore', () => {
  it('the reference memory store conforms', async () => {
    expect(await checkScittLogStore(() => new MemoryScittLogStore())).toEqual([]);
  });
  it('flags a store without compare-and-set, a non-atomic store and an aliasing store', async () => {
    const noCas = (): ScittLogStore => {
      const inner = new MemoryScittLogStore();
      return { size: () => inner.size(), getEntry: (i) => inner.getEntry(i), getNode: (l, i) => inner.getNode(l, i), append: async (_n, e, nodes) => inner.append(await inner.size(), e, nodes) };
    };
    expect(await checkScittLogStore(noCas)).toContain('append at a stale size was accepted (no compare-and-set)');
    const nonAtomic = (): ScittLogStore => {
      const inner = new MemoryScittLogStore();
      const nodes = new Map<string, Uint8Array>();
      return { size: () => inner.size(), getEntry: (i) => inner.getEntry(i), getNode: async (l, i) => nodes.get(`${l}:${i}`), append: async (n, e, ns) => { for (const x of ns) nodes.set(`${x.level}:${x.index}`, x.hash); return inner.append(n, e, ns); } };
    };
    expect(await checkScittLogStore(nonAtomic)).toContain('a refused append left a node behind (not atomic)');
    const aliasing = (): ScittLogStore => {
      const entries: Uint8Array[] = [];
      return { size: async () => entries.length, getEntry: async (i) => entries[i], getNode: async () => undefined, append: async (n, e) => { if (entries.length !== n) return false; entries.push(e); return true; } };
    };
    expect(await checkScittLogStore(aliasing)).toContain('a returned entry aliases the stored one (mutable)');
  });
  it('reports a store that throws', async () => {
    const r = await checkScittLogStore(() => ({ size: async () => { throw new Error('boom'); } }) as never);
    expect(r).toEqual(['the store threw: boom']);
  });
});
