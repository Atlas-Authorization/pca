import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { CborTag, COSE_SIGN1_TAG, CWT_ISS, HDR_CWT_CLAIMS, decodeCoseSign1, encode } from './core';
import { DurableTransparencyService, ScittLogError, checkScittLogStore, signStatement, type ScittLogStore, type StoredNode } from './index';
import { MemoryScittLogStore } from './testing';

const ts = generateKeyPairSync('ed25519');
const issuer = generateKeyPairSync('ed25519');
const stmt = (i: number) => signStatement({ n: i }, { alg: 'EdDSA', key: issuer.privateKey, issuer: 'rs' });
const mk = (store: ScittLogStore = new MemoryScittLogStore(), iss: string | null = 'ts') =>
  new DurableTransparencyService({ store, alg: 'EdDSA', key: ts.privateKey, ...(iss === null ? {} : { issuer: iss }) });
const wrap = (inner: ScittLogStore, over: Partial<ScittLogStore>): ScittLogStore => ({
  size: () => inner.size(),
  getEntry: (i) => inner.getEntry(i),
  getNode: (l, i) => inner.getNode(l, i),
  append: (n, e, ns) => inner.append(n, e, ns),
  ...over,
});
const rejection = async (p: Promise<unknown>): Promise<ScittLogError> => {
  try {
    await p;
  } catch (e) {
    return e as ScittLogError;
  }
  throw new Error('expected a rejection');
};
const receiptClaims = (receipt: Uint8Array) => decodeCoseSign1(receipt).protectedMap.get(HDR_CWT_CLAIMS);

describe('ScittLogError', () => {
  it('carries its name and code', () => {
    const e = new ScittLogError('out_of_range', 'm');
    expect(e.name).toBe('ScittLogError');
    expect(e.code).toBe('out_of_range');
    expect(e.message).toBe('m');
  });
});

describe('constructor', () => {
  const msg = 'a ScittLogStore (size, getEntry, getNode, append) is required; there is no in-memory default';
  it('refuses a missing options object and a missing store with the exact error', () => {
    for (const o of [undefined, {}]) {
      let err: ScittLogError | undefined;
      try {
        new DurableTransparencyService(o as never);
      } catch (e) {
        err = e as ScittLogError;
      }
      expect(err).toBeInstanceOf(ScittLogError);
      expect(err?.code).toBe('store_required');
      expect(err?.message).toBe(msg);
    }
  });
  it.each(['size', 'getEntry', 'getNode', 'append'] as const)('refuses a store whose %s is not a function', (name) => {
    const store = { ...wrap(new MemoryScittLogStore(), {}), [name]: 'nope' };
    let err: ScittLogError | undefined;
    try {
      new DurableTransparencyService({ store: store as never, alg: 'EdDSA', key: ts.privateKey });
    } catch (e) {
      err = e as ScittLogError;
    }
    expect(err?.code).toBe('store_required');
    expect(err?.message).toBe(msg);
  });
  it('puts the configured issuer in every receipt and omits the claims without one', async () => {
    const a = await mk(new MemoryScittLogStore(), 'ts://one').register(stmt(0));
    const claims = receiptClaims(a.receipt);
    expect(claims).toBeInstanceOf(Map);
    expect((claims as Map<number, unknown>).get(CWT_ISS)).toBe('ts://one');
    const b = await mk(new MemoryScittLogStore(), null).register(stmt(0));
    expect(receiptClaims(b.receipt)).toBeUndefined();
  });
});

describe('size', () => {
  it.each([NaN, 1.5, -1, -0, Infinity])('rejects the invalid size %s with the exact error', async (n) => {
    const bad = wrap(new MemoryScittLogStore(), { size: async () => n });
    const e = await rejection(mk(bad).size());
    expect(e.code).toBe('store_corrupt');
    expect(e.message).toBe('the store reported an invalid size');
  });
  it('accepts 0 and a positive size', async () => {
    expect(await mk(wrap(new MemoryScittLogStore(), { size: async () => 0 })).size()).toBe(0);
    const d = mk();
    await d.register(stmt(0));
    expect(await d.size()).toBe(1);
  });
});

describe('register', () => {
  it('refuses a detached payload with the exact message and appends nothing', async () => {
    const detached = encode(new CborTag(COSE_SIGN1_TAG, [new Uint8Array(0), new Map(), null, new Uint8Array(64)]));
    const store = new MemoryScittLogStore();
    const e = await rejection(mk(store).register(detached));
    expect(e.code).toBe('bad_statement');
    expect(e.message).toBe('cannot register: detached payload');
    expect(await store.size()).toBe(0);
  });
  it('carries the decoder message for a malformed statement', async () => {
    const e = await rejection(mk().register(Uint8Array.of(1, 2, 3)));
    expect(e.code).toBe('bad_statement');
    expect(e.message.startsWith('cannot register: ')).toBe(true);
    expect(e.message.length).toBeGreaterThan('cannot register: '.length);
  });
  it('names the missing or short left sibling by level and index', async () => {
    for (const lie of [undefined, new Uint8Array(31)]) {
      const inner = new MemoryScittLogStore();
      let lying = false;
      const store = wrap(inner, { getNode: async (l, i) => (lying ? lie : inner.getNode(l, i)) });
      const d = mk(store);
      await d.register(stmt(0));
      lying = true;
      const e = await rejection(d.register(stmt(1)));
      expect(e.code).toBe('store_corrupt');
      expect(e.message).toBe('missing subtree hash (0, 0)');
    }
  });
  it('names the missing left sibling at a higher level', async () => {
    const inner = new MemoryScittLogStore();
    const d = mk(inner);
    for (let i = 0; i < 3; i++) await d.register(stmt(i));
    // the 4th leaf completes level 2; hide the level-1 sibling (1-based: level 2 needs node (1, 0))
    const hide = wrap(inner, { getNode: async (l, i) => (l === 1 && i === 0 ? undefined : inner.getNode(l, i)) });
    const e = await rejection(mk(hide).register(stmt(3)));
    expect(e.message).toBe('missing subtree hash (1, 0)');
  });
  it('gives up after exactly 16 refused appends with the exact error', async () => {
    let calls = 0;
    const never = wrap(new MemoryScittLogStore(), { append: async () => { calls++; return false; } });
    const e = await rejection(mk(never).register(stmt(0)));
    expect(e.code).toBe('append_contention');
    expect(e.message).toBe('could not append: the log kept changing');
    expect(calls).toBe(16);
  });
  it('appendAndReceipt returns the signed statement with its registration', async () => {
    const d = mk();
    const r = await d.appendAndReceipt({ k: 1 }, { alg: 'EdDSA', key: issuer.privateKey, issuer: 'rs' });
    expect(r.index).toBe(0);
    expect(Buffer.from(r.statement).equals(Buffer.from(await d.getEntry(0)))).toBe(true);
    expect(r.root).toBe(await d.root());
    expect(r.receipt.length).toBeGreaterThan(0);
    expect(Object.keys(r).sort()).toEqual(['index', 'receipt', 'root', 'statement']);
  });
});

describe('reads', () => {
  it('names the missing or short stored subtree hash in the error', async () => {
    for (const lie of [undefined, new Uint8Array(31)]) {
      const d = mk(wrap(new MemoryScittLogStore(), { size: async () => 1, getNode: async () => lie }));
      const e = await rejection(d.root());
      expect(e.code).toBe('store_corrupt');
      expect(e.message).toBe('missing or malformed subtree hash (0, 0)');
    }
  });
  it('getEntry(0) works, and out-of-range errors carry their exact messages', async () => {
    const d = mk();
    const st = stmt(0);
    await d.register(st);
    expect(Buffer.from(await d.getEntry(0)).equals(Buffer.from(st))).toBe(true);
    expect((await rejection(d.getReceipt(1))).message).toBe('getReceipt: index out of range');
    expect((await rejection(d.getEntry(1))).message).toBe('getEntry: index out of range');
    expect((await rejection(d.getEntry(-1))).message).toBe('getEntry: index out of range');
    expect((await rejection(d.consistencyProof(2))).message).toBe('consistencyProof: size out of range');
    expect((await rejection(d.consistencyProof(0))).message).toBe('consistencyProof: size out of range');
    expect((await rejection(d.getReceipt(0.5))).code).toBe('out_of_range');
  });
  it('a missing entry is store_corrupt with its index', async () => {
    const d = mk(wrap(new MemoryScittLogStore(), { size: async () => 3, getEntry: async () => undefined }));
    const e = await rejection(d.getEntry(2));
    expect(e.code).toBe('store_corrupt');
    expect(e.message).toBe('entry 2 is missing');
  });
});

describe('checkScittLogStore failure messages', () => {
  const strict = (): ScittLogStore => {
    const inner = new MemoryScittLogStore();
    // refuses an append whose node list is empty or whose leaf hash does not match the entry byte
    return wrap(inner, { append: async (n, e, ns) => (ns.length === 0 || ns[0]!.hash[0] !== e[0] ? false : inner.append(n, e, ns)) });
  };
  it('a store that insists on a node list and a matching hash conforms', async () => {
    expect(await checkScittLogStore(strict)).toEqual([]);
  });
  it('flags a non-empty new store', async () => {
    const make = async () => {
      const s = new MemoryScittLogStore();
      await s.append(0, Uint8Array.of(7), [{ level: 0, index: 0, hash: new Uint8Array(32) }]);
      return s;
    };
    expect(await checkScittLogStore(make)).toContain('a new store is not empty');
  });
  it('flags a store that refuses the first append', async () => {
    expect(await checkScittLogStore(() => wrap(new MemoryScittLogStore(), { append: async () => false }))).toContain('append at the right size was refused');
  });
  it('flags a store with no compare-and-set by every consequence', async () => {
    const noCas = (): ScittLogStore => {
      const inner = new MemoryScittLogStore();
      // ignores the expected size and retries at the current one, so every concurrent append eventually wins
      return wrap(inner, { append: async (_n, e, ns) => { for (;;) if (await inner.append(await inner.size(), e, ns)) return true; } });
    };
    const f = await checkScittLogStore(noCas);
    expect(f).toContain('a refused append changed the size');
    expect(f).toContain('a refused append left an entry behind');
    expect(f).toContain('a refused append left a node behind (not atomic)');
    expect(f).toContain('concurrent appends at the same size did not produce exactly one winner');
    expect(f).toContain('the size after a race is not 2');
  });
  it('flags a size that is not 1 after a refused append, on its own', async () => {
    const inner = new MemoryScittLogStore();
    let refused = false;
    const make = (): ScittLogStore =>
      wrap(inner, {
        append: async (n, e, ns) => {
          const ok = await inner.append(n, e, ns);
          if (!ok) refused = true;
          return ok;
        },
        size: async () => ((await inner.size()) === 1 && refused ? 5 : inner.size()),
      });
    const f = await checkScittLogStore(make);
    expect(f).toContain('a refused append changed the size');
    expect(f).not.toContain('a refused append left an entry behind');
  });
  it('flags a leftover entry from a refused append on its own', async () => {
    const make = (): ScittLogStore => {
      const inner = new MemoryScittLogStore();
      return wrap(inner, { getEntry: async (i) => (i === 1 ? Uint8Array.of(1) : inner.getEntry(i)) });
    };
    const f = await checkScittLogStore(make);
    expect(f).toContain('a refused append left an entry behind');
    expect(f).not.toContain('a refused append changed the size');
  });
  it.each([
    ['missing', async () => undefined],
    ['too long', async () => Uint8Array.of(1, 1)],
    ['wrong byte', async () => Uint8Array.of(7)],
  ] as const)('flags a stored entry that is %s when read back', async (_n, read) => {
    const make = (): ScittLogStore => {
      const inner = new MemoryScittLogStore();
      return wrap(inner, { getEntry: async (i) => (i === 0 ? read() : inner.getEntry(i)) });
    };
    const f = await checkScittLogStore(make);
    expect(f).toContain('the stored entry does not read back');
    expect(f.some((x) => x.startsWith('the store threw'))).toBe(false);
  });
  it('flags a store where two racers can both win (and nothing else is wrong with its size)', async () => {
    const make = (): ScittLogStore => {
      const inner = new MemoryScittLogStore();
      let stale = false;
      return wrap(inner, {
        append: async (n, e, ns: readonly StoredNode[]) => {
          if (n === 1 && stale) return true; // second and later racers "win" without storing
          if (n === 1) stale = true;
          return inner.append(n, e, ns);
        },
      });
    };
    const f = await checkScittLogStore(make);
    expect(f).toContain('concurrent appends at the same size did not produce exactly one winner');
    expect(f).not.toContain('the size after a race is not 2');
  });
  it('flags a wrong size after a race on its own', async () => {
    const make = (): ScittLogStore => {
      const inner = new MemoryScittLogStore();
      let raced = false;
      return wrap(inner, {
        append: async (n, e, ns) => {
          const ok = await inner.append(n, e, ns);
          if (n === 1) raced = true;
          return ok;
        },
        size: async () => (raced ? 3 : inner.size()),
      });
    };
    const f = await checkScittLogStore(make);
    expect(f).toContain('the size after a race is not 2');
    expect(f).not.toContain('concurrent appends at the same size did not produce exactly one winner');
  });
});

