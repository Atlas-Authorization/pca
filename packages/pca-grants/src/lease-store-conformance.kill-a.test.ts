import { describe, expect, it } from 'vitest';
import { memoryLeaseKv, type LeaseKv } from './lease';
import { runLeaseStoreConformance, type LeaseStoreKit } from './lease-store-conformance';

interface Rev { target: string; value: string; sig: string; revoked_at: number }
interface Doc { leases: Record<string, { current: Record<string, unknown>; history: unknown[] }>; revocations: Rev[] }
const META = 'lease/meta';
const isDoc = (x: unknown): x is Doc => typeof x === 'object' && x !== null && 'leases' in x && 'revocations' in x;
const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const PASSED_ALL = ['spread', 'atomic update', 'independent leases', 'revocation placement', 'shard count is pinned', 'state survives a restart', 'pruning bounds revocations'];

async function messageOf(kit: LeaseStoreKit): Promise<string> {
  try {
    await runLeaseStoreConformance(kit);
  } catch (e) {
    return (e as Error).message;
  }
  throw new Error('the kit accepted a faulty store');
}
const prefix = 'lease store conformance: ';

/** A store that rewrites every shard document it persists. */
const rewriting = (tf: (doc: Doc) => Doc): LeaseStoreKit => ({
  open: () => {
    const real = memoryLeaseKv();
    return {
      get: (k) => real.get(k),
      update: (k, fn) =>
        real.update(k, (prev) => {
          const out = fn(prev);
          return k !== META && isDoc(out) ? tf(clone(out)) : out;
        }),
    };
  },
});

describe('lease store conformance kit: healthy stores', () => {
  it('passes on the in-memory store for several shard counts, with and without a restart check', async () => {
    for (const shards of [undefined, 5, 8, 32]) {
      expect(await runLeaseStoreConformance({ open: () => memoryLeaseKv(), reopen: (kv) => kv, ...(shards ? { shards } : {}) }), String(shards)).toEqual(PASSED_ALL);
    }
    expect(await runLeaseStoreConformance({ open: () => memoryLeaseKv() })).toEqual(PASSED_ALL.filter((n) => n !== 'state survives a restart'));
  });
});

describe('lease store conformance kit: spread', () => {
  it('rejects a shard count that spreads badly, naming the distribution', async () => {
    expect(await messageOf({ open: () => memoryLeaseKv(), shards: 1 })).toBe(`${prefix}spread: 256 leases landed [256]`);
    expect(await messageOf({ open: () => memoryLeaseKv(), shards: 4 })).toMatch(/^lease store conformance: spread: 256 leases landed \[[\d,]+\]$/);
    expect(await messageOf({ open: () => memoryLeaseKv(), shards: 400 })).toMatch(/^lease store conformance: spread: 256 leases landed \[[\d,]+\]$/);
  });
  it('rejects a store that refuses to take leases', async () => {
    const dead: LeaseKv = { get: async () => undefined, update: async () => { throw new Error('down'); } };
    expect(await messageOf({ open: () => dead })).toBe(`${prefix}spread: issue lease-0: got false, want true`);
  });
  it('rejects a store that accepts leases but cannot read them back', async () => {
    const real = memoryLeaseKv();
    expect(await messageOf({ open: () => ({ get: async () => undefined, update: real.update }) })).toBe(`${prefix}spread: lease-0 not found after issue`);
  });
});

describe('lease store conformance kit: atomic update', () => {
  it('rejects a store whose updates are not atomic', async () => {
    const lost = (): LeaseKv => {
      const real = memoryLeaseKv();
      return {
        get: (k) => real.get(k),
        update: async (k, fn) => {
          const prev = await real.get(k);
          await Promise.resolve();
          return real.update(k, () => fn(prev));
        },
      };
    };
    expect(await messageOf({ open: lost })).toMatch(/^lease store conformance: atomic: one winner: got \d+, want 1$/);
  });
  it('rejects a store where the losing writers are not told they forked', async () => {
    const busy = (): LeaseKv => {
      const real = memoryLeaseKv();
      const active = new Set<string>();
      return {
        get: (k) => real.get(k),
        update: async (k, fn) => {
          if (active.has(k)) throw new Error('busy');
          active.add(k);
          try {
            await Promise.resolve();
            return await real.update(k, fn);
          } finally {
            active.delete(k);
          }
        },
      };
    };
    expect(await messageOf({ open: busy })).toBe(`${prefix}atomic: the rest are forks: got 0, want 7`);
  });
  it('rejects a store that loses the renewal ledger', async () => {
    const noHistory = (): LeaseKv => {
      const real = memoryLeaseKv();
      return {
        update: (k, fn) => real.update(k, fn),
        get: async (k) => {
          const d = await real.get(k);
          if (!isDoc(d)) return d;
          const c = clone(d);
          for (const s of Object.values(c.leases)) s.history = [];
          return c;
        },
      };
    };
    expect(await messageOf({ open: noHistory })).toBe(`${prefix}atomic: ledger length: got [], want [1,2]`);
  });
});

describe('lease store conformance kit: independence', () => {
  it('rejects a store where unrelated leases interfere with each other', async () => {
    const crossKey = (): LeaseKv => {
      const real = memoryLeaseKv();
      const active = new Map<string, number>();
      const tail = new Map<string, Promise<unknown>>();
      return {
        get: (k) => real.get(k),
        update: async (k, fn) => {
          for (const [other, n] of active) if (other !== k && n > 0) throw new Error('interference');
          active.set(k, (active.get(k) ?? 0) + 1);
          const run = (tail.get(k) ?? Promise.resolve()).then(() => real.update(k, fn));
          tail.set(k, run.catch(() => undefined));
          try {
            return await run;
          } finally {
            active.set(k, (active.get(k) ?? 1) - 1);
          }
        },
      };
    };
    expect(await messageOf({ open: crossKey })).toBe(`${prefix}independence: got false, want true`);
  });
  it('rejects a store that refuses to persist the renewals of some leases', async () => {
    const kit = rewriting((d) => {
      if (Object.entries(d.leases).some(([id, s]) => id.startsWith('ind-') && s.history.length > 1)) throw new Error('refused');
      return d;
    });
    expect(await messageOf(kit)).toBe(`${prefix}independence: got false, want true`);
  });
});

describe('lease store conformance kit: revocation placement', () => {
  it('rejects a store that does not persist revocations', async () => {
    expect(await messageOf(rewriting((d) => ({ ...d, revocations: [] })))).toBe(`${prefix}lease revocation lands in exactly one shard: got 0, want 1`);
  });
  it('rejects a store that keeps lease revocations but loses prefix ones', async () => {
    expect(await messageOf(rewriting((d) => ({ ...d, revocations: d.revocations.filter((r) => r.target === 'lease') })))).toBe(`${prefix}prefix revocation in every shard: shard 0 lacks it`);
  });
  it('rejects a store that stores a prefix revocation twice', async () => {
    const kit = rewriting((d) => {
      const seen = new Set<string>();
      const out: Rev[] = [];
      for (const r of d.revocations) {
        if (seen.has(r.sig)) continue;
        seen.add(r.sig);
        out.push(r, ...(r.target === 'prefix' ? [r] : []));
      }
      return { ...d, revocations: out };
    });
    expect(await messageOf(kit)).toBe(`${prefix}no duplicate in shard 0: got 2, want 1`);
  });
  it('rejects a store where a revoked lease stays alive', async () => {
    const kit = rewriting((d) => ({ ...d, revocations: d.revocations.map((r) => (r.target === 'lease' ? { ...r, value: `x-${r.value}` } : r)) }));
    expect(await messageOf(kit)).toBe(`${prefix}revoked lease is dead: got "allow", want "deny"`);
  });
  it('rejects a store where prefix-revoked leases stay alive', async () => {
    const kit = rewriting((d) => ({ ...d, revocations: d.revocations.map((r) => (r.target === 'prefix' ? { ...r, value: `x-${r.value}` } : r)) }));
    expect(await messageOf(kit)).toBe(`${prefix}check rv-0: got "allow", want "deny"`);
  });
  it('rejects a store whose writers cannot see stored revocations', async () => {
    const blindWriters = (): LeaseKv => {
      const real = memoryLeaseKv();
      return {
        get: (k) => real.get(k),
        update: (k, fn) => real.update(k, (prev) => fn(isDoc(prev) ? { ...prev, revocations: [] } : prev)),
      };
    };
    expect(await messageOf({ open: blindWriters })).toBe(`${prefix}renewal of rv-0 refused: got true, want false`);
  });
  it('rejects a store where a revocation also kills leases issued after it', async () => {
    const kit = rewriting((d) => ({ ...d, revocations: d.revocations.map((r) => (r.target === 'prefix' ? { ...r, revoked_at: Number.MAX_SAFE_INTEGER } : r)) }));
    expect(await messageOf(kit)).toBe(`${prefix}a lease issued after the revocation is new: got false, want true`);
  });
  it('rejects a store that forgets leases once they are revoked by prefix', async () => {
    const kit = rewriting((d) => {
      const prefixes = d.revocations.filter((r) => r.target === 'prefix').map((r) => r.value);
      const leases = Object.fromEntries(Object.entries(d.leases).filter(([, s]) => !prefixes.some((p) => String(s.current.path) === p || String(s.current.path).startsWith(`${p}/`))));
      return { ...d, leases };
    });
    expect(await messageOf(kit)).toBe(`${prefix}revoke twice is idempotent: got {"ok":true,"revoked":0}, want {"ok":true,"revoked":64}`);
  });
});

describe('lease store conformance kit: restart', () => {
  it('rejects a reopened store that lost everything', async () => {
    expect(await messageOf({ open: () => memoryLeaseKv(), reopen: () => memoryLeaseKv() })).toBe(`${prefix}restart: renewal ledger: got [], want [1,2]`);
  });
  it('rejects a reopened store that lost its revocations', async () => {
    const reopen = (kv: LeaseKv): LeaseKv => ({
      update: (k, fn) => kv.update(k, fn),
      get: async (k) => {
        const d = await kv.get(k);
        return isDoc(d) ? { ...clone(d), revocations: [] } : d;
      },
    });
    expect(await messageOf({ open: () => memoryLeaseKv(), reopen })).toBe(`${prefix}restart: revocation kept: got 0, want 1`);
  });
  it('rejects a reopened store that resurrects a superseded record', async () => {
    let first: Record<string, unknown> | undefined;
    const open = (): LeaseKv => {
      const real = memoryLeaseKv();
      return {
        get: (k) => real.get(k),
        update: (k, fn) =>
          real.update(k, (prev) => {
            const out = fn(prev);
            const cur = isDoc(out) ? out.leases.persist?.current : undefined;
            if (cur && cur.seq === 1) first = clone(cur);
            return out;
          }),
      };
    };
    const reopen = (kv: LeaseKv): LeaseKv => ({
      update: (k, fn) => kv.update(k, fn),
      get: async (k) => {
        const d = await kv.get(k);
        if (!isDoc(d) || !d.leases.persist || !first) return d;
        const c = clone(d);
        c.leases.persist!.current = first;
        return c;
      },
    });
    expect(await messageOf({ open, reopen })).toBe(`${prefix}restart: old record still superseded: got "allow", want "deny"`);
  });
});

describe('lease store conformance kit: ceiling and pruning', () => {
  it('rejects a store that drops a revocation before the ceiling passes', async () => {
    expect(await messageOf(rewriting((d) => ({ ...d, revocations: d.revocations.filter((r) => r.value !== 'svc') })))).toBe(`${prefix}kept before the ceiling passes (shard 0): got 0, want 1`);
  });
  it('rejects a store that never prunes', async () => {
    const keepAll = (): LeaseKv => {
      const real = memoryLeaseKv();
      return {
        get: (k) => real.get(k),
        update: (k, fn) =>
          real.update(k, (prev) => {
            const before = prev === undefined ? undefined : clone(prev); // the registry prunes the stored document in place, so snapshot it first
            const out = fn(prev);
            if (k === META || !isDoc(out) || !isDoc(before)) return out;
            const sigs = new Set(out.revocations.map((r) => r.sig));
            return { ...out, revocations: [...out.revocations, ...before.revocations.filter((r) => !sigs.has(r.sig))] };
          }),
      };
    };
    expect(await messageOf({ open: keepAll })).toBe(`${prefix}pruning: shard 0 still holds the expired revocation`);
  });
  it('rejects a store that loses the fresh revocation', async () => {
    expect(await messageOf(rewriting((d) => ({ ...d, revocations: d.revocations.filter((r) => r.value !== 'zzz') })))).toBe(`${prefix}pruning: shard 0 lost the fresh revocation`);
  });
});
