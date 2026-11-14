import { describe, expect, it } from 'vitest';
import { memoryLeaseKv, shardOf, type LeaseKv } from './lease';
import { runLeaseStoreConformance } from './lease-store-conformance';

interface Doc { leases: Record<string, unknown>; revocations: unknown[] }
const isDoc = (x: unknown): x is Doc => typeof x === 'object' && x !== null && 'leases' in x && 'revocations' in x;
const prefix = 'lease store conformance: ';

async function messageOf(open: () => LeaseKv): Promise<string> {
  try {
    await runLeaseStoreConformance({ open });
  } catch (e) {
    return (e as Error).message;
  }
  throw new Error('the kit accepted a faulty store');
}

describe('lease store conformance kit: named failures', () => {
  it('names the check when a revocation by lease does not see the stored lease', async () => {
    // Once the lone lease is stored, every later update is handed a shard with no leases in view (the leases themselves are kept).
    const open = (): LeaseKv => {
      const real = memoryLeaseKv();
      let armed = false;
      return {
        get: (k) => real.get(k),
        update: (k, fn) =>
          real.update(k, (prev) => {
            if (armed && isDoc(prev)) {
              const out = fn({ ...prev, leases: {} });
              return isDoc(out) ? { ...out, leases: prev.leases } : out;
            }
            const out = fn(prev);
            if (isDoc(out) && 'lone' in out.leases) armed = true;
            return out;
          }),
      };
    };
    expect(await messageOf(open)).toBe(`${prefix}revoke by lease: got {"ok":true,"revoked":0}, want {"ok":true,"revoked":1}`);
  });

  it('names the shard that lacks the prefix revocation even when it holds another revocation', async () => {
    // The shard of the lone lease (which already holds that lease's own revocation) silently drops every prefix revocation.
    const lone = `lease/16/${shardOf('lone', 16)}`;
    const open = (): LeaseKv => {
      const real = memoryLeaseKv();
      return {
        get: (k) => real.get(k),
        update: (k, fn) =>
          real.update(k, (prev) => {
            const out = fn(prev);
            if (k === lone && isDoc(out)) return { ...out, revocations: out.revocations.filter((r) => (r as { target?: unknown }).target !== 'prefix') };
            return out;
          }),
      };
    };
    expect(await messageOf(open)).toBe(`${prefix}prefix revocation in every shard: shard ${shardOf('lone', 16)} lacks it`);
  });

  it('names the check when a registry opened with another shard count is allowed to write', async () => {
    // The store does not pin the shard count: the second registry is told its count is fine and its writes go through.
    const open = (): LeaseKv => {
      const real = memoryLeaseKv();
      let metaCalls = 0;
      return {
        get: (k) => real.get(k),
        update: async (k, fn) => {
          if (k === 'lease/meta') {
            metaCalls += 1;
            return metaCalls === 1 ? real.update(k, fn) : { v: 1, shards: 32 };
          }
          return real.update(k, fn);
        },
      };
    };
    expect((await messageOf(open)).startsWith(`${prefix}shard mismatch accept: got `)).toBe(true);
  });
});
