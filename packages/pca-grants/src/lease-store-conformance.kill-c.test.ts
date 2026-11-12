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

describe('lease store conformance kit: prefix revocation count', () => {
  it('names the check when a prefix revocation does not see the stored leases', async () => {
    // After the first (per-lease) revocation is stored, every later update is handed a shard with no leases in view,
    // while the stored leases themselves are kept: the prefix revocation then reports zero revoked leases.
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
            if (isDoc(out) && out.revocations.length > 0) armed = true;
            return out;
          }),
      };
    };
    expect(await messageOf(open)).toBe(`${prefix}revoke by prefix covers every lease in every shard: got {"ok":true,"revoked":0}, want {"ok":true,"revoked":64}`);
  });
});

describe('lease store conformance kit: shard-count mismatch', () => {
  it('names the check when a store serves a lease to a registry opened with another shard count', async () => {
    // The store does not pin the shard count: it tells a second registry its count is fine, refuses its writes, but answers its
    // reads from the layout of the first. A presented lease is then allowed through the mismatched registry.
    const open = (): LeaseKv => {
      const real = memoryLeaseKv();
      let metaCalls = 0;
      return {
        get: (k) => (k.startsWith('lease/32/') ? real.get(`lease/16/${shardOf('m1', 16)}`) : real.get(k)),
        update: async (k, fn) => {
          if (k === 'lease/meta') {
            metaCalls += 1;
            return metaCalls === 1 ? real.update(k, fn) : { v: 1, shards: 32 };
          }
          if (k.startsWith('lease/32/')) throw new Error('refused');
          return real.update(k, fn);
        },
      };
    };
    expect(await messageOf(open)).toBe(`${prefix}shard mismatch check: got "allow", want "deny"`);
  });
});
