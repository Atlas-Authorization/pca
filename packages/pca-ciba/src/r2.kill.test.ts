import { describe, expect, it } from 'vitest';
import { approvalBrokerCases } from './store-conformance';
import { createMemoryApprovalStore } from './testing';
import type { ApprovalStore } from './approval';

describe('broker case: a late decision on a decided request is refused', () => {
  it('reports a store that lets a decided request be decided again as a missing rejection', async () => {
    // After a read that returned a decided record, the next read returns a stale undecided copy and every write claims success.
    const make = (): ApprovalStore => {
      const inner = createMemoryApprovalStore();
      let lastUndecided: { version: number; value: unknown } | undefined;
      let servedDecided = false;
      return {
        get: async (k) => {
          const real = await inner.get(k);
          if (real === undefined || !k.startsWith('a:')) return real;
          const decided = (real.value as { decision?: string }).decision !== undefined;
          if (!decided) lastUndecided = real;
          if (servedDecided && lastUndecided !== undefined) {
            servedDecided = false;
            return structuredClone(lastUndecided);
          }
          servedDecided = decided;
          return real;
        },
        cas: async (k, e, v) => {
          await inner.cas(k, e, v);
          return true;
        },
      };
    };
    const err = await approvalBrokerCases(make)[2]!.run().then(
      () => undefined,
      (e: unknown) => e as Error,
    );
    expect(err).toBeInstanceOf(Error);
    expect(err!.message).toBe('expected a rejection');
  });
});
