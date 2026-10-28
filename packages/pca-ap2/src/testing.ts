import type { MandateContext } from './constraints';
import type { PurchaseLedger } from './ledger';

/** Single-process reference ledger for tests; production needs a durable store with a unique key and serialised sum. */
export function memoryPurchaseLedger(): PurchaseLedger & { usage(open: string): MandateContext } {
  const m = new Map<string, Map<string, number>>();
  const usage = (open: string): MandateContext => {
    const e = [...(m.get(open)?.values() ?? [])];
    return { totalAmount: e.reduce((a, b) => a + b, 0), totalUses: e.length };
  };
  return {
    usage,
    async reserve(open, tx, amount) {
      const e = m.get(open) ?? new Map<string, number>();
      if (e.has(tx)) return 'replayed';
      const before = usage(open);
      e.set(tx, amount);
      m.set(open, e);
      return before;
    },
    async release(open, tx) {
      m.get(open)?.delete(tx);
    },
  };
}
