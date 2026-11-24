import type { TrustBudget } from '@atlasauth/pca';
import type { ChargeBudgetStore } from './authorize';

/** Single-process reference store for tests; production needs a durable store with a conditional write. */
export function memoryChargeBudgetStore(): ChargeBudgetStore {
  const m = new Map<string, { budget: TrustBudget; version: number }>();
  return {
    async get(k) {
      return m.get(k);
    },
    async compareAndSet(k, expected, budget) {
      if (m.get(k)?.version !== expected) return false;
      m.set(k, { budget, version: (expected ?? 0) + 1 });
      return true;
    },
  };
}
