// A pca-state adapter whose store rejects every call; `mode=open-fails` makes open() reject; teardown is recorded to `log`.
import { appendFileSync } from 'node:fs';
export function createPcaStateAdapter(o) {
  const down = async () => {
    throw new Error('store down');
  };
  return {
    name: 'fixture pca-state probe',
    capabilities: { durable: false, shared: false },
    async open() {
      if (o.mode === 'open-fails') throw new Error('state backend down');
      return { store: { get: down, put: down } };
    },
    async teardown() {
      appendFileSync(o.log, 'teardown\n');
    },
  };
}
