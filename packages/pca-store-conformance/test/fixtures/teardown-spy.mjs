// A store adapter that records its teardown to the file named by the `log` option; `mode=open-fails` makes open() reject.
import { appendFileSync } from 'node:fs';
export function createAdapter(o) {
  const counters = new Map();
  return {
    name: 'fixture teardown spy',
    capabilities: { durable: false },
    async open() {
      if (o.mode === 'open-fails') throw new Error('backend down');
      return {
        async advance(key, counter) {
          const last = counters.get(key);
          if (last !== undefined && !(counter > last)) return false;
          counters.set(key, counter);
          return true;
        },
      };
    },
    async teardown() {
      appendFileSync(o.log, 'teardown\n');
    },
  };
}
