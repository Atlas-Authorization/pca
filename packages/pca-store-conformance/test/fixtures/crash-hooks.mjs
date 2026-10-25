// Records the backend crash / restart hooks the crash harness calls (parent side only).
import { appendFileSync } from 'node:fs';
export function createAdapter(o) {
  const counters = new Map();
  return {
    name: 'fixture crash hooks',
    capabilities: { durable: false },
    open: async () => ({
      async advance(key, counter) {
        const last = counters.get(key);
        if (last !== undefined && !(counter > last)) return false;
        counters.set(key, counter);
        return true;
      },
    }),
    crash: async () => appendFileSync(o.log, `crash ${process.pid}\n`),
    restart: async () => appendFileSync(o.log, `restart ${process.pid}\n`),
  };
}
