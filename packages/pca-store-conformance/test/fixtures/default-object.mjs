// A user adapter module: default export = the adapter object (a tiny correct in-memory store).
const seen = new Map();
const counters = new Map();
export default {
  name: 'fixture default object',
  capabilities: { durable: false },
  async open() {
    return {
      async consumeOnce(key, retainUntilMs, nowMs) {
        const until = seen.get(key);
        if (until !== undefined && until >= nowMs) return false;
        seen.set(key, retainUntilMs);
        return true;
      },
      async advance(key, counter) {
        const last = counters.get(key);
        if (last !== undefined && !(counter > last)) return false;
        counters.set(key, counter);
        return true;
      },
    };
  },
};
