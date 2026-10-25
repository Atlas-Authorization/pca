// A user adapter module: named createAdapter(options) factory.
export function createAdapter(options) {
  const counters = new Map();
  return {
    name: `fixture factory ${options.label ?? 'none'}`,
    capabilities: { durable: false },
    async open() {
      return {
        async advance(key, counter) {
          const last = counters.get(key);
          if (last !== undefined && !(counter > last)) return false;
          counters.set(key, counter);
          return true;
        },
      };
    },
  };
}
