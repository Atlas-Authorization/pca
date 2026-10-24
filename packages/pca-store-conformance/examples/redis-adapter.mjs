// Example store adapter: Redis (ioredis). SET NX PX for consume-once, a Lua compare-and-set for counters.
//   pca-store-conformance --adapter ./examples/redis-adapter.mjs --option url=redis://host:6379 --option prefix=myapp:
// The contract needs appendfsync always (or WAIT with a primary that never restarts empty) and maxmemory-policy noeviction.
import Redis from 'ioredis';

const ADVANCE = `local cur = redis.call('GET', KEYS[1])
if cur and tonumber(cur) >= tonumber(ARGV[1]) then return 0 end
redis.call('SET', KEYS[1], ARGV[1])
return 1`;

export function createAdapter(options) {
  const url = options.url ?? process.env.REDIS_URL ?? 'redis://127.0.0.1:6379';
  const prefix = options.prefix ?? 'pca-store-conformance:';
  const conns = [];
  return {
    name: `redis (SET NX PX / Lua advance, prefix ${prefix})`,
    capabilities: { durable: true },
    async open() {
      const r = new Redis(url, { maxRetriesPerRequest: 1, enableOfflineQueue: false, lazyConnect: true });
      await r.connect();
      conns.push(r);
      return {
        // The record expires on Redis's own clock: correct while Redis's clock is within the skew bound of the verifiers'.
        async consumeOnce(key, retainUntilMs, nowMs) {
          const ttl = Math.max(1, retainUntilMs - nowMs);
          return (await r.set(`${prefix}n:${key}`, String(retainUntilMs), 'PX', ttl, 'NX')) === 'OK';
        },
        async advance(key, counter) {
          return (await r.eval(ADVANCE, 1, `${prefix}c:${key}`, String(counter))) === 1;
        },
        close: async () => void (await r.quit()),
      };
    },
    async teardown() {
      await Promise.all(conns.map((c) => c.quit().catch(() => undefined)));
    },
  };
}
