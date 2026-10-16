// Example store adapter: Postgres (the `postgres` client). One atomic statement per operation.
//   pca-store-conformance --adapter ./examples/postgres-adapter.mjs --option url=postgres://user:pw@host:5432/db
// Uses its own tables (pca_sc_nonces / pca_sc_counters); never drops anything.
import postgres from 'postgres';

export function createAdapter(options) {
  const url = options.url ?? process.env.DATABASE_URL;
  const pools = [];
  let ready;
  const schema = async (sql) => {
    ready ??= (async () => {
      await sql`CREATE TABLE IF NOT EXISTS pca_sc_nonces (key text PRIMARY KEY, until bigint NOT NULL)`;
      await sql`CREATE TABLE IF NOT EXISTS pca_sc_counters (key text PRIMARY KEY, counter bigint NOT NULL)`;
    })();
    return ready;
  };
  return {
    name: 'postgres (INSERT .. ON CONFLICT .. WHERE until < now / UPDATE .. WHERE counter < $n)',
    capabilities: { durable: true },
    async open() {
      const sql = postgres(url, { max: 1, onnotice: () => {} });
      pools.push(sql);
      await schema(sql);
      return {
        // TRUE iff no live record: insert, or take over an expired one; RETURNING a row means this call won.
        async consumeOnce(key, retainUntilMs, nowMs) {
          const rows = await sql`
            INSERT INTO pca_sc_nonces (key, until) VALUES (${key}, ${retainUntilMs})
            ON CONFLICT (key) DO UPDATE SET until = EXCLUDED.until WHERE pca_sc_nonces.until < ${nowMs}
            RETURNING 1`;
          return rows.length === 1;
        },
        // TRUE iff strictly greater: seed the row, then one conditional UPDATE.
        async advance(key, counter) {
          const ins = await sql`INSERT INTO pca_sc_counters (key, counter) VALUES (${key}, ${counter}) ON CONFLICT (key) DO NOTHING RETURNING 1`;
          if (ins.length === 1) return true;
          const up = await sql`UPDATE pca_sc_counters SET counter = ${counter} WHERE key = ${key} AND counter < ${counter} RETURNING 1`;
          return up.length === 1;
        },
        close: () => sql.end({ timeout: 5 }),
      };
    },
    async teardown() {
      await Promise.all(pools.map((p) => p.end({ timeout: 5 })));
    },
  };
}
