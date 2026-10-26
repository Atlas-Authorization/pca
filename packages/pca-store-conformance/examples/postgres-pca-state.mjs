// Example pca-state adapter: the store behind requirePCA on Postgres (the `postgres` client). Atomic claim = ONE
// conditional statement (a primary-key insert, or an UPDATE guarded by the counter and the budget it was computed from).
//   pca-store-conformance --profile pca-state --adapter ./examples/postgres-pca-state.mjs --option url=postgres://user:pw@host:5432/db
// Uses its own table (pca_sc_state); never drops anything. Use the same statements in your own store.
import postgres from 'postgres';

const n = (v) => (v === null || v === undefined ? undefined : Number(v));
const row = (r) => {
  if (!r) return undefined;
  const s = {};
  if (r.last_counter !== null) s.lastCounter = n(r.last_counter);
  if (r.budget !== null) s.budget = r.budget;
  if (r.last_epoch !== null) s.lastEpoch = n(r.last_epoch);
  if (r.last_beacon_seq !== null) s.lastBeaconSeq = n(r.last_beacon_seq);
  return s;
};

export function postgresPcaStateStore(sql) {
  const json = (b) => (b === undefined ? null : sql.json(b));
  return {
    scope: 'shared',
    async get(key) {
      return row((await sql`SELECT * FROM pca_sc_state WHERE key = ${key}`)[0]);
    },
    async put(key, s) {
      await sql`
        INSERT INTO pca_sc_state (key, last_counter, budget, last_epoch, last_beacon_seq)
        VALUES (${key}, ${s.lastCounter ?? null}, ${json(s.budget)}, ${s.lastEpoch ?? null}, ${s.lastBeaconSeq ?? null})
        ON CONFLICT (key) DO UPDATE SET last_counter = EXCLUDED.last_counter, budget = EXCLUDED.budget,
          last_epoch = EXCLUDED.last_epoch, last_beacon_seq = EXCLUDED.last_beacon_seq`;
    },
    async claim(key, c) {
      const before = json(c.budgetBefore);
      if (c.budgetBefore === undefined) {
        // first action of this holder: the primary key makes exactly one insert win
        const ins = await sql`
          INSERT INTO pca_sc_state (key, last_counter, budget) VALUES (${key}, ${c.counter}, ${json(c.budgetAfter)})
          ON CONFLICT (key) DO NOTHING RETURNING 1`;
        if (ins.length === 1) return { ok: true };
      }
      const up = await sql`
        UPDATE pca_sc_state SET last_counter = ${c.counter}, budget = COALESCE(${json(c.budgetAfter)}::jsonb, budget)
        WHERE key = ${key} AND (last_counter IS NULL OR last_counter < ${c.counter}) AND budget IS NOT DISTINCT FROM ${before}::jsonb
        RETURNING 1`;
      if (up.length === 1) return { ok: true };
      // lost: classify (a read after the failed update only chooses the denial reason; requirePCA re-verifies on conflict)
      const cur = row((await sql`SELECT * FROM pca_sc_state WHERE key = ${key}`)[0]);
      return cur?.lastCounter !== undefined && !(c.counter > cur.lastCounter)
        ? { ok: false, reason: 'replay', lastCounter: cur.lastCounter }
        : { ok: false, reason: 'conflict' };
    },
    async raisePin(key, pin, value) {
      if (pin === 'lastEpoch') {
        await sql`INSERT INTO pca_sc_state (key, last_epoch) VALUES (${key}, ${value})
          ON CONFLICT (key) DO UPDATE SET last_epoch = GREATEST(COALESCE(pca_sc_state.last_epoch, EXCLUDED.last_epoch), EXCLUDED.last_epoch)`;
      } else {
        await sql`INSERT INTO pca_sc_state (key, last_beacon_seq) VALUES (${key}, ${value})
          ON CONFLICT (key) DO UPDATE SET last_beacon_seq = GREATEST(COALESCE(pca_sc_state.last_beacon_seq, EXCLUDED.last_beacon_seq), EXCLUDED.last_beacon_seq)`;
      }
    },
  };
}

export function createPcaStateAdapter(options) {
  const url = options.url ?? process.env.DATABASE_URL;
  const pools = [];
  let ready;
  const schema = (sql) =>
    (ready ??= sql`CREATE TABLE IF NOT EXISTS pca_sc_state (
      key text PRIMARY KEY, last_counter bigint, budget jsonb, last_epoch bigint, last_beacon_seq bigint)`.then(() => undefined));
  return {
    name: 'postgres pca-state (INSERT .. ON CONFLICT DO NOTHING / UPDATE .. WHERE last_counter < $n AND budget IS NOT DISTINCT FROM $before)',
    capabilities: { durable: true, shared: true },
    async open() {
      const sql = postgres(url, { max: 1, onnotice: () => {} });
      pools.push(sql);
      await schema(sql);
      return { store: postgresPcaStateStore(sql), close: () => sql.end({ timeout: 5 }) };
    },
    async teardown() {
      await Promise.all(pools.map((p) => p.end({ timeout: 5 })));
    },
  };
}
