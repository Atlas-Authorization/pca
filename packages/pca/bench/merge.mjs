// Merge per-suite benchmark files.
//   node merge.mjs fixtures OUT.json.gz IN1.json IN2.json ...   -> one gzipped fixture file (suites + threshold)
//   node merge.mjs results  OUT.json    IN1.json IN2.json ...   -> one result file (rows concatenated, hosts checked equal)
import { readFileSync, writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';

const [mode, out, ...ins] = process.argv.slice(2);
const load = (f) => JSON.parse(readFileSync(f, 'utf8'));
if (mode === 'fixtures') {
  const merged = { now_epoch_ms: undefined, aud: undefined, suites: {}, threshold: [] };
  for (const f of ins) {
    const x = load(f);
    merged.now_epoch_ms ??= x.now_epoch_ms;
    merged.aud ??= x.aud;
    if (x.now_epoch_ms !== merged.now_epoch_ms || x.aud !== merged.aud) throw new Error(`${f}: constants differ`);
    Object.assign(merged.suites, x.suites);
    merged.threshold.push(...x.threshold);
  }
  writeFileSync(out, gzipSync(Buffer.from(JSON.stringify(merged)), { level: 9 }));
  console.log(`wrote ${out}: ${Object.keys(merged.suites).length} suites, ${merged.threshold.length} threshold scenarios`);
} else if (mode === 'results') {
  const parts = ins.map(load);
  const host = { ...parts[0].host, pinned_cpu: undefined };
  for (const p of parts) for (const k of ['cpu_model', 'logical_cpus', 'node']) if (p.host[k] !== host[k]) throw new Error(`host ${k} differs`);
  const res = {
    tool: parts[0].tool,
    date: new Date().toISOString(),
    n_cap: parts[0].n_cap,
    min_n: parts[0].min_n,
    rel_ci: parts[0].rel_ci,
    warmup: parts[0].warmup,
    now_epoch_ms: parts[0].now_epoch_ms,
    host,
    method: 'one process per suite, each pinned to its own core (taskset); fixtures pre-signed, no signing inside the measured run',
    pinning: parts.map((p) => ({ suites: p.suites, cpu: p.host.pinned_cpu })),
    rows: parts.flatMap((p) => p.rows.map((r) => ({ ...r, cpu: p.host.pinned_cpu }))),
  };
  writeFileSync(out, JSON.stringify(res, null, 2) + '\n');
  console.log(`wrote ${out}: ${res.rows.length} rows`);
} else throw new Error('mode must be fixtures or results');
