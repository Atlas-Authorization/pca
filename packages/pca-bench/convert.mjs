#!/usr/bin/env node
// Turns the native output of a language's benchmark tool into one pca-bench-result/1 file.
//
//   convert.mjs <format> --in RAW --corpus corpus.json --lang L --impl NAME --impl-version V --tool T --runtime R --out result.json
//               [--status status.jsonl] [--cold id=ns ...] [--cold-json FILE]
//   formats: jmh (Java, Kotlin) | bdn (BenchmarkDotNet full JSON) | pytest (pytest-benchmark JSON) | phpbench (sample sidecar) | swift (swift-benchmark JSON)
//
// Scenario kind / group / pair come from the corpus, the runner description from the machine this runs on (CI converts on the machine
// that benchmarked). A scenario named in the status sidecar as skipped / error is reported as such; a scenario with neither a status nor
// a measurement is an error, never silently missing.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { arch, cpus, platform } from 'node:os';
import { RESULT_SCHEMA, median, summarize } from './lib.mjs';

const [format, ...rest] = process.argv.slice(2);
const a = { cold: [] };
for (let i = 0; i < rest.length; i += 2) {
  const k = rest[i].replace(/^--/, '');
  if (k === 'cold') a.cold.push(rest[i + 1]);
  else a[k] = rest[i + 1];
}
for (const k of ['in', 'corpus', 'lang', 'impl', 'out']) if (!a[k]) die(`missing --${k}`);
function die(m) {
  console.error(`convert: ${m}`);
  process.exit(2);
}

const corpus = JSON.parse(readFileSync(a.corpus, 'utf8'));
const NS = { ns: 1, us: 1e3, ms: 1e6, s: 1e9 };
const unitNs = (u) => NS[String(u).split('/')[0]] ?? die(`unknown time unit ${u}`);

/** id -> { samples?: ns per call in order, rounds?: ns, mean?, p50?, p95?, p99?, allocs?, bytes? } */
const data = new Map();
const sidecar = new Map();
const cold = {};
const coldRuns = {};

const files = a.in.split(',');
const raw = readFileSync(files[0], 'utf8');
const json = () => JSON.parse(raw);

if (format === 'jmh') {
  for (const b of json()) {
    const cls = b.benchmark.split('.').slice(-2).join('.');
    const pm = b.primaryMetric;
    const scale = unitNs(pm.scoreUnit);
    if (cls === 'ColdStart.firstVerify') {
      (coldRuns[b.params.scenario] ??= []).push(...pm.rawData.flat().map((x) => x * scale));
      continue;
    }
    if (cls !== 'PcaBench.run') continue;
    const row = data.get(b.params.scenario) ?? {};
    if (b.mode === 'avgt') {
      row.rounds = pm.rawData.flat().map((x) => x * scale);
      row.mean = pm.score * scale;
      const gc = b.secondaryMetrics?.['·gc.alloc.rate.norm'] ?? b.secondaryMetrics?.['gc.alloc.rate.norm'];
      if (gc) row.bytes = gc.score;
    } else if (b.mode === 'sample') {
      const p = pm.scorePercentiles;
      [row.p50, row.p95, row.p99] = [p['50.0'] * scale, p['95.0'] * scale, p['99.0'] * scale];
    }
    data.set(b.params.scenario, row);
  }
} else if (format === 'bdn') {
  // BenchmarkDotNet writes one report per benchmark class: --in takes them comma-separated
  const all = files.flatMap((f) => JSON.parse(readFileSync(f, 'utf8')).Benchmarks);
  for (const b of all) {
    const id = /scenario=([^\s,;&]+)/i.exec(b.Parameters ?? '')?.[1];
    if (!id) continue;
    const actual = (b.Measurements ?? []).filter((m) => m.IterationStage === 'Actual' && m.IterationMode === 'Workload');
    const ns = actual.map((m) => m.Nanoseconds / m.Operations);
    if (b.Method === 'FirstVerify') (coldRuns[id] ??= []).push(...ns);
    else if (b.Method === 'Run') data.set(id, { samples: ns, bytes: b.Memory?.BytesAllocatedPerOperation ?? null });
  }
} else if (format === 'pytest') {
  for (const b of json().benchmarks) {
    const e = b.extra_info ?? {};
    if (e.cold_start_ns !== undefined) coldRuns[e.scenario] = [e.cold_start_ns];
    else if (e.status === 'ok') data.set(e.scenario, { samples: e.samples_ns, bytes: e.bytes_per_op ?? null });
    else if (e.status) sidecar.set(e.scenario, { status: e.status, note: e.note });
  }
} else if (format === 'phpbench') {
  const byId = new Map();
  for (const line of raw.split('\n').filter(Boolean)) {
    const r = JSON.parse(line);
    if (r.status !== 'ok') sidecar.set(r.id, { status: r.status, note: r.note });
    else (byId.get(r.id) ?? byId.set(r.id, []).get(r.id)).push(r.samples_ns);
  }
  for (const [id, iters] of byId) {
    const all = iters.flat().sort((x, y) => x - y);
    const q = (f) => all[Math.min(all.length - 1, Math.max(0, Math.ceil(f * all.length) - 1))];
    const rounds = iters.map((s) => s.reduce((x, y) => x + y, 0) / s.length);
    data.set(id, { rounds, mean: rounds.reduce((x, y) => x + y, 0) / rounds.length, p50: q(0.5), p95: q(0.95), p99: q(0.99), bytes: null });
  }
} else if (format === 'swift') {
  // swift-benchmark's JSON: benchmark entries carrying a name and the per-iteration measurements in nanoseconds
  const walk = (v) => {
    if (Array.isArray(v)) return v.forEach(walk);
    if (v && typeof v === 'object') {
      const m = v.measurements ?? v.results;
      if (typeof v.name === 'string' && Array.isArray(m) && m.length && m.every((x) => typeof x === 'number')) data.set(v.name, { samples: m, bytes: null });
      else Object.values(v).forEach(walk);
    }
  };
  walk(json());
  if (data.size === 0) die('no benchmark entries found in the swift-benchmark JSON (unrecognised layout)');
} else die(`unknown format ${format}`);

// status sidecar (jsonl): an entry other than ok wins; later lines win over earlier ones
if (a.status && existsSync(a.status)) {
  for (const line of readFileSync(a.status, 'utf8').split('\n').filter(Boolean)) {
    const r = JSON.parse(line);
    if (r.status !== 'ok') sidecar.set(r.id, r);
  }
}
for (const [id, runs] of Object.entries(coldRuns)) cold[id] = median(runs);
for (const c of a.cold) {
  const [id, ns] = c.split('=');
  (coldRuns[id] ??= []).push(Number(ns));
  cold[id] = median(coldRuns[id]);
}
if (a['cold-json'] && existsSync(a['cold-json'])) {
  // one line per fresh process: {"verify.ed25519.d1": ns, ...}
  const per = {};
  for (const line of readFileSync(a['cold-json'], 'utf8').split('\n').filter(Boolean)) for (const [k, v] of Object.entries(JSON.parse(line))) (per[k] ??= []).push(v);
  for (const [k, v] of Object.entries(per)) cold[k] = median(v);
}

const scenarios = corpus.scenarios.map((s) => {
  const row = { id: s.id, kind: s.kind, group: s.group, ...(s.pair ? { pair: s.pair } : {}) };
  const side = sidecar.get(s.id);
  const d = data.get(s.id);
  if (side && side.status !== 'ok') return { ...row, status: side.status, ...(side.note ? { note: side.note } : {}) };
  if (!d) return { ...row, status: 'error', note: 'no measurement in the tool output' };
  try {
    if (d.samples) return { ...row, status: 'ok', ...summarize(d.samples, 7), allocs_per_op: null, bytes_per_op: d.bytes ?? null };
    if (!d.rounds?.length) throw new Error('no rounds');
    const mean = d.mean ?? d.rounds.reduce((x, y) => x + y, 0) / d.rounds.length;
    return { ...row, status: 'ok', ops_per_sec: 1e9 / mean, mean_ns: mean, p50_ns: d.p50 ?? median(d.rounds), p95_ns: d.p95 ?? Math.max(...d.rounds), p99_ns: d.p99 ?? Math.max(...d.rounds), rounds_ns: d.rounds, allocs_per_op: null, bytes_per_op: d.bytes ?? null };
  } catch (e) {
    return { ...row, status: 'error', note: String(e.message ?? e) };
  }
});

writeFileSync(
  a.out,
  JSON.stringify(
    {
      schema: RESULT_SCHEMA,
      lang: a.lang,
      impl: a.impl,
      impl_version: a['impl-version'] ?? 'unreleased',
      tool: a.tool ?? format,
      runtime: a.runtime ?? 'unknown',
      runner: { os: platform(), arch: arch(), cpu: cpus()[0]?.model ?? 'unknown', cores: cpus().length },
      corpus: { version: corpus.version, digest: corpus.digest },
      cold_start_ns: cold,
      scenarios,
    },
    null,
    1,
  ) + '\n',
);
