#!/usr/bin/env node
// The job plan and the collection of the Swift schema mutation pipeline (mutate.mjs schema-plan -> schema-build.mjs per group ->
// levels of `mutate.mjs run --items` jobs -> collect).
//   node schema-jobs.mjs plan --level=0 --builds=<dir: meta.json + reach.json per group> --oracle=<oracle.json> [--pool=<pool.json>]
//        --run-id=<id> --out=<dir> [--workers=3] [--matrices=16] [--concurrency=60]
//     Level 0: every schema mutant of every group (mode schema, packed per group), every fallback mutant (mode real), and the
//     SAMPLES: one schema mutant per schema job (deterministic in the run id), also run as a real per-mutant build so collect can
//     compare both ways. Jobs are packed by ESTIMATED cost (the reaching classes' traced seconds, the oracle group's measured duration,
//     the pooled earlier verdict when there is one) to `cap` worker-minutes per worker. Writes <out>/jobs/<n>.json and prints the
//     GitHub outputs: m<k> (matrix k: {job:[...]}) and n<k> for k < matrices, `par` (max-parallel per matrix: concurrency split over the
//     non-empty matrices).
//   node schema-jobs.mjs plan --level=<1..3> --pending=<dir: the previous level's job.json + pending.json> ... (same options)
//     The items the previous level did not decide (not started, killed at its deadline, or the attempts 2 and 3 of a first full suite
//     that timed out). Levels 1 is packed like level 0; levels 2 and 3 by WORST case (every limit hit), so nothing can be left over.
//   node schema-jobs.mjs collect --plan=<plan.json> --carried=<carried.json> --builds=<dir> --results=<dir> --out=<dir> --reports=<N>
//     Every planned mutant has exactly ONE decision (its judge, or its attempts: attempt 2's verdict when it ended, else attempt 3's, else
//     TIMEOUT); no item is left pending; every sample's real verdict equals its schema verdict (detected / survived / timeout). Writes
//     <out>/results.json (every mutant, carried ones included) and <out>/chunk-<k>.json (k = 1..N, contiguous in file order) for the
//     report shards. Any failure exits nonzero before anything is written.
//   node schema-jobs.mjs --self-test
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const argv = process.argv.slice(2), cmd = argv[0];
const opt = (n, d) => argv.find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3) ?? d;
const rdj = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));
const walk = (d, re) => { const o = []; const w = (x) => { if (!fs.existsSync(x)) return; for (const e of fs.readdirSync(x, { withFileTypes: true })) { const p = path.join(x, e.name); if (e.isDirectory()) w(p); else if (re.test(e.name)) o.push(p); } }; w(d); return o.sort(); };
const h = (s) => crypto.createHash('sha256').update(s).digest('hex');
const targetOfFile = (file) => file.includes('/AtlasPCASQLite/') ? 'AtlasPCASQLiteTests' : file.includes('/AtlasPCAStepUp/') ? 'AtlasPCAStepUpTests' : 'AtlasPCAVerifyTests';
const CAP = 40 * 60, WORST_CAP = 50 * 60; // worker-seconds per worker: expected (the deadline takes the overrun), worst case

// seconds: the full suite of a file's target (the slowest measured oracle group of that target: an upper estimate), and its time limit
export function suiteOf(oracle) {
  const by = {};
  for (const [k, v] of Object.entries(oracle.groups ?? {})) { const t = k.split('|')[0]; by[t] = Math.max(by[t] ?? 0, v.ms / 1000); }
  return (file) => { const full = by[targetOfFile(file)] ?? 900; return { full, limit: Math.max(150, 2 * full + 120) }; };
}
// expected and worst-case worker-seconds of one item
export function costOf(it, ctx) {
  const { full, limit } = ctx.suite(it.file);
  const prev = ctx.pool?.[it.key]?.s;
  // no earlier verdict: a mutant some class reaches is mostly decided there (survivors are mostly the unreached ones, costed as full)
  const pFull = prev === 'SURVIVED' || prev === 'TIMEOUT' ? 1 : prev ? 0.05 : it.subset == null ? 1 : 0.08;
  if (it.att) { const w = 1.5 * limit + (it.mode === 'real' ? 300 : 0); return { exp: w, worst: w }; }
  if (it.mode === 'real') {
    const exp = prev === 'NONVIABLE' ? 60 : 90 + 60 + pFull * full;
    return { exp, worst: 300 + 180 + limit };
  }
  const sub = it.subset; // traced seconds of the reaching classes (null: no subset run)
  if (sub == null) return { exp: 15 + full, worst: limit };
  return { exp: 20 + 0.6 * sub + pFull * full, worst: Math.min(limit, Math.max(180, 2 * sub + 120)) + limit };
}
// longest first onto the least loaded worker of the first job that keeps every worker under cap (a single item over cap gets its own job)
export function pack(items, W, cap, key) {
  const jobs = [];
  for (const it of items.slice().sort((a, b) => b[key] - a[key] || (a.k < b.k ? -1 : 1))) {
    let j = jobs.find((x) => Math.min(...x.load) + it[key] <= cap);
    if (!j) jobs.push(j = { load: new Array(W).fill(0), items: [] });
    const w = j.load.indexOf(Math.min(...j.load));
    j.load[w] += it[key]; j.items.push(it);
  }
  return jobs;
}
const verdictClass = (s) => (s === 'SURVIVED' ? 'survived' : s === 'TIMEOUT' ? 'timeout' : s === 'NONVIABLE' ? 'nonviable' : 'detected');
// one mutant's final verdict from its records (judge, or attempts 2/3 of a timed-out first full suite)
export function resolve(recs) {
  const judge = recs.filter((r) => !r.att);
  if (judge.length > 1) return { err: `${judge.length} decisions` };
  if (judge.length === 1) return recs.length === 1 ? { rec: judge[0] } : { err: 'a decision and attempts' };
  const a2 = recs.filter((r) => r.att === 2), a3 = recs.filter((r) => r.att === 3);
  if (a2.length !== 1 || a3.length !== 1) return { err: `attempts ${a2.length}+${a3.length} (want 1+1)` };
  const { att, ended, ...base } = a2[0].ended ? a2[0] : a3[0].ended ? a3[0] : { ...a3[0], status: 'TIMEOUT', evidence: `no verdict in three attempts (the first at the limit, attempts 2 and 3 at 1.5x it, on two runners); ${a2[0].evidence}; ${a3[0].evidence}` };
  return { rec: base };
}

function planLevel() {
  const level = Number(opt('level')), W = Number(opt('workers', '3')), M = Number(opt('matrices', '16')), C = Number(opt('concurrency', '60'));
  const out = opt('out'); fs.mkdirSync(path.join(out, 'jobs'), { recursive: true });
  const suite = suiteOf(rdj(opt('oracle'))), pool = opt('pool') && fs.existsSync(opt('pool')) ? rdj(opt('pool')) : null;
  const builds = new Map(walk(opt('builds'), /^meta\.json$/).map((f) => { const meta = rdj(f); return [meta.group, { meta, reach: rdj(path.join(path.dirname(f), 'reach.json')) }]; }));
  const info = (g, id) => { const b = builds.get(g); const m = b.meta.mutants[id - 1]; if (!m || m.id !== id) throw new Error(`group ${g} has no mutant ${id}`); return { b, m }; };
  const subsetSeconds = (b, m) => {
    if (b.reach.unattributed.includes(m.id)) return null;
    const t = targetOfFile(m.file), cs = (b.reach.sites[m.id] ?? []).map((i) => b.reach.classes[i]).filter((c) => c[0] === t);
    if (!cs.length) return null;
    const s = cs.reduce((a, c) => a + c[2], 0);
    return s >= 0.6 * suite(m.file).full ? null : s;
  };
  const ctx = { suite, pool };
  const items = []; // {mode, group?, id?|key, att?, sample?, file, exp, worst}
  const add = (it) => { const c = costOf(it, ctx); items.push({ ...it, ...c, k: `${it.group ?? ''}|${it.id ?? it.key}|${it.att ?? ''}|${it.sample ? 's' : ''}` }); };
  if (level === 0) {
    if (!builds.size) throw new Error('no schema build outputs');
    for (const [g, b] of [...builds].sort((x, y) => x[0] - y[0])) for (const m of b.meta.mutants) {
      if (m.st === 'schema') add({ mode: 'schema', group: g, id: m.id, key: m.key, file: m.file, subset: subsetSeconds(b, m) });
      else add({ mode: 'real', key: m.key, file: m.file });
    }
  } else {
    for (const f of walk(opt('pending'), /^pending\.json$/)) {
      const job = rdj(path.join(path.dirname(f), 'job.json'));
      for (const it of rdj(f)) {
        if (job.mode === 'schema') { const { b, m } = info(job.group, it.id); add({ mode: 'schema', group: job.group, id: it.id, key: m.key, file: m.file, att: it.att, subset: subsetSeconds(b, m) }); }
        else add({ mode: 'real', key: it.key, file: it.file ?? '', att: it.att, sample: it.sample });
      }
    }
  }
  const by = (k) => (level >= 2 ? 'worst' : 'exp');
  const cap = level >= 2 ? WORST_CAP : CAP;
  let jobs = [];
  const groups = [...new Set(items.filter((x) => x.mode === 'schema').map((x) => x.group))].sort((a, b) => a - b);
  for (const g of groups) jobs.push(...pack(items.filter((x) => x.mode === 'schema' && x.group === g), W, cap, by()).map((j) => ({ mode: 'schema', group: g, ...j })));
  const real = items.filter((x) => x.mode === 'real');
  if (level === 0) {
    // the self-check samples: one schema mutant per schema job, picked by the run id
    for (const j of jobs) {
      const pick = j.items.reduce((a, b) => (h(`${opt('run-id')}\0${a.key}`) <= h(`${opt('run-id')}\0${b.key}`) ? a : b));
      const it = { mode: 'real', key: pick.key, file: pick.file, sample: true };
      real.push({ ...it, ...costOf(it, ctx), k: `|${pick.key}||s` });
    }
  }
  jobs.push(...pack(real, W, cap, by()).map((j) => ({ mode: 'real', ...j })));
  if (jobs.length > 256 * M) throw new Error(`${jobs.length} jobs exceed ${M} matrices of 256`);
  const outs = {};
  jobs.forEach((j, n) => {
    const body = j.mode === 'schema' ? { mode: 'schema', group: j.group, items: j.items.map((x) => ({ id: x.id, ...(x.att ? { att: x.att } : {}) })) }
      : { mode: 'real', items: j.items.map((x) => ({ key: x.key, file: x.file, ...(x.att ? { att: x.att } : {}), ...(x.sample ? { sample: true } : {}) })) };
    fs.writeFileSync(path.join(out, 'jobs', `${n}.json`), JSON.stringify(body));
  });
  const per = Math.ceil(jobs.length / M), nonEmpty = Math.min(M, Math.ceil(jobs.length / Math.max(per, 1)));
  for (let k = 0; k < M; k++) {
    const ids = jobs.map((_, n) => n).slice(k * per, (k + 1) * per);
    outs[`n${k}`] = ids.length; outs[`m${k}`] = JSON.stringify({ job: ids.length ? ids : [-1] });
  }
  outs.par = Math.max(1, Math.floor(C / Math.max(nonEmpty, 1)));
  outs.jobs = jobs.length;
  outs.samples = level === 0 ? jobs.filter((j) => j.mode === 'schema').length : 0;
  const mins = (k) => (jobs.reduce((a, j) => a + j.items.reduce((b, x) => b + x[k], 0), 0) / 60).toFixed(0);
  console.error(`level ${level}: ${items.length} item(s) + ${level === 0 ? jobs.filter((j) => j.mode === 'schema').length : 0} sample(s) in ${jobs.length} job(s) of ${W} workers `
    + `(${jobs.filter((j) => j.mode === 'schema').length} schema, ${jobs.filter((j) => j.mode === 'real').length} real); estimated ${mins('exp')} worker-min (worst ${mins('worst')}); `
    + `fullest worker ${(Math.max(0, ...jobs.map((j) => Math.max(...j.load))) / 60).toFixed(0)} min; ${outs.par} concurrent per matrix`);
  return outs;
}

function collect() {
  const plan = rdj(opt('plan')), carried = rdj(opt('carried')), N = Number(opt('reports'));
  const metas = walk(opt('builds'), /^meta\.json$/).map(rdj);
  const errs = [];
  if (metas.length !== plan.groups.length) errs.push(`${metas.length} schema build(s), the plan has ${plan.groups.length} groups`);
  const planned = new Map(); // key -> 'schema' | 'fallback'
  for (const mt of metas) {
    const want = plan.groups[mt.group];
    if (!want || want.n !== mt.mutants.length) errs.push(`group ${mt.group}: ${mt.mutants.length} mutant(s) built, the plan has ${want?.n}`);
    for (const m of mt.mutants) planned.set(m.key, m.st);
  }
  const by = new Map(), samples = new Map();
  let leftover = 0;
  for (const f of walk(opt('results'), /^results\.json$/)) {
    for (const r of rdj(f)) { const t = r.sample ? samples : by; if (!t.has(r.key)) t.set(r.key, []); t.get(r.key).push(r); }
    const p = path.join(path.dirname(f), 'pending.json');
    // earlier levels' pending items were planned again; only the last level's are left over
    if (fs.existsSync(p) && path.basename(path.dirname(f)).startsWith(`lvl${opt('last-level', '3')}-`)) leftover += rdj(p).length;
  }
  // a job that never wrote results is a job that failed; its items have no decision and are reported below
  if (leftover && !opt('allow-pending')) errs.push(`${leftover} item(s) still pending after the last level`);
  const final = [];
  for (const [key, st] of planned) {
    const recs = by.get(key) ?? [];
    if (!recs.length) { errs.push(`no decision for ${key}`); continue; }
    if (recs.some((r) => (r.via === 'schema') !== (st === 'schema'))) errs.push(`${key}: decided by the ${recs[0].via} path, planned as ${st}`);
    const r = resolve(recs);
    if (r.err) errs.push(`${key}: ${r.err}`); else final.push(r.rec);
  }
  for (const key of by.keys()) if (!planned.has(key)) errs.push(`result for a mutant not in the plan: ${key}`);
  let same = 0;
  for (const [key, recs] of samples) {
    const s = resolve(recs), d = final.find((x) => x.key === key);
    if (s.err) { errs.push(`sample ${key}: ${s.err}`); continue; }
    if (!d || planned.get(key) !== 'schema') { errs.push(`sample ${key} is no schema-decided mutant`); continue; }
    if (verdictClass(s.rec.status) !== verdictClass(d.status)) errs.push(`SCHEMA MISMATCH: ${key}: schema ${d.status}, real build ${s.rec.status}`);
    else same++;
  }
  const wantSamples = Number(opt('samples', '-1'));
  if (wantSamples >= 0 && samples.size !== wantSamples) errs.push(`${samples.size} sample(s) decided, the plan has ${wantSamples}`);
  const keys = new Set(final.map((r) => r.key));
  for (const c of carried) { if (keys.has(c.key) || planned.has(c.key)) errs.push(`carried and run: ${c.key}`); final.push(c); }
  if (final.length !== plan.groups.reduce((a, g) => a + g.n, 0) + carried.length) errs.push(`${final.length} verdict(s), the plan has ${plan.groups.reduce((a, g) => a + g.n, 0)} + ${carried.length} carried`);
  for (const e of errs.slice(0, 60)) console.error('::error::' + e);
  if (errs.length) { console.error(`${errs.length} problem(s)`); process.exit(1); }
  const order = new Map(plan.files.map((f, i) => [f, i]));
  final.sort((a, b) => order.get(a.file) - order.get(b.file) || a.idx - b.idx);
  if (final.length < N) { console.error(`::error::${final.length} mutant(s) cannot fill ${N} reports`); process.exit(1); }
  const out = opt('out'); fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify(final));
  for (let k = 0; k < N; k++) fs.writeFileSync(path.join(out, `chunk-${k + 1}.json`), JSON.stringify(final.slice(Math.floor(k * final.length / N), Math.floor((k + 1) * final.length / N))));
  const c = {}; for (const r of final) c[r.status] = (c[r.status] ?? 0) + 1;
  console.log(`${final.length} mutant(s): ${[...planned.values()].filter((s) => s === 'schema').length} schema, ${[...planned.values()].filter((s) => s !== 'schema').length} real per-mutant builds, ${carried.length} carried; ${same}/${samples.size} sample(s) agree both ways; ${JSON.stringify(c)}`);
}

function selfTest() {
  const t = [];
  const ok = (c, w) => t.push([!!c, w]);
  const R = (o) => ({ key: 'k', file: 'f', idx: 0, status: 'SURVIVED', ...o });
  ok(resolve([R({})]).rec.status === 'SURVIVED', 'one judge');
  ok(resolve([R({}), R({})]).err, 'two judges fail');
  ok(resolve([R({ att: 2, ended: true, status: 'KILLED' }), R({ att: 3, ended: true, status: 'SURVIVED' })]).rec.status === 'KILLED', 'attempt 2 decides first');
  ok(resolve([R({ att: 2, ended: false, status: 'TIMEOUT', evidence: 'a' }), R({ att: 3, ended: true, status: 'SURVIVED' })]).rec.status === 'SURVIVED', 'attempt 3 when 2 did not end');
  const tt = resolve([R({ att: 2, ended: false, status: 'TIMEOUT', evidence: 'a' }), R({ att: 3, ended: false, status: 'TIMEOUT', evidence: 'b' })]).rec;
  ok(tt.status === 'TIMEOUT' && !('att' in tt) && !('ended' in tt), 'two timeouts: TIMEOUT');
  ok(resolve([R({ att: 2, ended: true })]).err, 'a missing attempt fails');
  const items = Array.from({ length: 20 }, (_, i) => ({ k: String(i), exp: 600 }));
  const js = pack(items, 3, 2400, 'exp');
  ok(js.length === 2 && js.every((j) => Math.max(...j.load) <= 2400) && js.reduce((a, j) => a + j.items.length, 0) === 20, 'packing keeps every worker under cap');
  ok(pack([{ k: 'x', exp: 5000 }], 3, 2400, 'exp').length === 1, 'an item over cap gets a job');
  const suite = suiteOf({ groups: { 'AtlasPCAVerifyTests|A': { ms: 500000 }, 'AtlasPCAVerifyTests|B': { ms: 900000 } } });
  ok(suite('Sources/AtlasPCAVerify/X.swift').full === 900 && suite('Sources/AtlasPCAVerify/X.swift').limit === 1920, 'suite estimate: slowest group, limit 2x+120');
  const c = costOf({ mode: 'schema', file: 'Sources/AtlasPCAVerify/X.swift', subset: null }, { suite });
  ok(c.exp === 915 && c.worst === 1920, 'unreached schema mutant costs the full suite');
  const bad = t.filter(([x]) => !x);
  for (const [, w] of bad) console.error('self-test failed: ' + w);
  if (bad.length) process.exit(1);
  console.log(`schema-jobs self-test ok (${t.length} checks)`);
}

if (argv.includes('--self-test')) selfTest();
else if (cmd === 'plan') {
  const o = planLevel();
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, Object.entries(o).map(([k, v]) => `${k}=${v}\n`).join(''));
  else console.log(JSON.stringify(o));
} else if (cmd === 'collect') collect();
else { console.error('usage: schema-jobs.mjs plan|collect|--self-test'); process.exit(2); }
