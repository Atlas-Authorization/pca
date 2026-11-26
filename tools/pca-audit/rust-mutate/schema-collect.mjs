#!/usr/bin/env node
// Fallback plan and collection of the schema runs (pca-rust mutation workflow).
//   node schema-collect.mjs fbplan --list=<dir> --decs=<dir> --crates=<CRATES json> --run-id=<id> --names-out=<dir> [--budget=45]
//     -> stdout: matrix={include:[...]}. The shard matrix: (a) every FALLBACK mutant (schema-gen could not hold it, or its schema
//     text did not compile) packed into real per-mutant shards (cargo-mutants / stmt-run --names) by estimated cost, `budget`
//     worker-minutes each; (b) SAMPLES: one schema mutant per run shard (deterministic in the run id), also run by the real
//     per-mutant tools in jobs of their own, so collect can compare both ways; (c) the proof crates' shards, unchanged.
//   node schema-collect.mjs collect --list=<dir> --decs=<dir> --sres=<dir> --fres=<dir> --dir=<crate dir> --key=<key> --out=<dir>
//     every planned mutant has exactly ONE decision (its schema run shard or its fallback shard); every sample's real outcome equals
//     the schema outcome (run_error counts as caught); then writes the crate's two report shards (1: cargo-mutants, 2: statement),
//     their run-error lists (all on 1) and results.json. Any failure exits nonzero before anything is written.
//   node schema-collect.mjs --self-test
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const argv = process.argv.slice(2), cmd = argv[0];
const opt = (n, d) => argv.find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3) ?? d;
const rdj = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));
const files = (d, re) => { const o = []; const w = (x) => { if (!fs.existsSync(x)) return; for (const e of fs.readdirSync(x, { withFileTypes: true })) { const p = path.join(x, e.name); if (e.isDirectory()) w(p); else if (re.test(e.name)) o.push(p); } }; w(d); return o.sort(); };

// worker-minutes per real per-mutant build + test (measured on 0.6: ~4; a mutant whose schema text failed to compile is most
// likely unviable, which stops at the build)
const cost = (f) => (f.why?.startsWith('schema build') ? 1.2 : 4);
const h = (s) => crypto.createHash('sha256').update(s).digest('hex');

export function fbplan(decs, cmNames, runId, budget) {
  const pack = (items, kind, sample) => {
    const bins = [];
    for (const it of items.sort((a, b) => cost(b) - cost(a) || a.name.localeCompare(b.name))) {
      let b = bins.find((x) => x.c + cost(it) <= budget);
      if (!b) bins.push(b = { c: 0, names: [] });
      b.c += cost(it); b.names.push(it.name);
    }
    return bins.map((b) => ({ kind, sample, names: b.names.sort(), est: b.c }));
  };
  const fb = decs.flatMap((d) => d.fallback);
  const samples = [];
  for (const d of decs) for (let r = 0; r < d.runs; r++) {
    const cand = d.schema.filter((_, i) => i % d.runs === r);
    if (!cand.length) continue;
    const pick = cand.reduce((a, b) => (h(`${runId}\0${a}`) <= h(`${runId}\0${b}`) ? a : b));
    samples.push({ name: pick, why: '' });
  }
  const k = (it) => (cmNames.has(it.name) ? 'cm' : 'stmt');
  return [
    ...pack(fb.filter((x) => k(x) === 'cm'), 'cm', false), ...pack(fb.filter((x) => k(x) === 'stmt'), 'stmt', false),
    ...pack(samples.filter((x) => k(x) === 'cm'), 'cm', true), ...pack(samples.filter((x) => k(x) === 'stmt'), 'stmt', true),
  ];
}

const norm = (s) => (s === 'run_error' ? 'caught' : s);
export function collect(planned, schemaRes, fbRes, sampleRes) {
  const errs = [], dec = new Map();
  for (const [src, rs] of [['schema', schemaRes], ['fallback', fbRes]]) for (const x of rs) {
    if (!planned.has(x.name)) errs.push(`${src} result for a mutant not in the plan: ${x.name}`);
    else if (dec.has(x.name)) errs.push(`two decisions for ${x.name} (${dec.get(x.name).src} and ${src})`);
    else dec.set(x.name, { src, status: x.status });
  }
  for (const n of planned) if (!dec.has(n)) errs.push(`no decision for ${n}`);
  let same = 0;
  for (const s of sampleRes) {
    const d = dec.get(s.name);
    if (!d || d.src !== 'schema') errs.push(`sample ${s.name} is not a schema-decided mutant`);
    else if (norm(d.status) !== norm(s.status)) errs.push(`SCHEMA MISMATCH: ${s.name}: schema ${d.status}, real build ${s.status}`);
    else same++;
  }
  return { errs, dec, same };
}

if (argv.includes('--self-test')) {
  const P = new Set(['a', 'b', 'c']);
  const ok = collect(P, [{ name: 'a', status: 'caught' }, { name: 'b', status: 'missed' }], [{ name: 'c', status: 'unviable' }], [{ name: 'a', status: 'run_error' }]);
  const t = [
    [ok.errs.length === 0 && ok.same === 1, 'a consistent run passes'],
    [collect(P, [{ name: 'a', status: 'caught' }], [{ name: 'c', status: 'caught' }], []).errs.some((e) => e.startsWith('no decision')), 'a missing decision fails'],
    [collect(P, [{ name: 'a', status: 'caught' }, { name: 'b', status: 'caught' }, { name: 'c', status: 'caught' }], [{ name: 'c', status: 'caught' }], []).errs.some((e) => e.startsWith('two decisions')), 'a double decision fails'],
    [collect(P, [{ name: 'a', status: 'missed' }, { name: 'b', status: 'caught' }], [{ name: 'c', status: 'caught' }], [{ name: 'a', status: 'caught' }]).errs.some((e) => e.startsWith('SCHEMA MISMATCH')), 'a sample mismatch fails'],
  ];
  const fp = fbplan([{ runs: 2, schema: ['x1', 'x2', 'x3'], fallback: [{ name: 'f1', why: 'const fn' }, { name: 'f2', why: 'schema build: E0308' }] }], new Set(['x1', 'x2', 'f1']), '7', 4);
  t.push([fp.filter((e) => e.sample).flatMap((e) => e.names).length === 2, 'one sample per run shard']);
  t.push([fp.filter((e) => !e.sample).flatMap((e) => e.names).sort().join() === 'f1,f2', 'every fallback planned once']);
  t.push([fp.every((e) => e.est <= 4), 'the budget holds']);
  const bad = t.filter(([c]) => !c);
  for (const [, w] of bad) console.error('self-test failed: ' + w);
  if (bad.length) process.exit(1);
  console.log(`schema-collect self-test ok (${t.length} checks)`);
  process.exit(0);
}

const L = opt('list');
const cm = rdj(path.join(L, 'cm.json')), stmt = rdj(path.join(L, 'stmt.json'));
const decs = files(opt('decs'), /^dec\.json$/).map(rdj);
if (decs.length !== rdj(path.join(L, 'groups.json')).groups.length) { console.error(`::error::${decs.length} schema group decision(s), the plan has ${rdj(path.join(L, 'groups.json')).groups.length}`); process.exit(1); }

if (cmd === 'fbplan') {
  const cs = JSON.parse(opt('crates')), include = [], no = opt('names-out');
  fs.mkdirSync(no, { recursive: true });
  const c0 = cs.find((c) => c.schema);
  const ex = (c) => [...(c.exclude ? [`${c.dir}/${c.exclude}/**`] : []), ...(c.win ? c.win.split(',').map((f) => `${c.dir}/${f}`) : [])].join(',');
  const plan = fbplan(decs, new Set(cm.map((m) => m.name)), opt('run-id'), Number(opt('budget', '45')));
  plan.forEach((e, i) => {
    const id = `${e.sample ? 's' : 'f'}${i + 1}`;
    fs.writeFileSync(path.join(no, `${id}.json`), JSON.stringify(e.names));
    include.push({ key: c0.key, pkg: c0.pkg, dir: c0.dir, exclude: ex(c0), shard: id, of: plan.length, kind: e.kind, k0: 0, kof: 1, names: id, sample: e.sample });
  });
  for (const c of cs) if (!c.schema) for (let shard = 1; shard <= c.cm + c.stmt; shard++) {
    const isCm = shard <= c.cm;
    include.push({ key: c.key, pkg: c.pkg, dir: c.dir, exclude: ex(c), shard, of: c.cm + c.stmt, kind: isCm ? 'cm' : 'stmt', k0: isCm ? shard - 1 : shard - c.cm - 1, kof: isCm ? c.cm : c.stmt, names: '', sample: false });
  }
  const nf = decs.reduce((a, d) => a + d.fallback.length, 0), ns = plan.filter((e) => e.sample).reduce((a, e) => a + e.names.length, 0);
  console.error(`fallback: ${nf} mutant(s) in ${plan.filter((e) => !e.sample).length} job(s); samples: ${ns} in ${plan.filter((e) => e.sample).length} job(s); ${include.length} shard job(s) in all`);
  const why = {}; for (const d of decs) for (const f of d.fallback) { const w = f.why.replace(/: E\d+.*/, ''); why[w] = (why[w] ?? 0) + 1; }
  console.error('fallback reasons: ' + JSON.stringify(why));
  if (include.length > 256) { console.error(`::error::${include.length} shard jobs exceed one matrix (256)`); process.exit(1); }
  console.log('matrix=' + JSON.stringify({ include }));
  process.exit(0);
}
if (cmd !== 'collect') { console.error('usage: schema-collect.mjs fbplan|collect|--self-test'); process.exit(2); }

const planned = new Set([...cm, ...stmt].map((m) => m.name));
const sres = files(opt('sres'), /^results\.json$/), fres = files(opt('fres'), /^results\.json$/);
const schemaRes = sres.flatMap(rdj), fb = [], samples = [];
for (const f of fres) (fs.existsSync(path.join(path.dirname(f), 'SAMPLE')) ? samples : fb).push(...rdj(f));
const want = decs.reduce((a, d) => a + d.runs, 0);
const { errs, dec, same } = collect(planned, schemaRes, fb, samples);
if (sres.length !== want) errs.push(`${sres.length} schema run result file(s), the plan has ${want} run shards`);
const sampleWant = decs.reduce((a, d) => a + Math.min(d.runs, d.schema.length), 0);
if (samples.length !== sampleWant) errs.push(`${samples.length} sample result(s), the plan has ${sampleWant}`);
for (const e of errs.slice(0, 50)) console.error('::error::' + e);
if (errs.length) { console.error(`${errs.length} problem(s)`); process.exit(1); }
console.log(`${planned.size} mutant(s): ${schemaRes.length} decided by the schema runs, ${fb.length} by real per-mutant builds (fallback); ${same}/${samples.length} sample(s) identical both ways`);

// the run errors of the deciders (schema runs + fallback shards; a sample's are duplicates of its schema run's)
const runErrors = [];
for (const f of [...sres, ...fres.filter((f) => !fs.existsSync(path.join(path.dirname(f), 'SAMPLE')))]) {
  const re = path.join(path.dirname(f), 'run-errors.json');
  if (!fs.existsSync(re)) { console.error(`::error::no run-error list beside ${f}`); process.exit(1); }
  runErrors.push(...rdj(re));
}
const out = opt('out'), pre = opt('dir') + '/';
fs.mkdirSync(out, { recursive: true });
const lines = new Map(); const line = (f, n) => { if (!lines.has(f)) lines.set(f, fs.readFileSync(f, 'utf8').split('\n')); return (lines.get(f)[n - 1] || '').trim(); };
for (const [k, list] of [[1, cm], [2, stmt]]) {
  const counts = { caught: 0, missed: 0, timeout: 0, unviable: 0 }, surv = [];
  for (const m of list) {
    const s = norm(dec.get(m.name).status);
    if (!(s in counts)) { console.error(`::error::unknown outcome ${s} for ${m.name}`); process.exit(1); }
    counts[s]++;
    if (s === 'missed') {
      const p = /^(.+?):(\d+):(\d+): (.*)$/.exec(m.name);
      if (!p || !p[1].startsWith(pre)) { console.error(`::error::mutant outside the crate: ${m.name}`); process.exit(1); }
      surv.push({ crate: opt('key'), file: p[1].slice(pre.length), mutant: p[4], line: line(p[1], +p[2]), lineno: +p[2] });
    }
  }
  fs.writeFileSync(path.join(out, `counts-${k}.json`), JSON.stringify(counts));
  fs.writeFileSync(path.join(out, `survivors-${k}.json`), JSON.stringify(surv));
  console.log(`report ${k} (${k === 1 ? 'cargo-mutants' : 'statement'}): ${JSON.stringify(counts)}`);
}
fs.writeFileSync(path.join(out, 'run-errors-1.json'), JSON.stringify(runErrors, null, 1));
fs.writeFileSync(path.join(out, 'run-errors-2.json'), '[]');
fs.mkdirSync(path.join(out, 'mut-results'), { recursive: true });
fs.writeFileSync(path.join(out, 'mut-results', 'results.json'), JSON.stringify([...dec].map(([name, d]) => ({ key: `schema|${name}`, name, status: d.status, decided_by: d.src }))));
