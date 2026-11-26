#!/usr/bin/env node
// Regenerates every ref-*.json.gz oracle corpus from tools/pca-audit/oracles/*.mts and compares it with the copies the native
// lanes commit (their test-data directories, fetched from the native repositories).
//   node oracle-corpora.mjs --lanes=<dir with the pca-<lang> clones> --report=<dir> [--jobs=4] [--shard=k/n | --list-generators]
// --shard=k/n runs generator shard k of n (longest-first over the measured generator times, so no shard is much longer than the vdf generator
// alone) and compares only the corpora those generators wrote; the shards together cover every generator (--list-generators prints them,
// the workflow's merge job checks the union of the shards' lists).
// Steps, as the generator headers say: tsx --tsconfig tools/pca-audit/oracles/tsconfig.json <generator>.mts (PCA_SEED_LOG names the
// seed labels each generator derived), then the key strip (strip-corpus-keys.py with those labels, the corpus-specific *-strip-keys.py
// and action-schema-strip.py) so no corpus carries raw key bytes, as the committed copies do. The -gen halves (cases carrying a
// private key) are never compared, never uploaded. Generators read only the public tree: withheld fixtures are not here to read.
// Writes <report>/corpora (the regenerated, stripped set), <report>/variants (lane-specific strips) and <report>/REPORT.md.
// Exit 1 on any generator or strip failure, any lane copy that differs from the regenerated corpus, and lane copies that disagree.
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { basename, join, relative, resolve } from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';

const arg = (k, d) => (process.argv.find((a) => a.startsWith(`--${k}=`)) ?? `--${k}=${d ?? ''}`).slice(k.length + 3);
const ROOT = resolve(arg('root', process.cwd()));
const LANES = resolve(arg('lanes'));
const REPORT = resolve(arg('report', 'oracle-report'));
const JOBS = Number(arg('jobs', '4'));
const OR = join(ROOT, 'tools/pca-audit/oracles');
const OUT = join(OR, 'out');
const TSX = join(ROOT, 'packages/pca/node_modules/.bin/tsx');
const SEEDS = join(REPORT, 'seed-labels');
const CORPORA = join(REPORT, 'corpora'), VARIANTS = join(REPORT, 'variants');
const problems = [];
const md = [];
const say = (s = '') => { md.push(s); console.log(s); };

rmSync(REPORT, { recursive: true, force: true });
for (const d of [SEEDS, CORPORA, VARIANTS]) mkdirSync(d, { recursive: true });
rmSync(OUT, { recursive: true, force: true });

// ---- 0. environment the generators were written for (this repository carries neither the native trees nor per-directory installs)
// (a) Some generators read a lane's committed data (test-data/*.json.gz) and write that lane's source data files (atlas_pca/*_data.py, ...)
//     under sdks/<lang>-pca; link every lane clone there. The writes land in the throwaway clone, never in a compared corpus.
// (b) Generators import jose, yaml and @noble/* bare from tools/, where pnpm's strict layout resolves nothing: expose the exact versions the
//     workspace packages that own them resolve, one directory up from the generators.
const link = (target, at) => { if (existsSync(target) && !existsSync(at)) { mkdirSync(resolve(at, '..'), { recursive: true }); symlinkSync(target, at, 'dir'); } };
for (const d of existsSync(LANES) ? readdirSync(LANES).filter((x) => x.startsWith('pca-')) : []) link(join(LANES, d), join(ROOT, 'sdks', `${d.slice(4)}-pca`));
for (const [mod, owner] of [['jose', 'pca-oidc'], ['yaml', 'pca-actions'], ['@noble', 'pca'], ['asn1js', 'pca'], ['pkijs', 'pca']]) link(join(ROOT, 'packages', owner, 'node_modules', mod), join(ROOT, 'tools/node_modules', mod));

// ---- 1. generators: every oracle that writes a corpus (the others emit source files or are imported helpers)
const gens = readdirSync(OR).filter((f) => f.endsWith('.mts')).filter((f) => f !== 'attest-roots-kit.mts' && /\b(refWrite|refWriteBlobs|splitWrite)\(/.test(readFileSync(join(OR, f), 'utf8'))).sort();
const allGens = gens.slice();
if (process.argv.includes('--list-generators')) { console.log(allGens.join('\n')); process.exit(0); }
const skipped = readdirSync(OR).filter((f) => f.endsWith('.mts') && !gens.includes(f));
// measured seconds of one generator pass (run 45568594634); anything else is ~10 s. Longest first onto the lightest shard.
const W = { 'vdf.mts': 459, 'abe-go.mts': 185, 'abe.mts': 179, 'analyzer.mts': 153, 'aggsig.mts': 93, 'frost-dkg.mts': 76, 'ratchet.mts': 74, 'attest-eat.mts': 60 };
const SHARD = arg('shard', '1/1').split('/').map(Number);
if (SHARD[1] > 1) {
  const bins = Array.from({ length: SHARD[1] }, () => ({ w: 0, g: [] }));
  for (const g of [...gens].sort((a, b) => (W[b] ?? 10) - (W[a] ?? 10) || a.localeCompare(b))) { const b = bins.reduce((m, x) => (x.w < m.w ? x : m)); b.w += W[g] ?? 10; b.g.push(g); }
  gens.splice(0, gens.length, ...bins[SHARD[0] - 1].g.sort());
  console.log(`shard ${SHARD[0]}/${SHARD[1]}: ${gens.length} of ${allGens.length} generators`);
}
writeFileSync(join(REPORT, 'generators.txt'), gens.join('\n') + '\n'); // the merge job checks the shards' union is every generator
const run1 = (g, extraEnv = {}) => new Promise((done) => {
  const t0 = Date.now();
  const p = spawn(TSX, ['--tsconfig', join(OR, 'tsconfig.json'), join(OR, g)], { cwd: ROOT, env: { ...process.env, ...extraEnv, PCA_SEED_LOG: join(SEEDS, g.replace(/\.mts$/, '.txt')), NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --import ${join(OR, 'determinism.mjs')}`.trim() }, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
  let err = '', timedOut = false;
  p.stderr.on('data', (d) => { err = (err + d).slice(-3000); });
  p.stdout.resume();
  // kill the whole process group: tsx runs the generator in a child that keeps the pipes open, so killing tsx alone never fires 'close'
  const timer = setTimeout(() => { timedOut = true; try { process.kill(-p.pid, 'SIGKILL'); } catch {} }, 30 * 60 * 1000);
  p.on('close', (code) => { clearTimeout(timer); done({ g, code: timedOut ? 'timeout (30 min)' : code, err, s: ((Date.now() - t0) / 1000).toFixed(0) }); });
});
const results = [];
let next = 0;
await Promise.all(Array.from({ length: JOBS }, async () => { while (next < gens.length) { const r = await run1(gens[next++]); results.push(r); console.log(`${r.code === 0 ? 'ok  ' : 'FAIL'} ${r.g} (${r.s}s)`); } }));
for (const r of results.filter((x) => x.code !== 0).sort((a, b) => a.g.localeCompare(b.g))) { problems.push(`generator ${r.g} exited ${r.code}`); console.log(`--- ${r.g}\n${r.err}`); }

// ---- 1b. determinism: a generator whose output once drifted between two runs of one commit (a proof nonce that was not pinned) is run
// a second time and must write the same bytes, before any strip
for (const g of ['oprf.mts', 'oprf-swift.mts']) {
  const name = `ref-${g.replace(/\.mts$/, '')}.json.gz`;
  if (!existsSync(join(OUT, name)) || results.some((r) => r.g === g && r.code !== 0)) continue;
  const first = readFileSync(join(OUT, name));
  const again = await run1(g);
  const second = existsSync(join(OUT, name)) ? readFileSync(join(OUT, name)) : Buffer.alloc(0);
  if (again.code !== 0 || !first.equals(second)) problems.push(`generator ${g} is not deterministic: two runs wrote different ${name}`);
  console.log(`${again.code === 0 && first.equals(second) ? 'same' : 'DIFF'} ${g} (second run)`);
}

// ---- 1b'. determinism: every generator runs a second time under the SAME frozen clock and must write the same bytes. A clock, a random source
// or any other input the shim does not control (a Date captured before it installs, performance.now, hrtime, an unseeded key) shows up here.
{
  const A1 = join(REPORT, 'same-clock-a');
  cpSync(OUT, A1, { recursive: true });
  let k = 0;
  await Promise.all(Array.from({ length: JOBS }, async () => { while (k < gens.length) { const r = await run1(gens[k++]); if (r.code !== 0) { problems.push(`generator ${r.g} exited ${r.code} on the same-clock rerun`); console.log(`FAIL ${r.g} same-clock rerun (${r.s}s)\n${r.err}`); } } }));
  const differ = readdirSync(A1).filter((f) => /^ref-.*\.json\.gz$/.test(f) && existsSync(join(OUT, f)) && !readFileSync(join(A1, f)).equals(readFileSync(join(OUT, f))));
  const caseLines = (p) => new Map(gunzipSync(readFileSync(p)).toString('utf8').split('\n').filter((l) => l.startsWith('{"fn"')).map((l) => [(l.match(/"name":("(?:[^"\\]|\\.)*")/) ?? [, l.slice(0, 60)])[1], l]));
  for (const f of differ) {
    const x = caseLines(join(A1, f)), y = caseLines(join(OUT, f));
    const which = [...new Set([...x.keys(), ...y.keys()])].filter((n) => x.get(n) !== y.get(n));
    problems.push(`${f} is not deterministic: two runs under the same clock wrote different bytes (${which.length} case(s): ${which.slice(0, 8).join(', ')}${which.length > 8 ? ', ...' : ''})`);
  }
  console.log(`determinism check: ${differ.length} corpus/corpora differ between two runs under the same clock${differ.length ? ': ' + differ.join(' ') : ''}`);
  rmSync(OUT, { recursive: true, force: true });
  cpSync(A1, OUT, { recursive: true });
  rmSync(A1, { recursive: true, force: true });
}

// ---- 1c. clock independence: the natives replay each case against THEIR clock, so a case whose expected result depends on the real clock
// (an exp / nbf / notAfter literal compared with the default clock) is wrong on one side of that date. Every generator runs again with the
// pinned clock moved five years on: a corpus that changes depends on the wall clock.
{
  const A = join(REPORT, 'clock-a');
  cpSync(OUT, A, { recursive: true });
  const later = String((process.env.PCA_ORACLE_NOW ? Number(process.env.PCA_ORACLE_NOW) : 1700000000000) + 5 * 365 * 86400000);
  const again = [];
  let k = 0;
  await Promise.all(Array.from({ length: JOBS }, async () => { while (k < gens.length) { const r = await run1(gens[k++], { PCA_ORACLE_NOW: later }); again.push(r); if (r.code !== 0) { problems.push(`generator ${r.g} exited ${r.code} with the clock five years on`); console.log(`FAIL ${r.g} clock-moved rerun (${r.s}s)\n${r.err}`); } } }));
  // the header records the clock the generator ran under ("clockMs"): that member is the one thing that is meant to move
  const noClock = (p) => gunzipSync(readFileSync(p)).toString('utf8').replace(/,"clockMs":-?\d+/, '');
  const moved = readdirSync(A).filter((f) => /^ref-.*\.json\.gz$/.test(f) && existsSync(join(OUT, f)) && noClock(join(A, f)) !== noClock(join(OUT, f)));
  const caseKey = (l) => { const m = l.match(/"name":("(?:[^"\\]|\\.)*")/); return m ? JSON.parse(m[1]) : l.slice(0, 60); };
  const caseNames = (p) => gunzipSync(readFileSync(p)).toString('utf8').split('\n').filter((l) => l.startsWith('{"fn"')).map((l) => [caseKey(l), l.replace(/,$/, '')]);
  // Every case runs against the frozen clock the generator ran under, and a case whose result carries that clock (an age, a "now" compared with a
  // literal date) cannot be reproduced under any other: those cases are named in the header as "clockCases", and a replay runs them with its clock
  // set to "clockMs" (the lanes read both members; no case name is hardcoded). A moved case that is not clock-derived would show up here too, so the
  // list is printed.
  const clockCases = new Map();
  for (const f of moved) {
    const before = new Map(caseNames(join(A, f))), after = new Map(caseNames(join(OUT, f)));
    const which = [...new Set([...before.keys(), ...after.keys()])].filter((k) => before.get(k) !== after.get(k));
    clockCases.set(f, which);
    console.log(`clock cases of ${f}: ${which.join(', ')}`);
  }
  console.log(`clock check: ${moved.length} corpus/corpora carry clock cases${moved.length ? ': ' + moved.join(' ') : ''}`);
  rmSync(OUT, { recursive: true, force: true });
  cpSync(A, OUT, { recursive: true });
  rmSync(A, { recursive: true, force: true });
  for (const [f, which] of clockCases) {
    const text = gunzipSync(readFileSync(join(OUT, f))).toString('utf8');
    const at = text.indexOf(',"cases":[\n');
    if (at < 0) { problems.push(`${f}: no cases member to attach clockCases to`); continue; }
    writeFileSync(join(OUT, f), gzipSync(Buffer.from(text.slice(0, at) + `,"clockCases":${JSON.stringify(which)}` + text.slice(at), 'utf8'), { level: 9, mtime: 0 }));
  }
}

// ---- 2. strip (no corpus may carry raw key bytes)
const py = (args, label) => {
  const r = spawnSync('python3', ['-I', ...args], { cwd: ROOT, encoding: 'utf8', env: { ...process.env, PCA_SEED_LABELS: SEEDS } });
  if (r.status !== 0) { problems.push(`${label} exited ${r.status}`); console.log(`--- ${label}\n${(r.stdout || '') + (r.stderr || '')}`.slice(0, 3000)); }
  return r.status === 0;
};
const corpusFiles = () => (existsSync(OUT) ? readdirSync(OUT).filter((f) => /^ref-.*\.json\.gz$/.test(f) && !/-gen\.json\.gz$/.test(f)).sort() : []);
const strip = (script, name, outName = name) => {
  const src = join(OUT, `ref-${name}.json.gz`);
  if (!existsSync(src)) return;
  const tmp = join(REPORT, `strip-${name}.tmp`);
  if (py([join(OR, script), src, tmp], `${script} ${name}`) && existsSync(tmp)) renameSync(tmp, src);
};
// --any: positional label-derived seeds (a bare argument, {"$bytes": x}) become {"$seed": label} too, so no corpus carries a derivable key
const all = corpusFiles().map((f) => join(OUT, f));
for (let i = 0; i < all.length; i += 40) py([join(OR, 'strip-corpus-keys.py'), '--any', ...all.slice(i, i + 40)], 'strip-corpus-keys.py --any');
for (const n of ['acp', 'bbs', 'notary', 'pq-threshold', 'scitt']) strip(`${n}-strip-keys.py`, n);
if (existsSync(join(OUT, 'ref-action-schema.json.gz'))) py([join(OR, 'action-schema-strip.py'), join(OUT, 'ref-action-schema.json.gz')], 'action-schema-strip.py');
// lane-specific copies (Swift): accepted next to the main corpus
for (const [script, name] of [['attest-eat-swift-strip.py', 'attest-eat'], ['wallet-swift-strip.py', 'wallet']]) {
  const src = join(OUT, `ref-${name}.json.gz`);
  if (existsSync(src)) py([join(OR, script), src, join(VARIANTS, `ref-${name}.json.gz`)], `${script}`);
}
for (const f of corpusFiles()) cpSync(join(OUT, f), join(CORPORA, f));

// ---- 3. compare with the lanes' committed copies
const lines = (gz) => gunzipSync(gz).toString('utf8');
const caseKey = (l) => { const m = l.match(/"name":("(?:[^"\\]|\\.)*")/); return m ? JSON.parse(m[1]) : l.slice(0, 60); };
function changedCases(a, b) { // a = regenerated, b = committed: names of cases that differ, appear or are missing
  const idx = (t) => { const m = new Map(); for (const l of t.split('\n')) if (l.includes('"fn"')) m.set(caseKey(l), (m.get(caseKey(l)) ?? []).concat(l.replace(/,$/, ''))); return m; };
  const A = idx(a), B = idx(b), out = [];
  for (const [k, v] of A) if (!B.has(k)) out.push(`+${k}`); else if (JSON.stringify(v) !== JSON.stringify(B.get(k))) out.push(`~${k}`);
  for (const k of B.keys()) if (!A.has(k)) out.push(`-${k}`);
  return out;
}
const laneDirs = existsSync(LANES) ? readdirSync(LANES).filter((d) => d.startsWith('pca-')).sort() : [];
const genOf = (p) => /"generator":"([^"]*)"/.exec(gunzipSync(readFileSync(p)).toString('utf8', 0, 600))?.[1] ?? null;
const byGen = new Map(); // generator header -> regenerated corpus names (a lane may carry a corpus under another file name)
for (const f of corpusFiles()) { const g = genOf(join(CORPORA, f)); if (g) byGen.set(g, [...(byGen.get(g) ?? []), f]); }
const laneFiles = new Map(); // corpus -> [{lane, path}]
const walk = (dir, depth, f) => { if (depth > 4) return; for (const e of readdirSync(dir, { withFileTypes: true })) { if (e.name === '.git' || e.name === 'node_modules') continue; const p = join(dir, e.name); if (e.isDirectory()) walk(p, depth + 1, f); else f(p); } };
for (const d of laneDirs) walk(join(LANES, d), 0, (p) => { const b = basename(p); if (/^ref-.*\.json\.gz$/.test(b) && !/-gen\.json\.gz$/.test(b)) {
  const g = genOf(p);
  // another shard's generator wrote this copy (java's ref-ciba.json.gz is ciba-java.mts output): it is compared in that shard, never with a same-named corpus here
  if (g && allGens.includes(g) && !gens.includes(g)) return;
  const c = byGen.get(g) ?? [];
  const key = existsSync(join(CORPORA, b)) && (c.length === 0 || c.includes(b)) ? b : c.length === 1 ? c[0] : b; // same name first, else the one corpus its generator wrote
  if (!laneFiles.has(key)) laneFiles.set(key, []); laneFiles.get(key).push({ lane: d.replace(/^pca-/, ''), path: relative(join(LANES, d), p), file: p });
} });

say('# Oracle corpora: regenerated vs the lanes\' committed copies');
say();
say(`generators run: ${gens.length} (${results.filter((r) => r.code === 0).length} ok); not corpus generators (emit sources or are imported): ${skipped.length}`);
say(`corpora regenerated: ${corpusFiles().length}; lane copies found: ${[...laneFiles.values()].reduce((n, v) => n + v.length, 0)} in ${laneDirs.length} lane repos`);
say();
let stale = 0, disagree = 0, orphans = [];
const sha = (s) => createHash('sha256').update(s).digest('hex').slice(0, 10);
for (const [name, copies] of [...laneFiles].sort()) {
  const fresh = existsSync(join(CORPORA, name)) ? lines(readFileSync(join(CORPORA, name))) : null;
  if (fresh === null) { orphans.push(name); continue; }
  const variant = existsSync(join(VARIANTS, name)) ? lines(readFileSync(join(VARIANTS, name))) : null;
  const groups = new Map(); // content hash -> {text, lanes}
  for (const c of copies) { const t = lines(readFileSync(c.file)); const k = sha(t); if (!groups.has(k)) groups.set(k, { text: t, lanes: [] }); groups.get(k).lanes.push(c.lane); }
  const bad = [...groups.values()].filter((g) => g.text !== fresh && g.text !== variant);
  if (groups.size > 1) disagree++;
  if (!bad.length) { if (groups.size > 1) say(`- ${name}: lane copies differ from each other, each equals the regenerated corpus or its lane-specific variant`); continue; }
  stale++;
  say(`## ${name}`);
  for (const g of bad) {
    const ch = changedCases(fresh, g.text);
    say(`- lanes ${g.lanes.join(', ')}: ${ch.length ? `${ch.length} case(s) changed` : 'same cases, other header or whitespace'} (+ new in regenerated, ~ changed, - only in the committed copy)`);
    for (const n of ch.slice(0, 25)) say(`    ${n}`);
    if (ch.length > 25) say(`    ... ${ch.length - 25} more`);
  }
  say(`- lane copies: ${groups.size} distinct content(s) among ${copies.length} lane(s)`);
}
say();
say(`## Summary`);
say(`- corpora whose lane copy differs from the regenerated one: ${stale}`);
say(`- corpora whose lane copies are not identical to each other: ${disagree}`);
if (orphans.length) say(`- lane copies with no generator output (not regenerated here): ${orphans.join(', ')}`);
const noLane = corpusFiles().filter((f) => !laneFiles.has(f) && f !== 'ref-dpop-rsa.json.gz'); // dpop-rsa carries the RSA test private key: lanes generate it in CI, never commit it
if (noLane.length) say(`- regenerated corpora no lane carries: ${noLane.join(', ')}`);
if (stale) problems.push(`${stale} corpus/corpora differ from the committed lane copies`);
if (!laneDirs.length) problems.push('no lane repositories found to compare with');
if (problems.length) { say(); say('## Failures'); for (const p of problems) say(`- ${p}`); }
writeFileSync(join(REPORT, 'REPORT.md'), md.join('\n') + '\n');
if (process.env.GITHUB_STEP_SUMMARY) writeFileSync(process.env.GITHUB_STEP_SUMMARY, md.join('\n').slice(0, 900000) + '\n', { flag: 'a' });
process.exit(problems.length ? 1 : 0);
