#!/usr/bin/env node
// Targeted-mode driver for cargo-mutants (pca-rust mutation workflow; scheme: ../mut-carry).
//   node carry.mjs files   --pkg=<crate>                                     -> stdout: every source file holding a mutant (repo-relative)
//   node carry.mjs run     --pkg=<crate> --shard=<k0> --of=<N> --out=<dir> [--carry=<pool.json>] [--dry] [-- <extra cargo-mutants args>]
// `run` lists the shard's mutants (cargo-mutants' own `--shard k/N`), decides per mutant whether an earlier result stands, runs
// cargo-mutants on ONLY the rest (a name filter, verified against `--list` before running), and writes <dir>/mutants.out/
// {caught,missed,timeout,unviable}.txt for the COMPLETE shard (carried results included, current-source names) plus
// <dir>/results.json (the next run's baseline). With no pool every mutant runs, exactly as before.
// A result is carried when the mutant's function (cargo-mutants' span) and the file's code outside every mutated function are
// unchanged (comments / blank lines aside; doc comments count: they are doctests) and it was `caught`; `unviable` is carried only
// when the whole production source is unchanged. `missed` and `timeout` results always run again.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { sha, normText, mayCarry, loadPool } from '../mut-carry/lib.mjs';

const argv = process.argv.slice(2);
const cmd = argv[0];
const dd = argv.indexOf('--');
const mine = dd < 0 ? argv.slice(1) : argv.slice(1, dd), extra = dd < 0 ? [] : argv.slice(dd + 1);
const opt = (n) => mine.find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3);
const pkg = opt('pkg');
const base = ['mutants', '-p', pkg, '--all-features', '--no-shuffle'];

function list(shard) {
  const r = spawnSync('cargo', [...base, '--list', '--json', ...(shard ? ['--shard', shard] : [])], { encoding: 'utf8', maxBuffer: 1 << 29 });
  if (r.status !== 0) { console.error(r.stderr); throw new Error('cargo mutants --list failed'); }
  return JSON.parse(r.stdout);
}
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

if (cmd === 'files') {
  console.log([...new Set(list().map((m) => m.file))].sort().join('\n'));
  process.exit(0);
}
if (cmd !== 'run') { console.error('usage: carry.mjs files|run'); process.exit(2); }

const [k0, of, out] = [Number(opt('shard')), Number(opt('of')), path.resolve(opt('out'))];
const all = list(), shard = list(`${k0}/${of}`);
// ---- per-file identity
const files = {};
const fileInfo = (f) => files[f] ??= (() => {
  const lines = fs.readFileSync(f, 'utf8').split('\n');
  const spans = all.filter((m) => m.file === f && m.function).map((m) => [m.function.span.start.line - 1, m.function.span.end.line - 1]);
  const inDef = new Set(); for (const [a, b] of spans) for (let l = a; l <= b; l++) inDef.add(l);
  return { lines, shell: sha(normText(lines.filter((_, i) => !inDef.has(i)).join('\n'))), defHash: new Map() };
})();
const defHash = (m) => {
  const fi = fileInfo(m.file), s = m.function.span, k = `${s.start.line}:${s.end.line}`;
  if (!fi.defHash.has(k)) fi.defHash.set(k, sha(normText(fi.lines.slice(s.start.line - 1, s.end.line).join('\n'))));
  return fi.defHash.get(k);
};
const srcHash = sha([...new Set(all.map((m) => m.file))].sort().map((f) => f + '\0' + fs.readFileSync(f, 'utf8')).join('\0'));
// keys: occurrence counted over the FULL list (stable whichever shard a mutant lands in)
const occ = {}, ident = new Map();
for (const m of all) {
  const nm = m.name.replace(/^[^:]+:\d+:\d+: /, '');
  const b = `${m.file}|${m.function?.function_name ?? ''}|${m.function?.return_type ?? ''}|${m.genre}|${nm}`;
  ident.set(m.name, { key: `${b}|${occ[b] = (occ[b] ?? -1) + 1}`, def_hash: m.function ? defHash(m) : sha(''), shell_hash: fileInfo(m.file).shell, src_hash: srcHash });
}
const pool = opt('carry') ? loadPool(opt('carry')) : null;
if (opt('carry') && !pool) throw new Error(`cannot read --carry ${opt('carry')}`);

// ---- decide
const status = new Map(), toRun = [];
let unseen = 0, changed = 0, nonkill = 0;
for (const m of shard) {
  const id = ident.get(m.name), e = pool?.[id.key];
  if (!pool) toRun.push(m);
  else if (!e) { unseen++; toRun.push(m); }
  else if (e.d !== id.def_hash || e.h !== id.shell_hash) { changed++; toRun.push(m); }
  else if (mayCarry(e, id, { killed: ['caught'], uncompilable: ['unviable'] })) status.set(m.name, { s: e.s, carried: true });
  else { nonkill++; toRun.push(m); }
}
if (pool) console.error(`carry: ${shard.length - toRun.length} result(s) carried, ${toRun.length} to run (${unseen} unseen, ${changed} function/file changed, ${nonkill} earlier missed/timeout or unviable under changed sources)`);

// ---- run the rest
const cmOut = path.join(out, 'cm'); fs.rmSync(out, { recursive: true, force: true }); fs.mkdirSync(out, { recursive: true });
let rc = 0;
if (toRun.length) {
  const sel = [];
  const runNames = new Set(toRun.map((m) => m.name));
  for (const m of toRun) sel.push('-F', `^${esc(m.name)}$`);
  // cargo-mutants 27 lets the StructField mutants (2 in this crate: `delete field .. from struct ..`) through ANY name filter, -F and
  // -E alike. They run as extras (their outcomes are ignored unless they belong to this shard).
  const filt = pool ? sel : [];
  const quirk = all.filter((m) => m.genre === 'StructField').map((m) => m.name);
  if (pool) {
    const chk = spawnSync('cargo', [...base, '--list', '--json', ...filt], { encoding: 'utf8', maxBuffer: 1 << 29 });
    const got = JSON.parse(chk.stdout).map((m) => m.name).sort();
    const want = [...new Set([...runNames, ...quirk])].sort();
    if (JSON.stringify(got) !== JSON.stringify(want)) { console.error(`the name filter selects ${got.length} mutant(s), expected ${want.length} (selection plus the StructField quirk): refusing to guess`); process.exit(1); }
  }
  if (mine.includes('--dry')) { console.error(`dry run: the filter selects exactly the ${toRun.length} mutant(s) to run`); process.exit(0); }
  const args = [...base, ...(pool ? filt : ['--shard', `${k0}/${of}`]), ...extra, '--output', cmOut];
  // CARRY_ULIMIT_KB: address-space cap for the mutants' processes only (a runaway allocation must die alone); not for this driver
  const kb = process.env.CARRY_ULIMIT_KB;
  rc = (kb ? spawnSync('bash', ['-c', `ulimit -v ${Number(kb)}; exec "$@"`, 'bash', 'cargo', ...args], { stdio: 'inherit' }) : spawnSync('cargo', args, { stdio: 'inherit' })).status ?? 1;
  // 0 = all caught, 2 = some missed, 3 = some timed out (results); anything else is a tool failure
  if (![0, 2, 3].includes(rc)) { console.error(`::error::cargo-mutants exited ${rc}`); process.exit(1); }
  const oc = JSON.parse(fs.readFileSync(path.join(cmOut, 'mutants.out/outcomes.json'), 'utf8')).outcomes;
  const map = { CaughtMutant: 'caught', MissedMutant: 'missed', Timeout: 'timeout', Unviable: 'unviable' };
  for (const o of oc) { const n = o.scenario?.Mutant?.name; if (n && runNames.has(n) && map[o.summary]) status.set(n, { s: map[o.summary] }); }
  const missing = toRun.filter((m) => !status.has(m.name));
  if (missing.length) { console.error(`::error::no outcome for ${missing.length} mutant(s), e.g. ${missing[0].name}`); process.exit(1); }
}
// ---- the complete shard
const lists = { caught: [], missed: [], timeout: [], unviable: [] }, results = [];
for (const m of shard) {
  const r = status.get(m.name), id = ident.get(m.name);
  (lists[r.s] ??= []).push(m.name);
  results.push({ key: id.key, status: r.s, def_hash: id.def_hash, shell_hash: id.shell_hash, src_hash: id.src_hash, name: m.name, ...(r.carried ? { carried: true } : {}) });
}
fs.mkdirSync(path.join(out, 'mutants.out'), { recursive: true });
for (const [k, v] of Object.entries(lists)) fs.writeFileSync(path.join(out, 'mutants.out', `${k}.txt`), v.length ? v.join('\n') + '\n' : '');
fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify(results));
console.error(`shard ${k0}/${of}: ${shard.length} mutant(s): ${Object.entries(lists).map(([k, v]) => `${k} ${v.length}`).join(', ')}`);
process.exit(0);
