#!/usr/bin/env node
// The Windows-only files (pca-rust mutation merge): each is mutated on windows-latest by BOTH tools (cargo-mutants and stmt-mut),
// every shard of each (file, tool) slice reported, its counts adding up to the slice's planned list, every mutant caught (no
// ledger on Windows), and no Linux shard reports a survivor in them (the Linux plan leaves them out; the snapshot job checks the
// plan itself). The check runs again on doctored copies (one Windows shard report dropped, one tool of a file dropped) and fails
// unless both are refused: the negative control.
//   node win-only-check.mjs --reports=<dir> --crate=<key> --win=src/a.rs,src/b.rs
// winonly-*.json (the windows job): { crate, os: "windows", tool: "cargo-mutants" | "stmt", file, k, n, planned, listed,
//   counts: {caught, missed, timeout, unviable}, survivors: [{crate, file, mutant, line, lineno}] }   (missed + timeout)
// shard-*.json (the Linux shards): mutation-shard-report.mjs's, survivors carry the crate-relative `file`.
import fs from 'node:fs';
import path from 'node:path';

const TOOLS = ['cargo-mutants', 'stmt'];
const opt = (n) => process.argv.slice(2).find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3);

export function check(win, linux, crate, files) {
  const errs = [], want = new Set(files), slices = new Map();
  for (const r of win) {
    const id = `${r.file} ${r.tool} ${r.k}/${r.n}`;
    if (r.crate !== crate || r.os !== 'windows') { errs.push(`${id}: report of another crate or OS`); continue; }
    if (!want.has(r.file)) { errs.push(`${id}: not a Windows-only file of this crate`); continue; }
    if (!TOOLS.includes(r.tool)) { errs.push(`${id}: unknown tool`); continue; }
    const n = Object.values(r.counts ?? {}).reduce((a, b) => a + b, 0);
    if (n !== r.listed) errs.push(`${id}: ${n} outcome(s) for ${r.listed} listed mutant(s)`);
    if ((r.survivors ?? []).length !== (r.counts?.missed ?? 0) + (r.counts?.timeout ?? 0)) errs.push(`${id}: survivor records do not match missed + timeout`);
    for (const s of r.survivors ?? []) errs.push(`${id}: SURVIVED on Windows (no ledger there): ${s.file}:${s.lineno} ${s.mutant}`);
    const key = `${r.file}\u0000${r.tool}`;
    if (!slices.has(key)) slices.set(key, []);
    slices.get(key).push(r);
  }
  for (const f of files) {
    for (const t of TOOLS) {
      const rs = slices.get(`${f}\u0000${t}`) ?? [];
      if (!rs.length) { errs.push(`${f}: no ${t} results from Windows`); continue; }
      const n = rs[0].n, planned = rs[0].planned;
      if (rs.some((r) => r.n !== n || r.planned !== planned)) { errs.push(`${f} ${t}: shard reports disagree on the shard count or the plan`); continue; }
      const ks = rs.map((r) => r.k).sort((a, b) => a - b);
      if (JSON.stringify(ks) !== JSON.stringify([...Array(n).keys()])) errs.push(`${f} ${t}: shards ${ks.join(',')} reported, want 0..${n - 1} once each`);
      const listed = rs.reduce((a, r) => a + r.listed, 0);
      if (listed !== planned) errs.push(`${f} ${t}: shards list ${listed} mutant(s), the slice plans ${planned}`);
    }
  }
  for (const r of linux) for (const s of r.survivors ?? []) if (want.has(s.file)) errs.push(`Linux shard ${r.shard} reports a mutant of the Windows-only ${s.file}: ${s.mutant}`);
  return errs;
}

function selfTest() {
  const rep = (file, tool, k, n, planned, listed, extra = {}) => ({ crate: 'c', os: 'windows', tool, file, k, n, planned, listed, counts: { caught: listed, missed: 0, timeout: 0, unviable: 0 }, survivors: [], ...extra });
  const good = [rep('src/w.rs', 'cargo-mutants', 0, 2, 5, 3), rep('src/w.rs', 'cargo-mutants', 1, 2, 5, 2), rep('src/w.rs', 'stmt', 0, 1, 0, 0)];
  const ok = (e) => { if (e.length) throw new Error(e.join('; ')); };
  const bad = (e) => { if (!e.length) throw new Error('expected a refusal'); };
  ok(check(good, [], 'c', ['src/w.rs']));
  bad(check(good.slice(1), [], 'c', ['src/w.rs'])); // a shard missing
  bad(check(good.slice(0, 2), [], 'c', ['src/w.rs'])); // a tool missing
  bad(check(good, [], 'c', ['src/w.rs', 'src/v.rs'])); // a file with no results
  bad(check([...good, good[0]], [], 'c', ['src/w.rs'])); // a shard twice
  bad(check([rep('src/w.rs', 'cargo-mutants', 0, 1, 5, 4), good[2]], [], 'c', ['src/w.rs'])); // a mutant not listed
  bad(check([...good.slice(0, 2), rep('src/w.rs', 'stmt', 0, 1, 1, 1, { counts: { caught: 0, missed: 1, timeout: 0, unviable: 0 }, survivors: [{ file: 'src/w.rs', mutant: 'm', lineno: 1 }] })], [], 'c', ['src/w.rs']));
  bad(check(good, [{ shard: 3, survivors: [{ file: 'src/w.rs', mutant: 'm' }] }], 'c', ['src/w.rs'])); // Linux mutated it
  console.log('win-only-check self-test ok');
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain && process.argv.includes('--self-test')) { selfTest(); process.exit(0); }
if (isMain) {
  const files = (opt('win') || '').split(',').filter(Boolean), crate = opt('crate');
  if (!files.length || !crate || !opt('reports')) { console.error('usage: win-only-check.mjs --reports=<dir> --crate=<key> --win=<files>'); process.exit(2); }
  const win = [], linux = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (/^winonly-.*\.json$/.test(e.name)) win.push(JSON.parse(fs.readFileSync(p, 'utf8'))); else if (/^shard-\d+\.json$/.test(e.name)) linux.push(JSON.parse(fs.readFileSync(p, 'utf8'))); } };
  walk(opt('reports'));
  const errs = check(win, linux, crate, files);
  for (const e of errs) console.error('::error::' + e);
  // negative control: one Windows shard report dropped, and one file's tool dropped, must each be refused
  let ctlBad = 0;
  if (win.length) {
    const t0 = win[0];
    for (const [what, rs] of [['one Windows report dropped', win.slice(1)], [`${t0.file}'s ${t0.tool} results dropped`, win.filter((r) => !(r.file === t0.file && r.tool === t0.tool))]]) {
      if (check(rs, linux, crate, files).length === 0) { console.error(`::error::negative control failed: the check passes with ${what}`); ctlBad++; }
      else console.log(`negative control (${what}): refused`);
    }
  }
  const total = win.reduce((a, r) => a + r.listed, 0);
  console.log(`Windows-only: ${files.length} file(s), ${win.length} report(s), ${total} mutant(s) (both tools); ${errs.length} problem(s)`);
  process.exit(errs.length || ctlBad ? 1 : 0);
}
