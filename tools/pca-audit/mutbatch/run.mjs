#!/usr/bin/env node
// Manual-mutant batch runner for the equivalent-mutant adversarial review.
// usage: node tools/pca-audit/mutbatch/run.mjs <spec.json> [parallel=4]   (run from the repo root, on a cloud box / queue job
//        after tools/pca-audit/mutbatch/prep.sh <pkgs...>; never on a laptop)
// spec: [{ name, pkg: "pca-abe", file: "abe.ts", from: "<exact text>", to: "<replacement>", nth?: k,
//          test?: "mutation-kill-x.test.ts", filters?: [vitest path filters] }]
// Each mutant is applied to a private copy of packages/<pkg> (node_modules symlinked) at packages/.mb-<name>.
// BASELINE: for every distinct (pkg, filters) the UNMUTATED copy is run first and its failing tests recorded; a mutant is
// KILLED only if some test fails that did not fail in the baseline (environmental / pre-existing failures never count).
// Output per mutant: KILLED (new failures) | SURVIVED | ABORT (text not found) | ERROR (no test output at all).
import fs from 'node:fs'; import path from 'node:path'; import { spawn } from 'node:child_process';
const root = process.cwd(); const spec = JSON.parse(fs.readFileSync(process.argv[2], 'utf8')); const par = Number(process.argv[3] ?? 4);
const base = path.join(root, 'packages'); // work dirs are packages/.mb-<name> so ../../tsconfig.base.json resolves

const ANSI = /\x1b\[[0-9;]*m/g;
function failures(out) {
  const s = new Set();
  for (const raw of out.split('\n')) {
    const l = raw.replace(ANSI, '');
    const m = /^\s*FAIL\s+(.+?)\s*$/.exec(l);
    if (m) s.add(m[1].replace(/\s+\d+ms$/, ''));
  }
  return s;
}
function copyPkg(pkgName, dst) {
  const pkg = path.join(root, 'packages', pkgName);
  fs.rmSync(dst, { recursive: true, force: true }); fs.mkdirSync(dst, { recursive: true });
  for (const ent of fs.readdirSync(pkg)) {
    if (['node_modules', 'dist', '.stryker-tmp', 'reports', 'coverage'].includes(ent)) continue;
    fs.cpSync(path.join(pkg, ent), path.join(dst, ent), { recursive: true });
  }
  fs.symlinkSync(path.join(pkg, 'node_modules'), path.join(dst, 'node_modules'));
}
function vitest(pkgName, dst, filters) {
  return new Promise((resolve) => {
    const pkg = path.join(root, 'packages', pkgName);
    const p = spawn(process.execPath, [path.join(pkg, 'node_modules', 'vitest', 'vitest.mjs'), 'run', ...filters, '--exclude', '**/node_modules/**'],
      { cwd: dst, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0' } });
    let out = ''; p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (out += d));
    const timer = setTimeout(() => p.kill('SIGKILL'), 900000);
    p.on('close', (code) => { clearTimeout(timer); resolve({ code, out }); });
  });
}
const filtersOf = (m) => m.filters ?? [`src/${m.test ?? ''}`];
const baselines = new Map();
async function baseline(m) {
  const key = m.pkg + '\0' + JSON.stringify(filtersOf(m));
  if (!baselines.has(key)) {
    baselines.set(key, (async () => {
      const dst = path.join(base, '.mb-base-' + Math.random().toString(36).slice(2));
      copyPkg(m.pkg, dst);
      const r = await vitest(m.pkg, dst, filtersOf(m));
      fs.rmSync(dst, { recursive: true, force: true });
      const f = failures(r.out);
      if (f.size) console.log(`[baseline] ${m.pkg} ${JSON.stringify(filtersOf(m))}: ${f.size} pre-existing failure(s)`);
      return { f, ran: /Tests\s+/.test(r.out) };
    })());
  }
  return baselines.get(key);
}
async function runOne(m) {
  const b = await baseline(m);
  const dst = path.join(base, '.mb-' + m.name);
  copyPkg(m.pkg, dst);
  const f = path.join(dst, 'src', m.file); const t = fs.readFileSync(f, 'utf8'); const n = t.split(m.from).length - 1;
  // `nth` (0-based) selects one occurrence of a line that appears several times; otherwise the line must be unique.
  if (m.nth === undefined ? n !== 1 : m.nth >= n) { fs.rmSync(dst, { recursive: true, force: true }); return `${m.name}: ABORT from-string occurs ${n} times`; }
  let at = -1; for (let k = 0; k <= (m.nth ?? 0); k++) at = t.indexOf(m.from, at + 1);
  fs.writeFileSync(f, t.slice(0, at) + m.to + t.slice(at + m.from.length));
  const r = await vitest(m.pkg, dst, filtersOf(m));
  fs.rmSync(dst, { recursive: true, force: true });
  const fresh = [...failures(r.out)].filter((x) => !b.f.has(x));
  if (fresh.length) return `${m.name}: KILLED (${fresh.length} new failure(s))${process.env.MB_FULL ? '\n  ' + fresh.slice(0, 8).join('\n  ') : ''}`;
  if (!/Tests\s+/.test(r.out.replace(ANSI, '')) && !b.ran) return `${m.name}: ERROR ${r.out.replace(ANSI, '').slice(-500).replace(/\n/g, ' ')}`;
  return `${m.name}: SURVIVED`;
}
const queue = [...spec];
await Promise.all(Array.from({ length: par }, async () => { while (queue.length) { const m = queue.shift(); console.log(await runOne(m)); } }));
