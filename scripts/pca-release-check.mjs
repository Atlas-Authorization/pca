#!/usr/bin/env node
/**
 * PCA release gate. For every non-private PCA package (`packages/*pca*`, incl. create-pca-app):
 *   1. `pnpm pack` into a temp dir and audit the tarball (LICENSE/README/dist present; no tests,
 *      fixtures, private keys, .env, node_modules, cargo target dirs; no `workspace:` in the manifest;
 *      size budget);
 *   2. check every @atlasauth/* dependency/peerDependency is either in this release set (at the version
 *      being released) or already live on npm (skipped with --offline);
 *   3. install ALL tarballs together into one empty temp project and prove each package loads with
 *      import() and, when it has a CJS entry, require(); bin entries must exist.
 *
 * Usage: node scripts/pca-release-check.mjs [--offline] [--build] [--keep] [--budget-kb=N] [--only=a,b]
 *   --offline    skip the live-registry check (npm install still needs the npm cache for third-party deps;
 *                it is run with --prefer-offline)
 *   --build      run `pnpm -r build` for the PCA packages first
 *   --keep       keep the temp dir (path printed)
 *   --budget-kb  per-tarball size budget (default 1024; wasm packages get their own larger budget)
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
const flag = (n) => args.includes(`--${n}`);
const opt = (n, d) => (args.find((a) => a.startsWith(`--${n}=`)) ?? '').split('=')[1] ?? d;
const OFFLINE = flag('offline');
const BUDGET = Number(opt('budget-kb', '1024')) * 1024;
const WASM_BUDGET = 1024 * 1024; // wasm packages ship crate sources + vendored deps
const ONLY = opt('only', '') ? opt('only', '').split(',') : null;

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pkgRoot = join(root, 'packages');
const tmp = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'pca-release-'));
const packDir = join(tmp, 'tarballs');
mkdirSync(packDir);

const FORBIDDEN = [
  [/(^|\/)node_modules\//, 'node_modules'],
  [/(^|\/)target\//, 'cargo target dir'],
  [/(^|\/)(test|tests|__tests__|test-support|testdata|fixtures)\//, 'tests/fixtures'],
  [/\.test\.[cm]?[jt]sx?(\.map)?$|\.test\.d\.ts$|\.spec\.[cm]?[jt]sx?$|\.test-util\./, 'test file'],
  [/(^|\/)\.env(\.|$)/, '.env file'],
  [/\.(pem|key|p12|pfx|jks)$/i, 'key material'],
  [/(^|\/)\.git(\/|$)|(^|\/)\.DS_Store$/, 'VCS/OS junk'],
  [/^src\//, 'src directory (only dist should ship)'],
];
// vendored third-party crate sources legitimately contain their own tests/benches dirs; they are skipped
const VENDOR = /^package\/crate\/vendor\//;

const dirs = readdirSync(pkgRoot).filter((d) => (/pca/.test(d)) && existsSync(join(pkgRoot, d, 'package.json')));
const pkgs = [];
for (const d of dirs) {
  const m = JSON.parse(readFileSync(join(pkgRoot, d, 'package.json'), 'utf8'));
  if (m.private) continue;
  if (ONLY && !ONLY.includes(m.name)) continue;
  pkgs.push({ dir: d, abs: join(pkgRoot, d), name: m.name, version: m.version, manifest: m, errors: [], notes: [] });
}
if (flag('build')) {
  console.log('building PCA packages...');
  for (const p of pkgs) {
    const r = spawnSync('pnpm', ['--filter', p.name, 'build'], { cwd: root, encoding: 'utf8' });
    if (r.status !== 0) p.errors.push('build failed: ' + (r.stderr || r.stdout).split('\n').slice(-5).join(' | '));
  }
}
const versions = new Set(pkgs.map((p) => p.version));
const releaseSet = new Map(pkgs.map((p) => [p.name, p.version]));

// ---- 1. pack + audit -----------------------------------------------------------------------------
for (const p of pkgs) {
  if (!existsSync(join(p.abs, 'dist'))) p.errors.push('dist/ missing (run with --build)');
  const r = spawnSync('pnpm', ['pack', '--pack-destination', packDir], { cwd: p.abs, encoding: 'utf8' });
  if (r.status !== 0) { p.errors.push('pnpm pack failed: ' + (r.stderr || r.stdout).trim().split('\n').pop()); continue; }
  const tgz = join(packDir, `${p.name.replace('@', '').replace('/', '-')}-${p.version}.tgz`);
  if (!existsSync(tgz)) { p.errors.push('tarball not found at ' + tgz); continue; }
  p.tgz = tgz;
  p.size = statSync(tgz).size;
  const list = execFileSync('tar', ['-tzf', tgz], { encoding: 'utf8', maxBuffer: 64 << 20 }).split('\n').filter(Boolean).filter((f) => !f.endsWith('/'));
  p.files = list.length;
  const has = (re) => list.some((f) => re.test(f));
  if (!has(/^package\/LICENSE$/)) p.errors.push('LICENSE missing');
  if (!has(/^package\/README\.md$/)) p.errors.push('README.md missing');
  if (!has(/^package\/dist\/.+\.js$/)) p.errors.push('dist/*.js missing');
  const bad = new Map();
  for (const f of list) {
    if (VENDOR.test(f)) continue;
    for (const [re, why] of FORBIDDEN) if (re.test(f.replace(/^package\//, ''))) { bad.set(why, [...(bad.get(why) ?? []), f]); break; }
  }
  for (const [why, fs] of bad) p.errors.push(`forbidden (${why}): ${fs.slice(0, 3).join(', ')}${fs.length > 3 ? ` (+${fs.length - 3})` : ''}`);
  const man = JSON.parse(execFileSync('tar', ['-xOzf', tgz, 'package/package.json'], { encoding: 'utf8' }));
  p.packed = man;
  if (/workspace:/.test(JSON.stringify(man))) p.errors.push('manifest still contains "workspace:"');
  if (man.version !== p.version) p.errors.push(`packed version ${man.version} != ${p.version}`);
  if (man.license !== 'MIT') p.errors.push('license != MIT');
  const budget = /-wasm$/.test(p.dir) ? WASM_BUDGET : BUDGET;
  if (p.size > budget) p.errors.push(`size ${(p.size / 1024).toFixed(0)} KiB exceeds budget ${(budget / 1024).toFixed(0)} KiB`);
  // every file named by main/types/bin/exports must be in the tarball
  const refs = new Set();
  const walk = (v) => { if (typeof v === 'string') { if (v.startsWith('./')) refs.add(v.slice(2)); } else if (v && typeof v === 'object') Object.values(v).forEach(walk); };
  walk(man.exports); walk(man.main); walk(man.types); walk(man.bin);
  for (const f of refs) if (!list.includes('package/' + f)) p.errors.push(`manifest references missing file ${f}`);
  // wasm packages must ship the binary
  if (/-wasm$/.test(p.dir) && !has(/^package\/wasm\/.+\.wasm$/)) p.errors.push('wasm binary missing');
}

// ---- 2. @atlasauth/* dependency check --------------------------------------------------------------
const liveCache = new Map();
function liveVersions(name) {
  if (liveCache.has(name)) return liveCache.get(name);
  const r = spawnSync('npm', ['view', name, 'versions', '--json'], { encoding: 'utf8' });
  let v = [];
  if (r.status === 0) { try { v = [].concat(JSON.parse(r.stdout)); } catch { /* none */ } }
  liveCache.set(name, v);
  return v;
}
for (const p of pkgs) {
  if (!p.packed) continue;
  for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies']) {
    for (const [dep, range] of Object.entries(p.packed[field] ?? {})) {
      if (!dep.startsWith('@atlasauth/')) continue;
      if (releaseSet.has(dep)) {
        const want = releaseSet.get(dep);
        const ok = range === want || range === `^${want}` || range === `~${want}` || range === '*' || range.includes(want);
        if (!ok) p.errors.push(`${field}.${dep}=${range} does not match release ${want}`);
      } else if (OFFLINE) {
        p.notes.push(`unchecked: ${dep} (offline)`);
      } else {
        const live = liveVersions(dep);
        if (live.length === 0) p.errors.push(`${field}.${dep} is not in the release set and not live on npm`);
      }
    }
  }
}

// ---- 3. one-project install + load -----------------------------------------------------------------
const proj = join(tmp, 'project');
mkdirSync(proj);
writeFileSync(join(proj, 'package.json'), JSON.stringify({ name: 'pca-release-check', version: '0.0.0', private: true }));
const tgzs = pkgs.filter((p) => p.tgz).map((p) => p.tgz);
let installOk = false;
if (tgzs.length) {
  const inst = spawnSync('npm', ['install', '--no-audit', '--no-fund', '--prefer-offline', ...tgzs], { cwd: proj, encoding: 'utf8', maxBuffer: 64 << 20 });
  installOk = inst.status === 0;
  if (!installOk) console.error('npm install FAILED:\n' + (inst.stderr || inst.stdout).split('\n').slice(-25).join('\n'));
}
const nm = (n) => join(proj, 'node_modules', ...n.split('/'));
for (const p of pkgs) {
  p.esm = p.cjs = p.bin = '-';
  if (!installOk || !p.tgz) { p.errors.push('not installed'); continue; }
  const hasCjs = p.packed.type !== 'module';
  const imp = spawnSync(process.execPath, ['-e', `import(${JSON.stringify(p.name)}).then(m=>{if(!m||Object.keys(m).length===0)throw new Error('no exports')}).catch(e=>{console.error(e&&e.stack||e);process.exit(1)})`], { cwd: proj, encoding: 'utf8' });
  p.esm = imp.status === 0 ? 'ok' : 'FAIL';
  if (imp.status !== 0) p.errors.push('import() failed: ' + (imp.stderr || '').split('\n').slice(0, 2).join(' '));
  if (hasCjs) {
    const req = spawnSync(process.execPath, ['-e', `const m=require(${JSON.stringify(p.name)});if(!m||Object.keys(m).length===0)throw new Error('no exports')`], { cwd: proj, encoding: 'utf8' });
    p.cjs = req.status === 0 ? 'ok' : 'FAIL';
    if (req.status !== 0) p.errors.push('require() failed: ' + (req.stderr || '').split('\n').slice(0, 2).join(' '));
  }
  if (p.packed.bin) {
    const bins = typeof p.packed.bin === 'string' ? [p.packed.bin] : Object.values(p.packed.bin);
    const missing = bins.filter((b) => !existsSync(join(nm(p.name), b)));
    p.bin = missing.length ? 'FAIL' : 'ok';
    if (missing.length) p.errors.push('bin missing: ' + missing.join(','));
  }
}

// ---- report ----------------------------------------------------------------------------------------
const pad = (s, n) => String(s).padEnd(n);
console.log(`\n${pad('package', 36)}${pad('version', 8)}${pad('KiB', 7)}${pad('files', 7)}${pad('import', 8)}${pad('require', 9)}${pad('bin', 5)}result`);
let failed = 0;
for (const p of pkgs) {
  const ok = p.errors.length === 0;
  if (!ok) failed++;
  console.log(`${pad(p.name, 36)}${pad(p.version, 8)}${pad(p.size ? (p.size / 1024).toFixed(1) : '-', 7)}${pad(p.files ?? '-', 7)}${pad(p.esm, 8)}${pad(p.cjs, 9)}${pad(p.bin, 5)}${ok ? 'PASS' : 'FAIL'}`);
  for (const e of p.errors) console.log(`    ! ${e}`);
}
const sizes = pkgs.filter((p) => p.size).sort((a, b) => b.size - a.size);
console.log(`\n${pkgs.length} packages, ${pkgs.length - failed} pass, ${failed} fail. Versions in set: ${[...versions].join(', ')}`);
console.log('Largest tarballs: ' + sizes.slice(0, 5).map((p) => `${p.name} ${(p.size / 1024).toFixed(0)} KiB`).join('; '));
if (OFFLINE) console.log('(offline: live-registry dependency check skipped)');
if (flag('keep')) console.log('kept: ' + tmp); else rmSync(tmp, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
