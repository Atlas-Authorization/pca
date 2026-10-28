#!/usr/bin/env node
// release-npm.mjs: the npm half of .github/workflows/release.yml. Run from the repository root.
//
//   node .github/scripts/release-npm.mjs plan                         the publish order, one "name@version" per line
//   node .github/scripts/release-npm.mjs filters                      pnpm --filter args that build the release set
//   node .github/scripts/release-npm.mjs check-version <X.Y.Z> [--warn] [--repo <owner/name>]
//                                                                     every package in the set is at <X.Y.Z> (lockstep;
//                                                                     --warn only warns) and, with --repo, declares that
//                                                                     repository in package.json (always an error)
//   node .github/scripts/release-npm.mjs pack <outdir> [--reproducible]
//                                                                     pin workspace: ranges in the manifests (below),
//                                                                     pnpm pack each package into <outdir> and write
//                                                                     <outdir>/publish-order.json; --reproducible packs
//                                                                     everything a second time and fails unless every
//                                                                     tarball is byte-identical
//   node .github/scripts/release-npm.mjs publish <outdir> [--dry-run] [--provenance] [--tag <dist-tag>]
//                                                                     npm publish each tarball in publish-order.json
//
// The release set: every packages/* directory whose name contains "pca", whose package.json is not private, and whose
// package name is @atlasauth/pca or @atlasauth/pca-* or create-pca-app.
// Order: dependencies first (dependencies, peerDependencies and optionalDependencies inside the set); among the packages
// that are ready, the core package @atlasauth/pca and the packages it depends on come first, then alphabetical. So the run
// opens with the core's own dependencies (its wasm and verified-core packages), then the core, then everything else.
// publish stops at the first failure, so a package is never published before what it depends on.
// publish is idempotent: a name@version already on npm is skipped, so a failed run can simply be re-run.
// Credentials: npm trusted publishing (OIDC) when the package has it configured; otherwise NPM_TOKEN from the
// environment, written to a temporary user config (never to the repository).
// pack rewrites every `workspace:` range in packages/*/package.json to the version pnpm would substitute (workspace:* ->
// X.Y.Z, workspace:^ -> ^X.Y.Z, workspace:~ -> ~X.Y.Z, workspace:<range> -> <range>) BEFORE packing: pnpm 9 makes the same
// substitution itself, but emits the rewritten dependencies in a run-dependent order, so the packed package.json (and
// the tarball hash) changed from one pack to the next. It edits the checkout in place; run it on a disposable tree.
// npm only accepts a provenance statement when the package's `repository` names the repository that built it, and it
// finds that out at upload time. check-version --repo finds it out before anything is published.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const CORE = '@atlasauth/pca';
const IN_SET = /^(@atlasauth\/pca(-[a-z0-9-]+)?|create-pca-app)$/;
const DEP_FIELDS = ['dependencies', 'peerDependencies', 'optionalDependencies'];

const [cmd, ...rest] = process.argv.slice(2);
const flag = (n) => rest.includes(`--${n}`);
const opt = (n) => { const i = rest.indexOf(`--${n}`); return i >= 0 ? rest[i + 1] : undefined; };
const die = (m, code = 1) => { console.error(`release-npm: ${m}`); process.exit(code); };
const summary = (line) => { if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, line + '\n'); };

function releaseSet() {
  const root = resolve('packages');
  if (!existsSync(root)) die('run from the repository root (no packages/ here)', 2);
  const pkgs = [];
  for (const dir of readdirSync(root).sort()) {
    const mf = join(root, dir, 'package.json');
    if (!/pca/.test(dir) || !existsSync(mf)) continue;
    const m = JSON.parse(readFileSync(mf, 'utf8'));
    if (m.private || !IN_SET.test(m.name ?? '')) continue;
    pkgs.push({ dir, abs: join(root, dir), name: m.name, version: m.version, manifest: m });
  }
  if (!pkgs.some((p) => p.name === CORE)) die(`the core package ${CORE} is not in the release set`);
  return pkgs;
}

function order(pkgs) {
  const byName = new Map(pkgs.map((p) => [p.name, p]));
  const deps = new Map(pkgs.map((p) => [p.name, new Set(DEP_FIELDS.flatMap((f) => Object.keys(p.manifest[f] ?? {})).filter((d) => byName.has(d) && d !== p.name))]));
  // the core and everything it depends on, transitively, inside the set
  const coreClosure = new Set();
  const visit = (n) => { if (coreClosure.has(n)) return; coreClosure.add(n); for (const d of deps.get(n) ?? []) visit(d); };
  if (byName.has(CORE)) visit(CORE);
  const rank = (p) => (p.name === CORE ? 0 : coreClosure.has(p.name) ? 1 : 2);
  const done = new Set();
  const out = [];
  while (out.length < pkgs.length) {
    const ready = pkgs.filter((p) => !done.has(p.name) && [...deps.get(p.name)].every((d) => done.has(d)))
      .sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));
    if (ready.length === 0) die('dependency cycle among: ' + pkgs.filter((p) => !done.has(p.name)).map((p) => p.name).join(', '));
    // one at a time, so the core goes first as soon as it is ready and each pick re-sorts
    done.add(ready[0].name);
    out.push(ready[0]);
  }
  return out;
}

// "git+https://github.com/Owner/Name.git", "github:Owner/Name", "https://github.com/Owner/Name" -> "owner/name"
function repoSlug(repository) {
  const url = typeof repository === 'string' ? repository : repository?.url ?? '';
  const m = /^(?:github:|(?:git\+)?(?:https?|ssh|git):\/\/(?:git@)?github\.com[/:]|git@github\.com:)([^/]+\/[^/#]+?)(?:\.git)?\/?$/i.exec(url.trim());
  return m ? m[1].toLowerCase() : null;
}

function pinWorkspaceRanges() {
  const root = resolve('packages');
  const manifests = readdirSync(root).sort().map((d) => join(root, d, 'package.json')).filter((f) => existsSync(f));
  const versions = new Map(manifests.map((f) => JSON.parse(readFileSync(f, 'utf8'))).filter((m) => m.name).map((m) => [m.name, m.version]));
  let pinned = 0;
  for (const f of manifests) {
    const m = JSON.parse(readFileSync(f, 'utf8'));
    let touched = false;
    for (const field of [...DEP_FIELDS, 'devDependencies']) {
      for (const [dep, range] of Object.entries(m[field] ?? {})) {
        if (typeof range !== 'string' || !range.startsWith('workspace:')) continue;
        const v = versions.get(dep);
        if (!v) die(`${m.name}: ${field}.${dep} is ${range} but no package in packages/ is named ${dep}`);
        const spec = range.slice('workspace:'.length);
        m[field][dep] = spec === '*' ? v : spec === '^' || spec === '~' ? spec + v : spec;
        touched = true;
        pinned++;
      }
    }
    if (touched) writeFileSync(f, JSON.stringify(m, null, 2) + '\n');
  }
  return pinned;
}

const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');

function packAll(pkgs, absOut) {
  const plan = [];
  for (const p of pkgs) {
    const r = run('pnpm', ['pack', '--pack-destination', absOut], { cwd: p.abs });
    if (r.status !== 0) die(`pnpm pack failed for ${p.name}:\n${r.out.split('\n').slice(-10).join('\n')}`);
    const file = tarballName(p);
    if (!existsSync(join(absOut, file))) die(`pnpm pack for ${p.name} did not produce ${file}`);
    const packed = JSON.parse(run('tar', ['-xOzf', join(absOut, file), 'package/package.json']).stdout);
    if (/"workspace:/.test(JSON.stringify(packed))) die(`${file}: packed manifest still has a workspace: range`);
    plan.push({ name: p.name, version: p.version, file });
  }
  return plan;
}

const tarballName = (p) => `${p.name.replace(/^@/, '').replace('/', '-')}-${p.version}.tgz`;

function run(bin, argv, opts = {}) {
  const r = spawnSync(bin, argv, { encoding: 'utf8', maxBuffer: 64 << 20, ...opts });
  return { status: r.status ?? 1, out: (r.stdout ?? '') + (r.stderr ?? ''), stdout: r.stdout ?? '' };
}

// 'live' | 'absent' | 'unknown'
function onNpm(name, version, env) {
  const r = run('npm', ['view', `${name}@${version}`, 'version', '--json'], { env });
  if (r.status === 0) {
    const v = r.stdout.trim();
    if (!v) return 'absent'; // npm prints nothing when the package exists but this version does not
    try { return [].concat(JSON.parse(v)).includes(version) ? 'live' : 'absent'; } catch { return 'unknown'; }
  }
  return /E404|404 Not Found|is not in this registry/.test(r.out) ? 'absent' : 'unknown';
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const RETRY_MS = Number(process.env.RELEASE_NPM_RETRY_MS ?? 20000); // back-off step between publish attempts

async function publish(dir) {
  const plan = JSON.parse(readFileSync(join(dir, 'publish-order.json'), 'utf8'));
  const dry = flag('dry-run');
  const env = { ...process.env };
  let tmp = null;
  const token = process.env.NPM_TOKEN ?? '';
  if (token) {
    tmp = mkdtempSync(join(process.env.RUNNER_TEMP ?? tmpdir(), 'npmrc-'));
    writeFileSync(join(tmp, '.npmrc'), `//registry.npmjs.org/:_authToken=${token}\n`, { mode: 0o600 });
    env.NPM_CONFIG_USERCONFIG = join(tmp, '.npmrc');
  }
  delete env.NPM_TOKEN;
  console.log(`credentials: ${token ? 'NPM_TOKEN (fallback) + trusted publishing when configured' : 'trusted publishing (OIDC) only'}`);
  summary(`### npm${dry ? ' (dry run: nothing uploaded)' : ''}\n\n| package | result |\n|---|---|`);
  const counts = { published: 0, skipped: 0, wouldPublish: 0 };
  let failed = null;
  try {
    for (const p of plan) {
      const file = join(dir, p.file);
      if (!existsSync(file)) { failed = `${p.name}: tarball ${p.file} missing`; break; }
      const state = onNpm(p.name, p.version, env);
      if (state === 'live') { console.log(`skip     ${p.name}@${p.version} (already on npm)`); summary(`| ${p.name}@${p.version} | already on npm |`); counts.skipped++; continue; }
      if (state === 'unknown' && !dry) { failed = `${p.name}: could not tell whether ${p.version} is already on npm`; break; }
      const tag = opt('tag') ?? (p.version.includes('-') ? 'next' : 'latest');
      const argv = ['publish', file, '--access', 'public', '--tag', tag];
      if (dry) argv.push('--dry-run');
      else if (flag('provenance')) argv.push('--provenance');
      let ok = false;
      let last = '';
      for (let attempt = 1; attempt <= 3 && !ok; attempt++) {
        const r = run('npm', argv, { env });
        last = r.out;
        if (r.status === 0) { ok = true; break; }
        // a timed-out request can still have landed: check before retrying
        if (!dry && onNpm(p.name, p.version, env) === 'live') { ok = true; break; }
        if (attempt < 3) { console.log(`retry    ${p.name}@${p.version} (attempt ${attempt} failed)`); await sleep(attempt * RETRY_MS); }
      }
      if (!ok) { console.error(last.split('\n').slice(-20).join('\n')); failed = `${p.name}@${p.version}: npm publish failed`; break; }
      console.log(`${dry ? 'dry-run ' : 'publish '} ${p.name}@${p.version} (dist-tag ${tag})`);
      summary(`| ${p.name}@${p.version} | ${dry ? 'would publish' : 'published'} (${tag}) |`);
      if (dry) counts.wouldPublish++; else counts.published++;
    }
  } finally {
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  }
  const line = `${counts.published} published, ${counts.wouldPublish} would publish, ${counts.skipped} already on npm, of ${plan.length}`;
  console.log(line);
  summary(`\n${line}`);
  if (failed) die(`${failed}. Stopped here; nothing after it in the order was published. Re-run after fixing (published versions are skipped).`);
}

switch (cmd) {
  case 'plan': {
    for (const p of order(releaseSet())) console.log(`${p.name}@${p.version}`);
    break;
  }
  case 'filters': {
    process.stdout.write(order(releaseSet()).map((p) => `--filter=${p.name}...`).join(' ') + '\n');
    break;
  }
  case 'check-version': {
    const want = rest[0];
    if (!want) die('check-version needs a version', 2);
    const set = releaseSet();
    const repo = opt('repo');
    if (repo) {
      const wrong = set.filter((p) => repoSlug(p.manifest.repository) !== repo.toLowerCase());
      if (wrong.length) {
        die(`${wrong.length} package(s) do not declare repository ${repo} (npm refuses their provenance): `
          + wrong.slice(0, 10).map((p) => `${p.name} (${JSON.stringify(p.manifest.repository?.url ?? p.manifest.repository ?? null)})`).join(', ')
          + (wrong.length > 10 ? ' ...' : ''));
      }
      console.log(`all ${set.length} packages declare repository ${repo}`);
    }
    const off = set.filter((p) => p.version !== want);
    if (off.length) {
      const msg = `${off.length} package(s) not at ${want}: ${off.slice(0, 10).map((p) => `${p.name}@${p.version}`).join(', ')}${off.length > 10 ? ' ...' : ''}`;
      if (flag('warn')) console.log(`::warning::${msg}`); else die(msg);
    } else console.log(`all ${set.length} packages are at ${want}`);
    break;
  }
  case 'pack': {
    const out = rest[0];
    if (!out) die('pack needs an output directory', 2);
    mkdirSync(out, { recursive: true });
    const absOut = resolve(out);
    const pkgs = order(releaseSet());
    console.log(`pinned ${pinWorkspaceRanges()} workspace: range(s) to their versions`);
    const plan = packAll(pkgs, absOut);
    for (const t of plan) console.log(`packed   ${t.file}`);
    if (flag('reproducible')) {
      // a second, independent pack of the same tree must give the same bytes: what was attested is what anyone rebuilds
      const again = mkdtempSync(join(process.env.RUNNER_TEMP ?? tmpdir(), 'repack-'));
      try {
        packAll(pkgs, again);
        const differ = plan.filter((t) => sha256(join(absOut, t.file)) !== sha256(join(again, t.file)));
        if (differ.length) die(`${differ.length} tarball(s) differ between two packs of the same tree: ${differ.map((t) => t.file).join(', ')}`);
        console.log(`reproducible: a second pack gave byte-identical tarballs for all ${plan.length}`);
        summary(`Reproducible: a second pack gave byte-identical tarballs for all ${plan.length} packages.`);
      } finally {
        rmSync(again, { recursive: true, force: true });
      }
    }
    writeFileSync(join(absOut, 'publish-order.json'), JSON.stringify(plan, null, 2) + '\n');
    console.log(`${plan.length} tarballs in ${out}`);
    break;
  }
  case 'publish': {
    if (!rest[0]) die('publish needs the directory pack wrote', 2);
    await publish(rest[0]);
    break;
  }
  default:
    die('usage: release-npm.mjs plan | filters | check-version <v> [--warn] [--repo o/n] | pack <outdir> [--reproducible] | publish <outdir> [--dry-run] [--provenance] [--tag t]', 2);
}
