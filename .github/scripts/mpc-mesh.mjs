#!/usr/bin/env node
// One MIXED-language MPC mesh over real TLS, every node its own OS process, all started from the SAME JSON config the reference's
// party-main reads. Parties 0..n-1 run the languages named by --parties; in trusted-dealer mode the dealer (node n) runs --dealer.
// Passes only when every node exits ok, every party's composed decision equals the cleartext composition computed by the TypeScript
// reference (composeClear), and every party reports the SAME transcript digest (a mixed mesh that disagrees on any broadcast aborts).
//
//   node mpc-mesh.mjs --parties ts,go,rust --offline trusted-dealer --dealer java [--q 4] [--timeout-s 900] [--name A]
//   node mpc-mesh.mjs --ot lwe --parties ts,rust [--count 16]   a base-OT pair: node 0 the ot-sender, node 1 the ot-receiver; passes when both
//                                                               exit ok, report the same kind and matched === true (the receiver's pad hashes agree)
//
// Party programs come from the environment (set by the workflow after it builds them):
//   PCA_MESH_TS_MAIN   dist/net/party-main.js of @atlasauth/pca-mpc       (run with node)
//   PCA_MESH_GO        the pca-mpc-party binary built from sdks/go-pca/cmd/pca-mpc-party
//   PCA_MESH_RUST      the pca-mpc-party binary of sdks/rust-pca (feature mpc-net-driver)
//   PCA_MESH_JAVA_CP   classpath holding the compiled sdks/java-pca classes + bcprov + lazysodium + jna (+ icu4j); PCA_MESH_JAVA = java
//   PCA_MESH_PY_ROOT   sdks/python-pca (put on PYTHONPATH); PCA_MESH_PY = python3
//   PCA_MESH_RUBY_ROOT sdks/ruby-pca (lib/ on the load path); PCA_MESH_RUBY = ruby
//   PCA_MESH_PHP_ROOT  sdks/php-pca (composer-installed; bin/pca-mpc-party); PCA_MESH_PHP = php
//   PCA_MESH_KOTLIN_CP classpath holding the compiled sdks/kotlin-pca classes + kotlin-stdlib + bcprov + lazysodium + jna + icu4j; PCA_MESH_JAVA = java
//   PCA_MESH_SWIFT     the pca-mpc-party binary of sdks/swift-pca (built with ATLAS_PCA_MPC=1); PCA_MESH_SWIFT_LIB = directories for LD_LIBRARY_PATH (OpenSSL 3.5)
//   PCA_MESH_DOTNET    the pca-mpc-party.dll of sdks/dotnet-pca/AtlasPca.MpcParty; PCA_MESH_DOTNET_BIN = dotnet
//   PCA_MESH_LWEOT_DIR directory of liblweot (LD_LIBRARY_PATH of the lwe base-OT runs)
//   PCA_MESH_<LANG>_LWE  (go, rust, ts, java, swift); dotnet needs none (its party loads liblweot through ATLAS_LWEOT_LIB, set here from PCA_MESH_LWEOT_DIR) a party program that also runs the post-quantum endemic base OT (--ot lwe); used instead of PCA_MESH_<LANG>
//   PCA_MESH_REF_DIST  packages/pca-mpc/dist (for composeClear), default ./packages/pca-mpc/dist
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const arg = (k, d) => {
  const i = process.argv.indexOf(`--${k}`);
  return i >= 0 ? process.argv[i + 1] : d;
};
const parties = (arg('parties', '') || '').split(',').filter(Boolean);
const offline = arg('offline', 'no-dealer');
const dealerLang = arg('dealer', '');
const Q = Number(arg('q', '4'));
const timeoutMs = Number(arg('timeout-s', '900')) * 1000;
const ot = arg('ot', '');
const otCount = Number(arg('count', '16'));
const name = arg('name', `${parties.join('+')} ${offline}`);
const need = (k) => {
  if (!process.env[k]) throw new Error(`mpc-mesh: ${k} is not set`);
  return process.env[k];
};

/** The command prefix of one language's party program; the config path (or `keygen <dir> <cn>`) is appended. */
function program(lang) {
  const p = program0(lang);
  // the base-OT lattice library (liblweot) is loaded at run time by the cgo (Go) and JNA (Java) party programs
  if (ot === 'lwe' && process.env.PCA_MESH_LWEOT_DIR) p.env = { LD_LIBRARY_PATH: process.env.PCA_MESH_LWEOT_DIR, ...p.env };
  return p;
}
function program0(lang) {
  const v = (k) => (ot === 'lwe' && process.env[`${k}_LWE`]) || need(k);
  switch (lang) {
    case 'ts': return { cmd: [process.execPath, v('PCA_MESH_TS_MAIN')], env: {} };
    case 'go': return { cmd: [v('PCA_MESH_GO')], env: {} };
    case 'rust': return { cmd: [v('PCA_MESH_RUST')], env: {} };
    case 'java': return { cmd: [process.env.PCA_MESH_JAVA || 'java', '--enable-native-access=ALL-UNNAMED', '-cp', v('PCA_MESH_JAVA_CP'), 'net.atlasauth.pca.mpc.net.PartyMain'], env: ot === 'lwe' && process.env.PCA_MESH_LWEOT_LIB ? { JAVA_TOOL_OPTIONS: `-Dpca.lweot.lib=${process.env.PCA_MESH_LWEOT_LIB}` } : {} };
    case 'kotlin': return { cmd: [process.env.PCA_MESH_JAVA || 'java', '--enable-native-access=ALL-UNNAMED', '-cp', need('PCA_MESH_KOTLIN_CP'), 'net.atlasauth.pca.mpc.net.PartyMain'], env: {} };
    case 'ruby': return { cmd: [process.env.PCA_MESH_RUBY || 'ruby', '-I', join(need('PCA_MESH_RUBY_ROOT'), 'lib'), '-e', 'require "atlas_pca/mpc_net/party_main"; AtlasPca::Mpc::Net::PartyMain.main(ARGV)'], env: {} };
    case 'php': return { cmd: [process.env.PCA_MESH_PHP || 'php', join(need('PCA_MESH_PHP_ROOT'), 'bin', 'pca-mpc-party')], env: {} };
    case 'swift': return { cmd: [v('PCA_MESH_SWIFT')], env: process.env.PCA_MESH_SWIFT_LIB ? { LD_LIBRARY_PATH: [process.env.PCA_MESH_SWIFT_LIB, process.env.LD_LIBRARY_PATH].filter(Boolean).join(':') } : {} };
    case 'dotnet': return { cmd: [process.env.PCA_MESH_DOTNET_BIN || 'dotnet', need('PCA_MESH_DOTNET')], env: { ATLAS_MPC_TLS13: '1', ...(ot === 'lwe' && process.env.PCA_MESH_LWEOT_DIR ? { ATLAS_LWEOT_LIB: `${process.env.PCA_MESH_LWEOT_DIR}/liblweot.so` } : {}) } };
    case 'python': return { cmd: [process.env.PCA_MESH_PY || 'python3', '-m', 'atlas_pca.mpc_net_party'], env: { PYTHONPATH: need('PCA_MESH_PY_ROOT') } };
    default: throw new Error(`mpc-mesh: unknown language ${lang}`);
  }
}

if (ot ? (!['ec', 'lwe'].includes(ot) || parties.length !== 2) : (parties.length < 2 || !['trusted-dealer', 'no-dealer'].includes(offline) || (offline === 'trusted-dealer' && !dealerLang))) {
  console.error('usage: mpc-mesh.mjs --ot lwe --parties ts,rust [--count 16] |');
  console.error('usage: mpc-mesh.mjs --parties ts,go,rust [--offline trusted-dealer --dealer java | --offline no-dealer] [--q 4] [--timeout-s 900] [--name X]');
  process.exit(2);
}

const freePorts = async (n) => {
  const servers = await Promise.all(Array.from({ length: n }, () => new Promise((res, rej) => {
    const s = createServer();
    s.once('error', rej);
    s.listen(0, '127.0.0.1', () => res(s));
  })));
  const ports = servers.map((s) => s.address().port);
  await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
  return ports;
};

const run = (p, args, timeout) => {
  const r = spawnSync(p.cmd[0], [...p.cmd.slice(1), ...args], { encoding: 'utf8', env: { ...process.env, ...p.env }, timeout });
  return r;
};

const dist = resolve(process.env.PCA_MESH_REF_DIST || 'packages/pca-mpc/dist');
const { composeClear } = await import(pathToFileURL(join(dist, 'index.js')).href);
const vectors = [{ allow: 1, t: 2, rQuant: 1 }, { allow: 0, t: 1, rQuant: 2 }, { allow: 1, t: 3, rQuant: 0 }, { allow: 1, t: 1, rQuant: 3 }]
  .slice(0, parties.length)
  .map((v) => ({ ...v, rQuant: Math.min(v.rQuant, Q) }));
const expected = ot ? null : composeClear(vectors, Q);

const n = parties.length;
const langs = !ot && offline === 'trusted-dealer' ? [...parties, dealerLang] : parties;
const dir = mkdtempSync(join(tmpdir(), 'pca-mpc-mesh-'));
let failed = false;
try {
  const ports = await freePorts(langs.length);
  const ids = langs.map((lang, i) => {
    const d = join(dir, `n${i}`);
    const r = run(program(lang), ['keygen', d, `mpc-node-${i}`], 120_000);
    if (r.status !== 0) throw new Error(`keygen failed for node ${i} (${lang}): ${r.stderr || r.stdout}`);
    return { keyPath: join(d, 'key.pem'), certPath: join(d, 'cert.pem') };
  });
  const sessionId = randomBytes(8).toString('hex');
  const nodes = langs.map((_, i) => ({ id: i, host: '127.0.0.1', port: ports[i], certPath: ids[i].certPath }));
  const common = { n, Q, sessionId, listenHost: '127.0.0.1', nodes, recvTimeoutMs: Math.min(timeoutMs, 600_000), connectTimeoutMs: 120_000, ...(ot ? {} : { offline }) };
  const procs = langs.map((lang, i) => {
    const isDealer = i === n;
    const cfg = ot
      ? { ...common, role: i === 0 ? 'ot-sender' : 'ot-receiver', id: i, keyPath: ids[i].keyPath, certPath: ids[i].certPath, ot: { kind: ot, count: otCount } }
      : isDealer
      ? { ...common, role: 'dealer', id: i, keyPath: ids[i].keyPath, certPath: ids[i].certPath, insecureTrustedDealer: true, dealerSeed: '424242' }
      : { ...common, role: 'party', id: i, keyPath: ids[i].keyPath, certPath: ids[i].certPath, input: vectors[i], ...(offline === 'trusted-dealer' ? { insecureTrustedDealer: true } : {}) };
    const cfgPath = join(dir, `n${i}.json`);
    writeFileSync(cfgPath, JSON.stringify(cfg));
    const p = program(lang);
    const child = spawn(p.cmd[0], [...p.cmd.slice(1), cfgPath], { env: { ...process.env, ...p.env }, stdio: ['ignore', 'pipe', 'pipe'] });
    const o = { i, lang, role: cfg.role, out: '', err: '', code: null };
    child.stdout.on('data', (d) => (o.out += d));
    child.stderr.on('data', (d) => (o.err += d));
    o.done = new Promise((res) => child.on('close', (c) => { o.code = c; res(); }));
    o.kill = () => child.kill('SIGKILL');
    return o;
  });
  const timer = setTimeout(() => procs.forEach((p) => p.kill()), timeoutMs);
  await Promise.all(procs.map((p) => p.done));
  clearTimeout(timer);

  console.log(`mesh "${name}": ${langs.map((l, i) => `${i}:${l}${i === n ? '(dealer)' : ''}`).join(' ')}  ${ot ? `base OT ${ot} x${otCount}` : `Q=${Q}  expected ${JSON.stringify(expected)}`}`);
  const digests = new Set();
  for (const p of procs) {
    let j = null;
    try { j = JSON.parse(p.out.trim().split('\n').pop()); } catch { /* not JSON */ }
    let why = null;
    if (p.code !== 0 || !j || j.ok !== true) why = `exit ${p.code}: ${j ? JSON.stringify(j.error ?? j).slice(0, 600) : p.out.slice(0, 300)}`;
    else if (ot) {
      const r = j.result;
      if (!r || r.matched !== true) why = `base OT not matched: ${JSON.stringify(r)}`;
      else if (r.kind !== ot) why = `ran the '${r.kind}' base OT, not '${ot}'`;
      else if (r.role !== (p.role === 'ot-sender' ? 'sender' : 'receiver')) why = `reports role '${r.role}'`;
    } else if (p.role === 'party') {
      const c = j.result?.composed;
      if (!c || c.allow !== expected.allow || c.t !== expected.t || c.rQuant !== expected.rQuant) why = `composed ${JSON.stringify(c)} != expected`;
      else if (typeof j.result.transcriptDigest !== 'string') why = 'no transcriptDigest';
      else digests.add(j.result.transcriptDigest);
    }
    console.log(`  node ${p.i} ${p.lang} ${p.role}: ${why ? 'FAIL ' + why : 'ok'}`);
    if (why) {
      failed = true;
      if (p.err) console.log(`    stderr: ${p.err.slice(-800).replace(/\n/g, '\n    ')}`);
    }
  }
  if (!failed && !ot && digests.size !== 1) {
    failed = true;
    console.log(`  FAIL parties disagree on the transcript digest: ${[...digests].join(' ')}`);
  }
  console.log(failed ? `mesh "${name}": FAILED` : ot ? `mesh "${name}": both nodes ok, pads matched` : `mesh "${name}": every node ok, composed == composeClear, one transcript digest`);
} catch (e) {
  failed = true;
  console.error(`mesh "${name}": ${e.stack || e}`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
