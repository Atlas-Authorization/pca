/**
 * launch-local.ts with a scripted node program instead of party-main.js: every process prints the config file it was given and
 * the hook environment flag, so each field the launcher writes, the process wiring, the output parsing and the kill timer are
 * observable without running the MPC protocol. (Stryker: active mutant ids are forwarded to child processes in beforeEach.)
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { freePort, launchLocal, launchOtLocal } from './launch-local';
import type { NodeConfig } from './party-main';
import { T, until } from './test-timing';

let dir = '';
let echoJs = '';
let hangJs = '';
let noisyJs = '';
let stdinJs = '';
let oneLineJs = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'pca-launch-kill-'));
  echoJs = join(dir, 'echo.js');
  writeFileSync(
    echoJs,
    `const fs = require('fs');
const p = process.argv[2];
const cfg = JSON.parse(fs.readFileSync(p, 'utf8'));
const files = { key: fs.existsSync(cfg.keyPath), cert: fs.existsSync(cfg.certPath) };
const certs = cfg.nodes.map((n) => fs.readFileSync(n.certPath, 'utf8').includes('BEGIN CERTIFICATE'));
const cns = cfg.nodes.map((n) => new (require('crypto').X509Certificate)(fs.readFileSync(n.certPath)).subject);
const mark = process.env.PCA_LAUNCH_TEST_MARK ?? null;
process.stdout.write('not json\\n');
process.stdout.write(JSON.stringify({ cfg, cfgPath: p, hooksEnv: process.env.PCA_MPC_UNSAFE_TEST_HOOKS ?? null, files, certs, cns, mark }) + '\\n\\n');
`,
  );
  hangJs = join(dir, 'hang.js');
  writeFileSync(hangJs, `process.stdout.write('{"started":true}\\n'); setInterval(() => {}, 1000);\n`);
  stdinJs = join(dir, 'stdin.js');
  writeFileSync(stdinJs, `process.stdin.on('data', () => {}); process.stdin.on('end', () => process.stdout.write('{"stdinEnded":true}\\n')); process.stdin.resume();\n`);
  oneLineJs = join(dir, 'oneline.js');
  writeFileSync(oneLineJs, `process.stdout.write('{"one":1}\\n   \\n');\n`);
  noisyJs = join(dir, 'noisy.js');
  writeFileSync(noisyJs, `process.stderr.write('e'.repeat(3000)); process.stdout.write('first line\\n{"x":1}\\n{"x":2}'); process.exitCode = 5;\n`);
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));
beforeEach(() => {
  const am = (globalThis as { __stryker__?: { activeMutant?: unknown } }).__stryker__?.activeMutant;
  if (am === undefined) delete process.env.__STRYKER_ACTIVE_MUTANT__;
  else process.env.__STRYKER_ACTIVE_MUTANT__ = String(am);
});

type Echo = { cfg: NodeConfig; cfgPath: string; hooksEnv: string | null; files: { key: boolean; cert: boolean }; certs: boolean[]; cns: string[]; mark: string | null };
const V = [
  { allow: 1, t: 1, rQuant: 2 },
  { allow: 0, t: 3, rQuant: 0 },
] as const;

describe('freePort', () => {
  it('returns a port that can be listened on', async () => {
    const p = await freePort();
    expect(Number.isInteger(p)).toBe(true);
    expect(p).toBeGreaterThan(0);
    const s = net.createServer();
    await new Promise<void>((r) => s.listen(p, '127.0.0.1', () => r()));
    s.close();
  });
});

describe('launchLocal (scripted node program)', () => {
  it('trusted-dealer: n parties + one dealer, each given its own complete config', async () => {
    const r = await launchLocal({ n: 2, Q: 7, vectors: [...V], mainJs: echoJs, dealerSeed: '42', recvTimeoutMs: 1234 });
    expect(r.outputs.map((o) => [o.id, o.role, o.exitCode])).toEqual([[0, 'party', 0], [1, 'party', 0], [2, 'dealer', 0]]);
    expect(r.proxyLog).toEqual([]);
    expect(r.wallMs).toBeGreaterThanOrEqual(0);
    expect(r.wallMs).toBeLessThan(600_000);
    const e = r.outputs.map((o) => o.json as Echo);
    const sid = e[0]!.cfg.sessionId;
    expect(sid).toMatch(/^[0-9a-f]{16}$/);
    const ports = e[0]!.cfg.nodes.map((x) => x.port);
    expect(new Set(ports).size).toBe(3);
    for (const [id, x] of e.entries()) {
      const c = x.cfg;
      expect(c.role).toBe(id === 2 ? 'dealer' : 'party');
      expect(c.id).toBe(id);
      expect(c.n).toBe(2);
      expect(c.Q).toBe(7);
      expect(c.offline).toBeUndefined();
      expect(c.sessionId).toBe(sid);
      expect(c.input).toEqual(id < 2 ? V[id] : undefined);
      expect(c.listenHost).toBe('127.0.0.1');
      expect(c.nodes.map((n) => [n.id, n.host, n.port])).toEqual(ports.map((p, j) => [j, '127.0.0.1', p]));
      expect(x.certs).toEqual([true, true, true]);
      expect(x.cns).toEqual(['CN=mpc-node-0', 'CN=mpc-node-1', 'CN=mpc-node-2']);
      expect(x.files).toEqual({ key: true, cert: true });
      expect(c.keyPath.endsWith(join(`node${id}`, 'key.pem'))).toBe(true);
      expect(c.certPath).toBe(c.nodes[id]!.certPath);
      expect(c.recvTimeoutMs).toBe(T(1234));
      expect(c.connectTimeoutMs).toBe(T(120_000));
      expect(c.dealerSeed).toBe(id === 2 ? '42' : undefined);
      expect(c.unsafeTestHooks).toBeUndefined();
      expect(x.hooksEnv).toBeNull();
      expect(x.cfgPath.endsWith(`cfg${id}.json`)).toBe(true);
      expect(existsSync(x.cfgPath)).toBe(false); // the run directory is removed afterwards
    }
    expect(new Set(e.map((x) => x.cfg.keyPath)).size).toBe(3);
  });
  it('defaults: recvTimeoutMs 30 s; every node gets a distinct identity', async () => {
    const r = await launchLocal({ n: 1, vectors: [V[0]], mainJs: echoJs });
    const e = r.outputs.map((o) => o.json as Echo);
    expect(e.map((x) => x.cfg.recvTimeoutMs)).toEqual([T(30_000), T(30_000)]);
    expect(e[0]!.cfg.Q).toBeUndefined();
    expect(e[1]!.cfg.dealerSeed).toBeUndefined();
    const certA = readCert(e[0]!.cfg.nodes[0]!.certPath);
    expect(certA).toBeNull(); // removed with the run directory
  });
  it('no-dealer: exactly n party processes, all with offline no-dealer', async () => {
    const r = await launchLocal({ n: 2, vectors: [...V], mainJs: echoJs, offline: 'no-dealer' });
    expect(r.outputs.map((o) => [o.id, o.role])).toEqual([[0, 'party'], [1, 'party']]);
    for (const o of r.outputs) {
      const c = (o.json as Echo).cfg;
      expect(c.role).toBe('party');
      expect(c.offline).toBe('no-dealer');
      expect(c.nodes.length).toBe(2);
      expect(c.input).toEqual(V[c.id]);
    }
  });
  it('overrides are merged per node; a test hook marks the config and sets the hook environment for that node only', async () => {
    const r = await launchLocal({
      n: 2,
      vectors: [...V],
      mainJs: echoJs,
      overrides: { 1: { behavior: { kind: 'open-lie', round: 'mul0' }, recvTimeoutMs: 5 }, 2: { dealerFault: { macFaultAtInput: 3 } } },
    });
    const e = r.outputs.map((o) => o.json as Echo);
    expect(e[0]!.cfg.unsafeTestHooks).toBeUndefined();
    expect(e[0]!.hooksEnv).toBeNull();
    expect(e[1]!.cfg.behavior).toEqual({ kind: 'open-lie', round: 'mul0' });
    expect(e[1]!.cfg.recvTimeoutMs).toBe(5);
    expect(e[1]!.cfg.unsafeTestHooks).toBe(true);
    expect(e[1]!.hooksEnv).toBe('1');
    expect(e[2]!.cfg.dealerFault).toEqual({ macFaultAtInput: 3 });
    expect(e[2]!.cfg.unsafeTestHooks).toBe(true);
    expect(e[2]!.hooksEnv).toBe('1');
    const ff = await launchLocal({ n: 1, vectors: [V[0]], mainJs: echoJs, overrides: { 0: { frameFault: { kind: 'drop', round: 'x' } } } });
    expect((ff.outputs[0]!.json as Echo).hooksEnv).toBe('1');
    expect((ff.outputs[1]!.json as Echo).hooksEnv).toBeNull();
  });
  it('nodes inherit the test process environment, except its hook flag when they have no hooks', async () => {
    process.env.PCA_MPC_UNSAFE_TEST_HOOKS = '1';
    process.env.PCA_LAUNCH_TEST_MARK = 'inherited';
    try {
      const r = await launchLocal({ n: 1, vectors: [V[0]], mainJs: echoJs, overrides: { 1: { behavior: { kind: 'crash', round: 'x' } } } });
      expect(r.outputs.map((o) => (o.json as Echo).hooksEnv)).toEqual([null, '1']);
      expect(r.outputs.map((o) => (o.json as Echo).mark)).toEqual(['inherited', 'inherited']);
    } finally {
      delete process.env.PCA_MPC_UNSAFE_TEST_HOOKS;
      delete process.env.PCA_LAUNCH_TEST_MARK;
    }
  });
  it('a node gets no stdin (it sees end-of-input at once)', async () => {
    const r = await launchLocal({ n: 1, vectors: [V[0]], mainJs: stdinJs, offline: 'no-dealer', killAfterMs: 10_000 });
    expect(r.outputs[0]!.json).toEqual({ stdinEnded: true });
    const o = await launchOtLocal({ kind: 'ec', count: 1, mainJs: stdinJs, killAfterMs: 10_000 });
    expect(o.outputs.map((x) => x.json)).toEqual([{ stdinEnded: true }, { stdinEnded: true }]);
  }, 30_000);
  it('trailing whitespace-only lines are ignored when reading the verdict', async () => {
    const r = await launchLocal({ n: 1, vectors: [V[0]], mainJs: oneLineJs, offline: 'no-dealer' });
    expect(r.outputs[0]!.json).toEqual({ one: 1 });
    const o = await launchOtLocal({ kind: 'ec', count: 1, mainJs: oneLineJs });
    expect(o.outputs.map((x) => x.json)).toEqual([{ one: 1 }, { one: 1 }]);
  });
  it('a wire fault routes exactly one link (dialer -> target) through a proxy on its own port, with the delay scaled', async () => {
    const r = await launchLocal({ n: 2, vectors: [...V], mainJs: echoJs, wireFault: { dialer: 1, target: 0, fault: { kind: 'delay', dir: 'c2s', afterBytes: 0, ms: 10 } } });
    const e = r.outputs.map((o) => o.json as Echo);
    const real = e[0]!.cfg.nodes.map((n) => n.port);
    const seenBy1 = e[1]!.cfg.nodes.map((n) => n.port);
    expect(seenBy1[1]).toBe(real[1]);
    expect(seenBy1[2]).toBe(real[2]);
    expect(seenBy1[0]).not.toBe(real[0]);
    expect(real).not.toContain(seenBy1[0]);
    expect(e[2]!.cfg.nodes.map((n) => n.port)).toEqual(real);
    expect(e[0]!.cfg.nodes.map((n) => n.port)).toEqual(real);
    // the proxy is closed after the run: its port becomes free again
    await until(
      () =>
        new Promise<boolean>((res) => {
          const s = net.createServer();
          s.once('error', () => res(false));
          s.listen(seenBy1[0], '127.0.0.1', () => s.close(() => res(true)));
        }),
      'the proxy port to be released',
      5000,
    );
  });
  it('the proxy forwards to the target node and logs a fired fault', async () => {
    // node 0's program listens on its own port and echoes one byte, so traffic through the proxy reaches the target
    const srvJs = join(dir, 'srv.js');
    writeFileSync(
      srvJs,
      `const fs = require('fs'); const net = require('net');
const cfg = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const me = cfg.nodes[cfg.id];
if (cfg.id === 0) {
  const s = net.createServer((c) => { c.on('data', () => { c.end('ok'); s.close(); }); });
  s.listen(me.port, '127.0.0.1', () => process.stdout.write('{"listening":true}\\n'));
} else if (cfg.id === 1) {
  const target = cfg.nodes[0];
  const tryIt = () => {
    const c = net.connect(target.port, '127.0.0.1');
    let got = '';
    let t = 0;
    c.on('connect', () => ((t = Date.now()), c.write('x'.repeat(10))));
    c.on('data', (d) => (got += d));
    c.on('error', () => undefined);
    // the proxy accepts before node 0 listens and then drops us: try again until node 0 answers
    c.on('close', () => (got === '' ? setTimeout(tryIt, 50) : process.stdout.write(JSON.stringify({ got, ms: Date.now() - t }) + '\\n')));
  };
  tryIt();
} else process.stdout.write('{}\\n');
`,
    );
    const r = await launchLocal({ n: 2, vectors: [...V], mainJs: srvJs, wireFault: { dialer: 1, target: 0, fault: { kind: 'none', dir: 'c2s', afterBytes: 0 } } });
    expect(r.outputs[1]!.json).toMatchObject({ got: 'ok' });
    expect(r.proxyLog).toEqual([]);
    const r2 = await launchLocal({ n: 2, vectors: [...V], mainJs: srvJs, wireFault: { dialer: 1, target: 0, fault: { kind: 'bitflip', dir: 'c2s', afterBytes: 0 } } });
    expect(r2.outputs[1]!.json).toMatchObject({ got: 'ok' });
    expect(r2.proxyLog).toEqual(['fault bitflip c2s after 0B']);
    // a delay fault without ms keeps the proxy's one-second default (the launcher only scales an ms that was given)
    const r3 = await launchLocal({ n: 2, vectors: [...V], mainJs: srvJs, wireFault: { dialer: 1, target: 0, fault: { kind: 'delay', dir: 'c2s', afterBytes: 0 } } });
    expect(r3.outputs[1]!.json.got).toBe('ok');
    expect(r3.outputs[1]!.json.ms).toBeGreaterThanOrEqual(950);
    expect(r3.proxyLog).toEqual(['fault delay c2s after 0B']);
  }, 60_000);
  it('output: the last non-empty stdout line is parsed; stderr is kept up to 2000 characters; the exit code is reported', async () => {
    const r = await launchLocal({ n: 1, vectors: [V[0]], mainJs: noisyJs, offline: 'no-dealer' });
    expect(r.outputs.length).toBe(1);
    expect(r.outputs[0]!.json).toEqual({ x: 2 });
    expect(r.outputs[0]!.stderr).toBe('e'.repeat(2000));
    expect(r.outputs[0]!.exitCode).toBe(5);
  });
  it('a program that prints nothing parseable gives json null', async () => {
    const bad = join(dir, 'bad.js');
    writeFileSync(bad, `process.stdout.write('{not json');\n`);
    const r = await launchLocal({ n: 1, vectors: [V[0]], mainJs: bad, offline: 'no-dealer' });
    expect(r.outputs[0]!.json).toBeNull();
    const silent = join(dir, 'silent.js');
    writeFileSync(silent, `\n`);
    const r2 = await launchLocal({ n: 1, vectors: [V[0]], mainJs: silent, offline: 'no-dealer' });
    expect(r2.outputs[0]!.json).toBeNull();
    expect(r2.outputs[0]!.exitCode).toBe(0);
  });
  it('a node that never exits is killed after killAfterMs (exit code null)', async () => {
    const t0 = Date.now();
    const r = await launchLocal({ n: 1, vectors: [V[0]], mainJs: hangJs, offline: 'no-dealer', killAfterMs: 1500 });
    expect(r.outputs[0]!.exitCode).toBeNull();
    expect(r.outputs[0]!.json).toEqual({ started: true });
    expect(Date.now() - t0).toBeGreaterThanOrEqual(T(1500) - 50);
  });
});

describe('launchOtLocal (scripted node program)', () => {
  it('two nodes: an OT sender and an OT receiver with the requested kind and count', async () => {
    const r = await launchOtLocal({ kind: 'lwe', count: 3, mainJs: echoJs, recvTimeoutMs: 777 });
    expect(r.outputs.map((o) => [o.id, o.role, o.exitCode])).toEqual([[0, 'dealer', 0], [1, 'party', 0]]);
    expect(r.wallMs).toBeGreaterThanOrEqual(0);
    expect(r.wallMs).toBeLessThan(600_000);
    const e = r.outputs.map((o) => o.json as Echo);
    const ports = e[0]!.cfg.nodes.map((n) => n.port);
    expect(new Set(ports).size).toBe(2);
    for (const [id, x] of e.entries()) {
      const c = x.cfg;
      expect(c.role).toBe(id === 0 ? 'ot-sender' : 'ot-receiver');
      expect(c.id).toBe(id);
      expect(c.n).toBe(2);
      expect(c.ot).toEqual({ kind: 'lwe', count: 3 });
      expect(c.sessionId).toMatch(/^[0-9a-f]{16}$/);
      expect(c.sessionId).toBe(e[0]!.cfg.sessionId);
      expect(c.listenHost).toBe('127.0.0.1');
      expect(c.nodes.map((n) => [n.id, n.host, n.port])).toEqual(ports.map((p, j) => [j, '127.0.0.1', p]));
      expect(c.keyPath.endsWith(join(`node${id}`, 'key.pem'))).toBe(true);
      expect(c.certPath).toBe(c.nodes[id]!.certPath);
      expect(x.files).toEqual({ key: true, cert: true });
      expect(x.certs).toEqual([true, true]);
      expect(x.cns).toEqual(['CN=mpc-ot-0', 'CN=mpc-ot-1']);
      expect(c.recvTimeoutMs).toBe(T(777));
      expect(c.connectTimeoutMs).toBe(T(120_000));
      expect(existsSync(x.cfgPath)).toBe(false);
    }
    const d = await launchOtLocal({ kind: 'ec', count: 1, mainJs: echoJs });
    expect((d.outputs[0]!.json as Echo).cfg.recvTimeoutMs).toBe(T(30_000));
  });
  it('output parsing and the kill timer work as for launchLocal', async () => {
    const r = await launchOtLocal({ kind: 'ec', count: 1, mainJs: noisyJs });
    expect(r.outputs.map((o) => o.json)).toEqual([{ x: 2 }, { x: 2 }]);
    expect(r.outputs[0]!.stderr).toBe('e'.repeat(2000));
    expect(r.outputs[0]!.exitCode).toBe(5);
    const bad = join(dir, 'bad2.js');
    writeFileSync(bad, `process.stdout.write('nope');\n`);
    expect((await launchOtLocal({ kind: 'ec', count: 1, mainJs: bad })).outputs.map((o) => o.json)).toEqual([null, null]);
    const h = await launchOtLocal({ kind: 'ec', count: 1, mainJs: hangJs, killAfterMs: 1500 });
    expect(h.outputs.map((o) => o.exitCode)).toEqual([null, null]);
  });
});

function readCert(p: string): string | null {
  try {
    return readFileSync(p, 'utf8');
  } catch {
    return null;
  }
}
