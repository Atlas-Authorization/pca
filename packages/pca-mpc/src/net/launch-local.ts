/**
 * Multi-process launcher: spawns the dealer and each party as its own OS process (`party-main.js`) on
 * localhost, generates a fresh per-run identity for each, optionally routes one link through a
 * `FaultProxy`, and collects each node's one-line JSON verdict. Used by the tests and the demo script;
 * the real multi-host run uses the same `party-main.js` with a config per host.
 */

import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import * as net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { generateIdentity } from './certs';
import { FaultProxy, type WireFault } from './faults';
import type { NodeConfig } from './party-main';
import type { DecisionVector } from '../party';
import { T, reservePorts } from './launch-support';

export interface NodeOutput {
  id: number;
  role: 'party' | 'dealer';
  exitCode: number | null;
  json: any; // eslint-disable-line @typescript-eslint/no-explicit-any
  stderr: string;
}

export interface LaunchOptions {
  n: number;
  Q?: number;
  vectors: DecisionVector[];
  /** Path to the compiled `party-main.js`. */
  mainJs: string;
  recvTimeoutMs?: number;
  /** Hard wall-clock cap for the whole run (kills stragglers; a hang is a test failure). */
  killAfterMs?: number;
  overrides?: Record<number, Partial<NodeConfig>>;
  /** Route the connection `dialer -> target` through a faulty TCP proxy. */
  wireFault?: { dialer: number; target: number; fault: WireFault };
  dealerSeed?: string;
  /** `no-dealer` (default: the parties run the OT offline phase) or `trusted-dealer` (spawns a dealer process; needs `insecureTrustedDealer: true`). */
  offline?: 'trusted-dealer' | 'no-dealer';
  insecureTrustedDealer?: boolean;
}

export async function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const p = (s.address() as net.AddressInfo).port;
      s.close(() => res(p));
    });
    s.on('error', rej);
  });
}

export async function launchLocal(o: LaunchOptions): Promise<{ outputs: NodeOutput[]; wallMs: number; proxyLog: string[] }> {
  const n = o.n;
  const mode = o.offline ?? 'no-dealer';
  if (mode === 'trusted-dealer' && o.insecureTrustedDealer !== true) throw new Error("launchLocal: offline 'trusted-dealer' requires insecureTrustedDealer: true");
  const noDealer = mode === 'no-dealer';
  const nodeCount = noDealer ? n : n + 1;
  const dir = mkdtempSync(join(tmpdir(), 'pca-mpc-net-'));
  const sessionId = randomBytes(8).toString('hex');
  const ports = await reservePorts(nodeCount + 1); // distinct, held together; the last one is for the optional fault proxy
  const ids: { keyPath: string; certPath: string }[] = [];
  for (let i = 0; i < nodeCount; i++) ids.push(generateIdentity(join(dir, `node${i}`), `mpc-node-${i}`));
  let proxy: FaultProxy | null = null;
  let proxyPort = 0;
  if (o.wireFault) {
    proxyPort = ports[nodeCount]!;
    proxy = new FaultProxy(proxyPort, { host: '127.0.0.1', port: ports[o.wireFault.target]! }, { ...o.wireFault.fault, ...(o.wireFault.fault.ms !== undefined ? { ms: T(o.wireFault.fault.ms) } : {}) });
    await proxy.listen();
  }
  const t0 = Date.now();
  const procs = Array.from({ length: nodeCount }, (_, id) => {
    const nodes = ids.map((x, j) => ({
      id: j,
      host: '127.0.0.1',
      port: o.wireFault && id === o.wireFault.dialer && j === o.wireFault.target ? proxyPort : ports[j]!,
      certPath: x.certPath,
    }));
    const cfg: NodeConfig = {
      role: !noDealer && id === n ? 'dealer' : 'party',
      id,
      n,
      Q: o.Q,
      offline: mode,
      insecureTrustedDealer: o.insecureTrustedDealer,
      sessionId,
      input: id < n ? o.vectors[id] : undefined,
      listenHost: '127.0.0.1',
      nodes,
      keyPath: ids[id]!.keyPath,
      certPath: ids[id]!.certPath,
      recvTimeoutMs: T(o.recvTimeoutMs ?? 30_000),
      connectTimeoutMs: T(120_000),
      dealerSeed: id === n ? o.dealerSeed : undefined,
      ...(o.overrides?.[id] ?? {}),
    };
    const hooks = cfg.behavior !== undefined || cfg.frameFault !== undefined || cfg.dealerFault !== undefined;
    if (hooks) cfg.unsafeTestHooks = true;
    const cfgPath = join(dir, `cfg${id}.json`);
    writeFileSync(cfgPath, JSON.stringify(cfg));
    const child = spawn(process.execPath, [o.mainJs, cfgPath], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: hooks ? { ...process.env, PCA_MPC_UNSAFE_TEST_HOOKS: '1' } : { ...process.env, PCA_MPC_UNSAFE_TEST_HOOKS: undefined },
    });
    let so = '';
    let se = '';
    child.stdout.on('data', (d) => (so += d));
    child.stderr.on('data', (d) => (se += d));
    return new Promise<NodeOutput>((resolve) => {
      child.on('close', (code) => {
        const line = so.trim().split('\n').filter(Boolean).pop();
        let json: any = null; // eslint-disable-line @typescript-eslint/no-explicit-any
        try {
          json = line ? JSON.parse(line) : null;
        } catch {
          /* leave null */
        }
        resolve({ id, role: !noDealer && id === n ? 'dealer' : 'party', exitCode: code, json, stderr: se.slice(0, 2000) });
      });
      const killer = setTimeout(() => child.kill('SIGKILL'), T(o.killAfterMs ?? 120_000));
      child.on('close', () => clearTimeout(killer));
    });
  });
  const outputs = await Promise.all(procs);
  proxy?.close();
  const proxyLog = proxy?.log ?? [];
  rmSync(dir, { recursive: true, force: true });
  return { outputs, wallMs: Date.now() - t0, proxyLog };
}

/** Two-process base-OT run (sender = node 0, receiver = node 1) over mutual TLS on localhost. */
export async function launchOtLocal(o: {
  kind: 'ec' | 'lwe';
  count: number;
  mainJs: string;
  recvTimeoutMs?: number;
  killAfterMs?: number;
}): Promise<{ outputs: NodeOutput[]; wallMs: number }> {
  const dir = mkdtempSync(join(tmpdir(), 'pca-mpc-ot-'));
  const sessionId = randomBytes(8).toString('hex');
  const ports = await reservePorts(2);
  const ids = [0, 1].map((i) => generateIdentity(join(dir, `node${i}`), `mpc-ot-${i}`));
  const nodes = ids.map((x, j) => ({ id: j, host: '127.0.0.1', port: ports[j]!, certPath: x.certPath }));
  const t0 = Date.now();
  const procs = [0, 1].map((id) => {
    const cfg: NodeConfig = {
      role: id === 0 ? 'ot-sender' : 'ot-receiver',
      id,
      n: 2,
      sessionId,
      listenHost: '127.0.0.1',
      nodes,
      keyPath: ids[id]!.keyPath,
      certPath: ids[id]!.certPath,
      recvTimeoutMs: T(o.recvTimeoutMs ?? 30_000),
      connectTimeoutMs: T(120_000),
      ot: { kind: o.kind, count: o.count },
    };
    const cfgPath = join(dir, `cfg${id}.json`);
    writeFileSync(cfgPath, JSON.stringify(cfg));
    const child = spawn(process.execPath, [o.mainJs, cfgPath], { stdio: ['ignore', 'pipe', 'pipe'] });
    let so = '';
    let se = '';
    child.stdout.on('data', (d) => (so += d));
    child.stderr.on('data', (d) => (se += d));
    return new Promise<NodeOutput>((resolve) => {
      const killer = setTimeout(() => child.kill('SIGKILL'), T(o.killAfterMs ?? 120_000));
      child.on('close', (code) => {
        clearTimeout(killer);
        const line = so.trim().split('\n').filter(Boolean).pop();
        let json: any = null; // eslint-disable-line @typescript-eslint/no-explicit-any
        try {
          json = line ? JSON.parse(line) : null;
        } catch {
          /* leave null */
        }
        resolve({ id, role: id === 0 ? 'dealer' : 'party', exitCode: code, json, stderr: se.slice(0, 2000) });
      });
    });
  });
  const outputs = await Promise.all(procs);
  rmSync(dir, { recursive: true, force: true });
  return { outputs, wallMs: Date.now() - t0 };
}
