/**
 * Multi-process launcher: spawns the dealer and each party as its own OS process (`party-main.js`) on
 * localhost, generates a fresh per-run identity for each, optionally routes one link through a
 * `FaultProxy`, and collects each node's one-line JSON verdict. Used by the tests and the demo script;
 * the real multi-host run uses the same `party-main.js` with a config per host.
 */

import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { generateIdentity } from './certs';
import { FaultProxy, type WireFault } from './faults';
import type { NodeConfig } from './party-main';
import type { DecisionVector } from '../party';
import { T } from './launch-support';

export interface NodeOutput {
  id: number;
  role: 'party' | 'dealer';
  exitCode: number | null;
  json: any; // eslint-disable-line @typescript-eslint/no-explicit-any
  stderr: string;
  /** How far the node got: spawned, listening (bound its port), ports-sent (got the peer map), exited. */
  stage?: string;
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
  /**
   * Overall cap for the whole run. When it is exceeded every child is killed and the launch FAILS with each child's stage,
   * events, stdout and stderr, so a hang names where it stopped. Set it safely under the caller's own test timeout.
   */
  capMs?: number;
  overrides?: Record<number, Partial<NodeConfig>>;
  /** Route the connection `dialer -> target` through a faulty TCP proxy. */
  wireFault?: { dialer: number; target: number; fault: WireFault };
  dealerSeed?: string;
  /** `no-dealer` (default: the parties run the OT offline phase) or `trusted-dealer` (spawns a dealer process; needs `insecureTrustedDealer: true`). */
  offline?: 'trusted-dealer' | 'no-dealer';
  insecureTrustedDealer?: boolean;
}

export interface NodeRun {
  id: number;
  role: 'party' | 'dealer';
  cfgPath: string;
  env?: NodeJS.ProcessEnv;
  /** The peer map this node is told: every reported real port (the one it dials may be a fault proxy). */
  ports: (reported: Map<number, number>) => Record<number, number>;
}

/**
 * Spawn every node bound-first: each child binds port 0 itself and reports the port it really holds on one stdout line
 * (`{"listening":<port>}`); once every child has reported (or exited), each live reporter gets the full port map on one stdin
 * line and only then dials. Nothing probes a port and releases it. A child that never speaks the protocol (a scripted stand-in)
 * is simply not in the map.
 */
export async function launchNodes(
  runs: NodeRun[],
  mainJs: string,
  o: { killAfterMs?: number; capMs?: number },
  onPorts?: (reported: Map<number, number>) => void,
): Promise<NodeOutput[]> {
  interface Kid {
    run: NodeRun;
    proc: ReturnType<typeof spawn>;
    so: string;
    se: string;
    stage: string;
    port: Promise<number | null>;
    done: Promise<NodeOutput>;
  }
  const kids: Kid[] = runs.map((run) => {
    const proc = spawn(process.execPath, [mainJs, run.cfgPath], { stdio: ['pipe', 'pipe', 'pipe'], env: run.env ?? process.env });
    let report!: (p: number | null) => void;
    const k: Kid = { run, proc, so: '', se: '', stage: 'spawned', port: new Promise((r) => (report = r)), done: null as never };
    proc.stdin!.on('error', () => undefined);
    proc.stdout!.on('data', (d) => {
      k.so += d;
      if (k.stage !== 'spawned') return;
      for (const ln of k.so.split('\n')) {
        try {
          const j = JSON.parse(ln) as { listening?: unknown };
          if (typeof j.listening === 'number') {
            k.stage = 'listening';
            report(j.listening);
          }
        } catch {
          /* not a status line */
        }
      }
    });
    proc.stderr!.on('data', (d) => (k.se += d));
    const killer = setTimeout(() => proc.kill('SIGKILL'), T(o.killAfterMs ?? 120_000));
    k.done = new Promise<NodeOutput>((resolve) => {
      proc.on('close', (code) => {
        clearTimeout(killer);
        k.stage = 'exited';
        report(null);
        const line = k.so.trim().split('\n').filter(Boolean).pop();
        let json: any = null; // eslint-disable-line @typescript-eslint/no-explicit-any
        try {
          json = line ? JSON.parse(line) : null;
        } catch {
          /* leave null */
        }
        if (json && typeof json.listening === 'number') json = null; // only the status line: no verdict
        resolve({ id: run.id, role: run.role, exitCode: code, json, stderr: k.se.slice(0, 2000), stage: 'exited' });
      });
    });
    return k;
  });

  void Promise.all(kids.map((k) => k.port)).then((ports) => {
    const reported = new Map<number, number>();
    kids.forEach((k, i) => ports[i] !== null && reported.set(k.run.id, ports[i]!));
    onPorts?.(reported);
    for (const k of kids) {
      if (!reported.has(k.run.id) || k.stage === 'exited') continue;
      k.stage = 'ports-sent';
      k.proc.stdin!.end(JSON.stringify({ ports: k.run.ports(reported) }) + '\n');
    }
  });

  const all = Promise.all(kids.map((k) => k.done));
  if (o.capMs === undefined) return all;
  // Killing the children makes `all` resolve, so the cap is recorded when it fires and judged when `all` settles: a race
  // between the two would hand back the killed nodes' outputs as if the run had finished.
  let where: string[] | null = null;
  const timer = setTimeout(() => {
    where = kids.map((k) => k.stage); // before the kill moves every node to 'exited'
    for (const k of kids) k.proc.kill('SIGKILL');
  }, o.capMs);
  return all
    .then((outs) => {
      if (where === null) return outs;
      const w = where as string[];
      const lines = kids.map(
        (k, i) =>
          `node ${k.run.id} (${k.run.role}) stage=${w[i]}\n  events: ${JSON.stringify(outs[i]!.json?.events ?? null)}\n  stdout: ${JSON.stringify(k.so.slice(-1500))}\n  stderr: ${JSON.stringify(k.se.slice(-1500))}`,
      );
      throw new Error(`launch: the run exceeded its ${o.capMs}ms cap\n${lines.join('\n')}`);
    })
    .finally(() => clearTimeout(timer));
}

export async function launchLocal(o: LaunchOptions): Promise<{ outputs: NodeOutput[]; wallMs: number; proxyLog: string[] }> {
  const n = o.n;
  const mode = o.offline ?? 'no-dealer';
  if (mode === 'trusted-dealer' && o.insecureTrustedDealer !== true) throw new Error("launchLocal: offline 'trusted-dealer' requires insecureTrustedDealer: true");
  const noDealer = mode === 'no-dealer';
  const nodeCount = noDealer ? n : n + 1;
  const dir = mkdtempSync(join(tmpdir(), 'pca-mpc-net-'));
  const sessionId = randomBytes(8).toString('hex');
  const ids: { keyPath: string; certPath: string }[] = [];
  for (let i = 0; i < nodeCount; i++) ids.push(generateIdentity(join(dir, `node${i}`), `mpc-node-${i}`));
  let proxy: FaultProxy | null = null;
  const proxyTarget = { host: '127.0.0.1', port: 0 }; // learns the target's real port when it reports
  try {
    if (o.wireFault) {
      proxy = new FaultProxy(0, proxyTarget, { ...o.wireFault.fault, ...(o.wireFault.fault.ms !== undefined ? { ms: T(o.wireFault.fault.ms) } : {}) });
      await proxy.listen();
    }
    const t0 = Date.now();
    const runs: NodeRun[] = Array.from({ length: nodeCount }, (_, id) => {
      const role = !noDealer && id === n ? 'dealer' : 'party';
      const nodes = ids.map((x, j) => ({ id: j, host: '127.0.0.1', port: 0, certPath: x.certPath }));
      const cfg: NodeConfig = {
        role,
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
        bindFirst: true,
        ...(o.overrides?.[id] ?? {}),
      };
      const hooks = cfg.behavior !== undefined || cfg.frameFault !== undefined || cfg.dealerFault !== undefined;
      if (hooks) cfg.unsafeTestHooks = true;
      const cfgPath = join(dir, `cfg${id}.json`);
      writeFileSync(cfgPath, JSON.stringify(cfg));
      return {
        id,
        role,
        cfgPath,
        env: hooks ? { ...process.env, PCA_MPC_UNSAFE_TEST_HOOKS: '1' } : { ...process.env, PCA_MPC_UNSAFE_TEST_HOOKS: undefined },
        ports: (rep) => Object.fromEntries([...rep].map(([j, p]) => [j, o.wireFault && id === o.wireFault.dialer && j === o.wireFault.target ? proxy!.port : p])),
      };
    });
    const outputs = await launchNodes(runs, o.mainJs, o, (rep) => {
      if (o.wireFault && rep.has(o.wireFault.target)) proxyTarget.port = rep.get(o.wireFault.target)!;
    });
    return { outputs, wallMs: Date.now() - t0, proxyLog: proxy?.log ?? [] };
  } finally {
    proxy?.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Two-process base-OT run (sender = node 0, receiver = node 1) over mutual TLS on localhost. */
export async function launchOtLocal(o: {
  kind: 'ec' | 'lwe';
  count: number;
  mainJs: string;
  recvTimeoutMs?: number;
  killAfterMs?: number;
  capMs?: number;
}): Promise<{ outputs: NodeOutput[]; wallMs: number }> {
  const dir = mkdtempSync(join(tmpdir(), 'pca-mpc-ot-'));
  const sessionId = randomBytes(8).toString('hex');
  try {
    const ids = [0, 1].map((i) => generateIdentity(join(dir, `node${i}`), `mpc-ot-${i}`));
    const nodes = ids.map((x, j) => ({ id: j, host: '127.0.0.1', port: 0, certPath: x.certPath }));
    const t0 = Date.now();
    const runs: NodeRun[] = [0, 1].map((id) => {
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
        bindFirst: true,
      };
      const cfgPath = join(dir, `cfg${id}.json`);
      writeFileSync(cfgPath, JSON.stringify(cfg));
      return { id, role: id === 0 ? 'dealer' : 'party', cfgPath, ports: (rep) => Object.fromEntries(rep) };
    });
    const outputs = await launchNodes(runs, o.mainJs, o);
    return { outputs, wallMs: Date.now() - t0 };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
