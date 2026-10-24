/**
 * Multi-process crash harness. Several client PROCESSES (each with several clients) run the windowed workload against the
 * same backend and append their histories to per-process files; the parent SIGKILLs a random client process every
 * `killEveryMs` and starts a replacement under a new identity, so killed processes leave PENDING operations. When the
 * adapter has `crash()`, the backend is crashed and restarted once mid-run. The parent waits for EVERY writer to exit
 * before reading the histories (a partial history can make a FALSE look unexplained).
 */
import { fork, type ChildProcess } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { OpKind } from './model';
import { clock, parseHistory } from './recorder';
import { prng, randomNamespace, type WorkloadOptions, type WorkloadResult } from './harness';
import { loadAdapter } from './load';

export interface CrashOptions extends WorkloadOptions {
  /** Adapter module path (or `builtin:<name>`); every process loads it. */
  module: string;
  /** Passed to the module's factory. */
  options?: Record<string, string>;
  /** Client processes alive at once (default 3); `clients` is per process (default 4). */
  processes?: number;
  /** Kill one client process this often (default 400 ms; 0 = never). */
  killEveryMs?: number;
  /** Crash + restart the backend once mid-run when the adapter has `crash()` (default true). */
  backendCrash?: boolean;
  /** History directory (default: a fresh temp dir). */
  dir?: string;
  /** The worker entry (default: the compiled `worker.js` next to this file). */
  workerPath?: string;
}

/** What one worker process is told to do (serialized on its command line). */
export interface WorkerConfig {
  module: string;
  options: Record<string, string>;
  kind: OpKind;
  proc: string;
  file: string;
  clients: number;
  namespace: string;
  windowMs: number;
  spread: number;
  values: number;
  retentionMs: number;
  opTimeoutMs: number;
  origin: number;
  deadline: number;
  seed: number;
}

export interface CrashResult extends WorkloadResult {
  kills: number;
  backendCrashes: number;
  torn: number;
  pending: number;
  processes: number;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export async function runCrash(kind: OpKind, o: CrashOptions): Promise<CrashResult> {
  const dir = o.dir ?? mkdtempSync(join(tmpdir(), 'pcasc-hist-'));
  const durationMs = o.durationMs ?? 3000;
  const killEveryMs = o.killEveryMs ?? 400;
  const seed = o.seed ?? Math.floor(Math.random() * 2 ** 31);
  const rand = prng(seed);
  const origin = clock();
  const deadline = origin + durationMs;
  const base = {
    module: o.module,
    options: o.options ?? {},
    kind,
    clients: o.clients ?? 4,
    namespace: o.namespace ?? randomNamespace(),
    windowMs: o.windowMs ?? 5,
    spread: o.spread ?? 3,
    values: o.values ?? 20,
    retentionMs: o.retentionMs ?? 600_000,
    opTimeoutMs: o.opTimeoutMs ?? 5000,
    origin,
    deadline,
  };
  const live = new Set<ChildProcess>();
  const exits: Promise<void>[] = [];
  let n = 0;
  const spawn = (): void => {
    const proc = `p${n}`;
    const cfg: WorkerConfig = { ...base, proc, file: join(dir, `h-${proc}.jsonl`), seed: seed + 7919 * n };
    n += 1;
    const ch = fork(o.workerPath ?? join(__dirname, 'worker.js'), [JSON.stringify(cfg)], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
    live.add(ch);
    exits.push(
      new Promise<void>((res) => {
        ch.on('exit', () => {
          live.delete(ch);
          res();
        });
      }),
    );
  };
  for (let i = 0; i < (o.processes ?? 3); i++) spawn();
  const control = o.backendCrash !== false ? await loadAdapter(o.module, o.options ?? {}) : undefined;
  let kills = 0;
  let backendCrashes = 0;
  const half = origin + durationMs / 2;
  while (killEveryMs > 0 && clock() + killEveryMs < deadline) {
    await sleep(killEveryMs);
    const victims = [...live];
    if (victims.length > 0) {
      victims[rand(victims.length)]!.kill('SIGKILL');
      kills += 1;
      spawn();
    }
    if (control?.crash && backendCrashes === 0 && clock() >= half) {
      await control.crash();
      await control.restart?.();
      backendCrashes += 1;
    }
  }
  await Promise.all(exits);
  await control?.teardown?.();
  const text = readdirSync(dir)
    .filter((f) => f.startsWith('h-') && f.endsWith('.jsonl'))
    .map((f) => readFileSync(join(dir, f), 'utf8'))
    .join('\n');
  const { ops, torn, pending } = parseHistory(text);
  return { ops, errors: ops.filter((x) => x.res === 'unknown').length, kills, backendCrashes, torn, pending, processes: n };
}
