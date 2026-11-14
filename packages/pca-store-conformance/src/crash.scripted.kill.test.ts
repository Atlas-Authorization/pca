// runCrash driven by scripted child processes and a scripted clock: exact worker configs, kill/crash ordering and loop bounds.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { runCrash, type WorkerConfig } from './crash';

const h = vi.hoisted(() => ({
  clockQueue: [] as number[],
  live: [] as Array<{ exit: () => void }>,
  forks: [] as Array<{ path: string; args: string[]; opts: unknown; killed: string[] }>,
  events: [] as string[],
  autoExit: false,
  calls: 0,
  releaseOn: 0,
  adapter: undefined as unknown,
}));

vi.mock('node:child_process', async () => {
  const { EventEmitter } = await import('node:events');
  return {
    fork: (path: string, args: string[], opts: unknown) => {
      const rec = { path, args, opts, killed: [] as string[] };
      h.forks.push(rec);
      h.events.push('spawn');
      const ch = new EventEmitter() as InstanceType<typeof EventEmitter> & { kill: (s: string) => boolean };
      let done = false;
      const exit = (): void => {
        if (!done) {
          done = true;
          ch.emit('exit');
        }
      };
      ch.kill = (s: string): boolean => {
        rec.killed.push(s);
        h.events.push('kill');
        exit();
        return true;
      };
      h.live.push({ exit });
      if (h.autoExit) queueMicrotask(exit);
      return ch;
    },
  };
});

vi.mock('./load', () => ({ loadAdapter: async () => h.adapter }));

// The scripted clock hands out its values in order; once they run out (or on call `releaseOn`) every child exits.
vi.mock('./recorder', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./recorder')>()),
  clock: (): number => {
    h.calls += 1;
    const v = h.clockQueue.shift();
    if (v === undefined) {
      for (const c of h.live) c.exit();
      return Infinity;
    }
    if (h.calls === h.releaseOn) for (const c of h.live) c.exit();
    return v;
  },
}));

const cfgs = (): WorkerConfig[] => h.forks.map((f) => JSON.parse(f.args[0]!) as WorkerConfig);
const adapterWith = (extra: Record<string, unknown>): void => {
  h.adapter = {
    name: 'scripted',
    teardown: async () => {
      h.events.push('teardown');
    },
    ...extra,
  };
};

beforeEach(() => {
  h.clockQueue = [];
  h.live = [];
  h.forks = [];
  h.events = [];
  h.autoExit = false;
  h.calls = 0;
  h.releaseOn = 0;
  h.adapter = undefined;
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe('runCrash worker configuration', () => {
  it('applies every default and hands each worker its own seed', async () => {
    vi.spyOn(Math, 'random').mockReturnValue(0.5);
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-scr-'));
    adapterWith({ crash: async () => void h.events.push('crash'), restart: async () => void h.events.push('restart') });
    h.clockQueue = [1000, 3599, 3599];
    h.releaseOn = 3;
    const r = await runCrash('advance', { module: 'm', dir });
    const c = cfgs();
    expect(c).toHaveLength(r.processes);
    expect(c.slice(0, 3)).toEqual(
      [0, 1, 2].map((n) => ({
        module: 'm',
        options: {},
        kind: 'advance',
        clients: 4,
        namespace: expect.any(String),
        windowMs: 5,
        spread: 3,
        values: 20,
        retentionMs: 600_000,
        opTimeoutMs: 5000,
        origin: 1000,
        deadline: 4000,
        proc: `p${n}`,
        file: join(dir, `h-p${n}.jsonl`),
        seed: 2 ** 30 + 7919 * n,
      })),
    );
    expect(c[0]!.namespace.length).toBeGreaterThan(0);
    expect(h.forks[0]!.path).toBe(join(__dirname, 'worker.js'));
    expect(h.forks[0]!.opts).toEqual({ stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
    expect(r.kills).toBe(1);
    expect(r.backendCrashes).toBe(1);
    expect(r.processes).toBe(4);
  });

  it('passes explicit values through unchanged', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-scr-'));
    h.clockQueue = [0, 985];
    const r = await runCrash('consume', {
      module: 'mod',
      options: { a: 'b' },
      dir,
      processes: 2,
      clients: 7,
      namespace: 'ns',
      windowMs: 11,
      spread: 13,
      values: 17,
      retentionMs: 19_000,
      opTimeoutMs: 23,
      durationMs: 1000,
      killEveryMs: 10,
      seed: 100,
      backendCrash: false,
      workerPath: 'worker-entry.js',
    });
    const c = cfgs();
    expect(c.slice(0, 2)).toEqual(
      [0, 1].map((n) => ({
        module: 'mod',
        options: { a: 'b' },
        kind: 'consume',
        clients: 7,
        namespace: 'ns',
        windowMs: 11,
        spread: 13,
        values: 17,
        retentionMs: 19_000,
        opTimeoutMs: 23,
        origin: 0,
        deadline: 1000,
        proc: `p${n}`,
        file: join(dir, `h-p${n}.jsonl`),
        seed: 100 + 7919 * n,
      })),
    );
    expect(h.forks[0]!.path).toBe('worker-entry.js');
    expect(h.forks[0]!.args).toEqual([JSON.stringify(c[0])]);
    // one kill: 985 + 10 is before the deadline of 1000
    expect(r.kills).toBe(1);
    expect(h.forks.filter((f) => f.killed.length > 0)).toHaveLength(1);
    expect(h.forks.flatMap((f) => f.killed)).toEqual(['SIGKILL']);
    expect(r.processes).toBe(3);
  });
});

describe('runCrash kill and backend-crash schedule', () => {
  it('crashes the backend once the half-way point is reached, and stops killing at the last full interval', async () => {
    const timers = vi.spyOn(globalThis, 'setTimeout');
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-scr-'));
    adapterWith({ crash: async () => void h.events.push('crash'), restart: async () => void h.events.push('restart') });
    // origin 100, deadline 1100, half-way 600. Passes: 500 (before half), 550 then 600 (exactly half: crash), then 1090 (1090 + 10 < 1100 is false).
    h.clockQueue = [100, 500, 500, 550, 600, 1090];
    h.releaseOn = 6;
    const r = await runCrash('advance', { module: 'm', dir, processes: 2, durationMs: 1000, killEveryMs: 10, seed: 5 });
    expect(h.events).toEqual(['spawn', 'spawn', 'kill', 'spawn', 'kill', 'spawn', 'crash', 'restart', 'teardown']);
    expect(r.kills).toBe(2);
    expect(r.backendCrashes).toBe(1);
    expect(r.processes).toBe(4);
    expect(timers.mock.calls.filter((a) => a[1] === 10)).toHaveLength(2);
  });

  it('on the boundary 1090 + 10 = 1100 the loop does not run another pass', async () => {
    const timers = vi.spyOn(globalThis, 'setTimeout');
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-scr-'));
    h.clockQueue = [100, 1090];
    h.releaseOn = 2;
    const r = await runCrash('advance', { module: 'm', dir, processes: 1, durationMs: 1000, killEveryMs: 10, backendCrash: false });
    expect(r.kills).toBe(0);
    expect(timers.mock.calls.filter((a) => a[1] === 10)).toHaveLength(0);
  });

  it('tolerates an adapter whose crash() has no restart() and never kills an already-exited process', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-scr-'));
    adapterWith({ crash: async () => void h.events.push('crash') });
    h.autoExit = true;
    h.clockQueue = [0, 600, 600];
    const r = await runCrash('advance', { module: 'm', dir, processes: 2, durationMs: 1000, killEveryMs: 5, seed: 1 });
    expect(r.backendCrashes).toBe(1);
    expect(r.kills).toBe(0);
    expect(r.processes).toBe(2);
    expect(h.forks.flatMap((f) => f.killed)).toEqual([]);
    expect(h.events).toEqual(['spawn', 'spawn', 'crash', 'teardown']);
  });

  it('with no client process alive there is nothing to kill', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-scr-'));
    h.clockQueue = [0, 100];
    const r = await runCrash('advance', { module: 'm', dir, processes: 0, durationMs: 1000, killEveryMs: 5, backendCrash: false });
    expect(r.kills).toBe(0);
    expect(r.processes).toBe(0);
    expect(h.events).toEqual([]);
  });
});
