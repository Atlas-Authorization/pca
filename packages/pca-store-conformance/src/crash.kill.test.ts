// runCrash driven with a scripted `fork`, a scripted clock and a scripted sleep: no real processes, fully deterministic.
import type { EventEmitter } from 'node:events';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { runCrash, type CrashOptions, type WorkerConfig } from './crash';
import { prng } from './harness';

interface FakeChild extends EventEmitter {
  kill(signal: string): void;
  killed: string[];
  finish(): void;
}
interface Control {
  crash?: () => Promise<void>;
  restart?: () => Promise<void>;
  teardown?: () => Promise<void>;
}

const h = vi.hoisted(() => ({
  now: 0,
  sleeps: [] as number[],
  onSleep: undefined as undefined | ((n: number) => void),
  forks: [] as { path: string; args: string[]; opts: unknown; child: unknown }[],
  killLog: [] as string[],
  loads: [] as unknown[][],
  control: {} as unknown,
}));

vi.mock('node:child_process', async () => {
  const { EventEmitter: Emitter } = await import('node:events');
  return {
    fork: (path: string, args: string[], opts: unknown) => {
      const ee = new Emitter() as FakeChild;
      let exited = false;
      ee.killed = [];
      ee.finish = () => {
        if (exited) return;
        exited = true;
        ee.emit('exit', null, null);
      };
      ee.kill = (s: string) => {
        ee.killed.push(s);
        h.killLog.push((JSON.parse(args[0]!) as { proc: string }).proc);
        queueMicrotask(ee.finish);
      };
      h.forks.push({ path, args, opts, child: ee });
      return ee;
    },
  };
});
vi.mock('./recorder', async (importOriginal) => ({ ...(await importOriginal<typeof import('./recorder')>()), clock: () => h.now }));
vi.mock('./load', () => ({
  loadAdapter: async (...a: unknown[]) => {
    h.loads.push(a);
    return h.control;
  },
}));

const cfgOf = (i: number): WorkerConfig => JSON.parse(h.forks[i]!.args[0]!) as WorkerConfig;
const child = (i: number): FakeChild => h.forks[i]!.child as FakeChild;

/** Start the run; once it can only be waiting for its workers to exit (everything else resolves in microtasks), let them all exit. */
async function drive(o: Partial<CrashOptions>): ReturnType<typeof runCrash> {
  const dir = mkdtempSync(join(tmpdir(), 'pcasc-ck-'));
  const p = runCrash('advance', { module: 'mod.js', dir, ...o });
  await new Promise<void>((r) => setImmediate(r));
  for (let i = 0; i < h.forks.length; i++) child(i).finish();
  return p;
}

beforeEach(() => {
  h.now = 0;
  h.sleeps = [];
  h.onSleep = undefined;
  h.forks = [];
  h.killLog = [];
  h.loads = [];
  h.control = {};
  vi.spyOn(globalThis, 'setTimeout').mockImplementation(((fn: () => void, ms?: number) => {
    h.sleeps.push(ms ?? 0);
    h.now += ms ?? 0;
    h.onSleep?.(h.sleeps.length);
    queueMicrotask(fn);
    return 0;
  }) as unknown as typeof setTimeout);
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe('runCrash defaults', () => {
  it('uses the documented defaults for every option left out', async () => {
    vi.spyOn(Math, 'random').mockReturnValue(0.5);
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-ck-dir-'));
    const r = await drive({ dir, backendCrash: false });
    // 3000 ms run, one kill per 400 ms: sleeps at t = 0, 400, ... 2400
    expect(h.sleeps).toEqual([400, 400, 400, 400, 400, 400, 400]);
    expect(r.kills).toBe(7);
    expect(r.processes).toBe(10);
    expect(r.backendCrashes).toBe(0);
    const seed = Math.floor(0.5 * 2 ** 31);
    expect(seed).toBe(1073741824);
    for (let n = 0; n < 3; n++) {
      expect(cfgOf(n)).toEqual({
        module: 'mod.js',
        options: {},
        kind: 'advance',
        proc: `p${n}`,
        file: join(dir, `h-p${n}.jsonl`),
        clients: 4,
        namespace: expect.stringMatching(/^pcasc-/),
        windowMs: 5,
        spread: 3,
        values: 20,
        retentionMs: 600_000,
        opTimeoutMs: 5000,
        origin: 0,
        deadline: 3000,
        seed: seed + 7919 * n,
      });
    }
    expect(cfgOf(3).seed).toBe(seed + 7919 * 3);
    expect(cfgOf(9).proc).toBe('p9');
    for (const f of h.forks) {
      expect(f.path).toBe(join(__dirname, 'worker.js'));
      expect(f.args).toHaveLength(1);
      expect(f.opts).toEqual({ stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
    }
  });

  it('passes every option given through to the workers, and the adapter module to the control load', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-ck-dir-'));
    h.control = { teardown: async () => undefined };
    await drive({
      dir,
      module: 'given.js',
      options: { a: '1' },
      processes: 2,
      clients: 7,
      namespace: 'nsX',
      windowMs: 11,
      spread: 9,
      values: 33,
      retentionMs: 777,
      opTimeoutMs: 1234,
      seed: 99,
      durationMs: 1000,
      killEveryMs: 250,
      workerPath: 'my-worker.js',
    });
    expect(h.sleeps).toEqual([250, 250, 250]);
    expect(h.loads).toEqual([['given.js', { a: '1' }]]);
    for (let n = 0; n < 2; n++) {
      expect(cfgOf(n)).toEqual({
        module: 'given.js',
        options: { a: '1' },
        kind: 'advance',
        proc: `p${n}`,
        file: join(dir, `h-p${n}.jsonl`),
        clients: 7,
        namespace: 'nsX',
        windowMs: 11,
        spread: 9,
        values: 33,
        retentionMs: 777,
        opTimeoutMs: 1234,
        origin: 0,
        deadline: 1000,
        seed: 99 + 7919 * n,
      });
    }
    expect(h.forks.map((f) => f.path).every((p) => p === 'my-worker.js')).toBe(true);
    expect(cfgOf(2).seed).toBe(99 + 7919 * 2);
    expect(cfgOf(2).proc).toBe('p2');
  });

  it('loads the control adapter with empty options when none are given', async () => {
    await drive({ backendCrash: true, durationMs: 100, killEveryMs: 0, processes: 1 });
    expect(h.loads).toEqual([['mod.js', {}]]);
    h.loads = [];
    await drive({ backendCrash: false, durationMs: 100, killEveryMs: 0, processes: 1 });
    expect(h.loads).toEqual([]);
  });
});

describe('runCrash kill loop', () => {
  it('kills a random live process every period (seeded), replaces it, and stops before the deadline', async () => {
    const r = await drive({ processes: 3, seed: 5, durationMs: 1000, killEveryMs: 250, backendCrash: false });
    const rand = prng(5);
    let live = ['p0', 'p1', 'p2'];
    let next = 3;
    const killed: string[] = [];
    for (let i = 0; i < 3; i++) {
      const v = live[rand(live.length)]!;
      killed.push(v);
      live = live.filter((x) => x !== v);
      live.push(`p${next++}`);
    }
    expect(h.killLog).toEqual(killed);
    expect(r.kills).toBe(3);
    expect(r.processes).toBe(6);
    expect(h.forks.flatMap((f) => (f.child as FakeChild).killed)).toEqual(['SIGKILL', 'SIGKILL', 'SIGKILL']);
  });

  it('the last sleep happens only if a whole period still fits before the deadline', async () => {
    // 1000 ms / 100 ms: sleeps at t = 0 .. 800 (t + 100 < 1000); t = 900 does not sleep again
    await drive({ processes: 1, durationMs: 1000, killEveryMs: 100, backendCrash: false });
    expect(h.sleeps).toHaveLength(9);
    h.sleeps = [];
    h.now = 0;
    // 1050 ms: t = 900 is still short of the deadline (1000 < 1050)
    await drive({ processes: 1, durationMs: 1050, killEveryMs: 100, backendCrash: false });
    expect(h.sleeps).toHaveLength(10);
  });

  it('kills nobody once every process has already exited by itself', async () => {
    h.onSleep = (n) => {
      if (n === 1) child(0).finish();
    };
    const r = await drive({ processes: 1, durationMs: 500, killEveryMs: 100, backendCrash: false });
    expect(r.kills).toBe(0);
    expect(r.processes).toBe(1);
    expect(h.forks).toHaveLength(1);
    expect(child(0).killed).toEqual([]);
    expect(h.killLog).toEqual([]);
  });
});

describe('runCrash backend crash', () => {
  it('crashes then restarts the backend once, at the first period boundary at or after the half-way point', async () => {
    const events: string[] = [];
    h.control = {
      crash: async () => void events.push(`crash@${h.now}`),
      restart: async () => void events.push(`restart@${h.now}`),
      teardown: async () => void events.push('teardown'),
    } satisfies Control;
    const r = await drive({ processes: 1, durationMs: 1000, killEveryMs: 100 });
    expect(events).toEqual(['crash@500', 'restart@500', 'teardown']);
    expect(r.backendCrashes).toBe(1);
    expect(h.sleeps).toHaveLength(9);
  });

  it('does not need a restart hook', async () => {
    const events: string[] = [];
    h.control = { crash: async () => void events.push(`crash@${h.now}`) } satisfies Control;
    const r = await drive({ processes: 1, durationMs: 1000, killEveryMs: 100 });
    expect(events).toEqual(['crash@500']);
    expect(r.backendCrashes).toBe(1);
  });

  it('never crashes an adapter that has no crash hook', async () => {
    h.control = { restart: async () => void h.loads.push(['restart']) } satisfies Control;
    const r = await drive({ processes: 1, durationMs: 1000, killEveryMs: 100 });
    expect(r.backendCrashes).toBe(0);
    expect(h.loads.filter((l) => l[0] === 'restart')).toEqual([]);
  });
});
