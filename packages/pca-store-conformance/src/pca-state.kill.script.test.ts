// The pca-state profile driven with scripted guards, a scripted child-process launcher and a scripted base-kit runner, so
// every decision of the profile's own logic (which outcome combination passes, which note is written, which handle gets
// wrapped, which process arguments are used) is pinned exactly, independent of any store.
import { EventEmitter } from 'node:events';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AtomicPcaStateStore, PcaStateStore } from '@atlasauth/pca';

type Req = { body: { pcactn: { counter: number } } };
type GuardOpts = { budgetStore: PcaStateStore; multiInstance: boolean; resolveGrant: (ref: string) => Promise<unknown> };

const st = vi.hoisted(() => ({
  created: [] as Array<{ opts: GuardOpts; calls: Req[] }>,
  callNo: 0,
  respond: ((): unknown => undefined) as (guardIdx: number, req: Req, callNo: number) => unknown,
  stateMode: 'scripted-mode',
  fork: ((): unknown => undefined) as (path: string, args: string[], opts: unknown) => unknown,
  runTest: ((): unknown => undefined) as (...a: unknown[]) => unknown,
}));

vi.mock('@atlasauth/pca', async (importOriginal) => {
  const orig = await importOriginal<typeof import('@atlasauth/pca')>();
  return {
    ...orig,
    requirePCA: (opts: GuardOpts) => {
      const idx = st.created.length;
      const rec = { opts, calls: [] as Req[] };
      st.created.push(rec);
      return Object.assign(
        async (req: Req) => {
          rec.calls.push(req);
          return st.respond(idx, req, st.callNo++);
        },
        { stateMode: st.stateMode },
      );
    },
  };
});
vi.mock('node:child_process', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:child_process')>()),
  fork: (path: string, args: string[], opts: unknown) => st.fork(path, args, opts),
}));
vi.mock('./runner', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./runner')>()),
  runTest: (...a: unknown[]) => st.runTest(...a),
}));

import {
  PCA_STATE_REFERENCE_ADAPTERS,
  makePcaStateFixture,
  pcaStateGuard,
  pcaStateWorkerMain,
  runPcaStateConformance,
  type PcaStateAdapter,
  type PcaStateCapabilities,
  type PcaStateHandle,
  type PcaStateWorkerConfig,
} from './pca-state';

type O = 'admitted' | 'replay' | 'error';
const result = (o: O): unknown => (o === 'admitted' ? { ok: true } : { ok: false, verdict: { checks: o === 'replay' ? { replay: 'fail' } : {} } });
const script = (...os: O[]): void => {
  const q = [...os];
  st.respond = () => result(q.shift()!);
};

interface WorkerLine { counter: number; admitted: number; replays: number; errors: number }
interface Forked { path: string; cfg: PcaStateWorkerConfig; opts: unknown }
let log: string[] = [];
let forks: Forked[] = [];
let forkScript: (cfg: PcaStateWorkerConfig, idx: number) => { lines?: WorkerLine[]; signal?: string } = () => ({});

beforeEach(() => {
  st.created.length = 0;
  st.callNo = 0;
  st.stateMode = 'scripted-mode';
  st.respond = () => {
    throw new Error('unscripted guard call');
  };
  log = [];
  forks = [];
  forkScript = () => ({});
  st.fork = (path, args, opts) => {
    const cfg = JSON.parse(args[0]!) as PcaStateWorkerConfig;
    const idx = forks.length;
    forks.push({ path, cfg, opts });
    log.push(`fork ${cfg.mode} ${cfg.counter ?? '-'}`);
    const s = forkScript(cfg, idx);
    if (s.lines) writeFileSync(cfg.out, s.lines.map((l) => `${JSON.stringify(l)}\n`).join(''));
    const ch = new EventEmitter();
    setImmediate(() => ch.emit('exit', s.signal ? null : 0, s.signal ?? null));
    return ch;
  };
});
afterEach(() => {
  vi.restoreAllMocks();
});

interface FakeOpts {
  caps?: PcaStateCapabilities;
  close?: boolean;
  crash?: boolean;
  restart?: boolean;
  teardown?: boolean;
  store?: (n: number) => PcaStateStore;
}
interface Fake extends PcaStateAdapter {
  handles: PcaStateHandle[];
}
function fake(o: FakeOpts = {}): Fake {
  const handles: PcaStateHandle[] = [];
  const a: Fake = {
    name: 'fake',
    handles,
    open: async () => {
      const n = handles.length;
      log.push(`open${n}`);
      const store = o.store ? o.store(n) : { get: async () => undefined, put: async () => undefined };
      const h: PcaStateHandle = { store, ...(o.close ? { close: async () => void log.push(`close${n}`) } : {}) };
      handles.push(h);
      return h;
    },
  };
  if (o.caps) a.capabilities = o.caps;
  if (o.crash) a.crash = async () => void log.push('crash');
  if (o.restart) a.restart = async () => void log.push('restart');
  if (o.teardown) a.teardown = async () => void log.push('teardown');
  return a;
}

const run = async (a: PcaStateAdapter, opts: Parameters<typeof runPcaStateConformance>[1] = {}) => runPcaStateConformance(a, opts);

describe('retry-after-timeout: which outcome combinations pass', () => {
  const cases: Array<{ outs: [O, O, O, O, O]; status: 'pass' | 'fail'; admitted: [number, number]; note: string }> = [
    { outs: ['error', 'replay', 'admitted', 'admitted', 'error'], status: 'pass', admitted: [0, 1], note: 'lost answer: first=error, retry=replay, next counter=admitted; in-flight retry: 1 admitted of 2' },
    { outs: ['replay', 'replay', 'admitted', 'admitted', 'error'], status: 'fail', admitted: [0, 1], note: 'lost answer: first=replay, retry=replay, next counter=admitted; in-flight retry: 1 admitted of 2' },
    { outs: ['admitted', 'replay', 'admitted', 'admitted', 'error'], status: 'fail', admitted: [1, 1], note: 'lost answer: first=admitted, retry=replay, next counter=admitted; in-flight retry: 1 admitted of 2' },
    { outs: ['error', 'error', 'admitted', 'admitted', 'error'], status: 'fail', admitted: [0, 1], note: 'lost answer: first=error, retry=error, next counter=admitted; in-flight retry: 1 admitted of 2' },
    { outs: ['error', 'admitted', 'admitted', 'admitted', 'error'], status: 'fail', admitted: [1, 1], note: 'lost answer: first=error, retry=admitted, next counter=admitted; in-flight retry: 1 admitted of 2' },
    { outs: ['error', 'replay', 'error', 'admitted', 'error'], status: 'fail', admitted: [0, 1], note: 'lost answer: first=error, retry=replay, next counter=error; in-flight retry: 1 admitted of 2' },
    { outs: ['error', 'replay', 'replay', 'admitted', 'error'], status: 'fail', admitted: [0, 1], note: 'lost answer: first=error, retry=replay, next counter=replay; in-flight retry: 1 admitted of 2' },
    { outs: ['error', 'replay', 'admitted', 'admitted', 'admitted'], status: 'fail', admitted: [0, 2], note: 'lost answer: first=error, retry=replay, next counter=admitted; in-flight retry: 2 admitted of 2' },
    { outs: ['error', 'replay', 'admitted', 'error', 'error'], status: 'fail', admitted: [0, 0], note: 'lost answer: first=error, retry=replay, next counter=admitted; in-flight retry: 0 admitted of 2' },
    { outs: ['admitted', 'admitted', 'admitted', 'admitted', 'error'], status: 'fail', admitted: [1, 1], note: 'lost answer: first=admitted, retry=admitted, next counter=admitted; in-flight retry: 1 admitted of 2' },
  ];
  for (const c of cases) {
    it(`${c.outs.join(' / ')} -> ${c.status}`, async () => {
      script(...c.outs);
      const r = await run(fake(), { tests: ['retry-after-timeout'] });
      expect(r.tests).toStrictEqual([{ test: 'retry-after-timeout', status: c.status, admitted: c.admitted, note: c.note }]);
    });
  }

  it('a one-instance adapter uses a single handle and says so', async () => {
    script('error', 'replay', 'admitted', 'admitted', 'error');
    const a = fake({ caps: { shared: false } });
    const r = await run(a, { tests: ['retry-after-timeout'] });
    expect(a.handles).toHaveLength(2);
    expect(r.tests[0]!.note).toBe('lost answer: first=error, retry=replay, next counter=admitted; in-flight retry: 1 admitted of 2 (one instance: shared: false)');
    expect(st.created[2]!.opts.budgetStore).toBe(a.handles[1]!.store);
  });

  it('a shared adapter retries on the second handle; the first handle is wrapped', async () => {
    script('error', 'replay', 'admitted', 'admitted', 'error');
    const a = fake();
    await run(a, { tests: ['retry-after-timeout'] });
    expect(a.handles).toHaveLength(3);
    expect(st.created[2]!.opts.budgetStore).toBe(a.handles[2]!.store);
    expect(st.created[3]!.opts.budgetStore).toBe(a.handles[2]!.store);
    expect(st.created[5]!.opts.budgetStore).toBe(a.handles[2]!.store);
    expect(st.created[1]!.opts.budgetStore).not.toBe(a.handles[1]!.store);
    expect(st.created[4]!.opts.budgetStore).not.toBe(a.handles[1]!.store);
  });
});

describe('retry-after-timeout: the commit hook', () => {
  it('atomic store: the first claim lands and then its answer is lost; later claims answer normally', async () => {
    script('error', 'replay', 'admitted', 'admitted', 'error');
    const a = fake({
      store: (n) =>
        ({
          get: async () => undefined,
          put: async (k: string) => void log.push(`put${n} ${k}`),
          claim: async (k: string, c: unknown) => {
            log.push(`claim${n} ${k} ${JSON.stringify(c)}`);
            return { ok: true };
          },
          raisePin: async () => undefined,
        }) as unknown as AtomicPcaStateStore,
    });
    await run(a, { tests: ['retry-after-timeout'] });
    log.length = 0;
    const lossy = st.created[1]!.opts.budgetStore as AtomicPcaStateStore;
    await expect(lossy.claim('k', { counter: 1 })).rejects.toThrow(new Error('timeout (answer lost after commit)'));
    expect(await lossy.claim('k', { counter: 2 })).toEqual({ ok: true });
    await lossy.put('k', {});
    const slow = st.created[4]!.opts.budgetStore as AtomicPcaStateStore;
    expect(await slow.claim('k', { counter: 9 })).toEqual({ ok: true });
    expect(log).toEqual(['claim1 k {"counter":1}', 'claim1 k {"counter":2}', 'put1 k', 'claim1 k {"counter":9}']);
  });

  it('lock-based store: the first put lands and then its answer is lost; the lock stays bound to the store', async () => {
    script('error', 'replay', 'admitted', 'admitted', 'error');
    const seen: unknown[] = [];
    const bases: PcaStateStore[] = [];
    const a = fake({
      store: (n) => {
        const base: PcaStateStore = {
          get: async () => ({ lastCounter: 41 }),
          put: async (k: string) => void log.push(`put${n} ${k}`),
          withKeyLock<T>(k: string, fn: () => Promise<T>): Promise<T> {
            seen.push(this);
            log.push(`lock${n} ${k}`);
            return fn();
          },
        };
        bases.push(base);
        return base;
      },
    });
    await run(a, { tests: ['retry-after-timeout'] });
    log.length = 0;
    const lossy = st.created[1]!.opts.budgetStore;
    expect('claim' in lossy).toBe(false);
    await expect(lossy.put('k', {})).rejects.toThrow(new Error('timeout (answer lost after commit)'));
    await lossy.put('k', {});
    expect(await lossy.get('k')).toEqual({ lastCounter: 41 });
    expect(await lossy.withKeyLock!('g', async () => 'v')).toBe('v');
    expect(seen[0]).toBe(bases[1]);
    expect(log).toEqual(['put1 k', 'put1 k', 'lock1 g']);
  });

  it('atomic store with a lock: the lock stays bound to the store as well', async () => {
    script('error', 'replay', 'admitted', 'admitted', 'error');
    const seen: unknown[] = [];
    const bases: unknown[] = [];
    const a = fake({
      store: () => {
        const base = {
          get: async () => undefined,
          put: async () => undefined,
          claim: async () => ({ ok: true }),
          raisePin: async () => undefined,
          withKeyLock<T>(_k: string, fn: () => Promise<T>): Promise<T> {
            seen.push(this);
            return fn();
          },
        };
        bases.push(base);
        return base as unknown as AtomicPcaStateStore;
      },
    });
    await run(a, { tests: ['retry-after-timeout'] });
    const lossy = st.created[1]!.opts.budgetStore;
    await lossy.withKeyLock!('g', async () => 1);
    expect(seen[0]).toBe(bases[1]);
  });
});

describe('crash-after-claim: in process', () => {
  it('declared non-durable: skipped without touching the backend further', async () => {
    const a = fake({ caps: { durable: false } });
    const r = await run(a, { tests: ['crash-after-claim'], module: 'm.js' });
    expect(r.tests).toStrictEqual([{ test: 'crash-after-claim', status: 'skip', note: 'the adapter declares durable: false (state dies with the process)' }]);
    expect(a.handles).toHaveLength(1);
    expect(forks).toHaveLength(0);
  });

  it('no module, no crash, no restart: re-open, note, handles opened and closed in order', async () => {
    script('admitted', 'replay', 'admitted');
    const a = fake({ close: true });
    const r = await run(a, { tests: ['crash-after-claim'] });
    expect(r.tests).toStrictEqual([
      { test: 'crash-after-claim', status: 'pass', note: 'in process: admitted=admitted, same proof after re-open=replay, next counter=admitted; process half skipped (needs the adapter module path)' },
    ]);
    expect(log).toEqual(['open0', 'close0', 'open1', 'open2', 'close2', 'close1']);
    expect(forks).toHaveLength(0);
  });

  it('crash then restart, in that order, and the note says so', async () => {
    script('admitted', 'replay', 'admitted');
    const a = fake({ crash: true, restart: true });
    const r = await run(a, { tests: ['crash-after-claim'] });
    expect(log).toEqual(['open0', 'open1', 'crash', 'restart', 'open2']);
    expect(r.tests[0]!.note).toBe('in process: admitted=admitted, same proof after crash + restart=replay, next counter=admitted; process half skipped (needs the adapter module path)');
  });

  it('crash only, restart only', async () => {
    script('admitted', 'replay', 'admitted');
    const c = await run(fake({ crash: true }), { tests: ['crash-after-claim'] });
    expect(c.tests[0]!.note).toMatch(/^in process: admitted=admitted, same proof after crash \+ re-open=replay, /);
    expect(log).toEqual(['open0', 'open1', 'crash', 'open2']);
    log.length = 0;
    script('admitted', 'replay', 'admitted');
    const r = await run(fake({ restart: true }), { tests: ['crash-after-claim'] });
    expect(r.tests[0]!.note).toMatch(/^in process: admitted=admitted, same proof after restart=replay, /);
    expect(log).toEqual(['open0', 'open1', 'restart', 'open2']);
  });

  it('fails when the first presentation is not admitted, or the next counter is not', async () => {
    script('error', 'replay', 'admitted');
    expect((await run(fake(), { tests: ['crash-after-claim'] })).tests[0]!.status).toBe('fail');
    script('replay', 'replay', 'admitted');
    expect((await run(fake(), { tests: ['crash-after-claim'] })).tests[0]!.status).toBe('fail');
    script('admitted', 'replay', 'error');
    expect((await run(fake(), { tests: ['crash-after-claim'] })).tests[0]!.status).toBe('fail');
    script('admitted', 'admitted', 'admitted');
    expect((await run(fake(), { tests: ['crash-after-claim'] })).tests[0]!.status).toBe('fail');
  });
});

const L = (counter: number, admitted: number, replays: number, errors = 0): WorkerLine => ({ counter, admitted, replays, errors });
const GOOD_CHILD: Record<string, { lines?: WorkerLine[]; signal?: string }> = {
  'a.jsonl': { lines: [L(3, 1, 0)], signal: 'SIGKILL' },
  'b.jsonl': { lines: [L(3, 0, 1)] },
  'c.jsonl': { lines: [L(4, 1, 0)] },
};
const crashWith = async (child: typeof GOOD_CHILD, inProc: [O, O, O] = ['admitted', 'replay', 'admitted'], a: PcaStateAdapter = fake()) => {
  script(...inProc);
  forkScript = (cfg) => child[basename(cfg.out)] ?? {};
  return (await run(a, { tests: ['crash-after-claim'], module: 'm.js', moduleOptions: { x: '1' }, workerPath: '/w/worker.js' })).tests[0]!;
};
const IN_PROC = 'in process: admitted=admitted, same proof after re-open=replay, next counter=admitted';

describe('crash-after-claim: child process half', () => {
  it('launches three workers with the exact arguments and passes', async () => {
    const r = await crashWith(GOOD_CHILD);
    expect(r).toStrictEqual({
      test: 'crash-after-claim',
      status: 'pass',
      note: `${IN_PROC}; child process: killed after admission=true, retry in a new process admitted 0, next counter admitted 1`,
    });
    expect(forks).toHaveLength(3);
    const dir = forks[0]!.cfg.fixture.replace(/[\\/]fixture\.json$/, '');
    expect(forks.map((f) => f.path)).toEqual(['/w/worker.js', '/w/worker.js', '/w/worker.js']);
    expect(forks.map((f) => f.opts)).toEqual(Array(3).fill({ stdio: ['ignore', 'ignore', 'inherit', 'ipc'] }));
    expect(forks.map((f) => f.cfg)).toEqual([
      { module: 'm.js', options: { x: '1' }, mode: 'admit-then-die', fixture: join(dir, 'fixture.json'), out: join(dir, 'a.jsonl'), counter: 3, copies: 1, instances: 1 },
      { module: 'm.js', options: { x: '1' }, mode: 'race', fixture: join(dir, 'fixture.json'), out: join(dir, 'b.jsonl'), counter: 3, copies: 1, instances: 1 },
      { module: 'm.js', options: { x: '1' }, mode: 'race', fixture: join(dir, 'fixture.json'), out: join(dir, 'c.jsonl'), counter: 4, copies: 1, instances: 1 },
    ]);
    expect((JSON.parse(readFileSync(forks[0]!.cfg.fixture, 'utf8')) as { proofs: unknown[] }).proofs).toHaveLength(4);
  });

  it('uses the worker next to the module and empty module options by default', async () => {
    script('admitted', 'replay', 'admitted');
    forkScript = (cfg) => GOOD_CHILD[basename(cfg.out)] ?? {};
    await run(fake(), { tests: ['crash-after-claim'], module: 'm.js' });
    expect(forks[0]!.path).toBe(join(__dirname, 'pca-state-worker.js'));
    expect(forks[0]!.cfg.options).toEqual({});
  });

  it('restarts the backend before each retry when it can, in order', async () => {
    await crashWith(GOOD_CHILD, ['admitted', 'replay', 'admitted'], fake({ restart: true }));
    expect(log).toEqual(['open0', 'open1', 'restart', 'open2', 'fork admit-then-die 3', 'restart', 'fork race 3', 'fork race 4']);
    log.length = 0;
    await crashWith(GOOD_CHILD, ['admitted', 'replay', 'admitted'], fake());
    expect(log).toEqual(['open0', 'open1', 'open2', 'fork admit-then-die 3', 'fork race 3', 'fork race 4']);
  });

  const bad: Array<[string, typeof GOOD_CHILD, string]> = [
    ['not killed', { ...GOOD_CHILD, 'a.jsonl': { lines: [L(3, 1, 0)] } }, 'killed after admission=false, retry in a new process admitted 0, next counter admitted 1'],
    ['killed but not admitted', { ...GOOD_CHILD, 'a.jsonl': { lines: [L(3, 0, 1)], signal: 'SIGKILL' } }, 'killed after admission=false, retry in a new process admitted 0, next counter admitted 1'],
    ['retry admitted again', { ...GOOD_CHILD, 'b.jsonl': { lines: [L(3, 1, 0)] } }, 'killed after admission=true, retry in a new process admitted 1, next counter admitted 1'],
    ['retry produced nothing', { ...GOOD_CHILD, 'b.jsonl': {} }, 'killed after admission=true, retry in a new process admitted 0, next counter admitted 1'],
    ['next counter refused', { ...GOOD_CHILD, 'c.jsonl': { lines: [L(4, 0, 1)] } }, 'killed after admission=true, retry in a new process admitted 0, next counter admitted 0'],
  ];
  for (const [name, child, tail] of bad) {
    it(`fails: ${name}`, async () => {
      const r = await crashWith(child);
      expect(r).toStrictEqual({ test: 'crash-after-claim', status: 'fail', note: `${IN_PROC}; child process: ${tail}` });
    });
  }

  it('fails when the in-process half failed even though the child half is clean', async () => {
    const r = await crashWith(GOOD_CHILD, ['error', 'replay', 'admitted']);
    expect(r.status).toBe('fail');
    expect(r.note).toBe(`in process: admitted=error, same proof after re-open=replay, next counter=admitted; child process: killed after admission=true, retry in a new process admitted 0, next counter admitted 1`);
  });
});

describe('processes', () => {
  it('skips a non-shared adapter and a missing module path', async () => {
    const r1 = await run(fake({ caps: { shared: false } }), { tests: ['processes'], module: 'm.js' });
    expect(r1.tests).toStrictEqual([{ test: 'processes', status: 'skip', note: 'the adapter declares shared: false (one instance only)' }]);
    const r2 = await run(fake(), { tests: ['processes'] });
    expect(r2.tests).toStrictEqual([{ test: 'processes', status: 'skip', note: 'needs the adapter module path (the guards run in child processes)' }]);
    expect(forks).toHaveLength(0);
  });

  const table = (): Record<string, { lines?: WorkerLine[]; signal?: string }> => ({
    'p0.jsonl': { lines: [L(1, 1, 3, 0), L(2, 0, 2, 2)] },
    'p1.jsonl': { lines: [L(1, 0, 3, 1), L(2, 1, 0, 3)] },
    'p2.jsonl': { lines: [L(1, 0, 4, 0), L(2, 0, 4, 0)] },
  });
  const go = async (t: ReturnType<typeof table>) => {
    vi.spyOn(Date, 'now').mockReturnValue(5_000_000);
    forkScript = (cfg) => t[basename(cfg.out)] ?? {};
    return (await run(fake(), { tests: ['processes'], module: 'm.js', moduleOptions: { x: '1' }, rounds: 2, copies: 4 })).tests[0]!;
  };

  it('sums admissions per round over all workers, counts fail-closed errors and passes', async () => {
    const r = await go(table());
    expect(r).toStrictEqual({ test: 'processes', status: 'pass', admitted: [1, 1], note: '3 processes x 2 instances x 4 copies per round; 6 fail-closed errors' });
    expect(forks).toHaveLength(3);
    const dir = forks[0]!.cfg.fixture.replace(/[\\/]fixture\.json$/, '');
    expect(forks.map((f) => f.path)).toEqual(Array(3).fill(join(__dirname, 'pca-state-worker.js')));
    expect(forks.map((f) => f.cfg)).toEqual(
      [0, 1, 2].map((p) => ({
        module: 'm.js',
        options: { x: '1' },
        mode: 'race',
        fixture: join(dir, 'fixture.json'),
        out: join(dir, `p${p}.jsonl`),
        rounds: 2,
        origin: 5_001_500,
        roundMs: 150,
        copies: 4,
        instances: 2,
      })),
    );
  });

  it('a round with other than exactly one admission fails', async () => {
    const t = table();
    t['p2.jsonl'] = { lines: [L(1, 1, 3, 0), L(2, 0, 4, 0)] };
    const r = await go(t);
    expect(r.status).toBe('fail');
    expect(r.admitted).toEqual([2, 1]);
  });

  it('a worker killed by a signal fails the test even with complete output', async () => {
    const t = table();
    t['p1.jsonl'] = { lines: [L(1, 0, 3, 1), L(2, 1, 0, 3)], signal: 'SIGKILL' };
    const r = await go(t);
    expect(r).toStrictEqual({ test: 'processes', status: 'fail', admitted: [1, 1], note: '3 processes x 2 instances x 4 copies per round; 6 fail-closed errors; 1 worker(s) did not finish' });
  });

  it('a worker with missing or short output counts as not finished', async () => {
    const t = table();
    delete t['p0.jsonl'];
    t['p2.jsonl'] = { lines: [L(1, 1, 3, 0)] };
    const r = await go(t);
    expect(r.status).toBe('fail');
    expect(r.admitted).toEqual([1, 1]);
    expect(r.note).toBe('3 processes x 2 instances x 4 copies per round; 4 fail-closed errors; 2 worker(s) did not finish');
  });
});

describe('runPcaStateConformance: defaults and base-kit tests', () => {
  const first = (): ((guardIdx: number, req: Req) => unknown) => {
    const seen = new Set<number>();
    return (_i, req) => {
      const c = req.body.pcactn.counter;
      if (seen.has(c)) return result('replay');
      seen.add(c);
      return result('admitted');
    };
  };

  it('defaults to 10 rounds of 16 copies', async () => {
    st.respond = first();
    const r = await run(fake(), { tests: ['one-instance'] });
    expect(r.tests).toStrictEqual([{ test: 'one-instance', status: 'pass', admitted: Array(10).fill(1), note: 'state mode scripted-mode' }]);
    expect(st.created[1]!.calls).toHaveLength(160);
    expect(r.stateMode).toBe('scripted-mode');
    expect(r.adapter).toBe('fake');
  });

  it('honours explicit rounds and copies', async () => {
    st.respond = first();
    const r = await run(fake(), { tests: ['one-instance'], rounds: 3, copies: 5 });
    expect(r.tests[0]!.admitted).toEqual([1, 1, 1]);
    expect(st.created[1]!.calls).toHaveLength(15);
  });

  it('a round with more than one admission fails even if another round has exactly one', async () => {
    const seen = new Map<number, number>();
    st.respond = (_i, req) => {
      const c = req.body.pcactn.counter;
      const n = (seen.get(c) ?? 0) + 1;
      seen.set(c, n);
      return result(n <= (c === 2 ? 2 : 1) ? 'admitted' : 'replay');
    };
    const r = await run(fake(), { tests: ['one-instance'], rounds: 3, copies: 4 });
    expect(r.tests[0]!.status).toBe('fail');
    expect(r.tests[0]!.admitted).toEqual([1, 2, 1]);
    expect(r.status).toBe('fail');
  });

  it('closes every handle it opens, in order', async () => {
    st.respond = first();
    const a = fake({ close: true });
    await run(a, { tests: ['one-instance'], rounds: 1, copies: 1 });
    expect(log).toEqual(['open0', 'close0', 'open1', 'close1']);
    log.length = 0;
    st.callNo = 0;
    st.respond = first();
    await run(fake({ close: true }), { tests: ['instances'], rounds: 1, copies: 3, instances: 3 });
    expect(log).toEqual(['open0', 'close0', 'open1', 'open2', 'open3', 'close1', 'close2', 'close3']);
  });

  it('instances: one guard per handle in multi-instance mode, copies spread evenly, one entry per round', async () => {
    st.respond = first();
    const r = await run(fake(), { tests: ['instances'], rounds: 3, copies: 6, instances: 3 });
    expect(r.tests).toStrictEqual([{ test: 'instances', status: 'pass', admitted: [1, 1, 1], note: '3 instances, state mode scripted-mode' }]);
    expect(st.created.slice(1).map((c) => c.opts.multiInstance)).toEqual([true, true, true]);
    expect(st.created.slice(1).map((c) => c.calls.length)).toEqual([6, 6, 6]);
  });

  it('instances: skipped for a non-shared adapter without opening more handles', async () => {
    const a = fake({ caps: { shared: false } });
    const r = await run(a, { tests: ['instances'] });
    expect(r.tests).toStrictEqual([{ test: 'instances', status: 'skip', note: 'the adapter declares shared: false (one instance only)' }]);
    expect(a.handles).toHaveLength(1);
  });

  it('the claim tests go through the base kit with the claim-as-advance adapter and its options', async () => {
    const calls: unknown[][] = [];
    const lr = (status: string, extra: object) => ({ test: 'x', kind: 'advance', status, ops: 5, keys: 1, errors: 0, violations: [], unresolved: 0, ...extra });
    st.runTest = (...a) => {
      calls.push(a);
      return a[1] === 'concurrent' ? lr('fail', { note: 'cn' }) : lr('pass', {});
    };
    const r = await run(fake(), { tests: ['claim-burst', 'claim-concurrent', 'claim-durability'] });
    expect(calls.map((c) => [(c[0] as PcaStateAdapter).name, c[1], c[2], c[3]])).toEqual([
      ['fake (claim as advance)', 'burst', 'advance', { durationMs: 1000 }],
      ['fake (claim as advance)', 'concurrent', 'advance', { durationMs: 1000 }],
      ['fake (claim as advance)', 'durability', 'advance', { durationMs: 1000 }],
    ]);
    expect(r.tests).toStrictEqual([
      { test: 'claim-burst', status: 'pass', linearizability: lr('pass', {}) },
      { test: 'claim-concurrent', status: 'fail', linearizability: lr('fail', { note: 'cn' }), note: 'cn' },
      { test: 'claim-durability', status: 'pass', linearizability: lr('pass', {}) },
    ]);
    expect(r.status).toBe('fail');
    calls.length = 0;
    await run(fake(), { tests: ['claim-burst'], claim: { durationMs: 50, clients: 2 } });
    expect(calls[0]![3]).toEqual({ durationMs: 50, clients: 2 });
  });
});

describe('pcaStateGuard', () => {
  it('resolves only its own grant and passes the store and instance mode through', async () => {
    const fx = makePcaStateFixture(1);
    const store = { get: async () => undefined, put: async () => undefined };
    pcaStateGuard(fx, store, { multiInstance: true });
    pcaStateGuard(fx, store);
    const [multi, single] = st.created;
    expect(multi!.opts.multiInstance).toBe(true);
    expect(single!.opts.multiInstance).toBe(false);
    expect(multi!.opts.budgetStore).toBe(store);
    expect(await multi!.opts.resolveGrant(fx.grant.id)).toBe(fx.grant);
    expect(await multi!.opts.resolveGrant('some-other-grant')).toBeNull();
  });
});

describe('pcaStateWorkerMain', () => {
  const registry = PCA_STATE_REFERENCE_ADAPTERS as unknown as Record<string, unknown>;
  const NAME = 'kill-test-worker';
  afterEach(() => {
    delete registry[NAME];
  });
  const prepare = (a: PcaStateAdapter, cfg: Partial<PcaStateWorkerConfig>) => {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-kill-worker-'));
    const fixture = join(dir, 'fixture.json');
    writeFileSync(fixture, JSON.stringify(makePcaStateFixture(4)));
    const options: Record<string, string>[] = [];
    registry[NAME] = (o: Record<string, string>) => (options.push(o), a);
    const full: PcaStateWorkerConfig = { module: `builtin:${NAME}`, options: { k: 'v' }, mode: 'race', fixture, out: join(dir, 'out.jsonl'), copies: 1, instances: 1, ...cfg };
    return { full, options };
  };
  const lines = (out: string): string => (existsSync(out) ? readFileSync(out, 'utf8') : '');
  const raw = (...ls: WorkerLine[]): string => ls.map((l) => `${JSON.stringify(l)}\n`).join('');

  it('race: rounds, counters, round-robin over instances, exact output lines, then close and teardown', async () => {
    const a = fake({ close: true, teardown: true });
    const { full, options } = prepare(a, { instances: 2, copies: 4, rounds: 2 });
    script('admitted', 'replay', 'replay', 'error', 'replay', 'admitted', 'error', 'error');
    await pcaStateWorkerMain(full);
    expect(options).toEqual([{ k: 'v' }]);
    expect(lines(full.out)).toBe(raw(L(1, 1, 2, 1), L(2, 1, 1, 2)));
    expect(st.created).toHaveLength(2);
    expect(st.created.map((c) => c.opts.multiInstance)).toEqual([true, true]);
    expect(st.created.map((c) => c.calls.map((r) => r.body.pcactn.counter))).toEqual([[1, 1, 2, 2], [1, 1, 2, 2]]);
    expect(log).toEqual(['open0', 'open1', 'close0', 'close1', 'teardown']);
  });

  it('race without close or teardown on the adapter', async () => {
    const { full } = prepare(fake(), { instances: 2, copies: 2, rounds: 1 });
    script('admitted', 'replay');
    await pcaStateWorkerMain(full);
    expect(lines(full.out)).toBe(raw(L(1, 1, 1, 0)));
  });

  it('defaults to one round with the counter of that round; a fixed counter is used for every round', async () => {
    const { full } = prepare(fake(), { copies: 1 });
    script('admitted');
    await pcaStateWorkerMain(full);
    expect(lines(full.out)).toBe(raw(L(1, 1, 0, 0)));
    const b = prepare(fake(), { copies: 1, rounds: 2, counter: 3 });
    script('replay', 'error');
    await pcaStateWorkerMain(b.full);
    expect(lines(b.full.out)).toBe(raw(L(3, 0, 1, 0), L(3, 0, 0, 1)));
    expect(st.created[1]!.calls.map((r) => r.body.pcactn.counter)).toEqual([3, 3]);
  });

  it('admit-then-die: one presentation of the counter, the line, then SIGKILL of itself before closing anything', async () => {
    const kill = vi.spyOn(process, 'kill').mockImplementation(() => true);
    const a = fake({ close: true, teardown: true });
    const { full } = prepare(a, { mode: 'admit-then-die', counter: 3 });
    script('admitted');
    await pcaStateWorkerMain(full);
    expect(lines(full.out)).toBe(raw(L(3, 1, 0, 0)));
    expect(kill.mock.calls).toEqual([[process.pid, 'SIGKILL']]);
    expect(st.created[0]!.calls.map((r) => r.body.pcactn.counter)).toEqual([3]);
    expect(log).toEqual(['open0']);
  });

  it('race mode never kills the process', async () => {
    const kill = vi.spyOn(process, 'kill').mockImplementation(() => true);
    const { full } = prepare(fake(), { copies: 1 });
    script('admitted');
    await pcaStateWorkerMain(full);
    expect(kill).not.toHaveBeenCalled();
  });

  it('multi-instance mode: on in a race and with several instances, off for a single admit-then-die guard', async () => {
    const modes = async (cfg: Partial<PcaStateWorkerConfig>): Promise<boolean[]> => {
      vi.spyOn(process, 'kill').mockImplementation(() => true);
      st.created.length = 0;
      const { full } = prepare(fake(), { copies: 1, counter: 1, ...cfg });
      script('admitted', 'admitted');
      await pcaStateWorkerMain(full);
      return st.created.map((c) => c.opts.multiInstance);
    };
    expect(await modes({ mode: 'race', instances: 1 })).toEqual([true]);
    expect(await modes({ mode: 'race', instances: 2 })).toEqual([true, true]);
    expect(await modes({ mode: 'admit-then-die', instances: 1 })).toEqual([false]);
    expect(await modes({ mode: 'admit-then-die', instances: 2 })).toEqual([true, true]);
  });

  it('waits for the start of each round in steps of at most 5 ms', async () => {
    const { full } = prepare(fake(), { copies: 0, rounds: 2, origin: 1012, roundMs: 20 });
    let clock = 1000;
    const delays: number[] = [];
    vi.spyOn(Date, 'now').mockImplementation(() => clock);
    vi.spyOn(globalThis, 'setTimeout').mockImplementation(((fn: () => void, ms?: number) => {
      delays.push(ms ?? -1);
      clock += ms ?? 0;
      queueMicrotask(fn);
      return 0;
    }) as unknown as typeof setTimeout);
    await pcaStateWorkerMain(full);
    expect(delays).toEqual([5, 5, 2, 5, 5, 5, 5]);
    expect(lines(full.out)).toBe(raw(L(1, 0, 0, 0), L(2, 0, 0, 0)));
  }, 5000);
});
