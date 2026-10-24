// Multi-process runs: the forked workers execute the COMPILED harness (dist/worker.js), so the package must be built.
import { existsSync, mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { checkHistory } from './check';
import { runCrash } from './crash';
import { parseHistory } from './recorder';
import { workerMain } from './worker';

const workerPath = join(__dirname, '..', 'dist', 'worker.js');
const fx = (f: string): string => join(__dirname, '..', 'test', 'fixtures', f);

describe('workerMain (in process)', () => {
  it('loads the adapter, runs the windowed workload and records every operation to its file', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-w-'));
    const now = performance.timeOrigin + performance.now();
    await workerMain({
      module: 'builtin:in-memory',
      options: {},
      kind: 'advance',
      proc: 'p7',
      file: join(dir, 'h-p7.jsonl'),
      clients: 3,
      namespace: 'wm',
      windowMs: 5,
      spread: 2,
      values: 4,
      retentionMs: 1000,
      opTimeoutMs: 1000,
      origin: now,
      deadline: now + 40,
      seed: 1,
    });
    const h = parseHistory(readFileSync(join(dir, 'h-p7.jsonl'), 'utf8'));
    expect(h.pending).toBe(0);
    expect(h.torn).toBe(0);
    expect(h.ops.length).toBeGreaterThan(10);
    expect(new Set(h.ops.map((o) => o.client))).toEqual(new Set(['p7c0', 'p7c1', 'p7c2']));
    expect(h.ops.every((o) => o.key.startsWith('wm:advance:'))).toBe(true);
    expect(checkHistory(h.ops).ok).toBe(true);
  });
});

describe.runIf(existsSync(workerPath))('runCrash (child processes, SIGKILL)', () => {
  it('a good multi-process store (durable-state files) stays linearizable while client processes are killed', async () => {
    const store = mkdtempSync(join(tmpdir(), 'pcasc-crash-store-'));
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-crash-hist-'));
    const r = await runCrash('consume', { module: 'builtin:durable-file', options: { dir: store }, processes: 3, clients: 2, durationMs: 2500, killEveryMs: 300, dir, workerPath });
    expect(r.kills).toBeGreaterThan(2);
    expect(r.processes).toBe(3 + r.kills);
    expect(readdirSync(dir).filter((f) => f.endsWith('.jsonl')).length).toBeLessThanOrEqual(r.processes);
    expect(r.ops.length).toBeGreaterThan(20);
    expect(r.errors).toBe(r.ops.filter((o) => o.res === 'unknown').length);
    const h = checkHistory(r.ops);
    expect(h.violations).toEqual([]);
    expect(r.backendCrashes).toBe(0); // the file store has no crash() hook
  }, 60_000);
  it('flags an in-memory store used from several processes (each process has its own map)', async () => {
    const r = await runCrash('consume', { module: 'builtin:in-memory', processes: 3, clients: 2, durationMs: 1500, killEveryMs: 0, workerPath, windowMs: 50, spread: 1 });
    expect(r.kills).toBe(0);
    expect(r.processes).toBe(3);
    expect(r.pending).toBe(0);
    expect(checkHistory(r.ops).violations.length).toBeGreaterThan(0);
  }, 60_000);
  it('crashes and restarts the backend once mid-run through the adapter hooks', async () => {
    const log = join(mkdtempSync(join(tmpdir(), 'pcasc-hooks-')), 'log');
    const r = await runCrash('advance', { module: fx('crash-hooks.mjs'), options: { log }, processes: 1, clients: 1, durationMs: 1200, killEveryMs: 100, workerPath });
    expect(r.backendCrashes).toBe(1);
    const lines = readFileSync(log, 'utf8').trim().split('\n');
    expect(lines.map((l) => l.split(' ')[0])).toEqual(['crash', 'restart']);
    expect(lines[0]!.split(' ')[1]).toBe(String(process.pid));
    const none = await runCrash('advance', { module: fx('crash-hooks.mjs'), options: { log: `${log}2` }, processes: 1, clients: 1, durationMs: 600, killEveryMs: 100, workerPath, backendCrash: false });
    expect(none.backendCrashes).toBe(0);
    expect(existsSync(`${log}2`)).toBe(false);
  }, 60_000);
});
