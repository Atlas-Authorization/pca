import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { prng } from './harness';
import { clock, FileRecorder, parseHistory } from './recorder';
import { fastCheck, type Op } from './model';
import { runTest } from './runner';
import type { StoreAdapter } from './types';
import { workerMain } from './worker';

describe('fastCheck', () => {
  it('a definite true needs no explanation as a false would, even when its own range is malformed', () => {
    const op: Op = { client: 'c', kind: 'advance', key: 'k', lo: 10, w: 5, call: 0, ret: 1, res: 'true' };
    expect(fastCheck([op])).toBe(true);
  });
});

describe('runTest', () => {
  const failing: StoreAdapter = {
    name: 'always failing',
    open: async () => ({
      consumeOnce: async () => {
        throw new Error('down');
      },
    }),
  };

  it('an adapter without declared capabilities is still run for durability, and the notes are joined', async () => {
    const r = await runTest(failing, 'durability', 'consume', { clients: 1 });
    expect(r.status).toBe('unresolved');
    expect(r.note).toBe('no restart() hook: clients closed and re-opened only; no definite answer was observed (every call failed or timed out)');
  });
});

describe('workerMain', () => {
  const run = async (): Promise<ReturnType<typeof parseHistory>> => {
    const file = join(mkdtempSync(join(tmpdir(), 'pcasc-worker-')), 'h-pw.jsonl');
    const origin = clock();
    await workerMain({
      module: 'builtin:in-memory',
      options: {},
      kind: 'advance',
      proc: 'pw',
      file,
      clients: 2,
      namespace: 'ns',
      windowMs: 5,
      spread: 3,
      values: 20,
      retentionMs: 600_000,
      opTimeoutMs: 1000,
      origin,
      deadline: origin + 60,
      seed: 100,
    });
    return parseHistory(readFileSync(file, 'utf8'));
  };

  it('each client draws from the generator seeded with seed + its index', async () => {
    const h = await run();
    const expected = (seed: number): number[] => {
      const rand = prng(seed);
      return Array.from({ length: 5 }, () => {
        rand(3);
        return rand(20);
      });
    };
    for (const i of [0, 1]) {
      const mine = h.ops.filter((o) => o.client === `pwc${i}`).map((o) => o.lo);
      expect(mine.length).toBeGreaterThanOrEqual(5);
      expect(mine.slice(0, 5)).toEqual(expected(100 + i));
    }
  });

  it('closes its history file', async () => {
    const close = vi.spyOn(FileRecorder.prototype, 'close');
    try {
      await run();
      expect(close).toHaveBeenCalledTimes(1);
    } finally {
      close.mockRestore();
    }
  });
});
