/** The file store flushes in the order open, write, fsync, close, rename: no step may be skipped. */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';

const calls: string[] = [];
vi.mock('node:fs', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:fs')>();
  const wrap = <K extends 'openSync' | 'writeSync' | 'fsyncSync' | 'closeSync' | 'renameSync'>(k: K): (typeof real)[K] =>
    ((...a: unknown[]) => {
      calls.push(k);
      return (real[k] as (...x: unknown[]) => unknown)(...a);
    }) as (typeof real)[K];
  return { ...real, openSync: wrap('openSync'), writeSync: wrap('writeSync'), fsyncSync: wrap('fsyncSync'), closeSync: wrap('closeSync'), renameSync: wrap('renameSync') };
});

const dir = mkdtempSync(join(tmpdir(), 'pca-revoke-order-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('FileRevocationStore durability order', () => {
  it('one add is open, write, fsync, close, rename', async () => {
    const { FileRevocationStore } = await import('./file-store');
    const s = new FileRevocationStore(join(dir, 'r.json'));
    calls.length = 0;
    await s.add({ kind: 'cap', value: 'c', reason: 'r', revokedAt: 1 });
    expect(calls).toEqual(['openSync', 'writeSync', 'fsyncSync', 'closeSync', 'renameSync']);
  });
  it('the descriptor is closed even when the write fails', async () => {
    const { FileRevocationStore } = await import('./file-store');
    const s = new FileRevocationStore(join(dir, 'r2.json'));
    calls.length = 0;
    // a value JSON.stringify cannot serialise makes the write step throw after the file was opened
    const loop: Record<string, unknown> = {};
    loop.self = loop;
    await expect(s.add({ kind: 'cap', value: 'c', reason: 'r', revokedAt: 1, extra: loop } as never)).rejects.toThrow();
    expect(calls).toEqual(['openSync', 'closeSync']);
  });
});
