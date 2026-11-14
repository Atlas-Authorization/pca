/** The directory KV must make the data durable and release every descriptor: observed through the fs calls it makes. */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';

const calls = vi.hoisted(() => ({ fsync: [] as number[], close: [] as number[], open: [] as number[], log: [] as string[] }));
vi.mock('node:fs', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:fs')>();
  return {
    ...real,
    openSync: ((...a: Parameters<typeof real.openSync>) => {
      const fd = real.openSync(...a);
      calls.open.push(fd);
      return fd;
    }) as typeof real.openSync,
    fsyncSync: (fd: number) => {
      calls.fsync.push(fd);
      calls.log.push('fsync');
      return real.fsyncSync(fd);
    },
    closeSync: (fd: number) => {
      calls.close.push(fd);
      calls.log.push('close');
      return real.closeSync(fd);
    },
    renameSync: ((...a: Parameters<typeof real.renameSync>) => {
      calls.log.push('rename');
      return real.renameSync(...a);
    }) as typeof real.renameSync,
  };
});

import { createDirectoryKv } from './kv-store';

describe('createDirectoryKv write path', () => {
  it('syncs the temp file before the rename publishes it and closes both descriptors', () => {
    const kv = createDirectoryKv(mkdtempSync(join(tmpdir(), 'ciba-kvfs-')));
    expect(kv.putIfEquals('k', undefined, 'v')).toBe(true);
    const [lockFd, tmpFd] = calls.open;
    expect(calls.fsync).toEqual([tmpFd]);
    expect([...calls.close].sort()).toEqual([lockFd, tmpFd].sort());
    expect(calls.log.indexOf('fsync')).toBeLessThan(calls.log.indexOf('rename'));
    expect(calls.log.indexOf('close')).toBeLessThan(calls.log.indexOf('rename'));
  });
  it('a refused swap still releases the lock descriptor', () => {
    const kv = createDirectoryKv(mkdtempSync(join(tmpdir(), 'ciba-kvfs-')));
    kv.putIfEquals('k', undefined, 'v');
    calls.open.length = 0;
    calls.close.length = 0;
    expect(kv.putIfEquals('k', undefined, 'again')).toBe(false);
    expect(calls.close).toEqual(calls.open);
    expect(calls.open).toHaveLength(1);
  });
});
