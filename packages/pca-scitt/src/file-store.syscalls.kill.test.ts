import { closeSync, fsyncSync, mkdtempSync, appendFileSync, readSync, writeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// Wrap the real syscalls: count close/fsync and force short reads and writes (as a real disk may), calling through.
vi.mock('node:fs', async (orig) => {
  const actual = await orig<typeof import('node:fs')>();
  return {
    ...actual,
    closeSync: vi.fn(actual.closeSync),
    fsyncSync: vi.fn(actual.fsyncSync),
    readSync: vi.fn((fd: number, buf: NodeJS.ArrayBufferView, off: number, len: number, pos: number) => actual.readSync(fd, buf, off, Math.min(len, 3), pos)),
    writeSync: vi.fn((fd: number, buf: NodeJS.ArrayBufferView, off: number, len: number, pos: number) => actual.writeSync(fd, buf, off, Math.min(len, 3), pos)),
  };
});

import { FileScittLogStore } from './file-store';

const tmp = () => join(mkdtempSync(join(tmpdir(), 'scitt-sys-')), 'log.bin');
const h = (b: number) => new Uint8Array(32).fill(b);
beforeEach(() => {
  vi.mocked(closeSync).mockClear();
  vi.mocked(fsyncSync).mockClear();
  vi.mocked(readSync).mockClear();
  vi.mocked(writeSync).mockClear();
});

describe('FileScittLogStore syscalls', () => {
  it('open closes its creation descriptor, close() closes the store descriptor', () => {
    const s = FileScittLogStore.open(tmp());
    expect(vi.mocked(closeSync)).toHaveBeenCalledTimes(1);
    s.close();
    expect(vi.mocked(closeSync)).toHaveBeenCalledTimes(2);
  });
  it('append fsyncs once per transaction; an intact reopen never fsyncs', async () => {
    const path = tmp();
    const s = FileScittLogStore.open(path);
    expect(await s.append(0, Uint8Array.of(1, 2, 3, 4, 5), [{ level: 0, index: 0, hash: h(1) }])).toBe(true);
    expect(vi.mocked(fsyncSync)).toHaveBeenCalledTimes(1);
    expect(await s.append(0, Uint8Array.of(9), [])).toBe(false); // refused: no fsync
    expect(vi.mocked(fsyncSync)).toHaveBeenCalledTimes(1);
    vi.mocked(fsyncSync).mockClear();
    FileScittLogStore.open(path);
    expect(vi.mocked(fsyncSync)).not.toHaveBeenCalled();
  });
  it('short writes are completed at the right offsets and short reads are reassembled', async () => {
    const path = tmp();
    const s = FileScittLogStore.open(path);
    const entries = [Uint8Array.from({ length: 40 }, (_, i) => i), Uint8Array.from({ length: 17 }, (_, i) => 100 + i)];
    for (const [i, e] of entries.entries()) expect(await s.append(i, e, [{ level: 0, index: i, hash: h(i + 1) }])).toBe(true);
    expect(vi.mocked(writeSync).mock.calls.length).toBeGreaterThan(4);
    const r = FileScittLogStore.open(path);
    expect(await r.size()).toBe(2);
    for (const [i, e] of entries.entries()) {
      expect(Buffer.from((await r.getEntry(i))!).equals(Buffer.from(e))).toBe(true);
      expect(Buffer.from((await r.getNode(0, i))!).equals(Buffer.from(h(i + 1)))).toBe(true);
    }
  });
  it('a torn tail is truncated and fsynced exactly once', async () => {
    const path = tmp();
    const s = FileScittLogStore.open(path);
    await s.append(0, Uint8Array.of(1), [{ level: 0, index: 0, hash: h(1) }]);
    appendFileSync(path, Buffer.from([0xaa, 0xbb]));
    vi.mocked(fsyncSync).mockClear();
    const r = FileScittLogStore.open(path);
    expect(await r.size()).toBe(1);
    expect(vi.mocked(fsyncSync)).toHaveBeenCalledTimes(1);
  });
});
