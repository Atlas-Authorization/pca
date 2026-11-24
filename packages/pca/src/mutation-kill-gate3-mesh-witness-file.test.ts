/**
 * Mutation kills for the 0.5.0 flagship gate survivors in durable-mesh-witness.ts: the save sequence (write, fsync and
 * close the temporary file, rename it over the state file, fsync and close the directory), observed through a node:fs
 * interception, and a state file whose state is null under a matching digest.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FileMeshWitnessStore } from './durable-mesh-witness';
import { hashCanonical } from './hash';

const hooks = vi.hoisted(() => ({ ev: [] as string[], fdPath: new Map<number, string>() }));
vi.mock('node:fs', async (importOriginal) => {
  const a = await importOriginal<typeof import('node:fs')>();
  const name = (fd: number) => hooks.fdPath.get(fd) ?? '?';
  return {
    ...a,
    openSync: (p: string, ...r: unknown[]) => {
      const fd = (a.openSync as (...x: unknown[]) => number)(p, ...r);
      hooks.fdPath.set(fd, String(p));
      hooks.ev.push(`open ${String(p)}`);
      return fd;
    },
    writeSync: (fd: number, ...r: unknown[]) => {
      hooks.ev.push(`write ${name(fd)}`);
      return (a.writeSync as (...x: unknown[]) => number)(fd, ...r);
    },
    fsyncSync: (fd: number) => {
      hooks.ev.push(`fsync ${name(fd)}`);
      return a.fsyncSync(fd);
    },
    closeSync: (fd: number) => {
      hooks.ev.push(`close ${name(fd)}`);
      return a.closeSync(fd);
    },
    renameSync: (from: string, to: string) => {
      hooks.ev.push(`rename ${from} ${to}`);
      return a.renameSync(from, to);
    },
  };
});

const dirs: string[] = [];
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), 'pca-mwf-'));
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  hooks.ev.length = 0;
});

describe('FileMeshWitnessStore.save', () => {
  it('writes, fsyncs and closes the temporary file, renames it, then fsyncs and closes the directory', () => {
    const file = join(tmp(), 'w.json');
    const s = new FileMeshWitnessStore(file);
    hooks.ev.length = 0;
    s.save({ seen: [] });
    const t = `${file}.tmp`;
    const d = dirname(file);
    expect(hooks.ev).toEqual([`open ${t}`, `write ${t}`, `fsync ${t}`, `close ${t}`, `rename ${t} ${file}`, `open ${d}`, `fsync ${d}`, `close ${d}`]);
    expect(s.load()).toEqual({ seen: [] });
  });
});

describe('FileMeshWitnessStore.load', () => {
  it('a null state is the wrong shape even when the digest matches it', () => {
    const file = join(tmp(), 'w.json');
    writeFileSync(file, JSON.stringify({ v: 1, state: null, digest: hashCanonical(null) }));
    expect(() => new FileMeshWitnessStore(file).load()).toThrow('FileMeshWitnessStore: the state file has an unexpected shape; refusing to start empty');
  });
});
