import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';
import { describe, expect, it } from 'vitest';
import { ApprovalStoreError, createDirectoryKv, createKvApprovalStore, type DurableKv } from './index';

const tmp = (): string => mkdtempSync(join(tmpdir(), 'ciba-kv-'));
const lockOf = (dir: string, key: string): string => join(dir, `${createHash('sha256').update(key).digest('hex')}.lock`);
const thrown = (fn: () => unknown): unknown => {
  try {
    fn();
  } catch (e) {
    return e;
  }
  return undefined;
};

describe('ApprovalStoreError', () => {
  it('carries its name and code', () => {
    const e = new ApprovalStoreError('bad_key', 'm');
    expect(e.name).toBe('ApprovalStoreError');
    expect(e.code).toBe('bad_key');
    expect(e.message).toBe('m');
  });
});

describe('createKvApprovalStore', () => {
  const msg = 'createKvApprovalStore: `kv` with get and putIfEquals is required';
  it('needs a kv with get and putIfEquals', () => {
    const ok: DurableKv = { get: () => undefined, putIfEquals: () => true };
    expect(() => createKvApprovalStore(undefined as never)).toThrow(new TypeError(msg));
    expect(() => createKvApprovalStore({ putIfEquals: ok.putIfEquals } as never)).toThrow(new TypeError(msg));
    expect(() => createKvApprovalStore({ get: ok.get } as never)).toThrow(new TypeError(msg));
    expect(() => createKvApprovalStore(ok)).not.toThrow();
  });
  it('a stored value that is not a valid versioned record is a typed corrupt_record', async () => {
    for (const raw of ['null', '{"version":0,"value":1}', '{"version":1.5,"value":1}', '{"version":1}', '"x"']) {
      const s = createKvApprovalStore({ get: () => raw, putIfEquals: () => true });
      await expect(s.get('k'), raw).rejects.toMatchObject({ code: 'corrupt_record', message: 'ciba: stored approval record has no valid version' });
    }
  });
});

describe('createDirectoryKv', () => {
  it('refuses a non-positive lock timeout', () => {
    for (const lockTimeoutMs of [0, -5, NaN]) {
      expect(() => createDirectoryKv(tmp(), { lockTimeoutMs })).toThrow(new TypeError('createDirectoryKv: lockTimeoutMs must be a positive number'));
    }
  });
  it('refuses a key that is not a non-empty string with a typed bad_key', () => {
    const kv = createDirectoryKv(tmp());
    for (const key of [5, '', undefined]) {
      const e = thrown(() => kv.get(key as never));
      expect(e).toBeInstanceOf(ApprovalStoreError);
      expect(e).toMatchObject({ code: 'bad_key', message: 'ciba: store key must be a non-empty string' });
    }
  });
  it('a held lock is a typed lock_timeout', () => {
    const dir = tmp();
    const kv = createDirectoryKv(dir, { lockTimeoutMs: 30 });
    writeFileSync(lockOf(dir, 'k'), '');
    const e = thrown(() => kv.putIfEquals('k', undefined, 'v'));
    expect(e).toBeInstanceOf(ApprovalStoreError);
    expect(e).toMatchObject({ code: 'lock_timeout', message: 'ciba: could not take the store lock in time' });
    expect(kv.get('k')).toBeUndefined();
  });
  it('an unrelated filesystem error is rethrown, not mistaken for a held lock', () => {
    const dir = tmp();
    const kv = createDirectoryKv(dir, { lockTimeoutMs: 50 });
    rmSync(dir, { recursive: true });
    const e = thrown(() => kv.putIfEquals('k', undefined, 'v'));
    expect(e).not.toBeInstanceOf(ApprovalStoreError);
    expect((e as NodeJS.ErrnoException).code).toBe('ENOENT');
  });
  it('waits for a lock that is released within the timeout instead of giving up at once', () => {
    const dir = tmp();
    const kv = createDirectoryKv(dir, { lockTimeoutMs: 8000 });
    const lock = lockOf(dir, 'k');
    writeFileSync(lock, '');
    const worker = new Worker(
      "const { workerData } = require('node:worker_threads'); Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 60); require('node:fs').unlinkSync(workerData.lock);",
      { eval: true, workerData: { lock } },
    );
    try {
      expect(kv.putIfEquals('k', undefined, 'v')).toBe(true);
      expect(kv.get('k')).toBe('v');
      expect(existsSync(lock)).toBe(false);
    } finally {
      void worker.terminate();
    }
  }, 20_000);
});
