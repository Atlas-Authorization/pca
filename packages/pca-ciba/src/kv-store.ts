/**
 * Shared-store reference for the durable broker: a versioned {@link ApprovalStore} built on a tiny durable key-value
 * interface that needs ONE primitive, a compare-and-swap on a string. Redis (a Lua script or WATCH/MULTI), DynamoDB
 * (a conditional put), SQL (`UPDATE ... WHERE value = ?`) and etcd (a transaction) all provide it.
 */
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import type { ApprovalStore, Versioned } from './approval';

/**
 * A durable string key-value store with compare-and-swap.
 * `putIfEquals(key, expected, next)` writes `next` only if the stored value is exactly `expected` (`undefined` means
 * "the key must be absent") and reports whether it wrote. It MUST be atomic across every process sharing the store, and
 * a write MUST be durable before it resolves. Any failure must throw: never return `true` for a write that may be lost.
 */
export interface DurableKv {
  get(key: string): string | undefined | Promise<string | undefined>;
  putIfEquals(key: string, expected: string | undefined, next: string): boolean | Promise<boolean>;
}

/** Thrown by the KV reference implementations; the broker treats any throw from the store as "no approval". */
export class ApprovalStoreError extends Error {
  readonly code: 'corrupt_record' | 'lock_timeout' | 'bad_key';
  constructor(code: 'corrupt_record' | 'lock_timeout' | 'bad_key', message: string) {
    super(message);
    this.name = 'ApprovalStoreError';
    this.code = code;
  }
}

function decode(raw: string): Versioned {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ApprovalStoreError('corrupt_record', 'ciba: stored approval record is not valid JSON');
  }
  const r = parsed as { version?: unknown; value?: unknown } | null;
  if (r === null || typeof r !== 'object' || !Number.isInteger(r.version) || (r.version as number) < 1 || !('value' in r)) {
    throw new ApprovalStoreError('corrupt_record', 'ciba: stored approval record has no valid version');
  }
  return { version: r.version as number, value: r.value };
}

/**
 * An {@link ApprovalStore} over a {@link DurableKv}. Each key holds `{version, value}` as JSON; `cas` re-reads the raw
 * string, checks the version, and swaps only if the raw string is still the one it read, so two processes racing on the
 * same expected version cannot both win. A stored value that is not a valid versioned record throws (`corrupt_record`).
 */
export function createKvApprovalStore(kv: DurableKv): ApprovalStore {
  if (!kv || typeof kv.get !== 'function' || typeof kv.putIfEquals !== 'function') {
    throw new TypeError('createKvApprovalStore: `kv` with get and putIfEquals is required');
  }
  return {
    async get(key) {
      const raw = await kv.get(key);
      return raw === undefined ? undefined : decode(raw);
    },
    async cas(key, expectedVersion, value) {
      const raw = await kv.get(key);
      const current = raw === undefined ? 0 : decode(raw).version;
      if (current !== expectedVersion) return false;
      const next = JSON.stringify({ version: expectedVersion + 1, value });
      return (await kv.putIfEquals(key, raw, next)) === true;
    },
  };
}

/**
 * A {@link DurableKv} on a directory, safe for several processes on ONE host (and one filesystem with atomic
 * exclusive-create and rename). One file per key; each swap takes a per-key lock file (exclusive create), compares,
 * writes a temp file and renames it over the key. A process that dies while holding the lock leaves it behind: every
 * later swap on that key then throws `lock_timeout` (fail closed) until an operator removes the `.lock` file.
 * For several hosts use a database-backed {@link DurableKv}.
 */
export function createDirectoryKv(dir: string, opts: { lockTimeoutMs?: number } = {}): DurableKv {
  const timeout = opts.lockTimeoutMs ?? 5000;
  if (!Number.isFinite(timeout) || timeout <= 0) throw new TypeError('createDirectoryKv: lockTimeoutMs must be a positive number');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  // The key is hashed into the file name, so no key can escape the directory.
  const fileOf = (key: string): string => {
    if (typeof key !== 'string' || key === '') throw new ApprovalStoreError('bad_key', 'ciba: store key must be a non-empty string');
    return join(dir, createHash('sha256').update(key).digest('hex'));
  };
  const sleepBuf = new Int32Array(new SharedArrayBuffer(4));
  return {
    get(key) {
      const f = fileOf(key);
      return existsSync(f) ? readFileSync(f, 'utf8') : undefined;
    },
    putIfEquals(key, expected, next) {
      const f = fileOf(key);
      const lock = `${f}.lock`;
      const deadline = Date.now() + timeout;
      let fd: number | undefined;
      while (fd === undefined) {
        try {
          fd = openSync(lock, 'wx', 0o600);
        } catch (e) {
          if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
          if (Date.now() >= deadline) throw new ApprovalStoreError('lock_timeout', 'ciba: could not take the store lock in time');
          Atomics.wait(sleepBuf, 0, 0, 2);
        }
      }
      try {
        const current = existsSync(f) ? readFileSync(f, 'utf8') : undefined;
        if (current !== expected) return false;
        const tmp = `${f}.${process.pid}.tmp`;
        const t = openSync(tmp, 'w', 0o600);
        try {
          writeSync(t, next);
          fsyncSync(t); // durable before the rename publishes it
        } finally {
          closeSync(t);
        }
        renameSync(tmp, f);
        return true;
      } finally {
        closeSync(fd);
        unlinkSync(lock);
      }
    },
  };
}
