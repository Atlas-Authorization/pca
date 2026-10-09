/**
 * Crash-safe, tamper-evident, multi-process-safe persistent key/value state for Node
 * (NODE ONLY: imports node:fs; deliberately not re-exported from the package index so browser bundles stay clean).
 *
 * WHY: rollback protection for signed allowlist manifests and MAA key sets (attest-allowlist, attest-maa-keys)
 * is only as good as the persistence of "the highest thing I ever accepted". This module is that persistence.
 *
 * LAYOUT (a directory you own, mode 0700): `state.journal` (hash-chained records, one JSON object per line),
 * `state.head` (seq + hash of the last record, written AFTER the journal), `state.lock` (advisory lock).
 *
 * WHAT IS GUARANTEED
 *   - CRASH SAFETY: every mutation is write-temp -> fsync(file) -> rename -> fsync(directory). A crash (SIGKILL,
 *     power loss on a filesystem honouring fsync) leaves either the old or the new journal, never a torn one. The
 *     head file trails the journal by at most ONE record and is repaired by the next writer.
 *   - NO LOST UPDATES across processes: every mutation (`set` / `update`) runs under an exclusive advisory lock
 *     (O_EXCL lock file with owner pid/host/nonce, stale-owner takeover by dead pid on the same host or by age,
 *     and a nonce re-check right before the commit rename). `update(key, fn)` is an atomic read-modify-write, so
 *     "monotone max" semantics hold under concurrency.
 *   - TAMPER / TRUNCATION EVIDENCE: records are hash-chained (sha256 over seq, prev hash, op, payload, time).
 *     Editing, reordering, inserting or deleting a record in the middle breaks the chain; truncating the tail or
 *     replacing the journal with an OLDER valid copy is caught by the head file (journal.seq < head.seq) and, in a
 *     running process, by the highest (seq, hash) this instance has already observed. Deleting ONLY the journal
 *     while the head survives is caught too. With `hmacKey`, every record and the head are HMAC-SHA256 tagged so
 *     an attacker without the key cannot forge or re-chain either.
 *   - FAIL CLOSED: corrupt, truncated or rolled-back state makes `openDurableState` / every operation throw a
 *     `DurableStateError`. It never silently starts empty. The ONLY way past is the explicit
 *     `recoverFromCorruption: true` option, which quarantines the bad files (kept for forensics, never deleted)
 *     and starts from genesis with `recovered === true` so the caller can re-establish trust.
 *
 * WHAT IS NOT GUARANTEED
 *   - An attacker who can write BOTH the journal and the head file AND has no HMAC key to defeat can restore an
 *     older consistent (journal, head) pair; without `hmacKey` that is undetectable locally. Deleting the whole
 *     directory is likewise indistinguishable from a first run. That residual gap is what the transparency-anchored
 *     check (attest-allowlist-anchor) exists for: it needs no local state at all.
 *   - fsync durability is whatever the OS/filesystem delivers (macOS fsync does not force the drive cache; use a
 *     filesystem/mount that honours it for power-loss guarantees). Process crash safety does not depend on this.
 *   - The advisory lock protects cooperating processes on ONE host (a shared network filesystem with a broken
 *     O_EXCL is out of scope). Lock takeover from a hung-but-alive owner older than `staleLockMs` is possible.
 *   - The journal is rewritten whole per mutation (it is for small state: versions, digests, key sets) and is
 *     compacted into a checkpoint record every `compactEvery` records.
 */
import { closeSync, constants, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync, chmodSync } from 'node:fs';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { hostname } from 'node:os';
import { join } from 'node:path';

export type DurableStateErrorCode = 'corrupt' | 'rollback' | 'lock-timeout' | 'key-mismatch' | 'invalid' | 'too-large';

export class DurableStateError extends Error {
  constructor(
    readonly code: DurableStateErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = 'DurableStateError';
  }
}

/** The persistence interface the allowlist / key-trust modules use. Values must be JSON-serialisable. */
export interface DurableKv {
  get(key: string): Promise<unknown | undefined>;
  /** Unconditional write (still serialised and hash-chained). Prefer `update` for monotone state. */
  set(key: string, value: unknown): Promise<void>;
  /**
   * Atomic read-modify-write. `fn` receives the current value (or undefined) and returns the next value, or
   * `undefined` to leave the key unchanged. Returns the value now stored. `fn` runs under the cross-process lock
   * and must be synchronous and quick.
   */
  update(key: string, fn: (prev: unknown | undefined) => unknown | undefined): Promise<unknown | undefined>;
  keys(): Promise<string[]>;
}

/** In-memory implementation (tests / single process). Same semantics, no durability. */
export function createMemoryDurableKv(): DurableKv & { snapshot(): Map<string, unknown> } {
  const m = new Map<string, string>();
  const dec = (s: string | undefined): unknown | undefined => (s === undefined ? undefined : (JSON.parse(s) as unknown));
  return {
    async get(k) {
      return dec(m.get(k));
    },
    async set(k, v) {
      const s = JSON.stringify(v);
      if (s === undefined) throw new DurableStateError('invalid', 'value is not JSON-serialisable');
      m.set(k, s);
    },
    async update(k, fn) {
      const next = fn(dec(m.get(k)));
      if (next !== undefined) {
        const s = JSON.stringify(next);
        if (s === undefined) throw new DurableStateError('invalid', 'value is not JSON-serialisable');
        m.set(k, s);
      }
      return dec(m.get(k));
    },
    async keys() {
      return [...m.keys()].sort();
    },
    snapshot: () => new Map([...m].map(([k, v]) => [k, JSON.parse(v) as unknown])),
  };
}

export interface DurableStateOptions {
  /** Directory holding the state (created 0700 if missing). */
  dir: string;
  /** Optional >= 32-byte HMAC key: records and head are tagged; forging/re-chaining then needs the key. */
  hmacKey?: Uint8Array;
  /** Explicit recovery: quarantine corrupt/rolled-back files and start from genesis. Default false (fail closed). */
  recoverFromCorruption?: boolean;
  /** Give up acquiring the lock after this long (default 10 s). */
  lockTimeoutMs?: number;
  /** Treat a lock older than this as abandoned (default 30 s). */
  staleLockMs?: number;
  /** Compact the journal into a checkpoint every N records (default 256). */
  compactEvery?: number;
  /** Max serialised value size (default 1 MiB). */
  maxValueBytes?: number;
  /** Clock for record timestamps (default Date.now). */
  now?: () => number;
  /** TEST ONLY: SIGKILL this process at the named point of a commit, to prove crash safety. */
  testCrashAt?: 'after-temp-write' | 'after-journal-rename';
}

export interface DurableState extends DurableKv {
  /** True when this open quarantined corrupt state (see `recoverFromCorruption`). */
  readonly recovered: boolean;
  /** Highest chain position this handle has observed. */
  position(): { seq: number; hash: string };
  /** Verify the chain from disk now; throws DurableStateError on any problem. */
  verify(): Promise<{ seq: number; hash: string }>;
}

const DOMAIN = 'pca-durable-state/v1\n';
const GENESIS = '0'.repeat(64);
const HEX64 = /^[0-9a-f]{64}$/;
const MAX_KEY = 256;

interface Rec {
  seq: number;
  prev: string;
  op: 'set' | 'checkpoint';
  payload: string;
  ts: number;
  h: string;
  mac?: string;
}
interface Head {
  seq: number;
  h: string;
  mac?: string;
}

const sha = (s: string): string => createHash('sha256').update(s).digest('hex');
const recHash = (r: Pick<Rec, 'seq' | 'prev' | 'op' | 'payload' | 'ts'>): string => sha(DOMAIN + JSON.stringify([r.seq, r.prev, r.op, r.payload, r.ts]));
const macOf = (key: Uint8Array, msg: string): string => createHmac('sha256', key).update(msg).digest('hex');
const macEq = (a: string, b: string): boolean => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const headMsg = (seq: number, h: string): string => `head\n${seq}\n${h}`;

function fsyncDir(dir: string): void {
  const fd = openSync(dir, constants.O_RDONLY);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function atomicWrite(path: string, data: string, crashAfterTemp: boolean): void {
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`;
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  if (crashAfterTemp) process.kill(process.pid, 'SIGKILL');
  renameSync(tmp, path);
  fsyncDir(join(path, '..'));
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM';
  }
}

interface Loaded {
  recs: Rec[];
  state: Map<string, string>;
  head: Head | undefined;
}

/** Open (creating if needed) a durable state directory. THROWS DurableStateError on corrupt/rolled-back state unless recovering. */
export async function openDurableState(opts: DurableStateOptions): Promise<DurableState> {
  if (typeof opts?.dir !== 'string' || opts.dir.length === 0) throw new DurableStateError('invalid', 'dir is required');
  if (opts.hmacKey !== undefined && opts.hmacKey.length < 32) throw new DurableStateError('invalid', 'hmacKey must be at least 32 bytes');
  const dir = opts.dir;
  const key = opts.hmacKey;
  const lockTimeout = opts.lockTimeoutMs ?? 10_000;
  const staleLock = opts.staleLockMs ?? 30_000;
  const compactEvery = Math.max(2, opts.compactEvery ?? 256);
  const maxValue = opts.maxValueBytes ?? 1_048_576;
  const now = opts.now ?? Date.now;
  const journalPath = join(dir, 'state.journal');
  const headPath = join(dir, 'state.head');
  const lockPath = join(dir, 'state.lock');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dir, 0o700);
  } catch {
    /* not ours to chmod (e.g. a shared parent); keep going */
  }

  let seen: { seq: number; hash: string } = { seq: 0, hash: GENESIS };
  let recovered = false;

  const readHead = (): Head | undefined => {
    if (!existsSync(headPath)) return undefined;
    let o: unknown;
    try {
      o = JSON.parse(readFileSync(headPath, 'utf8'));
    } catch {
      throw new DurableStateError('corrupt', 'state.head is not valid JSON');
    }
    const r = o as Record<string, unknown>;
    if (typeof o !== 'object' || o === null || !Number.isSafeInteger(r['seq']) || (r['seq'] as number) < 0 || typeof r['h'] !== 'string' || !HEX64.test(r['h'])) {
      throw new DurableStateError('corrupt', 'state.head has an invalid shape');
    }
    const head: Head = { seq: r['seq'] as number, h: r['h'] };
    if (typeof r['mac'] === 'string') head.mac = r['mac'];
    if (key) {
      if (head.mac === undefined || !macEq(head.mac, macOf(key, headMsg(head.seq, head.h)))) throw new DurableStateError('key-mismatch', 'state.head MAC does not verify (wrong key or forged head)');
    }
    return head;
  };

  const load = (): Loaded => {
    const head = readHead();
    const jExists = existsSync(journalPath);
    if (!jExists) {
      if (head !== undefined && head.seq > 0) throw new DurableStateError('rollback', `state.journal is missing but state.head records seq ${head.seq}`);
      if (seen.seq > 0) throw new DurableStateError('rollback', 'state was deleted while open');
      return { recs: [], state: new Map(), head };
    }
    const text = readFileSync(journalPath, 'utf8');
    const lines = text.split('\n');
    if (lines.length === 0 || lines[lines.length - 1] !== '') throw new DurableStateError('corrupt', 'journal does not end with a newline (torn or truncated)');
    lines.pop();
    const recs: Rec[] = [];
    const state = new Map<string, string>();
    let prevHash = GENESIS;
    let prevSeq = 0;
    for (const [i, line] of lines.entries()) {
      let o: unknown;
      try {
        o = JSON.parse(line);
      } catch {
        throw new DurableStateError('corrupt', `journal line ${i + 1} is not valid JSON`);
      }
      const r = o as Record<string, unknown>;
      if (
        typeof o !== 'object' || o === null || !Number.isSafeInteger(r['seq']) || typeof r['prev'] !== 'string' || !HEX64.test(r['prev']) ||
        (r['op'] !== 'set' && r['op'] !== 'checkpoint') || typeof r['payload'] !== 'string' || !Number.isSafeInteger(r['ts']) || typeof r['h'] !== 'string' || !HEX64.test(r['h'])
      ) {
        throw new DurableStateError('corrupt', `journal line ${i + 1} has an invalid shape`);
      }
      const rec: Rec = { seq: r['seq'] as number, prev: r['prev'], op: r['op'], payload: r['payload'], ts: r['ts'] as number, h: r['h'], ...(typeof r['mac'] === 'string' ? { mac: r['mac'] } : {}) };
      if (i === 0) {
        if (rec.op === 'set' && (rec.seq !== 1 || rec.prev !== GENESIS)) throw new DurableStateError('corrupt', 'journal does not start at genesis');
        if (rec.op === 'checkpoint' && rec.seq < 1) throw new DurableStateError('corrupt', 'bad checkpoint seq');
      } else {
        if (rec.seq !== prevSeq + 1) throw new DurableStateError('corrupt', `journal line ${i + 1}: sequence gap`);
        if (rec.prev !== prevHash) throw new DurableStateError('corrupt', `journal line ${i + 1}: hash chain broken`);
      }
      if (recHash(rec) !== rec.h) throw new DurableStateError('corrupt', `journal line ${i + 1}: record hash mismatch (edited)`);
      if (key) {
        if (rec.mac === undefined || !macEq(rec.mac, macOf(key, rec.h))) throw new DurableStateError('key-mismatch', `journal line ${i + 1}: MAC does not verify (wrong key or forged record)`);
      } else if (rec.mac !== undefined) {
        throw new DurableStateError('key-mismatch', 'journal is MAC-tagged but no hmacKey was supplied');
      }
      if (rec.op === 'checkpoint') {
        let entries: unknown;
        try {
          entries = JSON.parse(rec.payload);
        } catch {
          throw new DurableStateError('corrupt', 'checkpoint payload is not JSON');
        }
        if (!Array.isArray(entries)) throw new DurableStateError('corrupt', 'checkpoint payload is not an array');
        state.clear();
        for (const e of entries) {
          if (!Array.isArray(e) || e.length !== 2 || typeof e[0] !== 'string' || typeof e[1] !== 'string') throw new DurableStateError('corrupt', 'checkpoint entry is malformed');
          state.set(e[0], e[1]);
        }
      } else {
        const nl = rec.payload.indexOf('\n');
        if (nl < 1) throw new DurableStateError('corrupt', `journal line ${i + 1}: malformed payload`);
        state.set(rec.payload.slice(0, nl), rec.payload.slice(nl + 1));
      }
      recs.push(rec);
      prevHash = rec.h;
      prevSeq = rec.seq;
    }
    const last = recs[recs.length - 1];
    const lastSeq = last?.seq ?? 0;
    if (head !== undefined) {
      if (lastSeq < head.seq) throw new DurableStateError('rollback', `journal is at seq ${lastSeq} but state.head recorded seq ${head.seq} (truncation or older copy)`);
      if (lastSeq > head.seq + 1) throw new DurableStateError('corrupt', `journal (seq ${lastSeq}) is more than one record ahead of state.head (seq ${head.seq})`);
      if (last !== undefined) {
        if (lastSeq === head.seq && last.h !== head.h) throw new DurableStateError('corrupt', 'journal tail does not match state.head');
        if (lastSeq === head.seq + 1 && last.prev !== head.h) throw new DurableStateError('corrupt', 'journal tail is not chained from state.head');
      }
    } else if (lastSeq > 1) {
      throw new DurableStateError('rollback', `state.head is missing but the journal is at seq ${lastSeq}`);
    }
    if (last !== undefined) {
      if (last.seq < seen.seq) throw new DurableStateError('rollback', `state moved backwards from seq ${seen.seq} to ${last.seq} while open`);
      if (last.seq === seen.seq && last.h !== seen.hash) throw new DurableStateError('rollback', `state forked at seq ${last.seq} while open`);
    } else if (seen.seq > 0) {
      throw new DurableStateError('rollback', 'state was emptied while open');
    }
    return { recs, state, head };
  };

  const quarantine = (): void => {
    const tag = `${now()}-${randomBytes(3).toString('hex')}`;
    for (const p of [journalPath, headPath]) {
      if (existsSync(p)) renameSync(p, `${p}.quarantine-${tag}`);
    }
    fsyncDir(dir);
    seen = { seq: 0, hash: GENESIS };
    recovered = true;
  };

  const loadOrRecover = (): Loaded => {
    try {
      return load();
    } catch (e) {
      if (opts.recoverFromCorruption === true && e instanceof DurableStateError) {
        quarantine();
        return load();
      }
      throw e;
    }
  };

  const observe = (l: Loaded): void => {
    const last = l.recs[l.recs.length - 1];
    if (last && last.seq >= seen.seq) seen = { seq: last.seq, hash: last.h };
  };

  async function withLock<T>(fn: () => T): Promise<T> {
    const nonce = randomBytes(12).toString('hex');
    const body = JSON.stringify({ pid: process.pid, host: hostname(), nonce, t: Date.now() });
    const deadline = Date.now() + lockTimeout;
    for (;;) {
      try {
        const fd = openSync(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
        try {
          writeSync(fd, body);
          fsyncSync(fd);
        } finally {
          closeSync(fd);
        }
        break;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
        tryBreakStale();
        if (Date.now() > deadline) throw new DurableStateError('lock-timeout', `could not acquire ${lockPath} within ${lockTimeout} ms`);
        await sleep(5 + Math.floor(Math.random() * 15));
      }
    }
    try {
      return fn();
    } finally {
      try {
        const cur = JSON.parse(readFileSync(lockPath, 'utf8')) as { nonce?: unknown };
        if (cur.nonce === nonce) unlinkSync(lockPath);
      } catch {
        /* lock already gone or replaced; nothing of ours to release */
      }
    }
  }

  function tryBreakStale(): void {
    let raw: string;
    try {
      raw = readFileSync(lockPath, 'utf8');
    } catch {
      return;
    }
    let owner: { pid?: unknown; host?: unknown; t?: unknown } | undefined;
    try {
      owner = JSON.parse(raw) as { pid?: unknown; host?: unknown; t?: unknown };
    } catch {
      owner = undefined; // torn lock body (owner died between create and write)
    }
    let ageMs = 0;
    try {
      ageMs = Date.now() - statSync(lockPath).mtimeMs;
    } catch {
      return;
    }
    const sameHost = owner?.host === hostname();
    const dead = owner !== undefined && sameHost && typeof owner.pid === 'number' && !pidAlive(owner.pid);
    const tornAndOld = owner === undefined && ageMs > 1000;
    const tooOld = ageMs > staleLock;
    if (!(dead || tornAndOld || tooOld)) return;
    const graveyard = `${lockPath}.stale-${process.pid}-${randomBytes(4).toString('hex')}`;
    try {
      renameSync(lockPath, graveyard);
    } catch {
      return; // someone else took it first
    }
    try {
      if (readFileSync(graveyard, 'utf8') !== raw) {
        // We moved a FRESH lock, not the stale one: put it back if the slot is still free.
        try {
          if (!existsSync(lockPath)) renameSync(graveyard, lockPath);
        } catch {
          /* slot taken again; the displaced owner will notice its nonce is gone only at release (harmless) */
        }
        return;
      }
      unlinkSync(graveyard);
    } catch {
      /* best effort */
    }
  }

  const commit = (l: Loaded, key_: string, valueJson: string): void => {
    const last = l.recs[l.recs.length - 1];
    const seq = (last?.seq ?? 0) + 1;
    const prev = last?.h ?? GENESIS;
    const base = { seq, prev, op: 'set' as const, payload: `${key_}\n${valueJson}`, ts: now() };
    const rec: Rec = { ...base, h: recHash(base) };
    if (key) rec.mac = macOf(key, rec.h);
    let all = [...l.recs, rec];
    if (all.length > compactEvery) {
      // Compact: ONE checkpoint at the same seq the new record would have, chained from the current tail and
      // carrying the full state (including the new value). Head lag stays at most one record.
      const next = new Map(l.state);
      next.set(key_, valueJson);
      const cb = { seq, prev, op: 'checkpoint' as const, payload: JSON.stringify([...next.entries()].sort((x, y) => (x[0] < y[0] ? -1 : 1))), ts: now() };
      const cp: Rec = { ...cb, h: recHash(cb) };
      if (key) cp.mac = macOf(key, cp.h);
      all = [cp];
    }
    const tail = all[all.length - 1]!;
    // Journal first (atomic), head second (atomic). A crash between leaves head one record behind: repaired below.
    atomicWrite(journalPath, `${all.map((r) => JSON.stringify(r)).join('\n')}\n`, opts.testCrashAt === 'after-temp-write');
    if (opts.testCrashAt === 'after-journal-rename') process.kill(process.pid, 'SIGKILL');
    writeHead(tail);
    seen = { seq: tail.seq, hash: tail.h };
  };

  const writeHead = (tail: Rec): void => {
    const head: Head = { seq: tail.seq, h: tail.h };
    if (key) head.mac = macOf(key, headMsg(head.seq, head.h));
    atomicWrite(headPath, `${JSON.stringify(head)}\n`, false);
  };

  const encode = (value: unknown): string => {
    const s = JSON.stringify(value);
    if (s === undefined) throw new DurableStateError('invalid', 'value is not JSON-serialisable');
    if (s.length > maxValue) throw new DurableStateError('too-large', `value exceeds maxValueBytes=${maxValue}`);
    return s;
  };
  const checkKey = (k: string): void => {
    if (typeof k !== 'string' || k.length === 0 || k.length > MAX_KEY || k.includes('\n')) throw new DurableStateError('invalid', 'key must be 1..256 chars without newlines');
  };

  // Initial open: verify under the lock (so a half-finished writer is not mistaken for corruption), repair the head.
  await withLock(() => {
    const l = loadOrRecover();
    observe(l);
    const last = l.recs[l.recs.length - 1];
    if (last && (l.head === undefined || l.head.seq !== last.seq)) writeHead(last);
  });

  const self: DurableState = {
    get recovered() {
      return recovered;
    },
    position: () => ({ ...seen }),
    // Reads take the same lock so they see a consistent (journal, head) pair, never a mid-commit mix.
    async verify() {
      return withLock(() => {
        observe(load());
        return { ...seen };
      });
    },
    async get(k) {
      checkKey(k);
      return withLock(() => {
        const l = load();
        observe(l);
        const v = l.state.get(k);
        return v === undefined ? undefined : (JSON.parse(v) as unknown);
      });
    },
    async keys() {
      return withLock(() => {
        const l = load();
        observe(l);
        return [...l.state.keys()].sort();
      });
    },
    async set(k, value) {
      checkKey(k);
      const vj = encode(value);
      await withLock(() => {
        const l = load();
        const last = l.recs[l.recs.length - 1];
        if (last && (l.head === undefined || l.head.seq !== last.seq)) writeHead(last);
        commit(l, k, vj);
      });
    },
    async update(k, fn) {
      checkKey(k);
      return withLock(() => {
        const l = load();
        const last = l.recs[l.recs.length - 1];
        if (last && (l.head === undefined || l.head.seq !== last.seq)) writeHead(last);
        const curJson = l.state.get(k);
        const next = fn(curJson === undefined ? undefined : (JSON.parse(curJson) as unknown));
        if (next === undefined) return curJson === undefined ? undefined : (JSON.parse(curJson) as unknown);
        const vj = encode(next);
        if (vj !== curJson) commit(l, k, vj);
        return JSON.parse(vj) as unknown;
      });
    },
  };
  return self;
}
